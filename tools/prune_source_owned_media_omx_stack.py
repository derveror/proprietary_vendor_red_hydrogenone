#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BP = ROOT / "Android.bp"

SOURCE_OWNED = (
    {
        "tier": "P1",
        "path": "vendor/bin/hw/android.hardware.media.omx@1.0-service",
        "module": "android.hardware.media.omx@1.0-service",
        "size": 10948,
        "sha256": "9c130527c59717f0e1fa37083a3ced9fa68a333c2a11b198b9411c9536e4de49",
    },
    {
        "tier": "P1",
        "path": "vendor/lib/libgui_vendor.so",
        "module": "libgui_vendor",
        "size": 493060,
        "sha256": "c97538573ab128f6301dc83827d2b2e898aa416649201b56323648fcd32f6efe",
    },
    {
        "tier": "P1",
        "path": "vendor/lib/vndk/libstagefright_foundation.so",
        "module": "libstagefright_foundation-v28",
        "size": 150348,
        "sha256": "aa0926cc75878d82ead74bcfbdbcb3e681d1ffb2abb77aa9f958e2523a8edc2b",
    },
    {
        "tier": "P1",
        "path": "vendor/lib/vndk/libstagefright_omx.so",
        "module": "libstagefright_omx-v28",
        "size": 306416,
        "sha256": "23bbc5282e5cdaeb014dd2c837c1fd29a0f9aba6facfcc207024530c8c208165",
    },
)
SOURCE_PATHS = {entry["path"] for entry in SOURCE_OWNED}
SOURCE_MODULES = {entry["module"] for entry in SOURCE_OWNED}
MEDIA_HAL = "android.hardware.media.omx"


def load_json(name: str) -> dict:
    return json.loads((ROOT / name).read_text(encoding="utf-8"))


def write_json(name: str, value: dict) -> None:
    (ROOT / name).write_text(
        json.dumps(value, indent=2) + "\n",
        encoding="utf-8",
    )


def selected_path(raw: str) -> str | None:
    line = raw.strip()
    if not line or line.startswith("#"):
        return None
    body = line.split(";", 1)[0]
    return body.split(":", 1)[0].lstrip("-")


def preflight_payload_identity() -> None:
    manifest = load_json("proprietary-manifest.json")
    by_path = {entry["path"]: entry for entry in manifest["files"]}

    manifest_present = SOURCE_PATHS & set(by_path)
    payload_present = {
        entry["path"]
        for entry in SOURCE_OWNED
        if (ROOT / "proprietary" / entry["path"]).is_file()
    }

    if not manifest_present and not payload_present:
        return

    if manifest_present != SOURCE_PATHS or payload_present != SOURCE_PATHS:
        raise SystemExit(
            "partial media OMX source-owned state: "
            f"manifest={sorted(manifest_present)}, payload={sorted(payload_present)}"
        )

    for expected in SOURCE_OWNED:
        current = by_path[expected["path"]]
        metadata = {
            key: expected[key]
            for key in ("tier", "path", "size", "sha256")
        }
        if current != metadata:
            raise SystemExit(
                f"manifest identity mismatch for {expected['path']}: {current}"
            )

        payload = ROOT / "proprietary" / expected["path"]
        if payload.stat().st_size != expected["size"]:
            raise SystemExit(f"size mismatch for {expected['path']}")
        digest = hashlib.sha256(payload.read_bytes()).hexdigest()
        if digest != expected["sha256"]:
            raise SystemExit(
                f"SHA-256 mismatch for {expected['path']}: {digest}"
            )


def assert_legacy_closure_is_self_contained() -> None:
    audit = load_json("ANDROID15_ELF_AUDIT.json")
    modules = audit.get("modules", {})
    violations: list[str] = []

    for name, record in modules.items():
        if name in SOURCE_MODULES:
            continue
        for arch, data in record.get("architectures", {}).items():
            overlap = set(data.get("shared_libs", [])) & SOURCE_MODULES
            if overlap:
                violations.append(
                    f"{name}[{arch}] -> {', '.join(sorted(overlap))}"
                )

    if violations:
        raise SystemExit(
            "retained proprietary consumers still depend on the obsolete "
            "RED media wrapper closure: "
            + "; ".join(sorted(violations))
        )

    service = modules.get("android.hardware.media.omx@1.0-service")
    omx = modules.get("libstagefright_omx-v28")
    if service is not None:
        deps = {
            dep
            for data in service.get("architectures", {}).values()
            for dep in data.get("shared_libs", [])
        }
        if "libstagefright_omx-v28" not in deps:
            raise SystemExit("unexpected stock OMX service dependency graph")
    if omx is not None:
        deps = {
            dep
            for data in omx.get("architectures", {}).values()
            for dep in data.get("shared_libs", [])
        }
        required = {"libgui_vendor", "libstagefright_foundation-v28"}
        if not required.issubset(deps):
            raise SystemExit(
                "unexpected stock libstagefright_omx-v28 dependency graph"
            )


def prune_payload() -> dict:
    preflight_payload_identity()
    manifest = load_json("proprietary-manifest.json")

    for entry in SOURCE_OWNED:
        payload = ROOT / "proprietary" / entry["path"]
        if payload.is_file():
            payload.unlink()

    manifest["files"] = [
        entry for entry in manifest["files"]
        if entry["path"] not in SOURCE_PATHS
    ]
    manifest["files"].sort(key=lambda entry: (entry["tier"], entry["path"]))
    counts = Counter(entry["tier"] for entry in manifest["files"])
    manifest["counts"] = {
        "P0": counts.get("P0", 0),
        "P1": counts.get("P1", 0),
        "P2": counts.get("P2", 0),
        "total": len(manifest["files"]),
    }
    write_json("proprietary-manifest.json", manifest)

    path = ROOT / "proprietary-files.txt"
    lines = path.read_text(encoding="utf-8").splitlines()
    lines = [raw for raw in lines if selected_path(raw) not in SOURCE_PATHS]
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return manifest


def prebuilt_blocks(text: str) -> list[tuple[int, int, str]]:
    lines = text.splitlines(keepends=True)
    blocks: list[tuple[int, int, str]] = []
    i = 0
    while i < len(lines):
        if not re.match(
            r"^cc_prebuilt_(?:binary|library_shared)\s*\{\s*$",
            lines[i],
        ):
            i += 1
            continue
        start = i
        depth = lines[i].count("{") - lines[i].count("}")
        i += 1
        while i < len(lines) and depth > 0:
            depth += lines[i].count("{") - lines[i].count("}")
            i += 1
        block = "".join(lines[start:i])
        match = re.search(r'(?m)^\s*name:\s*"([^"]+)"', block)
        if match:
            blocks.append((start, i, match.group(1)))
    return blocks


def prune_prebuilt_modules() -> None:
    text = BP.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    removals = [
        (start, end)
        for start, end, name in prebuilt_blocks(text)
        if name in SOURCE_MODULES
    ]
    for start, end in sorted(removals, reverse=True):
        lines[start:end] = []
    BP.write_text(
        re.sub(r"\n{3,}", "\n\n", "".join(lines)).rstrip() + "\n",
        encoding="utf-8",
    )


def prune_vendor_packages() -> None:
    path = ROOT / "hydrogenone-vendor.mk"
    text = path.read_text(encoding="utf-8")
    for module in SOURCE_MODULES:
        text = re.sub(
            rf"(?m)^\s*{re.escape(module)}\s*\\\s*\n",
            "",
            text,
        )
        text = re.sub(
            rf"(?m)^\s*{re.escape(module)}\s*$\n?",
            "",
            text,
        )
    path.write_text(text, encoding="utf-8")


def update_vintf_ownership() -> None:
    fragment = ROOT / "vintf/media-omx.xml"
    if fragment.exists():
        fragment.unlink()

    contract = load_json("VINTF_PROPRIETARY_CONTRACT.json")
    exclusions = set(contract.get("source_owned_exclusions", []))
    exclusions.add(MEDIA_HAL)
    contract["source_owned_exclusions"] = sorted(exclusions)
    contract.get("modules", {}).pop(
        "android.hardware.media.omx@1.0-service",
        None,
    )
    contract["proprietary_fqname_count"] = sum(
        len(fqnames)
        for record in contract.get("modules", {}).values()
        for fqnames in record.get("hals", {}).values()
    )
    write_json("VINTF_PROPRIETARY_CONTRACT.json", contract)


def update_elf_metadata() -> tuple[int, int]:
    exceptions_doc = load_json("ANDROID15_ELF_EXCEPTIONS.json")
    exceptions = exceptions_doc.get("exceptions", {})
    for module in SOURCE_MODULES:
        exceptions.pop(module, None)
    exceptions_doc["exceptions"] = exceptions
    write_json("ANDROID15_ELF_EXCEPTIONS.json", exceptions_doc)

    audit = load_json("ANDROID15_ELF_AUDIT.json")
    modules = audit.get("modules", {})
    for module in SOURCE_MODULES:
        modules.pop(module, None)
    audit["modules"] = modules
    total = len(modules)
    exception_count = len(exceptions)
    audit["summary"] = {
        **audit.get("summary", {}),
        "total_modules": total,
        "checkelf_enabled": total - exception_count,
        "checkelf_exceptions": exception_count,
    }
    write_json("ANDROID15_ELF_AUDIT.json", audit)
    return total, exception_count


def update_project_metadata(
    manifest: dict,
    modules: int,
    exceptions: int,
) -> None:
    counts = manifest["counts"]
    selected_bytes = sum(int(entry["size"]) for entry in manifest["files"])

    generated = load_json("GENERATED_VENDOR_AUDIT.json")
    generated.update(
        {
            "selected_files": len(manifest["files"]),
            "p0": counts["P0"],
            "p1": counts["P1"],
            "p2": counts["P2"],
            "selected_bytes": selected_bytes,
            "elf_modules": modules,
            "checkelf_enabled": modules - exceptions,
            "checkelf_exceptions": exceptions,
        }
    )
    write_json("GENERATED_VENDOR_AUDIT.json", generated)

    lock = load_json("SOURCE_LOCK.json")
    lock["selected_files"] = len(manifest["files"])
    android15 = lock.setdefault("android15_contract", {})
    android15["legacy_vndk28_stagefright_namespaced"] = False
    android15["source_owned_media_omx_stack_pruned"] = True
    android15["source_owned_media_omx_modules"] = [
        "android.hardware.media.omx@1.0-service",
        "libgui_vendor",
        "libstagefright_foundation",
        "libstagefright_omx",
    ]
    android15["checkelf_enabled_modules"] = modules - exceptions
    android15["checkelf_exception_modules"] = exceptions
    write_json("SOURCE_LOCK.json", lock)

    tree = load_json("VENDOR_TREE_AUDIT.json")
    tree["counts"] = counts
    notes = list(tree.get("notes", []))
    note = (
        "RED .118 media OMX wrapper closure "
        "(android.hardware.media.omx@1.0-service, libgui_vendor, "
        "libstagefright_omx VNDK28, libstagefright_foundation VNDK28) "
        "is pruned after the Android 15 ABI gate proved the legacy GUI/media "
        "interfaces incompatible and the reverse dependency graph proved the "
        "closure self-contained. LineageOS 22.2 source owns the OMX frontend; "
        "Qualcomm codec payload remains proprietary."
    )
    if note not in notes:
        notes.append(note)
    tree["notes"] = notes
    write_json("VENDOR_TREE_AUDIT.json", tree)


def main() -> int:
    assert_legacy_closure_is_self_contained()
    manifest = prune_payload()
    prune_prebuilt_modules()
    prune_vendor_packages()
    update_vintf_ownership()
    modules, exceptions = update_elf_metadata()
    update_project_metadata(manifest, modules, exceptions)
    print(
        "Pruned source-owned media OMX wrapper closure: "
        f"total={manifest['counts']['total']}, modules={modules}, "
        f"checkelf={modules - exceptions}, exceptions={exceptions}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
