#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BP = ROOT / "Android.bp"
VENDOR_MK = ROOT / "hydrogenone-vendor.mk"

SOURCE_OWNED = (
    {
        "tier": "P1",
        "path": "vendor/lib/libgps.utils.so",
        "module": "libgps.utils",
        "size": 74448,
        "sha256": "ed2bbc9a7d48a221d8224d53919689c47ce534f4adbda86e3e60144d724a8662",
    },
    {
        "tier": "P1",
        "path": "vendor/lib64/libgps.utils.so",
        "module": "libgps.utils",
        "size": 134464,
        "sha256": "dc61233f6157b0ea63a002b4a6e8c1e63693735338211a4bb0efc2b511d7d9e1",
    },
    {
        "tier": "P1",
        "path": "vendor/lib/libloc_core.so",
        "module": "libloc_core",
        "size": 243124,
        "sha256": "6b6b76aa0a16d49caa9ae6703fdb5a0ff3f3babf388dd29f8b85576c6214898c",
    },
    {
        "tier": "P1",
        "path": "vendor/lib64/libloc_core.so",
        "module": "libloc_core",
        "size": 268296,
        "sha256": "00f042d2284a63ee359bcc975c16296f7b944946d9c2e28cb21a19d80eda8af5",
    },
    {
        "tier": "P1",
        "path": "vendor/lib/liblocation_api.so",
        "module": "liblocation_api",
        "size": 75712,
        "sha256": "57d8f4160e212ed32e58a25b8e7ec13e6422b26e370ab889c1f401a1abce2395",
    },
    {
        "tier": "P1",
        "path": "vendor/lib64/liblocation_api.so",
        "module": "liblocation_api",
        "size": 135464,
        "sha256": "5528d33c29fd78b185a16430c23d276f22150a45cff779bb1efcbb9c87392573",
    },
)
SOURCE_MODULES = {entry["module"] for entry in SOURCE_OWNED}
SOURCE_PATHS = {entry["path"] for entry in SOURCE_OWNED}

# Complete direct RED .118 proprietary consumer set for the three source-owned
# Qualcomm location providers above. This list was derived from the generated
# Android.bp DT_NEEDED/shared_libs graph, not from package-name guesses. Keep
# the whole closure intact when replacing the old core providers with source.
PROPRIETARY_LOCATION_CONSUMERS = {
    "libDRPlugin",
    "libdataitems",
    "libdrplugin_client",
    "libevent_observer",
    "libflp",
    "libgdtap",
    "libgeofence",
    "libizat_client_api",
    "libizat_core",
    "liblbs_core",
    "libloc_api_v02",
    "liblocationservice",
    "liblocationservice_glue",
    "liblowi_wifihal",
    "libulp2",
    "libxtadapter",
    "libxtwifi_ulp_adaptor",
    "vendor.qti.gnss@1.0-impl",
    "xtwifi-client",
    "xtwifi-inet-agent",
}


def load_json(name: str) -> dict:
    return json.loads((ROOT / name).read_text(encoding="utf-8"))


def write_json(name: str, value: dict) -> None:
    (ROOT / name).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def selected_path(raw: str) -> str | None:
    line = raw.strip()
    if not line or line.startswith("#"):
        return None
    body = line.split(";", 1)[0]
    return body.split(":", 1)[0].lstrip("-")


def prebuilt_blocks(text: str) -> list[tuple[int, int, str]]:
    lines = text.splitlines(keepends=True)
    blocks: list[tuple[int, int, str]] = []
    i = 0
    while i < len(lines):
        if not re.match(r"^cc_prebuilt_(?:binary|library_shared)\s*\{\s*$", lines[i]):
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


def product_packages() -> set[str]:
    packages: set[str] = set()
    in_packages = False
    for raw in VENDOR_MK.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line.startswith("PRODUCT_PACKAGES +="):
            in_packages = True
            continue
        if not in_packages:
            continue
        if not line:
            in_packages = False
            continue
        package = line.rstrip("\\").strip()
        if package:
            packages.add(package)
        if not line.endswith("\\"):
            in_packages = False
    return packages


def ensure_source_packages_retained() -> None:
    missing = sorted(SOURCE_MODULES - product_packages())
    if missing:
        raise SystemExit(
            "source-owned Qualcomm location packages must stay selected: "
            + ", ".join(missing)
        )


def module_names() -> set[str]:
    text = BP.read_text(encoding="utf-8")
    return {name for _, _, name in prebuilt_blocks(text)}


def ensure_proprietary_consumers_retained() -> None:
    missing = sorted(PROPRIETARY_LOCATION_CONSUMERS - module_names())
    if missing:
        raise SystemExit(
            "required proprietary Qualcomm location consumers disappeared: "
            + ", ".join(missing)
        )


def validate_source_owned_payload() -> dict:
    """Validate the complete prune set before mutating any vendor state."""
    manifest = load_json("proprietary-manifest.json")
    by_path = {entry["path"]: entry for entry in manifest["files"]}

    for expected in SOURCE_OWNED:
        current = by_path.get(expected["path"])
        payload = ROOT / "proprietary" / expected["path"]

        if current is None:
            if payload.exists():
                raise SystemExit(
                    f"payload exists but manifest entry is absent: {expected['path']}"
                )
            continue

        metadata = {
            key: expected[key]
            for key in ("tier", "path", "size", "sha256")
        }
        if current != metadata:
            raise SystemExit(
                f"manifest identity mismatch for {expected['path']}: {current}"
            )

        if not payload.is_file():
            raise SystemExit(
                f"manifest selects payload but file is missing: {expected['path']}"
            )
        if payload.stat().st_size != expected["size"]:
            raise SystemExit(f"size mismatch for {expected['path']}")
        digest = hashlib.sha256(payload.read_bytes()).hexdigest()
        if digest != expected["sha256"]:
            raise SystemExit(
                f"SHA-256 mismatch for {expected['path']}: {digest}"
            )

    return manifest


def prune_payload(manifest: dict) -> dict:
    selected = {entry["path"] for entry in manifest["files"]}

    for expected in SOURCE_OWNED:
        if expected["path"] not in selected:
            continue
        payload = ROOT / "proprietary" / expected["path"]
        payload.unlink()

    manifest["files"] = [
        entry for entry in manifest["files"] if entry["path"] not in SOURCE_PATHS
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


def update_project_metadata(manifest: dict, modules: int, exceptions: int) -> None:
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
    android15["source_owned_location_core_pruned"] = True
    android15["source_owned_location_core_packages_retained"] = sorted(SOURCE_MODULES)
    android15["proprietary_location_consumers_retained"] = sorted(
        PROPRIETARY_LOCATION_CONSUMERS
    )
    android15["checkelf_enabled_modules"] = modules - exceptions
    android15["checkelf_exception_modules"] = exceptions
    write_json("SOURCE_LOCK.json", lock)

    tree = load_json("VENDOR_TREE_AUDIT.json")
    tree["counts"] = counts
    notes = list(tree.get("notes", []))
    note = (
        "RED .118 libgps.utils/libloc_core/liblocation_api prebuilts are pruned because "
        "they override the LineageOS 22.2 source Qualcomm location stack and cause "
        "libgnss undefined symbols. Proprietary Qualcomm location consumers remain and "
        "bind to the source core; Hydrogen One uses the cheryl LineageOS 22.2 legacy "
        "Qualcomm GNSS ABI because it matches RED .118 Pie-era location consumers."
    )
    if note not in notes:
        notes.append(note)
    tree["notes"] = notes
    write_json("VENDOR_TREE_AUDIT.json", tree)


def main() -> int:
    # Preflight every invariant before the first destructive operation.
    ensure_source_packages_retained()
    ensure_proprietary_consumers_retained()
    manifest = validate_source_owned_payload()

    manifest = prune_payload(manifest)
    prune_prebuilt_modules()
    modules, exceptions = update_elf_metadata()
    update_project_metadata(manifest, modules, exceptions)
    print(
        "Pruned source-owned Qualcomm location core prebuilts: "
        f"total={manifest['counts']['total']}, modules={modules}, "
        f"checkelf={modules - exceptions}, exceptions={exceptions}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
