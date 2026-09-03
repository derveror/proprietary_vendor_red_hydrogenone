#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BP = ROOT / "Android.bp"

SOURCE_MODULE = "vendor.qti.hardware.camera.device@1.0"
STALE_ALIAS = "vendor.qti.hardware.camera.device@1.0-v28"
SOURCE_OWNED = (
    {
        "tier": "P1",
        "path": "vendor/lib/vendor.qti.hardware.camera.device@1.0.so",
        "size": 83204,
        "sha256": "9e83e5abca9a6e94aefce7b1f427f1819e29a84bd26ad31ffd609c85e9cfff0e",
    },
    {
        "tier": "P1",
        "path": "vendor/lib64/vendor.qti.hardware.camera.device@1.0.so",
        "size": 135768,
        "sha256": "02a5a67a8fe6433bfb07f3733fa32f3eecc2152b7ae21a1bebd7b42db296e031",
    },
)


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


def prune_payload() -> dict:
    manifest = load_json("proprietary-manifest.json")
    by_path = {entry["path"]: entry for entry in manifest["files"]}
    pruned = {entry["path"] for entry in SOURCE_OWNED}

    for expected in SOURCE_OWNED:
        current = by_path.get(expected["path"])
        metadata = {
            key: expected[key]
            for key in ("tier", "path", "size", "sha256")
        }
        if current is not None and current != metadata:
            raise SystemExit(
                f"manifest identity mismatch for {expected['path']}: {current}"
            )

        payload = ROOT / "proprietary" / expected["path"]
        if not payload.is_file():
            continue
        if payload.stat().st_size != expected["size"]:
            raise SystemExit(f"size mismatch for {expected['path']}")
        digest = hashlib.sha256(payload.read_bytes()).hexdigest()
        if digest != expected["sha256"]:
            raise SystemExit(
                f"SHA-256 mismatch for {expected['path']}: {digest}"
            )
        payload.unlink()

    manifest["files"] = [
        entry for entry in manifest["files"] if entry["path"] not in pruned
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
    lines = [raw for raw in lines if selected_path(raw) not in pruned]
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return manifest


def prebuilt_blocks(text: str) -> list[tuple[int, int, str, str]]:
    lines = text.splitlines(keepends=True)
    blocks: list[tuple[int, int, str, str]] = []
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
            blocks.append((start, i, match.group(1), block))
    return blocks


def rewrite_android_bp() -> None:
    text = BP.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    removals = []
    for start, end, name, _block in prebuilt_blocks(text):
        if name in {SOURCE_MODULE, STALE_ALIAS}:
            removals.append((start, end))

    for start, end in sorted(removals, reverse=True):
        lines[start:end] = []

    out = "".join(lines)
    out = re.sub(
        rf'(?m)^(\s*)"{re.escape(STALE_ALIAS)}",(\s*)$',
        rf'\1"{SOURCE_MODULE}",\2',
        out,
    )
    out = re.sub(r"\n{3,}", "\n\n", out).rstrip() + "\n"
    BP.write_text(out, encoding="utf-8")


def update_vendor_mk() -> None:
    path = ROOT / "hydrogenone-vendor.mk"
    text = path.read_text(encoding="utf-8")
    for module in (SOURCE_MODULE, STALE_ALIAS):
        text = re.sub(
            rf"(?m)^\s*{re.escape(module)}\s*\\\s*\n",
            "",
            text,
        )
    path.write_text(text, encoding="utf-8")


def rewrite_value(value):
    if isinstance(value, str):
        return value.replace(STALE_ALIAS, SOURCE_MODULE)
    if isinstance(value, list):
        return [rewrite_value(item) for item in value]
    if isinstance(value, dict):
        return {key: rewrite_value(item) for key, item in value.items()}
    return value


def update_elf_metadata() -> tuple[int, int]:
    exceptions_doc = load_json("ANDROID15_ELF_EXCEPTIONS.json")
    exceptions = exceptions_doc.get("exceptions", {})
    exceptions.pop(SOURCE_MODULE, None)
    exceptions.pop(STALE_ALIAS, None)
    exceptions_doc["exceptions"] = rewrite_value(exceptions)
    write_json("ANDROID15_ELF_EXCEPTIONS.json", exceptions_doc)

    audit = load_json("ANDROID15_ELF_AUDIT.json")
    modules = audit.get("modules", {})
    modules.pop(SOURCE_MODULE, None)
    modules.pop(STALE_ALIAS, None)
    audit["modules"] = rewrite_value(modules)
    total = len(audit["modules"])
    exception_count = len(exceptions_doc["exceptions"])
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
    android15["source_owned_qti_camera_interface_pruned"] = True
    android15["legacy_red_qti_camera_interface_namespaced"] = False
    android15["checkelf_enabled_modules"] = modules - exceptions
    android15["checkelf_exception_modules"] = exceptions
    write_json("SOURCE_LOCK.json", lock)

    tree = load_json("VENDOR_TREE_AUDIT.json")
    tree["counts"] = counts
    notes = list(tree.get("notes", []))
    note = (
        "LineageOS 22.2 QTI camera/device@1.0 generates the vendor interface ABI "
        "consumed by RED .118 camera.device@1.0-impl; duplicate RED .118 interface "
        "libraries are pruned so only one vendor SONAME owner remains."
    )
    if note not in notes:
        notes.append(note)
    tree["notes"] = notes
    write_json("VENDOR_TREE_AUDIT.json", tree)


def main() -> int:
    manifest = prune_payload()
    rewrite_android_bp()
    update_vendor_mk()
    modules, exceptions = update_elf_metadata()
    update_project_metadata(manifest, modules, exceptions)
    print(
        "Pruned duplicate RED QTI camera interface: "
        f"total={manifest['counts']['total']}, modules={modules}, "
        f"checkelf={modules - exceptions}, exceptions={exceptions}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
