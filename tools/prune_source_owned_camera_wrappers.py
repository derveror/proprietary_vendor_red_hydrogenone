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
        "path": "vendor/lib/camera.device@1.0-impl.so",
        "module": "camera.device@1.0-impl",
        "size": 120412,
        "sha256": "19c1d6cb34da39cce3b6f5caa0bb8b93f38c119da9d35961f9bcf7ebdf87b935",
    },
    {
        "tier": "P1",
        "path": "vendor/lib64/camera.device@1.0-impl.so",
        "module": "camera.device@1.0-impl",
        "size": 200840,
        "sha256": "916deee6f3581889c6989d6255b9bc576f55ed96f0df7dfc9f43f4bcc2fb7fe1",
    },
    {
        "tier": "P1",
        "path": "vendor/lib/camera.device@3.2-impl.so",
        "module": "camera.device@3.2-impl",
        "size": 174448,
        "sha256": "fb747720294c8bc89a02e8c313d2c4cc8e7909926e2bb20710b57050e8ed9c5c",
    },
    {
        "tier": "P1",
        "path": "vendor/lib64/camera.device@3.2-impl.so",
        "module": "camera.device@3.2-impl",
        "size": 266664,
        "sha256": "9151e5e8f42ff8c8844c1c11ce7a35638dd280f8165c9487d268fa055b8b6177",
    },
    {
        "tier": "P1",
        "path": "vendor/lib/camera.device@3.3-impl.so",
        "module": "camera.device@3.3-impl",
        "size": 32144,
        "sha256": "601c58773b031fd2581e298c358dd7997e224544e0dbe715a03545272a1a96b2",
    },
    {
        "tier": "P1",
        "path": "vendor/lib64/camera.device@3.3-impl.so",
        "module": "camera.device@3.3-impl",
        "size": 68928,
        "sha256": "2e2bba086337cce4ba2e563b9242388eb21507e7e1315b1fb7144726fdbb01b9",
    },
    {
        "tier": "P1",
        "path": "vendor/lib/camera.device@3.4-external-impl.so",
        "module": "camera.device@3.4-external-impl",
        "size": 240804,
        "sha256": "c3348cc51ab5cd8796c1b5b743097e6178f0e4cc22d4e38fc0ab1b98ec238150",
    },
    {
        "tier": "P1",
        "path": "vendor/lib64/camera.device@3.4-external-impl.so",
        "module": "camera.device@3.4-external-impl",
        "size": 332616,
        "sha256": "ef6efa3bfdac341eedd4643cfc340a7ee90ffcaf9c4080be37ae26f378f5cd30",
    },
    {
        "tier": "P1",
        "path": "vendor/lib/camera.device@3.4-impl.so",
        "module": "camera.device@3.4-impl",
        "size": 120096,
        "sha256": "100e05bd658fef15d1eaed14c1f3b64bbd2ded146c0fb6fc5d211385b9136527",
    },
    {
        "tier": "P1",
        "path": "vendor/lib64/camera.device@3.4-impl.so",
        "module": "camera.device@3.4-impl",
        "size": 200896,
        "sha256": "adc6c9e6ff21d05e313487c47931f33c243d8d45bcd7e5b3cb286e8a29af5bc6",
    },
)
SOURCE_MODULES = {entry["module"] for entry in SOURCE_OWNED}
SOURCE_PATHS = {entry["path"] for entry in SOURCE_OWNED}
QTI_CAMERA_INTERFACE = "vendor.qti.hardware.camera.device@1.0"


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
        if payload.is_file():
            if payload.stat().st_size != expected["size"]:
                raise SystemExit(f"size mismatch for {expected['path']}")
            digest = hashlib.sha256(payload.read_bytes()).hexdigest()
            if digest != expected["sha256"]:
                raise SystemExit(
                    f"SHA-256 mismatch for {expected['path']}: {digest}"
                )
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
    text = VENDOR_MK.read_text(encoding="utf-8")
    required = set(SOURCE_MODULES)
    packages = product_packages()
    missing_wrappers = sorted(required - packages)
    if missing_wrappers:
        raise SystemExit(
            "source-owned camera wrapper packages must stay selected: "
            + ", ".join(missing_wrappers)
        )

    if QTI_CAMERA_INTERFACE not in packages:
        anchor = "    camera.msm8998 \\\n"
        if anchor not in text:
            raise SystemExit("camera.msm8998 package anchor not found")
        text = text.replace(
            anchor,
            anchor + f"    {QTI_CAMERA_INTERFACE} \\\n",
            1,
        )
        VENDOR_MK.write_text(text, encoding="utf-8")


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
    android15["source_owned_camera_wrappers_pruned"] = True
    android15["source_owned_camera_wrapper_packages_retained"] = sorted(SOURCE_MODULES)
    android15["source_owned_qti_camera_interface_package_retained"] = True
    android15["checkelf_enabled_modules"] = modules - exceptions
    android15["checkelf_exception_modules"] = exceptions
    write_json("SOURCE_LOCK.json", lock)

    tree = load_json("VENDOR_TREE_AUDIT.json")
    tree["counts"] = counts
    notes = list(tree.get("notes", []))
    note = (
        "RED .118 camera.device@1.0/3.x generic HIDL wrapper prebuilts are pruned. "
        "LineageOS 22.2 source wrappers own those module names so camera provider gets "
        "the exported CameraDevice/convert headers required by Android 15. The actual "
        "RED 32-bit camera.msm8998 hardware HAL and lower proprietary camera stack remain."
    )
    if note not in notes:
        notes.append(note)
    tree["notes"] = notes
    write_json("VENDOR_TREE_AUDIT.json", tree)


def main() -> int:
    manifest = prune_payload()
    prune_prebuilt_modules()
    ensure_source_packages_retained()
    modules, exceptions = update_elf_metadata()
    update_project_metadata(manifest, modules, exceptions)
    print(
        "Pruned source-owned camera HIDL wrappers: "
        f"total={manifest['counts']['total']}, modules={modules}, "
        f"checkelf={modules - exceptions}, exceptions={exceptions}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
