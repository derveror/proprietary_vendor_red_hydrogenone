#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BP = ROOT / "Android.bp"

OBSOLETE = (
    {
        "tier": "P1",
        "path": "vendor/lib64/soundfx/libaudiopreprocessing.so",
        "module": "libaudiopreprocessing",
        "size": 47112,
        "sha256": "810488604119153ba1afc3b018ce44365595d1436188704214a417889637dd52",
    },
    {
        "tier": "P1",
        "path": "vendor/lib64/libwebrtc_audio_preprocessing.so",
        "module": "libwebrtc_audio_preprocessing",
        "size": 1253728,
        "sha256": "4a0af25730ddf62a812d674fc89e095e1197c4d43f620b651961041b32a8ba9d",
    },
)
OBSOLETE_PATHS = {entry["path"] for entry in OBSOLETE}
OBSOLETE_MODULES = {entry["module"] for entry in OBSOLETE}
SOURCE_PACKAGE = "libaudiopreprocessing"
PRIVATE_COMPANION = "libwebrtc_audio_preprocessing"


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


def assert_dependency_is_self_contained() -> None:
    audit = load_json("ANDROID15_ELF_AUDIT.json")
    modules = audit.get("modules", {})
    violations: list[str] = []
    for name, record in modules.items():
        if name in OBSOLETE_MODULES:
            continue
        needed = set(record.get("shared_libs", []))
        overlap = needed & OBSOLETE_MODULES
        if overlap:
            violations.append(f"{name} -> {', '.join(sorted(overlap))}")
    if violations:
        raise SystemExit(
            "obsolete audio preprocessing stack has retained proprietary consumers: "
            + "; ".join(sorted(violations))
        )

    legacy = modules.get(SOURCE_PACKAGE)
    if legacy is not None:
        needed = set(legacy.get("shared_libs", []))
        if PRIVATE_COMPANION not in needed:
            raise SystemExit(
                "unexpected RED libaudiopreprocessing dependency graph: "
                f"missing {PRIVATE_COMPANION}"
            )


def prune_payload() -> dict:
    manifest = load_json("proprietary-manifest.json")
    by_path = {entry["path"]: entry for entry in manifest["files"]}

    for expected in OBSOLETE:
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
                raise SystemExit(
                    f"size mismatch for {expected['path']}: "
                    f"{payload.stat().st_size} != {expected['size']}"
                )
            digest = hashlib.sha256(payload.read_bytes()).hexdigest()
            if digest != expected["sha256"]:
                raise SystemExit(
                    f"SHA-256 mismatch for {expected['path']}: {digest}"
                )
            payload.unlink()

    manifest["files"] = [
        entry for entry in manifest["files"] if entry["path"] not in OBSOLETE_PATHS
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
    lines = [raw for raw in lines if selected_path(raw) not in OBSOLETE_PATHS]
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
        if name in OBSOLETE_MODULES
    ]
    for start, end in sorted(removals, reverse=True):
        lines[start:end] = []
    BP.write_text(
        re.sub(r"\n{3,}", "\n\n", "".join(lines)).rstrip() + "\n",
        encoding="utf-8",
    )


def package_selected(text: str, module: str) -> bool:
    return bool(re.search(rf"(?m)^\s*{re.escape(module)}\s*\\?\s*$", text))


def update_vendor_packages() -> None:
    path = ROOT / "hydrogenone-vendor.mk"
    text = path.read_text(encoding="utf-8")

    # The private Android 9 WebRTC shared library has no modern owner and is
    # intentionally removed from PRODUCT_PACKAGES.
    text = re.sub(
        rf"(?m)^\s*{re.escape(PRIVATE_COMPANION)}\s*\\?\s*\n",
        "",
        text,
    )

    # Keep the generic module name selected after removing the RED prebuilt so
    # LineageOS 22.2's vendor source libaudiopreprocessing owns the package.
    if not package_selected(text, SOURCE_PACKAGE):
        anchor = "    libaudioalsa \\\n"
        if anchor not in text:
            raise SystemExit("cannot locate libaudioalsa package anchor")
        text = text.replace(
            anchor,
            anchor + f"    {SOURCE_PACKAGE} \\\n",
            1,
        )

    path.write_text(text, encoding="utf-8")


def update_elf_metadata() -> tuple[int, int]:
    exceptions_doc = load_json("ANDROID15_ELF_EXCEPTIONS.json")
    exceptions = exceptions_doc.get("exceptions", {})
    for module in OBSOLETE_MODULES:
        exceptions.pop(module, None)
    exceptions_doc["exceptions"] = exceptions
    write_json("ANDROID15_ELF_EXCEPTIONS.json", exceptions_doc)

    audit = load_json("ANDROID15_ELF_AUDIT.json")
    modules = audit.get("modules", {})
    for module in OBSOLETE_MODULES:
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
    android15["obsolete_audio_preprocessing_pruned"] = True
    android15["source_owned_audio_preprocessing_package"] = SOURCE_PACKAGE
    android15["obsolete_audio_preprocessing_paths"] = sorted(OBSOLETE_PATHS)
    android15["checkelf_enabled_modules"] = modules - exceptions
    android15["checkelf_exception_modules"] = exceptions
    write_json("SOURCE_LOCK.json", lock)

    tree = load_json("VENDOR_TREE_AUDIT.json")
    tree["counts"] = counts
    notes = list(tree.get("notes", []))
    note = (
        "RED .118 libaudiopreprocessing/libwebrtc_audio_preprocessing are pruned: "
        "the legacy pair is self-contained, the active RED effect configuration uses "
        "Qualcomm voice preprocessing, and LineageOS 22.2 provides the generic vendor "
        "libaudiopreprocessing package from current source."
    )
    if note not in notes:
        notes.append(note)
    tree["notes"] = notes
    write_json("VENDOR_TREE_AUDIT.json", tree)


def main() -> int:
    assert_dependency_is_self_contained()
    manifest = prune_payload()
    prune_prebuilt_modules()
    update_vendor_packages()
    modules, exceptions = update_elf_metadata()
    update_project_metadata(manifest, modules, exceptions)
    print(
        "Pruned obsolete RED audio preprocessing stack: "
        f"total={manifest['counts']['total']}, modules={modules}, "
        f"checkelf={modules - exceptions}, exceptions={exceptions}; "
        f"source package retained={SOURCE_PACKAGE}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
