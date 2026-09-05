#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STOCK_ARCHIVE_SHA256 = "7277a1accf9595bb727f2189863cf5f6249dd99322e2953432bca6e448365f1e"
TARGET_REL = "vendor/bin/imsdatadaemon"
TARGET = ROOT / "proprietary" / TARGET_REL
REGISTRY = ROOT / "ANDROID15_IMSDATA_HWBINDER_FIXUP.json"
STOCK_SIZE = 201744
STOCK_SHA256 = "30d2e071021fe7d46de594024879e806bc17e5b23770e78d269e2b37362dd06a"
OLD_NEEDED = "libhwbinder.so"
NEW_NEEDED = "libhidlbase.so"
SYMBOL = "_ZN7android8hardware12ProcessState16initWithMmapSizeEm"

def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))

def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")

def needed(path: Path) -> list[str]:
    out = subprocess.run(
        ["readelf", "-d", str(path)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return re.findall(r"\(NEEDED\).*Shared library: \[([^\]]+)\]", out)

def has_required_import(path: Path) -> bool:
    out = subprocess.run(
        ["readelf", "--dyn-syms", "--wide", str(path)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return any(" UND " in line and SYMBOL in line for line in out.splitlines())

def resolve_patchelf(explicit: str | None) -> Path:
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    top = os.environ.get("ANDROID_BUILD_TOP")
    if top:
        candidates.append(Path(top) / "prebuilts/extract-tools/linux-x86/bin/patchelf-0_18")
    candidates.append(ROOT.parents[2] / "prebuilts/extract-tools/linux-x86/bin/patchelf-0_18")
    system = shutil.which("patchelf")
    if system:
        candidates.append(Path(system))
    for path in candidates:
        if path.is_file() and os.access(path, os.X_OK):
            return path.resolve()
    raise SystemExit("patchelf not found")

def verify_stock_authority() -> None:
    manifest = load_json(ROOT / "proprietary-manifest.json")
    if manifest.get("canonical_stock", {}).get("sha256") != STOCK_ARCHIVE_SHA256:
        raise SystemExit("unexpected canonical stock authority")
    entry = next((e for e in manifest["files"] if e["path"] == TARGET_REL), None)
    if entry is None:
        raise SystemExit(f"missing canonical stock manifest entry: {TARGET_REL}")
    if entry.get("size") != STOCK_SIZE or entry.get("sha256") != STOCK_SHA256:
        raise SystemExit(f"canonical RED .118 imsdatadaemon identity mismatch: {entry}")

def verify_patched_registry(current_hash: str, current_size: int) -> dict:
    if not REGISTRY.is_file():
        raise SystemExit("imsdatadaemon is patched but fixup registry is missing")
    data = load_json(REGISTRY)
    expected = {
        "schema_version": 1,
        "stock_archive_sha256": STOCK_ARCHIVE_SHA256,
        "path": TARGET_REL,
        "operation": "replace_needed",
        "old_needed": OLD_NEEDED,
        "new_needed": NEW_NEEDED,
        "symbol": SYMBOL,
        "stock_size": STOCK_SIZE,
        "stock_sha256": STOCK_SHA256,
    }
    for key, value in expected.items():
        if data.get(key) != value:
            raise SystemExit(f"imsdatadaemon fixup registry mismatch for {key}: {data.get(key)!r}")
    if data.get("patched_size") != current_size or data.get("patched_sha256") != current_hash:
        raise SystemExit("patched imsdatadaemon identity mismatch")
    return data

def update_metadata(record: dict) -> None:
    source_lock_path = ROOT / "SOURCE_LOCK.json"
    source_lock = load_json(source_lock_path)
    source_lock.setdefault("android15_contract", {})["imsdatadaemon_hwbinder_fixup"] = {
        "path": TARGET_REL,
        "operation": "replace_needed",
        "from": OLD_NEEDED,
        "to": NEW_NEEDED,
        "symbol": SYMBOL,
        "stock_sha256": STOCK_SHA256,
        "patched_sha256": record["patched_sha256"],
    }
    write_json(source_lock_path, source_lock)

    generated_path = ROOT / "GENERATED_VENDOR_AUDIT.json"
    generated = load_json(generated_path)
    manifest = load_json(ROOT / "proprietary-manifest.json")
    generated["actual_selected_bytes_after_fixups"] = sum(
        (ROOT / "proprietary" / e["path"]).stat().st_size
        for e in manifest["files"]
        if (ROOT / "proprietary" / e["path"]).is_file()
    )
    generated["imsdatadaemon_hwbinder_fixups"] = 1
    write_json(generated_path, generated)

    tree_path = ROOT / "VENDOR_TREE_AUDIT.json"
    tree = load_json(tree_path)
    notes = list(tree.get("notes", []))
    note = (
        "RED .118 imsdatadaemon is Android 9 and directly DT_NEEDED libhwbinder.so "
        "for android::hardware::ProcessState::initWithMmapSize. Android 15 folds the "
        "hwbinder implementation into libhidlbase, so the exact stock daemon is "
        "patched to DT_NEEDED libhidlbase.so; original and patched identities are "
        "pinned in ANDROID15_IMSDATA_HWBINDER_FIXUP.json."
    )
    if note not in notes:
        notes.append(note)
    tree["notes"] = notes
    write_json(tree_path, tree)

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--patchelf")
    args = parser.parse_args()

    verify_stock_authority()
    if not TARGET.is_file():
        raise SystemExit(f"missing imsdatadaemon payload: {TARGET_REL}")
    if not has_required_import(TARGET):
        raise SystemExit("RED imsdatadaemon ProcessState import changed")

    current_hash = digest(TARGET)
    current_size = TARGET.stat().st_size
    deps = needed(TARGET)

    if current_hash == STOCK_SHA256 and current_size == STOCK_SIZE:
        if OLD_NEEDED not in deps or NEW_NEEDED in deps:
            raise SystemExit("canonical RED imsdatadaemon DT_NEEDED surface changed")
        patchelf = resolve_patchelf(args.patchelf)
        subprocess.run(
            [str(patchelf), "--replace-needed", OLD_NEEDED, NEW_NEEDED, str(TARGET)],
            check=True,
        )
    else:
        verify_patched_registry(current_hash, current_size)

    deps = needed(TARGET)
    if OLD_NEEDED in deps or NEW_NEEDED not in deps:
        raise SystemExit("imsdatadaemon hwbinder->hidlbase replacement did not take effect")
    if not has_required_import(TARGET):
        raise SystemExit("imsdatadaemon ProcessState import unexpectedly changed after patch")

    record = {
        "schema_version": 1,
        "stock_archive_sha256": STOCK_ARCHIVE_SHA256,
        "path": TARGET_REL,
        "operation": "replace_needed",
        "old_needed": OLD_NEEDED,
        "new_needed": NEW_NEEDED,
        "symbol": SYMBOL,
        "stock_size": STOCK_SIZE,
        "stock_sha256": STOCK_SHA256,
        "patched_size": TARGET.stat().st_size,
        "patched_sha256": digest(TARGET),
    }
    write_json(REGISTRY, record)
    update_metadata(record)
    print(
        "Applied RED imsdatadaemon hwbinder compatibility fixup: "
        f"{OLD_NEEDED} -> {NEW_NEEDED}; patched_sha256={record['patched_sha256']}"
    )
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
