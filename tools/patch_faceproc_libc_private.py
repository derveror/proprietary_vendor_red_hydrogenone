#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STOCK_ARCHIVE_SHA256 = "7277a1accf9595bb727f2189863cf5f6249dd99322e2953432bca6e448365f1e"
TARGET_REL = "vendor/lib/libmmcamera_faceproc.so"
TARGET = ROOT / "proprietary" / TARGET_REL
TARGET64_REL = "vendor/lib64/libmmcamera_faceproc.so"
TARGET64 = ROOT / "proprietary" / TARGET64_REL
REGISTRY = ROOT / "ANDROID15_FACEPROC_LIBC_PRIVATE_FIXUP.json"
STOCK_SIZE = 1246820
STOCK_SHA256 = "388cd36dcd54f7c3842c8178ad0888fabbed045f791de0d6d3c3c29876c3a056"
STOCK64_SIZE = 1312840
STOCK64_SHA256 = "e5aad3eb48220d4a5ef98bf4ba7a56bba846e231857a51f51fb76e8cd8bafed6"
SYMBOLS = (
    "__aeabi_memcpy",
    "__aeabi_memset",
    "__gnu_Unwind_Find_exidx",
)

def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))

def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")

def dyn_symbols(path: Path) -> str:
    return subprocess.run(
        ["readelf", "--dyn-syms", "--wide", str(path)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout

def symbol_lines(path: Path, symbol: str) -> list[str]:
    return [
        line for line in dyn_symbols(path).splitlines()
        if " UND " in line and symbol in line
    ]

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
        if not (path.is_file() and os.access(path, os.X_OK)):
            continue
        version = subprocess.check_output([str(path), "--version"], text=True).strip()
        if "0.18" in version or path.name == "patchelf-0_18":
            return path.resolve()
    raise SystemExit("patchelf 0.18 not found")

def verify_stock_authority() -> None:
    manifest = load_json(ROOT / "proprietary-manifest.json")
    if manifest.get("canonical_stock", {}).get("sha256") != STOCK_ARCHIVE_SHA256:
        raise SystemExit("unexpected canonical stock authority")
    entries = {e["path"]: e for e in manifest["files"]}
    entry = entries.get(TARGET_REL)
    if entry is None or entry.get("size") != STOCK_SIZE or entry.get("sha256") != STOCK_SHA256:
        raise SystemExit(f"canonical RED .118 ARM faceproc identity mismatch: {entry}")
    entry64 = entries.get(TARGET64_REL)
    if entry64 is None or entry64.get("size") != STOCK64_SIZE or entry64.get("sha256") != STOCK64_SHA256:
        raise SystemExit(f"canonical RED .118 ARM64 faceproc identity mismatch: {entry64}")
    if TARGET64.stat().st_size != STOCK64_SIZE or digest(TARGET64) != STOCK64_SHA256:
        raise SystemExit("ARM64 faceproc changed; fixup must remain ARM32-only")

def validate_symbol_surface(path: Path, require_private: bool) -> None:
    for symbol in SYMBOLS:
        lines = symbol_lines(path, symbol)
        if not lines:
            raise SystemExit(f"missing expected faceproc import: {symbol}")
        has_private = any(f"{symbol}@LIBC_PRIVATE" in line for line in lines)
        if has_private != require_private:
            state = "versioned" if require_private else "unversioned"
            raise SystemExit(f"faceproc {symbol} is not in expected {state} state: {lines}")

def verify_patched_registry(current_hash: str, current_size: int) -> dict:
    if not REGISTRY.is_file():
        raise SystemExit("faceproc is patched but fixup registry is missing")
    data = load_json(REGISTRY)
    expected = {
        "schema_version": 1,
        "stock_archive_sha256": STOCK_ARCHIVE_SHA256,
        "path": TARGET_REL,
        "operation": "clear_symbol_versions",
        "symbols": list(SYMBOLS),
        "stock_size": STOCK_SIZE,
        "stock_sha256": STOCK_SHA256,
    }
    for key, value in expected.items():
        if data.get(key) != value:
            raise SystemExit(f"faceproc fixup registry mismatch for {key}: {data.get(key)!r}")
    if data.get("patched_size") != current_size or data.get("patched_sha256") != current_hash:
        raise SystemExit("patched faceproc identity mismatch")
    return data

def update_metadata(record: dict) -> None:
    source_lock_path = ROOT / "SOURCE_LOCK.json"
    source_lock = load_json(source_lock_path)
    source_lock.setdefault("android15_contract", {})["faceproc_libc_private_fixup"] = {
        "path": TARGET_REL,
        "operation": "clear_symbol_versions",
        "symbols": list(SYMBOLS),
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
    generated["faceproc_libc_private_fixups"] = 1
    write_json(generated_path, generated)

    tree_path = ROOT / "VENDOR_TREE_AUDIT.json"
    tree = load_json(tree_path)
    notes = list(tree.get("notes", []))
    note = (
        "RED .118 ARM32 libmmcamera_faceproc.so imports __aeabi_memcpy, "
        "__aeabi_memset and __gnu_Unwind_Find_exidx with the obsolete "
        "LIBC_PRIVATE symbol version. LineageOS 22.2 cheryl, mata and "
        "OnePlus msm8998-common clear those exact symbol versions; the "
        "Hydrogen One keeps its stock camera blob and applies the same "
        "ARM32-only compatibility fixup with original/patched identities pinned."
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
        raise SystemExit(f"missing faceproc payload: {TARGET_REL}")

    current_hash = digest(TARGET)
    current_size = TARGET.stat().st_size

    if current_hash == STOCK_SHA256 and current_size == STOCK_SIZE:
        validate_symbol_surface(TARGET, require_private=True)
        patchelf = resolve_patchelf(args.patchelf)
        for symbol in SYMBOLS:
            subprocess.run(
                [str(patchelf), "--clear-symbol-version", symbol, str(TARGET)],
                check=True,
            )
    else:
        verify_patched_registry(current_hash, current_size)

    validate_symbol_surface(TARGET, require_private=False)
    record = {
        "schema_version": 1,
        "stock_archive_sha256": STOCK_ARCHIVE_SHA256,
        "path": TARGET_REL,
        "operation": "clear_symbol_versions",
        "symbols": list(SYMBOLS),
        "stock_size": STOCK_SIZE,
        "stock_sha256": STOCK_SHA256,
        "patched_size": TARGET.stat().st_size,
        "patched_sha256": digest(TARGET),
    }
    write_json(REGISTRY, record)
    update_metadata(record)
    print(
        "Applied RED ARM32 faceproc LIBC_PRIVATE compatibility fixup; "
        f"patched_sha256={record['patched_sha256']}"
    )
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
