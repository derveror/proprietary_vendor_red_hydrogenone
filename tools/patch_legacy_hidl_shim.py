#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

from tools.legacy_hidl_shim_consumers import (
    EXPECTED_HIDLBASE_SHIM_CONSUMER_COUNT,
    HIDLBASE_SHIM_CONSUMERS,
    HIDLBASE_SHIM_MODULE,
    HIDLBASE_SHIM_SONAME,
    HIDLBASE_SHIM_SYMBOLS,
)

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "ANDROID15_BLOB_FIXUPS.json"
STOCK_SHA256 = "7277a1accf9595bb727f2189863cf5f6249dd99322e2953432bca6e448365f1e"


def load_json(name: str) -> dict:
    return json.loads((ROOT / name).read_text(encoding="utf-8"))


def write_json(name: str, value: dict) -> None:
    (ROOT / name).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def elf_needed(path: Path) -> set[str]:
    output = subprocess.run(
        ["readelf", "-d", str(path)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return {
        line.split("[", 1)[1].split("]", 1)[0]
        for line in output.splitlines()
        if "(NEEDED)" in line and "[" in line and "]" in line
    }


def undefined_compat_symbols(path: Path) -> list[str]:
    output = subprocess.run(
        ["readelf", "--dyn-syms", "--wide", str(path)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    result = []
    for name, symbol in HIDLBASE_SHIM_SYMBOLS.items():
        if any(" UND " in line and symbol in line for line in output.splitlines()):
            result.append(name)
    return sorted(result)


def resolve_patchelf(explicit: str | None) -> Path:
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    top = os.environ.get("ANDROID_BUILD_TOP")
    if top:
        candidates.append(
            Path(top) / "prebuilts/extract-tools/linux-x86/bin/patchelf-0_18"
        )
    candidates.append(
        ROOT.parents[2] / "prebuilts/extract-tools/linux-x86/bin/patchelf-0_18"
    )
    path = shutil.which("patchelf")
    if path:
        candidates.append(Path(path))

    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate.resolve()
    raise SystemExit(
        "patchelf not found; expected LineageOS "
        "prebuilts/extract-tools/linux-x86/bin/patchelf-0_18"
    )


def selected_manifest() -> tuple[dict, dict[str, dict]]:
    manifest = load_json("proprietary-manifest.json")
    authority = manifest.get("canonical_stock", {})
    if authority.get("sha256") != STOCK_SHA256:
        raise SystemExit(
            f"unexpected canonical stock authority: {authority.get('sha256')}"
        )
    return manifest, {entry["path"]: entry for entry in manifest["files"]}


def discover_surface(by_path: dict[str, dict]) -> dict[str, list[str]]:
    discovered: dict[str, list[str]] = {}
    for relative in sorted(by_path):
        path = ROOT / "proprietary" / relative
        if not path.is_file():
            continue
        with path.open("rb") as stream:
            if stream.read(4) != b"\x7fELF":
                continue
        symbols = undefined_compat_symbols(path)
        if symbols:
            discovered[relative] = symbols
    return discovered


def preflight(by_path: dict[str, dict]) -> dict[str, list[str]]:
    expected = set(HIDLBASE_SHIM_CONSUMERS)
    if len(expected) != EXPECTED_HIDLBASE_SHIM_CONSUMER_COUNT:
        raise SystemExit("internal HIDL shim consumer list has duplicate entries")

    missing_manifest = sorted(expected - set(by_path))
    if missing_manifest:
        raise SystemExit(
            "HIDL shim consumer missing from selected manifest: "
            + ", ".join(missing_manifest)
        )

    discovered = discover_surface(by_path)
    if set(discovered) != expected:
        raise SystemExit(
            "legacy HIDL compatibility surface changed; "
            f"missing={sorted(expected - set(discovered))}, "
            f"unexpected={sorted(set(discovered) - expected)}"
        )

    wrong_symbols = {
        path: symbols
        for path, symbols in discovered.items()
        if symbols != ["gBnConstructorMap"]
    }
    if wrong_symbols:
        raise SystemExit(
            "unexpected Lineage HIDL shim symbol surface: "
            + json.dumps(wrong_symbols, sort_keys=True)
        )
    return discovered


def existing_registry() -> dict:
    if not REGISTRY.is_file():
        return {}
    data = json.loads(REGISTRY.read_text(encoding="utf-8"))
    if data.get("schema_version") != 1:
        raise SystemExit("unsupported ANDROID15_BLOB_FIXUPS.json schema")
    if data.get("stock_archive_sha256") != STOCK_SHA256:
        raise SystemExit("HIDL fixup registry stock authority mismatch")
    if data.get("fixup") != f"add_needed:{HIDLBASE_SHIM_SONAME}":
        raise SystemExit("HIDL fixup registry operation mismatch")
    return data


def verify_or_patch_payloads(
    by_path: dict[str, dict],
    discovered: dict[str, list[str]],
    patchelf: Path | None,
) -> dict:
    old_registry = existing_registry()
    old_records = old_registry.get("consumers", {})
    records: dict[str, dict] = {}

    # Validate every input before mutating the first ELF.
    for relative in HIDLBASE_SHIM_CONSUMERS:
        stock = by_path[relative]
        path = ROOT / "proprietary" / relative
        if not path.is_file():
            raise SystemExit(f"missing HIDL shim payload: {relative}")
        needed = elf_needed(path)
        current_hash = sha256(path)
        current_size = path.stat().st_size

        if HIDLBASE_SHIM_SONAME in needed:
            record = old_records.get(relative)
            if not record:
                raise SystemExit(
                    f"{relative} is already patched but has no trusted fixup registry record"
                )
            if (
                record.get("stock_sha256") != stock["sha256"]
                or record.get("stock_size") != stock["size"]
                or record.get("patched_sha256") != current_hash
                or record.get("patched_size") != current_size
                or record.get("symbols") != discovered[relative]
            ):
                raise SystemExit(f"patched HIDL payload identity mismatch: {relative}")
        else:
            if current_hash != stock["sha256"] or current_size != stock["size"]:
                raise SystemExit(
                    f"unpatched HIDL payload is not canonical RED .118: {relative}"
                )

    for relative in HIDLBASE_SHIM_CONSUMERS:
        stock = by_path[relative]
        path = ROOT / "proprietary" / relative
        if HIDLBASE_SHIM_SONAME not in elf_needed(path):
            if patchelf is None:
                raise SystemExit("patchelf is required for an unpatched HIDL payload")
            subprocess.run(
                [str(patchelf), "--add-needed", HIDLBASE_SHIM_SONAME, str(path)],
                check=True,
            )

        needed = elf_needed(path)
        if HIDLBASE_SHIM_SONAME not in needed:
            raise SystemExit(f"patchelf did not add {HIDLBASE_SHIM_SONAME}: {relative}")

        records[relative] = {
            "stock_size": stock["size"],
            "stock_sha256": stock["sha256"],
            "patched_size": path.stat().st_size,
            "patched_sha256": sha256(path),
            "symbols": discovered[relative],
        }

    registry = {
        "schema_version": 1,
        "stock_archive_sha256": STOCK_SHA256,
        "fixup": f"add_needed:{HIDLBASE_SHIM_SONAME}",
        "source_module": HIDLBASE_SHIM_MODULE,
        "consumer_count": len(records),
        "consumers": records,
    }
    write_json("ANDROID15_BLOB_FIXUPS.json", registry)
    return registry


def update_project_metadata(registry: dict) -> None:
    source_lock = load_json("SOURCE_LOCK.json")
    android15 = source_lock.setdefault("android15_contract", {})
    android15["legacy_hidlbase_shim_fixup"] = {
        "module": HIDLBASE_SHIM_MODULE,
        "soname": HIDLBASE_SHIM_SONAME,
        "consumer_count": registry["consumer_count"],
        "symbols": sorted(HIDLBASE_SHIM_SYMBOLS),
        "consumers": sorted(registry["consumers"]),
    }
    write_json("SOURCE_LOCK.json", source_lock)

    generated = load_json("GENERATED_VENDOR_AUDIT.json")
    generated["android15_blob_fixups"] = registry["consumer_count"]
    manifest = load_json("proprietary-manifest.json")
    actual_selected_bytes = 0
    for entry in manifest["files"]:
        path = ROOT / "proprietary" / entry["path"]
        if path.is_file():
            actual_selected_bytes += path.stat().st_size
    generated["actual_selected_bytes_after_fixups"] = actual_selected_bytes
    write_json("GENERATED_VENDOR_AUDIT.json", generated)

    tree = load_json("VENDOR_TREE_AUDIT.json")
    notes = list(tree.get("notes", []))
    note = (
        "63 retained RED .118 Android 9 HIDL interface blobs require the removed "
        "android::hardware::details::gBnConstructorMap ABI. They are patched with "
        "DT_NEEDED libhidlbase_shim.so, the LineageOS 22.2 compatibility provider; "
        "canonical stock hashes remain in proprietary-manifest.json and patched "
        "identities are recorded separately in ANDROID15_BLOB_FIXUPS.json."
    )
    if note not in notes:
        notes.append(note)
    tree["notes"] = notes
    write_json("VENDOR_TREE_AUDIT.json", tree)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--patchelf")
    parser.add_argument(
        "--payload-only",
        action="store_true",
        help="patch ELF payload and registry only; do not update generated project metadata",
    )
    args = parser.parse_args()

    _, by_path = selected_manifest()
    discovered = preflight(by_path)
    needs_patch = any(
        HIDLBASE_SHIM_SONAME
        not in elf_needed(ROOT / "proprietary" / relative)
        for relative in HIDLBASE_SHIM_CONSUMERS
    )
    patchelf = resolve_patchelf(args.patchelf) if needs_patch else None
    registry = verify_or_patch_payloads(by_path, discovered, patchelf)

    if not args.payload_only:
        update_project_metadata(registry)

    print(
        "Applied LineageOS legacy HIDL shim fixup: "
        f"consumers={registry['consumer_count']}, "
        f"soname={HIDLBASE_SHIM_SONAME}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
