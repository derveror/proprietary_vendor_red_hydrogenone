from __future__ import annotations

import hashlib
import json
import subprocess
import unittest
from pathlib import Path

from tools.legacy_hidl_shim_consumers import (
    EXPECTED_HIDLBASE_SHIM_CONSUMER_COUNT,
    HIDLBASE_SHIM_CONSUMERS,
    HIDLBASE_SHIM_SONAME,
    HIDLBASE_SHIM_SYMBOLS,
)

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "ANDROID15_BLOB_FIXUPS.json"


def elf_dynsyms(path: Path) -> str:
    return subprocess.run(
        ["readelf", "--dyn-syms", "--wide", str(path)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def elf_needed(path: Path) -> set[str]:
    output = subprocess.run(
        ["readelf", "-d", str(path)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    needed: set[str] = set()
    for line in output.splitlines():
        if "(NEEDED)" not in line or "[" not in line or "]" not in line:
            continue
        needed.add(line.split("[", 1)[1].split("]", 1)[0])
    return needed


def undefined_compat_symbols(path: Path) -> set[str]:
    output = elf_dynsyms(path)
    result: set[str] = set()
    for name, symbol in HIDLBASE_SHIM_SYMBOLS.items():
        if any(" UND " in line and symbol in line for line in output.splitlines()):
            result.add(name)
    return result


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class LegacyHidlShimContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = json.loads(
            (ROOT / "proprietary-manifest.json").read_text(encoding="utf-8")
        )
        self.by_path = {entry["path"]: entry for entry in self.manifest["files"]}

    def test_exact_red118_compatibility_surface_is_selected(self) -> None:
        expected = set(HIDLBASE_SHIM_CONSUMERS)
        self.assertEqual(len(expected), EXPECTED_HIDLBASE_SHIM_CONSUMER_COUNT)
        missing = sorted(expected - set(self.by_path))
        self.assertEqual(missing, [], f"legacy HIDL compatibility payload missing: {missing}")

        discovered: set[str] = set()
        by_symbol = {name: set() for name in HIDLBASE_SHIM_SYMBOLS}
        for relative in sorted(self.by_path):
            path = ROOT / "proprietary" / relative
            if not path.is_file():
                continue
            with path.open("rb") as stream:
                if stream.read(4) != b"\x7fELF":
                    continue
            symbols = undefined_compat_symbols(path)
            if symbols:
                discovered.add(relative)
                for name in symbols:
                    by_symbol[name].add(relative)

        self.assertEqual(discovered, expected)
        self.assertEqual(by_symbol["gBnConstructorMap"], expected)
        self.assertEqual(by_symbol["gBsConstructorMap"], set())
        self.assertEqual(by_symbol["Parcel::setData"], set())

    def test_every_legacy_hidl_consumer_loads_lineage_shim(self) -> None:
        missing = []
        for relative in HIDLBASE_SHIM_CONSUMERS:
            path = ROOT / "proprietary" / relative
            if HIDLBASE_SHIM_SONAME not in elf_needed(path):
                missing.append(relative)
        self.assertEqual(
            missing,
            [],
            "RED Android 9 HIDL blobs still lack libhidlbase_shim DT_NEEDED: "
            + ", ".join(missing),
        )

    def test_fixup_registry_preserves_stock_and_patched_identity(self) -> None:
        self.assertTrue(REGISTRY.is_file(), "ANDROID15_BLOB_FIXUPS.json is required")
        if not REGISTRY.is_file():
            return
        registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
        self.assertEqual(registry.get("schema_version"), 1)
        self.assertEqual(
            registry.get("stock_archive_sha256"),
            self.manifest["canonical_stock"]["sha256"],
        )
        self.assertEqual(registry.get("fixup"), "add_needed:libhidlbase_shim.so")
        consumers = registry.get("consumers", {})
        self.assertEqual(set(consumers), set(HIDLBASE_SHIM_CONSUMERS))

        invalid = []
        for relative, record in consumers.items():
            stock = self.by_path[relative]
            path = ROOT / "proprietary" / relative
            if (
                record.get("stock_size") != stock["size"]
                or record.get("stock_sha256") != stock["sha256"]
                or record.get("patched_size") != path.stat().st_size
                or record.get("patched_sha256") != sha256(path)
                or record.get("symbols") != ["gBnConstructorMap"]
            ):
                invalid.append(relative)
        self.assertEqual(invalid, [], f"invalid HIDL fixup registry records: {invalid}")


if __name__ == "__main__":
    unittest.main()
