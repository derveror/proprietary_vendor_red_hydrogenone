from __future__ import annotations

import hashlib
import json
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
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

def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def dyn_symbols(path: Path) -> str:
    return subprocess.check_output(
        ["readelf", "--dyn-syms", "--wide", str(path)], text=True
    )

def module_block(name: str) -> str:
    text = (ROOT / "Android.bp").read_text()
    match = re.search(
        rf'cc_prebuilt_library_shared\s*\{{(?:(?!\n\}}).)*?name:\s*"{re.escape(name)}"(?:(?!\n\}}).)*?\n\}}',
        text,
        re.S,
    )
    if match is None:
        raise AssertionError(f"missing Android.bp module: {name}")
    return match.group(0)

class FaceprocLibcPrivateFixupTest(unittest.TestCase):
    def test_manifest_keeps_exact_red118_stock_identity(self):
        manifest = json.loads((ROOT / "proprietary-manifest.json").read_text())
        entry = next(e for e in manifest["files"] if e["path"] == TARGET_REL)
        self.assertEqual(entry["size"], STOCK_SIZE)
        self.assertEqual(entry["sha256"], STOCK_SHA256)
        entry64 = next(e for e in manifest["files"] if e["path"] == TARGET64_REL)
        self.assertEqual(entry64["size"], STOCK64_SIZE)
        self.assertEqual(entry64["sha256"], STOCK64_SHA256)

    def test_arm32_runtime_payload_clears_only_obsolete_libc_private_versions(self):
        dyn = dyn_symbols(TARGET)
        for symbol in SYMBOLS:
            lines = [line for line in dyn.splitlines() if " UND " in line and symbol in line]
            self.assertTrue(lines, symbol)
            self.assertFalse(any(f"{symbol}@LIBC_PRIVATE" in line for line in lines), lines)
        self.assertNotIn("@LIBC_PRIVATE", "\n".join(
            line for line in dyn.splitlines() if any(symbol in line for symbol in SYMBOLS)
        ))

    def test_arm64_faceproc_remains_exact_stock_blob(self):
        self.assertEqual(TARGET64.stat().st_size, STOCK64_SIZE)
        self.assertEqual(sha256(TARGET64), STOCK64_SHA256)

    def test_fixup_registry_pins_original_and_patched_identity(self):
        data = json.loads(REGISTRY.read_text())
        self.assertEqual(data["schema_version"], 1)
        self.assertEqual(data["path"], TARGET_REL)
        self.assertEqual(data["operation"], "clear_symbol_versions")
        self.assertEqual(data["symbols"], list(SYMBOLS))
        self.assertEqual(data["stock_size"], STOCK_SIZE)
        self.assertEqual(data["stock_sha256"], STOCK_SHA256)
        self.assertEqual(data["patched_size"], TARGET.stat().st_size)
        self.assertEqual(data["patched_sha256"], sha256(TARGET))

    def test_checkelf_stays_enabled_and_no_undefined_escape_is_added(self):
        block = module_block("libmmcamera_faceproc")
        self.assertNotIn("check_elf_files: false", block)
        self.assertNotIn("allow_undefined_symbols: true", block)
        self.assertIn('"libc",', block)

    def test_pipeline_applies_fixup_before_final_elf_generation(self):
        text = (ROOT / "tools/apply_android15_vendor_contract.py").read_text()
        self.assertEqual(text.count('"patch_faceproc_libc_private.py",'), 2)
        for marker in ("BASELINE_PIPELINE", "POST_CAMERA_PIPELINE"):
            section = text.split(marker, 1)[1].split(")", 1)[0]
            self.assertLess(
                section.index('"patch_imsdatadaemon_hwbinder.py",'),
                section.index('"patch_faceproc_libc_private.py",'),
            )
            self.assertLess(
                section.index('"patch_faceproc_libc_private.py",'),
                section.rindex('"generate_elf_contract.py",'),
            )

if __name__ == "__main__":
    unittest.main()
