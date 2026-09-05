from __future__ import annotations

import hashlib
import json
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET_REL = "vendor/bin/imsdatadaemon"
TARGET = ROOT / "proprietary" / TARGET_REL
REGISTRY = ROOT / "ANDROID15_IMSDATA_HWBINDER_FIXUP.json"
STOCK_SHA256 = "30d2e071021fe7d46de594024879e806bc17e5b23770e78d269e2b37362dd06a"
STOCK_SIZE = 201744
SYMBOL = "_ZN7android8hardware12ProcessState16initWithMmapSizeEm"

def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def needed(path: Path) -> list[str]:
    out = subprocess.check_output(["readelf", "-d", str(path)], text=True)
    return re.findall(r"\(NEEDED\).*Shared library: \[([^\]]+)\]", out)

class ImsDataHwbinderFixupTest(unittest.TestCase):
    def test_manifest_keeps_exact_red118_stock_identity(self):
        manifest = json.loads((ROOT / "proprietary-manifest.json").read_text())
        entry = next(e for e in manifest["files"] if e["path"] == TARGET_REL)
        self.assertEqual(entry["size"], STOCK_SIZE)
        self.assertEqual(entry["sha256"], STOCK_SHA256)

    def test_runtime_payload_retargets_old_hwbinder_needed_to_libhidlbase(self):
        deps = needed(TARGET)
        self.assertIn("libhidlbase.so", deps)
        self.assertNotIn("libhwbinder.so", deps)
        dyn = subprocess.check_output(
            ["readelf", "--dyn-syms", "--wide", str(TARGET)], text=True
        )
        self.assertTrue(any(" UND " in line and SYMBOL in line for line in dyn.splitlines()))

    def test_fixup_registry_pins_original_and_patched_identity(self):
        data = json.loads(REGISTRY.read_text())
        self.assertEqual(data["schema_version"], 1)
        self.assertEqual(data["path"], TARGET_REL)
        self.assertEqual(data["operation"], "replace_needed")
        self.assertEqual(data["old_needed"], "libhwbinder.so")
        self.assertEqual(data["new_needed"], "libhidlbase.so")
        self.assertEqual(data["symbol"], SYMBOL)
        self.assertEqual(data["stock_size"], STOCK_SIZE)
        self.assertEqual(data["stock_sha256"], STOCK_SHA256)
        self.assertEqual(data["patched_size"], TARGET.stat().st_size)
        self.assertEqual(data["patched_sha256"], sha256(TARGET))

    def test_generated_checkelf_graph_uses_actual_patched_provider(self):
        bp = (ROOT / "Android.bp").read_text()
        match = re.search(
            r'cc_prebuilt_binary\s*\{(?:(?!\n\}).)*?name:\s*"imsdatadaemon"(?:(?!\n\}).)*?\n\}',
            bp,
            re.S,
        )
        self.assertIsNotNone(match)
        block = match.group(0)
        self.assertIn('"libhidlbase",', block)
        self.assertNotIn('"libhwbinder",', block)

        audit = json.loads((ROOT / "ANDROID15_ELF_AUDIT.json").read_text())
        libs = audit["modules"]["imsdatadaemon"]["architectures"]["android_arm64"]["shared_libs"]
        self.assertIn("libhidlbase", libs)
        self.assertNotIn("libhwbinder", libs)

    def test_pipeline_applies_fixup_before_post_fixup_generation(self):
        text = (ROOT / "tools/apply_android15_vendor_contract.py").read_text()
        self.assertEqual(text.count('"patch_imsdatadaemon_hwbinder.py",'), 2)
        for marker in ("BASELINE_PIPELINE", "POST_CAMERA_PIPELINE"):
            section = text.split(marker, 1)[1].split(")", 1)[0]
            self.assertLess(
                section.index('"patch_legacy_hidl_shim.py",'),
                section.index('"patch_imsdatadaemon_hwbinder.py",'),
            )
            self.assertLess(
                section.index('"patch_imsdatadaemon_hwbinder.py",'),
                section.rindex('"generate_elf_contract.py",'),
            )
