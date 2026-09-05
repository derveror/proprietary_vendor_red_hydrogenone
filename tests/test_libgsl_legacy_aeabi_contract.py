from __future__ import annotations

import hashlib
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RED_LIBGSL_ARM = ROOT / "proprietary/vendor/lib/libgsl.so"
EXPECTED_SHA256 = "dc22e2b816dcb16a49797b9c758a2872ffa65a3bb4871a2b50b5866dcc4573cb"

def prebuilt_block(name: str) -> str:
    text = (ROOT / "Android.bp").read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    for i, line in enumerate(lines):
        if not re.match(r"^cc_prebuilt_(?:binary|library_shared)\s*\{\s*$", line):
            continue
        depth = line.count("{") - line.count("}")
        j = i + 1
        while j < len(lines) and depth > 0:
            depth += lines[j].count("{") - lines[j].count("}")
            j += 1
        block = "".join(lines[i:j])
        if re.search(rf'(?m)^\s*name:\s*"{re.escape(name)}"\s*,?$', block):
            return block
    raise AssertionError(f"missing prebuilt block: {name}")

class LibgslLegacyAeabiContractTest(unittest.TestCase):
    def test_red_arm_libgsl_has_precise_legacy_undefined_symbol_allowance(self) -> None:
        self.assertTrue(RED_LIBGSL_ARM.is_file())
        self.assertEqual(hashlib.sha256(RED_LIBGSL_ARM.read_bytes()).hexdigest(), EXPECTED_SHA256)
        block = prebuilt_block("libgsl")
        self.assertNotIn("check_elf_files: false", block)
        self.assertRegex(block, r"(?s)arch:\s*\{.*?arm:\s*\{.*?allow_undefined_symbols:\s*true,.*?\}.*?\}")
        arch_block = re.search(r"(?s)\n    arch:\s*\{\n(.*?)\n    \},\n    compile_multilib", block)
        self.assertIsNotNone(arch_block)
        self.assertNotIn("arm64:", arch_block.group(1))

    def test_audit_records_only_the_legacy_arm_runtime_symbol_allowance(self) -> None:
        audit = json.loads((ROOT / "ANDROID15_ELF_AUDIT.json").read_text(encoding="utf-8"))
        libgsl = audit["modules"]["libgsl"]
        self.assertEqual(libgsl.get("allowed_undefined_symbols"), {"android_arm": ["__aeabi_uldivmod"]})
        self.assertEqual(libgsl.get("undefined_symbol_runtime_providers"), {"android_arm": {"__aeabi_uldivmod": "libc.so"}})
        self.assertTrue(libgsl["check_elf_files"])

if __name__ == "__main__":
    unittest.main()
