from __future__ import annotations

import hashlib
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RED_MCT_ARM = ROOT / "proprietary/vendor/lib/libmmcamera2_mct.so"
EXPECTED_SHA256 = "e78927faa3ace5dd9f7b2c6d78636d9737495c4f3ab44e77dde14842aa64d40a"


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


class CameraMctLegacyAeabiContractTest(unittest.TestCase):
    def test_exact_red118_mct_blob_has_arm_only_allowance(self) -> None:
        self.assertTrue(RED_MCT_ARM.is_file())
        self.assertEqual(
            hashlib.sha256(RED_MCT_ARM.read_bytes()).hexdigest(),
            EXPECTED_SHA256,
        )
        block = prebuilt_block("libmmcamera2_mct")
        self.assertNotIn("check_elf_files: false", block)
        self.assertRegex(
            block,
            r"(?s)arch:\s*\{.*?arm:\s*\{.*?allow_undefined_symbols:\s*true,.*?\}.*?\}",
        )
        self.assertNotIn("arm64:", block)

    def test_audit_records_only_ldivmod_from_libc(self) -> None:
        audit = json.loads(
            (ROOT / "ANDROID15_ELF_AUDIT.json").read_text(encoding="utf-8")
        )
        module = audit["modules"]["libmmcamera2_mct"]
        self.assertEqual(
            module.get("allowed_undefined_symbols"),
            {"android_arm": ["__aeabi_ldivmod"]},
        )
        self.assertEqual(
            module.get("undefined_symbol_runtime_providers"),
            {"android_arm": {"__aeabi_ldivmod": "libc.so"}},
        )
        self.assertTrue(module["check_elf_files"])


if __name__ == "__main__":
    unittest.main()
