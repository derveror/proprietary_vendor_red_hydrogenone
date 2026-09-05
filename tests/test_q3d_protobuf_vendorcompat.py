from __future__ import annotations
import hashlib, json, re, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def block(name: str) -> str:
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
        item = "".join(lines[i:j])
        if re.search(rf'(?m)^\s*name:\s*"{re.escape(name)}"\s*,?$', item):
            return item
    raise AssertionError(name)

class Q3dProtobufVendorcompatTest(unittest.TestCase):
    def test_q3d_exact_red118_blob_has_arm_only_uldivmod_allowance(self):
        path = ROOT / "proprietary/vendor/lib/egl/libq3dtools_adreno.so"
        self.assertEqual(
            hashlib.sha256(path.read_bytes()).hexdigest(),
            "45e1b1cbc2e916f530e7e82a5b472ee4473fc67fea3be6805134217986537af0",
        )
        item = block("libq3dtools_adreno")
        self.assertNotIn("check_elf_files: false", item)
        self.assertRegex(item, r"(?s)arch:\s*\{.*?arm:\s*\{.*?allow_undefined_symbols:\s*true")
        audit = json.loads((ROOT / "ANDROID15_ELF_AUDIT.json").read_text())
        record = audit["modules"]["libq3dtools_adreno"]
        self.assertEqual(record.get("allowed_undefined_symbols"), {"android_arm": ["__aeabi_uldivmod"]})
        self.assertEqual(record.get("undefined_symbol_runtime_providers"), {"android_arm": {"__aeabi_uldivmod": "libc.so"}})
        self.assertTrue(record["check_elf_files"])

    def test_libsettings_uses_lineage_vendorcompat_provider(self):
        expected = {
            ROOT / "proprietary/vendor/lib/libsettings.so": "f0c4e6b163e24f913baea635b1893fff0cb656baa7d163da60ba3d3eea0e67ae",
            ROOT / "proprietary/vendor/lib64/libsettings.so": "52e804e9878844810e7381e011588500e78e648917c0ce251a2b2bb97dfca123",
        }
        for path, digest in expected.items():
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
        item = block("libsettings")
        self.assertNotIn("check_elf_files: false", item)
        self.assertIn('"libprotobuf-cpp-full-vendorcompat"', item)
        self.assertNotRegex(item, r'(?m)^\s*"libprotobuf-cpp-full",\s*$')
        audit = json.loads((ROOT / "ANDROID15_ELF_AUDIT.json").read_text())
        record = audit["modules"]["libsettings"]
        self.assertTrue(record["check_elf_files"])
        for arch in ("android_arm", "android_arm64"):
            self.assertIn("libprotobuf-cpp-full-vendorcompat", record["architectures"][arch]["shared_libs"])
            self.assertIn("libprotobuf-cpp-full-vendorcompat", record["architectures"][arch]["needed"][next(iter(record["architectures"][arch]["needed"]))])

    def test_generator_records_vendorcompat_as_source_verified(self):
        text = (ROOT / "tools/generate_elf_contract.py").read_text()
        self.assertIn('"libprotobuf-cpp-full-vendorcompat"', text)
        self.assertIn('soname == "libprotobuf-cpp-full.so"', text)
