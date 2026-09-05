from __future__ import annotations
import hashlib, json, re, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {
    "libQTapGLES": (
        ROOT / "proprietary/vendor/lib/egl/libQTapGLES.so",
        "6e1f3d61559115d144fcd53214e42a426a76dea3e173eebb1b9bafbce17fa2fe",
    ),
    "libmmcamera_interface": (
        ROOT / "proprietary/vendor/lib/libmmcamera_interface.so",
        "1027f4b5bb00fa050088ccdd484ec23ae48a601bb4c8549df3dc1fcb9c832531",
    ),
}

def block(name: str) -> str:
    text = (ROOT / "Android.bp").read_text()
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

class ObservedPair(unittest.TestCase):
    def test_exact_blobs_and_arm_allowance(self):
        for module, (path, digest) in EXPECTED.items():
            with self.subTest(module=module):
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
                item = block(module)
                self.assertNotIn("check_elf_files: false", item)
                self.assertRegex(item, r"(?s)arch:\s*\{.*?arm:\s*\{.*?allow_undefined_symbols:\s*true")

    def test_audit_is_only_ldivmod_from_libc(self):
        audit = json.loads((ROOT / "ANDROID15_ELF_AUDIT.json").read_text())
        for module in EXPECTED:
            with self.subTest(module=module):
                item = audit["modules"][module]
                self.assertEqual(item.get("allowed_undefined_symbols"), {"android_arm": ["__aeabi_ldivmod"]})
                self.assertEqual(item.get("undefined_symbol_runtime_providers"), {"android_arm": {"__aeabi_ldivmod": "libc.so"}})
                self.assertTrue(item["check_elf_files"])
