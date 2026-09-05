from __future__ import annotations
import ast
import hashlib
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GENERATOR = ROOT / "tools/generate_elf_contract.py"
BP = ROOT / "Android.bp"
HELPERS = {"__aeabi_ldivmod", "__aeabi_uldivmod"}

def registry() -> dict:
    tree = ast.parse(GENERATOR.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "LEGACY_RUNTIME_UNDEFINED_SYMBOLS":
                    return ast.literal_eval(node.value)
    raise AssertionError("registry missing")

def arm_modules() -> dict[str, str]:
    text = BP.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    result: dict[str, str] = {}
    i = 0
    while i < len(lines):
        if not re.match(r"^cc_prebuilt_library_shared\s*\{\s*$", lines[i]):
            i += 1
            continue
        start = i
        depth = lines[i].count("{") - lines[i].count("}")
        i += 1
        while i < len(lines) and depth > 0:
            depth += lines[i].count("{") - lines[i].count("}")
            i += 1
        block = "".join(lines[start:i])
        name = re.search(r'(?m)^\s*name:\s*"([^"]+)"', block)
        arm = re.search(r"android_arm:\s*\{(.*?)\n\s*\},", block, re.S)
        if not name or not arm:
            continue
        srcs = re.findall(r'"(proprietary/vendor/lib(?:/[^\"]*)?\.so)"', arm.group(1))
        if len(srcs) == 1:
            result[name.group(1)] = srcs[0]
    return result

def helper_imports(path: Path) -> list[str]:
    out = subprocess.check_output(["readelf", "-Ws", str(path)], text=True)
    found = set()
    for line in out.splitlines():
        if " UND " not in f" {line} ":
            continue
        name = line.split()[-1].split("@", 1)[0]
        if name in HELPERS:
            found.add(name)
    return sorted(found)

class CompleteArmAeabiCoverageTest(unittest.TestCase):
    def test_registry_exactly_covers_every_retained_arm32_divmod_import(self):
        observed = {}
        for module, rel in arm_modules().items():
            symbols = helper_imports(ROOT / rel)
            if symbols:
                observed[module] = {"path": rel, "symbols": symbols}

        declared = registry()
        declared_projection = {
            module: {"path": data["path"], "symbols": sorted(data["symbols"])}
            for module, data in declared.items()
            if set(data["symbols"]) <= HELPERS
        }
        self.assertEqual(declared_projection, observed)

    def test_every_registry_entry_pins_exact_blob_and_arm_libc_provider(self):
        for module, data in registry().items():
            if not set(data["symbols"]) <= HELPERS:
                continue
            self.assertEqual(data["arch"], "android_arm", module)
            self.assertEqual(data["runtime_provider"], "libc.so", module)
            path = ROOT / data["path"]
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), data["sha256"], module)

    def test_no_arm64_aeabi_allowance_is_generated(self):
        text = BP.read_text(encoding="utf-8")
        self.assertNotRegex(text, r"(?s)arch:\s*\{\s*arm64:\s*\{\s*allow_undefined_symbols:\s*true")
