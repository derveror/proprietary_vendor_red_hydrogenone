from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_RED_DEPENDENCY_PATHS = {
    "vendor/lib/libsdm-disp-apis.so",
    "vendor/lib64/libsdm-disp-apis.so",
}


def bp_prebuilt_blocks() -> list[str]:
    text = (ROOT / "Android.bp").read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    blocks: list[str] = []
    i = 0
    while i < len(lines):
        if not re.match(r"^cc_prebuilt_(?:binary|library_shared)\s*\{\s*$", lines[i]):
            i += 1
            continue
        start = i
        depth = lines[i].count("{") - lines[i].count("}")
        i += 1
        while i < len(lines) and depth > 0:
            depth += lines[i].count("{") - lines[i].count("}")
            i += 1
        blocks.append("".join(lines[start:i]))
    return blocks


def module_name(block: str) -> str:
    match = re.search(r'(?m)^\s*name:\s*"([^"]+)"', block)
    if not match:
        raise AssertionError("prebuilt block without name")
    return match.group(1)


def manifest_paths() -> set[str]:
    data = json.loads((ROOT / "proprietary-manifest.json").read_text(encoding="utf-8"))
    return {entry["path"] for entry in data["files"]}


class ElfContractTest(unittest.TestCase):
    def test_required_red_dependency_provider_is_selected(self) -> None:
        selected = manifest_paths()
        missing_manifest = sorted(REQUIRED_RED_DEPENDENCY_PATHS - selected)
        missing_payload = sorted(
            path
            for path in REQUIRED_RED_DEPENDENCY_PATHS
            if not (ROOT / "proprietary" / path).is_file()
        )
        self.assertEqual(missing_manifest, [], f"RED DT_NEEDED providers absent from manifest: {missing_manifest}")
        self.assertEqual(missing_payload, [], f"RED DT_NEEDED providers absent from payload: {missing_payload}")

    def test_checkelf_is_not_blanket_disabled(self) -> None:
        blocks = bp_prebuilt_blocks()
        disabled = [module_name(block) for block in blocks if "check_elf_files: false" in block]
        self.assertLess(
            len(disabled),
            len(blocks),
            "every proprietary ELF has check_elf_files disabled; dependency declarations have not been implemented",
        )

    def test_every_remaining_checkelf_exception_is_documented(self) -> None:
        registry_path = ROOT / "ANDROID15_ELF_EXCEPTIONS.json"
        self.assertTrue(registry_path.is_file(), "ANDROID15_ELF_EXCEPTIONS.json is required")
        if not registry_path.is_file():
            return
        registry = json.loads(registry_path.read_text(encoding="utf-8"))
        exceptions = registry.get("exceptions", {})
        disabled = {
            module_name(block)
            for block in bp_prebuilt_blocks()
            if "check_elf_files: false" in block
        }
        self.assertEqual(set(exceptions), disabled, "exception registry must exactly match disabled modules")
        invalid: list[str] = []
        for name, record in exceptions.items():
            if not record.get("reason") or not record.get("blocking_dependencies") or not record.get("evidence"):
                invalid.append(name)
        self.assertEqual(invalid, [], f"ELF exceptions without concrete evidence: {invalid}")


if __name__ == "__main__":
    unittest.main()
