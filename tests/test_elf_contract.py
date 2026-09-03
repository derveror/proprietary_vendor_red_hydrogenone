from __future__ import annotations

import hashlib
import json
import re
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from tools.generate_elf_contract import (
    ensure_required_provider_module,
    module_for_soname,
    recovered_display_color_provider_files,
)

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

    def test_legacy_ubsan_sonames_are_normalized_to_android15_module(self) -> None:
        self.assertEqual(
            module_for_soname("libclang_rt.ubsan_standalone-aarch64-android.so", {}),
            "libclang_rt.ubsan_standalone",
        )
        self.assertEqual(
            module_for_soname("libclang_rt.ubsan_standalone-arm-android.so", {}),
            "libclang_rt.ubsan_standalone",
        )

    def test_display_color_provider_module_is_added_when_stock_blobs_exist(self) -> None:
        blocks = [
            {
                "kind": "cc_prebuilt_library_shared",
                "name": "libsdm-disp-apis",
                "relative_install_path": None,
                "compile_multilib": "both",
                "arch_srcs": {
                    "android_arm": ["proprietary/vendor/lib/libsdm-disp-apis.so"],
                    "android_arm64": ["proprietary/vendor/lib64/libsdm-disp-apis.so"],
                },
            }
        ]
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            for rel in (
                "proprietary/vendor/lib/vendor.display.color@1.0.so",
                "proprietary/vendor/lib64/vendor.display.color@1.0.so",
            ):
                path = root / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"stock-red-118-test-placeholder")

            with patch("tools.generate_elf_contract.ROOT", root):
                ensure_required_provider_module(blocks)

        color = next(block for block in blocks if block["name"] == "vendor.display.color@1.0")
        self.assertEqual(color["kind"], "cc_prebuilt_library_shared")
        self.assertEqual(color["compile_multilib"], "both")
        self.assertEqual(
            color["arch_srcs"],
            {
                "android_arm": ["proprietary/vendor/lib/vendor.display.color@1.0.so"],
                "android_arm64": ["proprietary/vendor/lib64/vendor.display.color@1.0.so"],
            },
        )

    def test_display_color_provider_metadata_is_derived_from_actual_stock_blobs(self) -> None:
        payloads = {
            "vendor/lib/vendor.display.color@1.0.so": b"red118-display-color-32",
            "vendor/lib64/vendor.display.color@1.0.so": b"red118-display-color-64",
        }
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            for rel, payload in payloads.items():
                path = root / "proprietary" / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(payload)

            with patch("tools.generate_elf_contract.ROOT", root):
                entries = recovered_display_color_provider_files()

        self.assertEqual(
            entries,
            [
                {
                    "tier": "P1",
                    "path": rel,
                    "size": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }
                for rel, payload in payloads.items()
            ],
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
