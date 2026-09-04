from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

LEGACY_PATHS = {
    "vendor/bin/hw/android.hardware.media.omx@1.0-service",
    "vendor/lib/libgui_vendor.so",
    "vendor/lib/vndk/libstagefright_foundation.so",
    "vendor/lib/vndk/libstagefright_omx.so",
}
LEGACY_MODULES = {
    "android.hardware.media.omx@1.0-service",
    "libgui_vendor",
    "libstagefright_foundation-v28",
    "libstagefright_omx-v28",
}
NFC_MODULES = {
    "nfc_nci.nqx.default",
    "nfc_nci.nqx.default.hw",
}


def selected_paths() -> set[str]:
    manifest = json.loads((ROOT / "proprietary-manifest.json").read_text())
    return {entry["path"] for entry in manifest["files"]}


def bp_block(module: str) -> str | None:
    text = (ROOT / "Android.bp").read_text()
    pattern = re.compile(
        r"cc_prebuilt_(?:binary|library_shared)\s*\{(?:(?!\n\}).)*?"
        + r'\bname:\s*"'
        + re.escape(module)
        + r'"(?:(?!\n\}).)*?\n\}',
        re.S,
    )
    match = pattern.search(text)
    return match.group(0) if match else None


class MediaOmxOwnershipTest(unittest.TestCase):
    def test_obsolete_red_media_wrapper_payload_is_not_selected(self) -> None:
        self.assertTrue(LEGACY_PATHS.isdisjoint(selected_paths()))
        for rel in LEGACY_PATHS:
            self.assertFalse((ROOT / "proprietary" / rel).exists(), rel)

    def test_vendor_has_no_prebuilt_owner_for_source_media_frontend(self) -> None:
        for module in LEGACY_MODULES:
            self.assertIsNone(bp_block(module), module)

        vendor_mk = (ROOT / "hydrogenone-vendor.mk").read_text()
        for module in LEGACY_MODULES:
            self.assertNotRegex(
                vendor_mk,
                rf"(?m)^\s*{re.escape(module)}\s*\\?\s*$",
                module,
            )

    def test_nfc_prebuilts_are_retained_with_checkelf_enabled(self) -> None:
        exceptions = json.loads(
            (ROOT / "ANDROID15_ELF_EXCEPTIONS.json").read_text()
        )["exceptions"]
        for module in NFC_MODULES:
            self.assertNotIn(module, exceptions)
            block = bp_block(module)
            self.assertIsNotNone(block, module)
            self.assertNotIn("check_elf_files: false", block)

    def test_media_omx_vintf_is_device_owned(self) -> None:
        contract = json.loads(
            (ROOT / "VINTF_PROPRIETARY_CONTRACT.json").read_text()
        )
        self.assertIn(
            "android.hardware.media.omx",
            contract["source_owned_exclusions"],
        )
        self.assertNotIn(
            "android.hardware.media.omx@1.0-service",
            contract["modules"],
        )
        self.assertFalse((ROOT / "vintf/media-omx.xml").exists())

    def test_pipeline_reproduces_media_ownership(self) -> None:
        pipeline = (ROOT / "tools/apply_android15_vendor_contract.py").read_text()
        self.assertIn("prune_source_owned_media_omx_stack.py", pipeline)
        lock = json.loads((ROOT / "SOURCE_LOCK.json").read_text())
        android15 = lock["android15_contract"]
        self.assertTrue(android15.get("source_owned_media_omx_stack_pruned"))
        self.assertTrue(android15.get("nfc_legacy_hal_checkelf_verified"))


if __name__ == "__main__":
    unittest.main()
