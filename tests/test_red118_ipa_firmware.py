from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROPRIETARY = ROOT / "proprietary"

EXPECTED_SHA256 = {
    "vendor/firmware/ipa_fws.b00": "98392dd51753daaaa61b4218f6577895dc3596053551b61a8c9d40de2abf5bfa",
    "vendor/firmware/ipa_fws.b01": "5621af93fbd78adf54b485bc305076bd5d6a95e65ac81793236b3103ec6fde6a",
    "vendor/firmware/ipa_fws.b02": "402234ff0f0cdac076339c89bb4488f040bb92df5ff53718e655d37169001cb4",
    "vendor/firmware/ipa_fws.b03": "14024088f436ebd24b097cb113b2177e12c939efdac0211d560c7cc498611507",
    "vendor/firmware/ipa_fws.b04": "8d572c4b4dee9572d90ab90137ec030331856bbfd8bf2e6ee315da4a5bab3373",
    "vendor/firmware/ipa_fws.elf": "7ba9f1f8ae793832c83ee94baa40de397dee0e0ab90658b6d05e05d73e98d435",
    "vendor/firmware/ipa_fws.mdt": "18ca393d578434d3eaa45e80f923d4804fe495f3c3507a0c94ad301ddef25684",
}


class Red118IpaFirmwareTest(unittest.TestCase):
    def test_exact_stock_118_ipa_pil_payload_is_present(self) -> None:
        for relative, expected in EXPECTED_SHA256.items():
            path = PROPRIETARY / relative
            self.assertTrue(path.is_file(), relative)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), expected, relative)

    def test_ipa_payload_is_selected_and_installed_in_vendor_firmware(self) -> None:
        selected = (ROOT / "proprietary-files.txt").read_text(encoding="utf-8")
        vendor_mk = (ROOT / "hydrogenone-vendor.mk").read_text(encoding="utf-8")
        for relative in EXPECTED_SHA256:
            self.assertIn(f"\n{relative}\n", f"\n{selected}")
            source = f"vendor/red/hydrogenone/proprietary/{relative}"
            destination = f"$(TARGET_COPY_OUT_VENDOR)/{relative.removeprefix('vendor/')}"
            self.assertIn(f"{source}:{destination}", vendor_mk)

    def test_manifest_and_source_lock_pin_red_118_identity(self) -> None:
        manifest = json.loads(
            (ROOT / "proprietary-manifest.json").read_text(encoding="utf-8")
        )
        by_path = {entry["path"]: entry for entry in manifest["files"]}
        for relative, expected in EXPECTED_SHA256.items():
            self.assertIn(relative, by_path)
            self.assertEqual(by_path[relative]["sha256"], expected, relative)
            self.assertEqual(by_path[relative]["tier"], "P0", relative)

        source_lock = json.loads((ROOT / "SOURCE_LOCK.json").read_text(encoding="utf-8"))
        ipa = source_lock["android15_contract"]["red118_ipa_firmware"]
        self.assertEqual(ipa["source"], "RED stock .118 vendor.img /vendor/firmware")
        self.assertEqual(ipa["kernel_trigger"], "write /dev/ipa 1")
        self.assertEqual(ipa["sha256"], EXPECTED_SHA256)


if __name__ == "__main__":
    unittest.main()
