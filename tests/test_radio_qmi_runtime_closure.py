from __future__ import annotations

import hashlib
import json
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROPRIETARY = ROOT / "proprietary"

# FP3 6.A.025.0 QMI client/IDL set. The exact same bytes are shipped by the
# maintained LineageOS 22.2 msm8998 reference trees for mata, cheryl, Nubia,
# and OnePlus. Mixing these with RED .118 QMI libraries makes DMS client
# creation fail with QMI_CLIENT_PARAM_ERR (-17).
EXPECTED_SHA256 = {
    "vendor/lib/libqdi.so": "c49f920a35aa16028125225dc953d827ba0bb11972e4a67a8a0c730e88532ce4",
    "vendor/lib64/libqmi.so": "29c9662d9963e84083bd1ff0b20620f5c4779d8fa8447e6c083904b13637e51c",
    "vendor/lib64/libqmi_cci.so": "999bc5970bd060717d988257cbdbf50d6d2124a4814d3fd61f08991e84803f1a",
    "vendor/lib64/libqmi_client_helper.so": "bb29e28161c674b17a36bcf6fe5e26e9115ee049a8eff8110ef6bcb02723698e",
    "vendor/lib64/libqmi_client_qmux.so": "db2d40cb7ca2ab72e63cdf88c32e86ed04193615783c7b7f07ecf2e198f2ff93",
    "vendor/lib64/libqmi_common_so.so": "2bf4a6e5cc66b7e78b67831099a4a1f6eef986b5dc1028469ac846a4708a4673",
    "vendor/lib64/libqmi_encdec.so": "fee603c696b21404492c2d54855353e3f89deb20250564195af9898a00a4e7c6",
    "vendor/lib64/libqdi.so": "e8ab3959656dade28a320e5038c8569929cfb02ac3767031fbd41f9c1e288690",
    "vendor/lib64/libqmiservices.so": "504988dc23ed6b6452df6c0d8c5525652cb34b94f327ce3838c54c6d1fd5673e",
    "vendor/lib64/librilqmiservices.so": "e18586048f409e59443db26d2356e695ec5bf0f3bc41f6181e1355c9e1224561",
    "vendor/lib64/qcrild_librilutils.so": "2182f7fc0173cb39b49f8b05a41b52e94061dd3bdc83add871ca27cb8062cf6a",
    "vendor/radio/qcril_database/qcril.db": "596f8b2712bdcd23c40a9bb53088eb64598e04c2c776de6f76383024a61bf3ae",
}


class RadioQmiRuntimeClosureTest(unittest.TestCase):
    def test_qcril_uses_one_byte_verified_qmi_generation(self) -> None:
        for relative, expected in EXPECTED_SHA256.items():
            path = PROPRIETARY / relative
            self.assertTrue(path.is_file(), relative)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), expected, relative)

    def test_all_qcril_database_upgrades_are_packaged(self) -> None:
        upgrade = PROPRIETARY / "vendor/radio/qcril_database/upgrade"
        self.assertEqual(
            {path.name for path in upgrade.glob("*.sql")},
            {
                "0_initial.sql",
                "1_version_intro.sql",
                "2_version_add_wps_config.sql",
                "3_version_update_wps_config.sql",
                "4_version_update_ecc_table.sql",
                "5_version_update_ecc_table.sql",
                "6_version_update_ecc_table.sql",
                "7_version_update_ecc_table.sql",
                "8_version_update_ecc_table.sql",
                "9_version_update_ecc_table.sql",
                "10_version_update_ecc_table.sql",
            },
        )

    def test_source_lock_records_complete_qmi_runtime_closure(self) -> None:
        source_lock = json.loads((ROOT / "SOURCE_LOCK.json").read_text(encoding="utf-8"))
        radio = source_lock["android15_contract"]["radio_compatibility"]
        self.assertEqual(radio["donor_build"], "FP3 6.A.025.0")
        self.assertTrue(set(EXPECTED_SHA256).issubset(set(radio["paths"])))

    def test_manifest_records_complete_qmi_runtime_identity(self) -> None:
        manifest = json.loads(
            (ROOT / "proprietary-manifest.json").read_text(encoding="utf-8")
        )
        by_path = {entry["path"]: entry for entry in manifest["files"]}
        for relative in ("vendor/lib/libqdi.so", "vendor/lib64/libqdi.so"):
            expected = EXPECTED_SHA256[relative]
            self.assertIn(relative, by_path)
            self.assertEqual(by_path[relative]["sha256"], expected, relative)
            self.assertEqual(by_path[relative]["tier"], "P1", relative)

    def test_stock_ims_private_idl_uses_its_matching_stock_provider(self) -> None:
        consumer = PROPRIETARY / "vendor/lib64/lib-imsrcs-v2.so"
        provider = PROPRIETARY / "vendor/lib64/lib-imsrcsbaseimpl.so"
        dynamic = subprocess.run(
            ["readelf", "-d", consumer], check=True, capture_output=True, text=True
        ).stdout
        self.assertIn("Shared library: [lib-imsrcsbaseimpl.so]", dynamic)

        symbols = subprocess.run(
            ["nm", "-D", "--defined-only", provider],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        self.assertIn("imsprivate_get_service_object_internal_v01", symbols)

    def test_stock_imsrcsd_runtime_loaded_uce_service_is_packaged(self) -> None:
        daemon = PROPRIETARY / "vendor/bin/imsrcsd"
        provider = PROPRIETARY / "vendor/lib64/lib-uceservice.so"
        runtime_names = subprocess.run(
            ["strings", "-a", daemon], check=True, capture_output=True, text=True
        ).stdout
        self.assertIn("lib-uceservice.so", runtime_names)
        self.assertTrue(provider.is_file(), "imsrcsd dlopen provider is missing")
        self.assertEqual(
            hashlib.sha256(provider.read_bytes()).hexdigest(),
            "8ee42d4a11c05676196ebf1bfa9fa960e81b2fd663a18e0627091d691d212814",
        )

        android_bp = (ROOT / "Android.bp").read_text(encoding="utf-8")
        self.assertIn('name: "lib-uceservice"', android_bp)
        self.assertIn(
            '"proprietary/vendor/lib64/lib-uceservice.so"', android_bp
        )
        vendor_makefile = (ROOT / "hydrogenone-vendor.mk").read_text(
            encoding="utf-8"
        )
        self.assertRegex(vendor_makefile, r"(?m)^\s*lib-uceservice(?:\s*\\)?$")

    def test_extraction_replays_stock_ims_private_provider_fixup(self) -> None:
        extraction = (
            ROOT.parents[2] / "device/red/hydrogenone/extract-files.py"
        ).read_text(encoding="utf-8")
        self.assertIn("'vendor/lib64/lib-imsrcs-v2.so':", extraction)
        self.assertIn(".add_needed('lib-imsrcsbaseimpl.so')", extraction)


if __name__ == "__main__":
    unittest.main()
