from __future__ import annotations

import hashlib
import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROPRIETARY = ROOT / "proprietary"

# The complete FP3 data-plane generation used together by the maintained
# LineageOS 22.2 msm8998 reference trees.  Keeping this byte-verified prevents
# qcrild/libdsi from being paired with the older RED .118 netmgr/DPM stack.
EXPECTED_SHA256 = {
    "system_ext/bin/dpmd": "7a5379734f6cbd23adfb8e3729087beb19ef584303425e0bf298e15c7fcb0263",
    "system_ext/etc/dpm/dpm.conf": "87f839379ce8f1882e2f287f83d4abc84b3b749873f7ffa6ae2303936352c7a7",
    "system_ext/etc/init/dpmd.rc": "977c0d6987108d4a8a5952efadbbf66892ff4efaef3414b6e95e347229a77b24",
    "system_ext/etc/permissions/com.qti.dpmframework.xml": "f0f06e0ffbe31064be2639ca338f0f944df96835e934ba60778a62d6ef9142c9",
    "system_ext/etc/permissions/dpmapi.xml": "03dc2d5f62228102224eea64ff7bf98a4416146123497750e1a6bdb77b10d520",
    "system_ext/framework/com.qti.dpmframework.jar": "160f4818af5ae8bff97373e31d11b97af6be9e330c24bcd20a83986ac3ece2cf",
    "system_ext/framework/dpmapi.jar": "5b57736888c16de41f99264cfb980a41b470737b9b222f4c7ea9e2cd6ed9fe96",
    "system_ext/lib64/com.qualcomm.qti.dpm.api@1.0.so": "07634cb2cc208c90e395b182c761d66dc41d84c7da831c3f4e747054f2f78037",
    "system_ext/lib64/libdpmctmgr.so": "256d54e25d860c049d263f53ff5d214b3aff02af2d7cebb7fd307fd8948bbe32",
    "system_ext/lib64/libdpmfdmgr.so": "b0af4f9c6ff59cbc88a3af6852b1e34c4a97094bd052048e6ae1aad9859be3b7",
    "system_ext/lib64/libdpmframework.so": "a57ca3847cdd619c424c4e0dedfe603a0400f50fde44d5797ad21d27faf5662b",
    "system_ext/lib64/libdpmtcm.so": "d7356f33ec0cfd7b72cc1a8d5424b67ce0aa37ba6c6e9f9edded0fbe28ac39e4",
    "system_ext/lib64/libdiag_system.so": "9d2cba558f3382c6f88e8acab4a82f899fa6d0a3b01d7398fdd2482c7de2bdc4",
    "system_ext/lib64/vendor.qti.diaghal@1.0.so": "21050415b2af475f36e90058b913a12f366fb9782d9bfc7a5e154494661a6b20",
    "system_ext/priv-app/dpmserviceapp/dpmserviceapp.apk": "bcadad9924174bab6fef54b95f69aeecf2a1f36d3e90495364cf63a62f29e580",
    "vendor/bin/dpmQmiMgr": "00a56585d294769d65addf61d0be73b0513ab74897ddb2d1bc34def7723ccecb",
    "vendor/bin/netmgrd": "48a8aaf29aa52220b9071fcd0edef8d75bc93da7738b208eea1adefe8607c1f3",
    "vendor/etc/data/netmgr_config.xml": "68218668d7d7e0edd6972762322d3516588dc764b04d75a75ff58804544b0568",
    "vendor/etc/init/dpmQmiMgr.rc": "525fba1911f28e3ee37bebc84033d94ea5c15ed89ce91c8ddeb02919ff8805dc",
    "vendor/etc/init/netmgrd.rc": "568143f3edf386dda7a13503cea2df6cc03904cfa798e14dfab5487aa8e6403b",
    "vendor/lib64/com.qualcomm.qti.dpm.api@1.0.so": "9c758d219a5ac3f34a92d95eb7ebb6d422abc3104bc218625257cf2a07f40fc9",
    "vendor/lib64/libdpmqmihal.so": "0c18eba12d4d4e14b234e8c71abba99b260318f72b6b30f4db86c39e3c2b6ebe",
    "vendor/lib64/libnetmgr.so": "3a89fb2746fdb7268b20015effe6edb40ddd5bc87c0622ad40bd7663a2ce9734",
    "vendor/lib64/libnetmgr_common.so": "ef9e8fbd56651bf6004d0d3deadd975656e468a66dfe7699f2d06c72fc57036e",
    "vendor/lib64/libnetmgr_nr_fusion.so": "b2579c20a31c02bbd58175723ceb91c548159061806f8cbab6216e4a84be0c47",
    "vendor/lib64/libnetmgr_rmnet_ext.so": "462881e7fa7a378c2952171c04ff7fc7be811f731c108ec6237ab1ad2566afd8",
    "vendor/lib64/libnlnetmgr.so": "e1f5a382194342e7991f5ed81d450ec0129b2a7680a7640b7f58e2f3dc5e2c69",
}


class RadioDataPlaneClosureTest(unittest.TestCase):
    def test_data_plane_uses_one_byte_verified_fp3_generation(self) -> None:
        for relative, expected in EXPECTED_SHA256.items():
            path = PROPRIETARY / relative
            self.assertTrue(path.is_file(), relative)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), expected, relative)

    def test_source_lock_records_complete_data_plane_closure(self) -> None:
        source_lock = json.loads((ROOT / "SOURCE_LOCK.json").read_text(encoding="utf-8"))
        radio = source_lock["android15_contract"]["radio_compatibility"]
        self.assertEqual(radio["donor_build"], "FP3 6.A.025.0")
        self.assertTrue(set(EXPECTED_SHA256).issubset(set(radio["paths"])))
        self.assertTrue(radio["dpm_system_side_complete"])

    def test_manifest_records_installed_data_plane_identity(self) -> None:
        manifest = json.loads(
            (ROOT / "proprietary-manifest.json").read_text(encoding="utf-8")
        )
        by_path = {entry["path"]: entry for entry in manifest["files"]}
        for relative, expected in EXPECTED_SHA256.items():
            self.assertIn(relative, by_path)
            self.assertEqual(by_path[relative]["sha256"], expected, relative)
            self.assertEqual(by_path[relative]["tier"], "P1", relative)

    def test_rmnetctl_is_source_owned_and_exports_fp3_netmgr_symbol(self) -> None:
        selected = (ROOT / "proprietary-files.txt").read_text(encoding="utf-8")
        self.assertNotRegex(selected, r"(?m)^vendor/lib64/librmnetctl\.so(?:[|;]|$)")
        source = (
            ROOT.parents[2]
            / "vendor/qcom/opensource/dataservices/rmnetctl/src/librmnetctl.c"
        ).read_text(encoding="utf-8")
        self.assertRegex(
            source,
            re.compile(r"\bint\s+rtrmnet_set_uplink_aggregation_params\s*\("),
        )

    def test_vendor_dpm_api_has_partition_suffix(self) -> None:
        selected = (ROOT / "proprietary-files.txt").read_text(encoding="utf-8")
        self.assertIn(
            "vendor/lib64/com.qualcomm.qti.dpm.api@1.0.so;MODULE_SUFFIX=_vendor|",
            selected,
        )

    def test_generated_dpm_modules_keep_their_partitions(self) -> None:
        android_bp = (ROOT / "Android.bp").read_text(encoding="utf-8")
        self.assertRegex(
            android_bp,
            re.compile(
                r'name: "com\.qualcomm\.qti\.dpm\.api@1\.0".*?'
                r'system_ext_specific: true,',
                re.S,
            ),
        )
        self.assertRegex(
            android_bp,
            re.compile(
                r'name: "com\.qualcomm\.qti\.dpm\.api@1\.0_vendor".*?'
                r'soc_specific: true,',
                re.S,
            ),
        )


if __name__ == "__main__":
    unittest.main()
