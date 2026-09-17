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


if __name__ == "__main__":
    unittest.main()
