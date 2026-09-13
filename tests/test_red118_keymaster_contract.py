from __future__ import annotations

import hashlib
import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

KEYMASTER_FILES = {
    "vendor/bin/hw/android.hardware.keymaster@3.0-service-qti": (
        68336,
        "0c3718edce7060377f7f999ba05081b9c66defc84471a704ae605c8cd020aee3",
    ),
    "vendor/etc/init/android.hardware.keymaster@3.0-service-qti.rc": (
        140,
        "69d8d0cc9afc4665deba3f578f0719094bba8a5b8c3ff59a90eaff98d6981717",
    ),
    "vendor/lib64/hw/android.hardware.keymaster@3.0-impl-qti.so": (
        138656,
        "ac0de6004c875f8104361ee945875cfd5879bbd3dc67e4a4b29c790ba41984b0",
    ),
    "vendor/lib64/libkeymasterdeviceutils.so": (
        68216,
        "e423dc1bff0ec0a9bfdcf65d753582b2ab1ff81afa64c13c893fbe216620e738",
    ),
}


def selected_paths() -> set[str]:
    return {
        line.strip().split(";", 1)[0].split(":", 1)[0].lstrip("-")
        for line in (ROOT / "proprietary-files.txt").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }


class Red118KeymasterContractTest(unittest.TestCase):
    def test_exact_stock118_keymaster_payload_is_present(self) -> None:
        for relative, (size, expected_sha256) in KEYMASTER_FILES.items():
            path = ROOT / "proprietary" / relative
            self.assertTrue(path.is_file(), f"missing RED .118 Keymaster file: {relative}")
            if not path.is_file():
                continue
            payload = path.read_bytes()
            self.assertEqual(len(payload), size, relative)
            self.assertEqual(hashlib.sha256(payload).hexdigest(), expected_sha256, relative)

    def test_keymaster_payload_is_selected_and_manifested_as_p0(self) -> None:
        expected = set(KEYMASTER_FILES)
        self.assertTrue(expected.issubset(selected_paths()))
        manifest = json.loads(
            (ROOT / "proprietary-manifest.json").read_text(encoding="utf-8")
        )
        records = {entry["path"]: entry for entry in manifest["files"]}
        for relative, (size, sha256) in KEYMASTER_FILES.items():
            self.assertEqual(
                records.get(relative),
                {"tier": "P0", "path": relative, "size": size, "sha256": sha256},
            )

    def test_qti_keymaster_modules_are_packaged(self) -> None:
        packages = (ROOT / "hydrogenone-vendor.mk").read_text(encoding="utf-8")
        bp = (ROOT / "Android.bp").read_text(encoding="utf-8")
        modules = set(re.findall(r'(?m)^\s*name:\s*"([^"]+)"\s*,?$', bp))
        for module in (
            "android.hardware.keymaster@3.0-impl-qti",
            "android.hardware.keymaster@3.0-service-qti",
            "libkeymasterdeviceutils",
        ):
            self.assertRegex(packages, rf"(?m)^\s*{re.escape(module)}\s*\\?\s*$")
            self.assertIn(module, modules)
        self.assertRegex(
            bp,
            r'(?s)name:\s*"libkeymasterdeviceutils".*?'
            r'shared_libs:\s*\[.*?"libion"',
        )

    def test_stock_service_runs_with_red118_credentials(self) -> None:
        rc = (
            ROOT
            / "proprietary/vendor/etc/init/android.hardware.keymaster@3.0-service-qti.rc"
        ).read_text(encoding="utf-8")
        self.assertEqual(
            rc,
            "service keymaster-3-0 "
            "/vendor/bin/hw/android.hardware.keymaster@3.0-service-qti\n"
            "    class early_hal\n"
            "    user system\n"
            "    group system drmrpc\n",
        )


if __name__ == "__main__":
    unittest.main()
