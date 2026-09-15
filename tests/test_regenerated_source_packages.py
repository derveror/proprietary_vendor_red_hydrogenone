from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools/ensure_source_owned_packages.py"
PIPELINE = ROOT / "tools/apply_android15_vendor_contract.py"

SOURCE_PACKAGES = {
    "camera.device@1.0-impl",
    "camera.device@3.2-impl",
    "camera.device@3.3-impl",
    "camera.device@3.4-external-impl",
    "camera.device@3.4-impl",
    "libaudiopreprocessing",
    "libcld80211",
    "libgps.utils",
    "libhidlbase_shim",
    "libkeystore-engine-wifi-hidl",
    "libkeystore-wifi-hidl",
    "libloc_core",
    "liblocation_api",
    "libwifi-hal",
    "vendor.qti.hardware.camera.device@1.0",
}


def selected_packages(text: str) -> list[str]:
    packages: list[str] = []
    in_packages = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("PRODUCT_PACKAGES +="):
            in_packages = True
            continue
        if not in_packages:
            continue
        if not line:
            in_packages = False
            continue
        packages.append(line.rstrip("\\").strip())
        if not line.endswith("\\"):
            in_packages = False
    return packages


class RegeneratedSourcePackagesTest(unittest.TestCase):
    def test_pipeline_restores_source_packages_before_pruning_guards(self) -> None:
        self.assertTrue(TOOL.is_file(), f"missing source package restorer: {TOOL}")
        pipeline = PIPELINE.read_text(encoding="utf-8")
        self.assertIn('"ensure_source_owned_packages.py"', pipeline)
        self.assertLess(
            pipeline.index('"ensure_source_owned_packages.py"'),
            pipeline.index('"prune_source_owned_wifi_keystore.py"'),
        )

    def test_restorer_is_idempotent_on_raw_extract_utils_output(self) -> None:
        self.assertTrue(TOOL.is_file(), f"missing source package restorer: {TOOL}")
        if not TOOL.is_file():
            return

        with tempfile.TemporaryDirectory() as temp_dir:
            vendor_mk = Path(temp_dir) / "hydrogenone-vendor.mk"
            vendor_mk.write_text(
                "PRODUCT_PACKAGES += \\\n"
                "    adsprpcd \\\n"
                "    thermal-engine\n",
                encoding="utf-8",
            )
            command = [sys.executable, str(TOOL), "--vendor-mk", str(vendor_mk)]
            subprocess.run(command, check=True, capture_output=True, text=True)
            first = vendor_mk.read_text(encoding="utf-8")
            subprocess.run(command, check=True, capture_output=True, text=True)
            second = vendor_mk.read_text(encoding="utf-8")

        packages = selected_packages(first)
        self.assertEqual(SOURCE_PACKAGES - set(packages), set())
        for package in SOURCE_PACKAGES:
            self.assertEqual(packages.count(package), 1, package)
        self.assertEqual(second, first)

    def test_restorer_keeps_shell_scripts_as_copy_files(self) -> None:
        self.assertTrue(TOOL.is_file(), f"missing source package restorer: {TOOL}")
        if not TOOL.is_file():
            return

        with tempfile.TemporaryDirectory() as temp_dir:
            vendor_mk = Path(temp_dir) / "hydrogenone-vendor.mk"
            vendor_mk.write_text(
                "PRODUCT_PACKAGES += \\\n"
                "    init.qcom.sensors \\\n"
                "    init.qti.ims \\\n"
                "    thermal-engine\n",
                encoding="utf-8",
            )
            subprocess.run(
                [sys.executable, str(TOOL), "--vendor-mk", str(vendor_mk)],
                check=True,
                capture_output=True,
                text=True,
            )
            result = vendor_mk.read_text(encoding="utf-8")

        self.assertNotIn("init.qcom.sensors", selected_packages(result))
        self.assertNotIn("init.qti.ims", selected_packages(result))
        self.assertIn(
            "vendor/red/hydrogenone/proprietary/vendor/bin/init.qcom.sensors.sh:"
            "$(TARGET_COPY_OUT_VENDOR)/bin/init.qcom.sensors.sh",
            result,
        )
        self.assertIn(
            "vendor/red/hydrogenone/proprietary/vendor/bin/init.qti.ims.sh:"
            "$(TARGET_COPY_OUT_VENDOR)/bin/init.qti.ims.sh",
            result,
        )


if __name__ == "__main__":
    unittest.main()
