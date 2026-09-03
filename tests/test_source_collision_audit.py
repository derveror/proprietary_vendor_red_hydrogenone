from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from tools.audit_android15_source_collisions import audit


class SourceCollisionAuditTest(unittest.TestCase):
    def test_inherited_vendor_available_is_high_risk(self) -> None:
        with TemporaryDirectory() as temp_dir:
            top = Path(temp_dir)
            vendor = top / "vendor/red/hydrogenone"
            vendor.mkdir(parents=True)
            (vendor / "Android.bp").write_text(
                'cc_prebuilt_library_shared {\n'
                '    name: "libfoo",\n'
                '    soc_specific: true,\n'
                '}\n',
                encoding="utf-8",
            )
            source = top / "system/media"
            source.mkdir(parents=True)
            (source / "Android.bp").write_text(
                'cc_defaults {\n'
                '    name: "foo_defaults",\n'
                '    vendor_available: true,\n'
                '}\n'
                'cc_library {\n'
                '    name: "libfoo",\n'
                '    defaults: ["foo_defaults"],\n'
                '}\n',
                encoding="utf-8",
            )

            report = audit(top, vendor)

        self.assertIn("libfoo", {item["name"] for item in report["high_risk"]})

    def test_system_ext_source_is_high_risk_for_vendor_prebuilt(self) -> None:
        with TemporaryDirectory() as temp_dir:
            top = Path(temp_dir)
            vendor = top / "vendor/red/hydrogenone"
            vendor.mkdir(parents=True)
            (vendor / "Android.bp").write_text(
                'cc_prebuilt_library_shared {\n'
                '    name: "vendor.qti.hardware.foo@1.0",\n'
                '    soc_specific: true,\n'
                '}\n',
                encoding="utf-8",
            )
            source = top / "vendor/qcom/opensource/interfaces/foo/1.0"
            source.mkdir(parents=True)
            (source / "Android.bp").write_text(
                'hidl_interface {\n'
                '    name: "vendor.qti.hardware.foo@1.0",\n'
                '    system_ext_specific: true,\n'
                '}\n',
                encoding="utf-8",
            )

            report = audit(top, vendor)

        high = {item["name"] for item in report["high_risk"]}
        self.assertIn("vendor.qti.hardware.foo@1.0", high)

    def test_vendor_only_source_is_not_high_risk(self) -> None:
        with TemporaryDirectory() as temp_dir:
            top = Path(temp_dir)
            vendor = top / "vendor/red/hydrogenone"
            vendor.mkdir(parents=True)
            (vendor / "Android.bp").write_text(
                'cc_prebuilt_library_shared {\n'
                '    name: "libfoo",\n'
                '    soc_specific: true,\n'
                '}\n',
                encoding="utf-8",
            )
            source = top / "hardware/foo"
            source.mkdir(parents=True)
            (source / "Android.bp").write_text(
                'cc_library_shared {\n'
                '    name: "libfoo",\n'
                '    vendor: true,\n'
                '}\n',
                encoding="utf-8",
            )

            report = audit(top, vendor)

        self.assertEqual(report["high_risk"], [])


if __name__ == "__main__":
    unittest.main()
