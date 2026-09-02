from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SOURCE_OWNED_STANDARD = {
    "vendor/etc/permissions/android.hardware.nfc.hce.xml",
    "vendor/etc/permissions/android.hardware.nfc.xml",
}

VENDOR_OWNED_RED118 = {
    "vendor/etc/libnfc-nci.conf",
    "vendor/etc/thermal-engine.conf",
}


def selected_paths() -> set[str]:
    result: set[str] = set()
    for raw in (ROOT / "proprietary-files.txt").read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        body = line.split(";", 1)[0]
        result.add(body.split(":", 1)[0].lstrip("-"))
    return result


def manifest_paths() -> set[str]:
    manifest = json.loads((ROOT / "proprietary-manifest.json").read_text(encoding="utf-8"))
    return {entry["path"] for entry in manifest["files"]}


class CrossTreeCopyOwnershipTest(unittest.TestCase):
    def test_aosp_identical_feature_xmls_are_source_owned(self) -> None:
        selected = selected_paths()
        manifest = manifest_paths()
        vendor_mk = (ROOT / "hydrogenone-vendor.mk").read_text(encoding="utf-8")

        for path in sorted(SOURCE_OWNED_STANDARD):
            self.assertNotIn(path, selected, path)
            self.assertNotIn(path, manifest, path)
            self.assertNotIn(f"proprietary/{path}", vendor_mk, path)
            self.assertFalse((ROOT / "proprietary" / path).exists(), path)

    def test_red118_hardware_configs_remain_vendor_owned(self) -> None:
        selected = selected_paths()
        manifest = manifest_paths()
        vendor_mk = (ROOT / "hydrogenone-vendor.mk").read_text(encoding="utf-8")

        for path in sorted(VENDOR_OWNED_RED118):
            self.assertIn(path, selected, path)
            self.assertIn(path, manifest, path)
            self.assertIn(f"proprietary/{path}", vendor_mk, path)
            self.assertTrue((ROOT / "proprietary" / path).is_file(), path)


if __name__ == "__main__":
    unittest.main()
