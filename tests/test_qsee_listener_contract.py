from __future__ import annotations

import hashlib
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LIBSSD = "vendor/lib64/libssd.so"
LIBSSD_SIZE = 68208
LIBSSD_SHA256 = "9a6b9bee2d010fb6156f2931a6cbea72c0bbab26b565e49524fee10c93024c74"


class QseeListenerContractTest(unittest.TestCase):
    def test_stock118_ssd_listener_is_present_with_exact_identity(self) -> None:
        path = ROOT / "proprietary" / LIBSSD
        self.assertTrue(path.is_file(), f"missing boot-critical QSEE listener: {LIBSSD}")
        if not path.is_file():
            return
        payload = path.read_bytes()
        self.assertEqual(len(payload), LIBSSD_SIZE)
        self.assertEqual(hashlib.sha256(payload).hexdigest(), LIBSSD_SHA256)

    def test_ssd_listener_is_selected_and_packaged(self) -> None:
        selected = {
            line.strip().split(";", 1)[0].split(":", 1)[0].lstrip("-")
            for line in (ROOT / "proprietary-files.txt").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
        packages = (ROOT / "hydrogenone-vendor.mk").read_text(encoding="utf-8")
        modules = set(
            re.findall(
                r'(?m)^\s*name:\s*"([^"]+)"\s*,?$',
                (ROOT / "Android.bp").read_text(encoding="utf-8"),
            )
        )
        self.assertIn(LIBSSD, selected)
        self.assertRegex(packages, r"(?m)^\s*libssd\s*\\?\s*$")
        self.assertIn("libssd", modules)

    def test_ssd_listener_is_pinned_as_stock118_p0(self) -> None:
        manifest = json.loads(
            (ROOT / "proprietary-manifest.json").read_text(encoding="utf-8")
        )
        record = next(
            (entry for entry in manifest["files"] if entry["path"] == LIBSSD),
            None,
        )
        self.assertEqual(
            record,
            {
                "tier": "P0",
                "path": LIBSSD,
                "size": LIBSSD_SIZE,
                "sha256": LIBSSD_SHA256,
            },
        )


if __name__ == "__main__":
    unittest.main()
