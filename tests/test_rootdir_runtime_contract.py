from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED = {
    "spdaemon": "vendor/bin/spdaemon",
    "hvdcp_opti": "vendor/bin/hvdcp_opti",
    "energy-awareness": "vendor/bin/energy-awareness",
}


def selected_paths() -> set[str]:
    paths: set[str] = set()
    for raw in (ROOT / "proprietary-files.txt").read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        body = line.split(";", 1)[0]
        paths.add(body.split(":", 1)[0].lstrip("-"))
    return paths


def module_src(module: str) -> str | None:
    text = (ROOT / "Android.bp").read_text(encoding="utf-8")
    pattern = re.compile(
        r"cc_prebuilt_binary\s*\{(?:(?!\n\}).)*?"
        + r'\bname:\s*"'
        + re.escape(module)
        + r'"(?:(?!\n\}).)*?\n\}',
        re.S,
    )
    match = pattern.search(text)
    if not match:
        return None
    src = re.search(r'"proprietary/([^"]+)"', match.group(0))
    return src.group(1) if src else None


class RootdirRuntimeVendorContractTest(unittest.TestCase):
    def test_device_rootdir_daemons_have_verified_vendor_payload_owners(self) -> None:
        selected = selected_paths()
        manifest = json.loads((ROOT / "proprietary-manifest.json").read_text(encoding="utf-8"))
        manifest_paths = {entry["path"] for entry in manifest["files"]}

        for module, path in REQUIRED.items():
            self.assertIn(path, selected, f"{path} is required by device init.target.rc")
            self.assertIn(path, manifest_paths, f"{path} has no pinned stock manifest identity")
            self.assertTrue((ROOT / "proprietary" / path).is_file(), f"missing RED .118 payload: {path}")
            self.assertEqual(module_src(module), path, f"{module} does not own {path} in Android.bp")

    def test_rootdir_daemon_modules_are_packaged(self) -> None:
        mk = (ROOT / "hydrogenone-vendor.mk").read_text(encoding="utf-8")
        for module in REQUIRED:
            self.assertRegex(mk, rf"(?m)^\s*{re.escape(module)}\s*\\?\s*$")


if __name__ == "__main__":
    unittest.main()
