from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SOURCE_OWNED_MODULES = {
    "android.hidl.base@1.0",
    "libalsautils",
}
SOURCE_OWNED_PATHS = {
    "vendor/lib/android.hidl.base@1.0.so",
    "vendor/lib/libalsautils.so",
    "vendor/lib64/libalsautils.so",
}
LEGACY_VNDK = {
    "libstagefright_foundation-v28": {
        "stem": "libstagefright_foundation",
        "src": "proprietary/vendor/lib/vndk/libstagefright_foundation.so",
    },
    "libstagefright_omx-v28": {
        "stem": "libstagefright_omx",
        "src": "proprietary/vendor/lib/vndk/libstagefright_omx.so",
    },
}


def active_paths() -> set[str]:
    paths = set()
    for raw in (ROOT / "proprietary-files.txt").read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        body = line.split(";", 1)[0]
        paths.add(body.split(":", 1)[0].lstrip("-"))
    manifest = json.loads((ROOT / "proprietary-manifest.json").read_text(encoding="utf-8"))
    paths.update(entry["path"] for entry in manifest["files"])
    return paths


def module_blocks() -> dict[str, str]:
    text = (ROOT / "Android.bp").read_text(encoding="utf-8")
    blocks = {}
    for match in re.finditer(r"cc_prebuilt_(?:binary|library_shared)\s*\{(.*?)\n\}", text, re.S):
        block = match.group(0)
        name = re.search(r'(?m)^\s*name:\s*"([^"]+)"', block)
        if name:
            blocks[name.group(1)] = block
    return blocks


class Android15CollisionResolutionTest(unittest.TestCase):
    def test_platform_source_owned_modules_are_not_selected_as_prebuilts(self) -> None:
        blocks = module_blocks()
        self.assertEqual(sorted(SOURCE_OWNED_MODULES & set(blocks)), [])
        self.assertEqual(sorted(SOURCE_OWNED_PATHS & active_paths()), [])

    def test_api28_stagefright_vndk_is_retained_under_unique_soong_names(self) -> None:
        blocks = module_blocks()
        for module, expected in LEGACY_VNDK.items():
            self.assertIn(module, blocks)
            block = blocks[module]
            self.assertIn(f'stem: "{expected["stem"]}"', block)
            self.assertIn('relative_install_path: "vndk"', block)
            self.assertIn(expected["src"], block)
        self.assertNotIn("libstagefright_foundation", blocks)
        self.assertNotIn("libstagefright_omx", blocks)

    def test_api28_stagefright_consumers_bind_to_legacy_modules(self) -> None:
        blocks = module_blocks()
        service = blocks["android.hardware.media.omx@1.0-service"]
        legacy_omx = blocks["libstagefright_omx-v28"]
        self.assertIn('"libstagefright_omx-v28"', service)
        self.assertIn('"libstagefright_foundation-v28"', legacy_omx)


if __name__ == "__main__":
    unittest.main()
