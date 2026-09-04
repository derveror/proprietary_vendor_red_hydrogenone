from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

OBSOLETE_PATHS = {
    "vendor/lib64/soundfx/libaudiopreprocessing.so",
    "vendor/lib64/libwebrtc_audio_preprocessing.so",
}
OBSOLETE_MODULES = {
    "libaudiopreprocessing",
    "libwebrtc_audio_preprocessing",
}
SOURCE_PACKAGE = "libaudiopreprocessing"
OBSOLETE_PACKAGE = "libwebrtc_audio_preprocessing"


def selected_paths() -> set[str]:
    manifest = json.loads((ROOT / "proprietary-manifest.json").read_text(encoding="utf-8"))
    return {entry["path"] for entry in manifest["files"]}


def proprietary_file_paths() -> set[str]:
    result: set[str] = set()
    for raw in (ROOT / "proprietary-files.txt").read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        body = line.split(";", 1)[0]
        result.add(body.split(":", 1)[0].lstrip("-"))
    return result


def package_selected(text: str, module: str) -> bool:
    return bool(re.search(rf"(?m)^\s*{re.escape(module)}\s*\\?\s*$", text))


class AudioPreprocessingOwnershipTest(unittest.TestCase):
    def test_obsolete_red_preprocessing_payload_is_not_selected(self) -> None:
        self.assertTrue(OBSOLETE_PATHS.isdisjoint(selected_paths()))
        self.assertTrue(OBSOLETE_PATHS.isdisjoint(proprietary_file_paths()))
        for path in OBSOLETE_PATHS:
            self.assertFalse((ROOT / "proprietary" / path).exists(), path)

    def test_generated_vendor_modules_do_not_shadow_android15_preprocessing(self) -> None:
        bp = (ROOT / "Android.bp").read_text(encoding="utf-8")
        vendor_mk = (ROOT / "hydrogenone-vendor.mk").read_text(encoding="utf-8")
        exceptions = json.loads(
            (ROOT / "ANDROID15_ELF_EXCEPTIONS.json").read_text(encoding="utf-8")
        )["exceptions"]

        for module in OBSOLETE_MODULES:
            self.assertNotRegex(bp, rf'(?m)^\s*name:\s*"{re.escape(module)}"\s*,')
            self.assertNotIn(module, exceptions)

        # Keep the generic package name so LineageOS 22.2 source provides the
        # current vendor libaudiopreprocessing implementation.  The old RED
        # private libwebrtc companion has no modern shared-library owner and
        # must not remain selected.
        self.assertTrue(package_selected(vendor_mk, SOURCE_PACKAGE))
        self.assertFalse(package_selected(vendor_mk, OBSOLETE_PACKAGE))

    def test_contract_pipeline_reproduces_pruning_decision(self) -> None:
        pipeline = (ROOT / "tools/apply_android15_vendor_contract.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("prune_obsolete_audio_preprocessing_stack.py", pipeline)

        lock = json.loads((ROOT / "SOURCE_LOCK.json").read_text(encoding="utf-8"))
        self.assertTrue(
            lock["android15_contract"].get("obsolete_audio_preprocessing_pruned"),
            lock["android15_contract"],
        )
        self.assertEqual(
            lock["android15_contract"].get("source_owned_audio_preprocessing_package"),
            SOURCE_PACKAGE,
        )


if __name__ == "__main__":
    unittest.main()
