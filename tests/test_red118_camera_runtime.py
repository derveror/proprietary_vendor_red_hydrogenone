from __future__ import annotations

import hashlib
import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.record_red118_camera_runtime import camera_runtime_paths

STILL_CAPTURE_PATHS = {
    "vendor/lib/libjpegdhw.so",
    "vendor/lib/libjpegdmahw.so",
    "vendor/lib/libjpegehw.so",
    "vendor/lib/libmmcamera_tintless_algo.so",
    "vendor/lib/libmmcamera_tintless_bg_pca_algo.so",
    "vendor/lib/libmmjpeg.so",
    "vendor/lib/libmmqjpeg_codec.so",
    "vendor/lib/libmmqjpegdma.so",
    "vendor/lib/libqomx_jpegdec.so",
    "vendor/lib/libqomx_jpegenc.so",
    "vendor/lib/libqomx_jpegenc_pipe.so",
}


def make_variable_tokens(text: str, variable: str) -> set[str]:
    values: set[str] = set()
    logical = ""
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].rstrip()
        logical = f"{logical} {line}".strip()
        if logical.endswith("\\"):
            logical = logical[:-1].rstrip()
            continue
        match = re.match(rf"^{re.escape(variable)}\s*\+=\s*(.*)$", logical)
        if match:
            values.update(match.group(1).split())
        logical = ""
    return values


class Red118CameraRuntimeTest(unittest.TestCase):
    def test_all_camera_runtime_files_are_pinned_to_the_manifest(self) -> None:
        paths = camera_runtime_paths()
        missing_runtime = sorted(STILL_CAPTURE_PATHS - paths)
        self.assertEqual(
            missing_runtime,
            [],
            "missing still-capture runtime paths:\n" + "\n".join(missing_runtime),
        )
        self.assertEqual(len(paths), 196)
        self.assertIn("vendor/lib/libremosaic_daemon.so", paths)
        manifest = json.loads(
            (ROOT / "proprietary-manifest.json").read_text(encoding="utf-8")
        )
        by_path = {entry["path"]: entry for entry in manifest["files"]}
        missing = sorted(paths - by_path.keys())
        self.assertEqual(missing, [], "unpinned camera runtime files:\n" + "\n".join(missing))
        for path in sorted(paths):
            data = (ROOT / "proprietary" / path).read_bytes()
            self.assertEqual(by_path[path]["tier"], "P1", path)
            self.assertEqual(by_path[path]["size"], len(data), path)
            self.assertEqual(by_path[path]["sha256"], hashlib.sha256(data).hexdigest(), path)

    def test_still_capture_libraries_are_32_bit_arm_elf(self) -> None:
        failures = []
        for path in sorted(STILL_CAPTURE_PATHS):
            blob = ROOT / "proprietary" / path
            if not blob.is_file():
                failures.append(f"missing {path}")
                continue
            header = blob.read_bytes()[:20]
            if header[:4] != b"\x7fELF":
                failures.append(f"{path}: not ELF")
                continue
            if header[4] != 1:
                failures.append(f"{path}: not ELFCLASS32")
            if int.from_bytes(header[18:20], "little") != 40:
                failures.append(f"{path}: not ARM")
        self.assertEqual(failures, [], "invalid still-capture blobs:\n" + "\n".join(failures))

    def test_pipeline_replays_camera_manifest_recording(self) -> None:
        pipeline = (ROOT / "tools" / "apply_android15_vendor_contract.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('"record_red118_camera_runtime.py"', pipeline)

    def test_every_camera_runtime_file_is_packaged_and_audited(self) -> None:
        paths = camera_runtime_paths()
        elf_modules = {
            Path(path).name.removesuffix(".so")
            for path in paths
            if path.endswith(".so")
        }
        self.assertEqual(len(elf_modules), 195)
        android_bp = (ROOT / "Android.bp").read_text(encoding="utf-8")
        vendor_mk = (ROOT / "hydrogenone-vendor.mk").read_text(encoding="utf-8")
        declared = set(re.findall(r'(?m)^\s*name:\s*"([^"]+)"', android_bp))
        packaged = make_variable_tokens(vendor_mk, "PRODUCT_PACKAGES")
        audit = json.loads((ROOT / "ANDROID15_ELF_AUDIT.json").read_text(encoding="utf-8"))
        self.assertEqual(sorted(elf_modules - declared), [], "missing Soong camera modules")
        self.assertEqual(sorted(elf_modules - packaged), [], "unpackaged camera modules")
        self.assertEqual(sorted(elf_modules - audit["modules"].keys()), [], "unaudited camera modules")
        disabled = sorted(
            name
            for name in elf_modules
            if not audit["modules"][name]["check_elf_files"]
        )
        self.assertEqual(disabled, [], "camera modules with checkelf disabled")
        firmware_rule = (
            "vendor/red/hydrogenone/proprietary/vendor/firmware/"
            "cpp_firmware_v1_12_0.fw:$(TARGET_COPY_OUT_VENDOR)/firmware/"
            "cpp_firmware_v1_12_0.fw"
        )
        self.assertIn(firmware_rule, make_variable_tokens(vendor_mk, "PRODUCT_COPY_FILES"))

    def test_camera_runtime_audit_has_one_current_note(self) -> None:
        audit = json.loads((ROOT / "VENDOR_TREE_AUDIT.json").read_text(encoding="utf-8"))
        notes = [
            note
            for note in audit["notes"]
            if note.startswith("RED .118 production camera runtime closure retains")
        ]
        self.assertEqual(len(notes), 1)
        self.assertIn(
            "58 sensor, ISP, image-processing, JPEG, flash, and firmware files",
            notes[0],
        )

    def test_checkelf_summaries_are_consistent(self) -> None:
        elf = json.loads((ROOT / "ANDROID15_ELF_AUDIT.json").read_text(encoding="utf-8"))
        generated = json.loads(
            (ROOT / "GENERATED_VENDOR_AUDIT.json").read_text(encoding="utf-8")
        )
        tree = json.loads((ROOT / "VENDOR_TREE_AUDIT.json").read_text(encoding="utf-8"))
        summary = elf["summary"]
        expected = (
            summary["total_modules"],
            summary["checkelf_enabled"],
            summary["checkelf_exceptions"],
        )
        self.assertEqual(
            expected,
            (
                generated["elf_modules"],
                generated["checkelf_enabled"],
                generated["checkelf_exceptions"],
            ),
        )
        checkelf_notes = [
            note
            for note in tree["notes"]
            if note.startswith("Current ELF contract:")
        ]
        self.assertEqual(
            checkelf_notes,
            [
                f"Current ELF contract: {expected[1]} of {expected[0]} proprietary "
                f"ELF modules have check_elf_files enabled; {expected[2]} exceptions remain."
            ],
        )


if __name__ == "__main__":
    unittest.main()
