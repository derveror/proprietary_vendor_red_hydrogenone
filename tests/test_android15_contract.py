from __future__ import annotations

import fnmatch
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# These components are intentionally source-owned by device/red/hydrogenone or
# by the Android 15 platform. Keeping the Android 9 prebuilt wrapper as an
# active package creates duplicate module/service ownership or starts the wrong
# legacy HAL.
FORBIDDEN_VENDOR_MODULES = {
    "android.hardware.audio.effect@2.0-impl",
    "android.hardware.audio.effect@4.0-impl",
    "android.hardware.audio@2.0-impl",
    "android.hardware.audio@4.0-impl",
    "android.hardware.audio@2.0-service",
    "android.hardware.camera.provider@2.4-impl",
    "android.hardware.camera.provider@2.4-service",
    "android.hardware.gnss@1.0-impl-qti",
    "android.hardware.sensors@1.0-impl",
    "android.hardware.sensors@1.0-service",
    "android.hardware.soundtrigger@2.1-impl",
    "android.hardware.usb@1.0-service",
    "android.hardware.wifi@1.0-service",
    "audio.primary.msm8998",
    "audio.r_submix.default",
    "audio.usb.default",
    "libdrm",
    "libeffects",
    "libeffectsconfig",
    "libgnss",
    "libgnsspps",
    "libwifi-hal-qcom",
    "libwpa_client",
}

SOURCE_OWNED_VENDOR_PATHS = {
    "vendor/lib64/libdrm.so",
    "vendor/lib/libeffects.so",
    "vendor/lib64/libeffects.so",
    "vendor/lib/libeffectsconfig.so",
    "vendor/lib64/libeffectsconfig.so",
}

FORBIDDEN_STOCK_RC = {
    "vendor/etc/init/android.hardware.audio@2.0-service.rc",
    "vendor/etc/init/android.hardware.boot@1.0-service.rc",
    "vendor/etc/init/android.hardware.camera.provider@2.4-service.rc",
    "vendor/etc/init/android.hardware.configstore@1.1-service.rc",
    "vendor/etc/init/android.hardware.gatekeeper@1.0-service-qti.rc",
    "vendor/etc/init/android.hardware.graphics.allocator@2.0-service.rc",
    "vendor/etc/init/android.hardware.graphics.composer@2.1-service.rc",
    "vendor/etc/init/android.hardware.health@2.0-service.rc",
    "vendor/etc/init/android.hardware.keymaster@3.0-service-qti.rc",
    "vendor/etc/init/android.hardware.light@2.0-service.rc",
    "vendor/etc/init/android.hardware.sensors@1.0-service.rc",
    "vendor/etc/init/android.hardware.usb@1.0-service.rc",
    "vendor/etc/init/android.hardware.vibrator@1.0-service.rc",
    "vendor/etc/init/android.hardware.wifi@1.0-service.rc",
}

DEBUG_TEST_GLOBS = (
    "vendor/bin/audioflacapp",
    "vendor/bin/fpc_tee_test",
    "vendor/bin/mm-*-test",
    "vendor/bin/mm-audio-ftm",
    "vendor/bin/mm-qcamera-app",
    "vendor/bin/qmi_simple_ril_test",
    "vendor/bin/sensorrdiag",
)

MUST_RETAIN = {
    "vendor/bin/thermal-engine",
    "vendor/bin/hw/qcrild",
    "vendor/bin/hw/rild",
    "vendor/lib/hw/camera.msm8998.so",
    "vendor/lib/libmmcamera2_mct.so",
    "vendor/firmware/leia_pfp_470.fw",
    "vendor/firmware/leia_pm4_470.fw",
}


def proprietary_paths() -> set[str]:
    paths: set[str] = set()
    for raw in (ROOT / "proprietary-files.txt").read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        body = line.split(";", 1)[0]
        paths.add(body.split(":", 1)[0].lstrip("-"))
    return paths


def manifest_paths() -> set[str]:
    data = json.loads((ROOT / "proprietary-manifest.json").read_text(encoding="utf-8"))
    return {entry["path"] for entry in data["files"]}


def package_names() -> set[str]:
    text = (ROOT / "hydrogenone-vendor.mk").read_text(encoding="utf-8")
    package_text = "\n".join(
        block.group(1)
        for block in re.finditer(
            r"PRODUCT_PACKAGES\s*\+=\s*\\\n(.*?)(?=\n\n|\n[A-Z_]+\s*[:+]?=|\Z)",
            text,
            re.S,
        )
    )
    return set(re.findall(r"(?m)^\s*([A-Za-z0-9_.@+:-]+)\s*\\?\s*$", package_text))


def bp_module_names() -> set[str]:
    text = (ROOT / "Android.bp").read_text(encoding="utf-8")
    return set(re.findall(r'(?m)^\s*name:\s*"([^"]+)"\s*,?\s*$', text))


class Android15VendorContractTest(unittest.TestCase):
    def test_vendor_does_not_request_unavailable_vndk_28_snapshot(self) -> None:
        for name in ("BoardConfigVendor.mk", "hydrogenone-vendor.mk"):
            text = (ROOT / name).read_text(encoding="utf-8")
            self.assertNotRegex(
                text,
                r"(?m)^\s*PRODUCT_EXTRA_VNDK_VERSIONS\s*[:+?]?=.*(?:^|\s)28(?:\s|$)",
                f"{name} must not request the unavailable LineageOS 22.2 VNDK 28 snapshot",
            )

    def test_source_owned_modules_are_not_packaged_as_stock_prebuilts(self) -> None:
        active = package_names()
        declared = bp_module_names()
        conflicts = sorted(FORBIDDEN_VENDOR_MODULES & (active | declared))
        self.assertEqual(conflicts, [], f"source-owned vendor modules remain: {conflicts}")

    def test_android15_source_owned_elf_files_are_not_selected(self) -> None:
        selected = proprietary_paths() | manifest_paths()
        conflicts = sorted(SOURCE_OWNED_VENDOR_PATHS & selected)
        self.assertEqual(conflicts, [], f"Android 15 source-owned ELF files remain: {conflicts}")

    def test_source_owned_stock_rc_files_are_not_selected(self) -> None:
        paths = proprietary_paths() | manifest_paths()
        conflicts = sorted(FORBIDDEN_STOCK_RC & paths)
        self.assertEqual(conflicts, [], f"source-owned stock rc files remain: {conflicts}")

    def test_factory_and_debug_executables_are_not_selected(self) -> None:
        paths = proprietary_paths() | manifest_paths()
        conflicts = sorted(
            path
            for path in paths
            if any(fnmatch.fnmatch(path, pattern) for pattern in DEBUG_TEST_GLOBS)
        )
        self.assertEqual(conflicts, [], f"factory/debug executables remain: {conflicts}")

    def test_pruning_keeps_required_red_runtime_payload(self) -> None:
        paths = proprietary_paths() & manifest_paths()
        missing = sorted(MUST_RETAIN - paths)
        self.assertEqual(missing, [], f"required RED runtime payload missing: {missing}")

    def test_no_red_common_tree_reference_is_introduced(self) -> None:
        for path in (ROOT / "Android.bp", ROOT / "hydrogenone-vendor.mk", ROOT / "BoardConfigVendor.mk"):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("vendor/red/msm8998-common", text, path.name)
            self.assertNotIn("device/red/msm8998-common", text, path.name)


if __name__ == "__main__":
    unittest.main()
