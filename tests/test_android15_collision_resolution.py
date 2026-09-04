from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

CAMERA_SOURCE_WRAPPERS = {
    "camera.device@1.0-impl",
    "camera.device@3.2-impl",
    "camera.device@3.3-impl",
    "camera.device@3.4-external-impl",
    "camera.device@3.4-impl",
}
LOCATION_SOURCE_CORE = {
    "libgps.utils",
    "libloc_core",
    "liblocation_api",
}
MEDIA_SOURCE_FRONTEND_PREBUILTS = {
    "android.hardware.media.omx@1.0-service",
    "libgui_vendor",
    "libstagefright_foundation-v28",
    "libstagefright_omx-v28",
}
MEDIA_SOURCE_FRONTEND_PATHS = {
    "vendor/bin/hw/android.hardware.media.omx@1.0-service",
    "vendor/lib/libgui_vendor.so",
    "vendor/lib/vndk/libstagefright_foundation.so",
    "vendor/lib/vndk/libstagefright_omx.so",
}
# Complete direct RED .118 proprietary consumer set for the source-owned
# Qualcomm location providers above. This is derived from the generated
# Android.bp DT_NEEDED/shared_libs graph.
PROPRIETARY_LOCATION_CONSUMERS = {
    "libDRPlugin",
    "libdataitems",
    "libdrplugin_client",
    "libevent_observer",
    "libflp",
    "libgdtap",
    "libgeofence",
    "libizat_client_api",
    "libizat_core",
    "liblbs_core",
    "libloc_api_v02",
    "liblocationservice",
    "liblocationservice_glue",
    "liblowi_wifihal",
    "libulp2",
    "libxtadapter",
    "libxtwifi_ulp_adaptor",
    "vendor.qti.gnss@1.0-impl",
    "xtwifi-client",
    "xtwifi-inet-agent",
}
SOURCE_OWNED_MODULES = {
    "android.hidl.base@1.0",
    *CAMERA_SOURCE_WRAPPERS,
    *LOCATION_SOURCE_CORE,
    *MEDIA_SOURCE_FRONTEND_PREBUILTS,
    "libalsautils",
    "libcld80211",
    "libkeystore-engine-wifi-hidl",
    "libkeystore-wifi-hidl",
    "libwifi-hal",
    "vendor.qti.hardware.camera.device@1.0",
    "vendor.qti.hardware.camera.device@1.0-v28",
    "vendor.qti.hardware.wifi.hostapd@1.0",
    "vendor.qti.hardware.wifi.supplicant@2.0",
}
SOURCE_OWNED_PATHS = {
    "vendor/lib/android.hidl.base@1.0.so",
    "vendor/lib/camera.device@1.0-impl.so",
    "vendor/lib/camera.device@3.2-impl.so",
    "vendor/lib/camera.device@3.3-impl.so",
    "vendor/lib/camera.device@3.4-external-impl.so",
    "vendor/lib/camera.device@3.4-impl.so",
    "vendor/lib/libalsautils.so",
    "vendor/lib/libgps.utils.so",
    "vendor/lib/libloc_core.so",
    "vendor/lib/liblocation_api.so",
    "vendor/lib64/camera.device@1.0-impl.so",
    "vendor/lib64/camera.device@3.2-impl.so",
    "vendor/lib64/camera.device@3.3-impl.so",
    "vendor/lib64/camera.device@3.4-external-impl.so",
    "vendor/lib64/camera.device@3.4-impl.so",
    "vendor/lib64/libalsautils.so",
    "vendor/lib64/libcld80211.so",
    "vendor/lib64/libgps.utils.so",
    "vendor/lib64/libkeystore-engine-wifi-hidl.so",
    "vendor/lib64/libkeystore-wifi-hidl.so",
    "vendor/lib64/libloc_core.so",
    "vendor/lib64/liblocation_api.so",
    "vendor/lib64/libwifi-hal.so",
    "vendor/lib/vendor.qti.hardware.camera.device@1.0.so",
    "vendor/lib64/vendor.qti.hardware.camera.device@1.0.so",
    "vendor/lib64/vendor.qti.hardware.wifi.hostapd@1.0.so",
    "vendor/lib64/vendor.qti.hardware.wifi.supplicant@2.0.so",
    *MEDIA_SOURCE_FRONTEND_PATHS,
}
SOURCE_PACKAGES_REQUIRED = {
    *CAMERA_SOURCE_WRAPPERS,
    *LOCATION_SOURCE_CORE,
    "libcld80211",
    "libkeystore-engine-wifi-hidl",
    "libkeystore-wifi-hidl",
    "libwifi-hal",
    "vendor.qti.hardware.camera.device@1.0",
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


def product_packages() -> set[str]:
    text = (ROOT / "hydrogenone-vendor.mk").read_text(encoding="utf-8")
    packages: set[str] = set()
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
        package = line.rstrip("\\").strip()
        if package:
            packages.add(package)
        if not line.endswith("\\"):
            in_packages = False
    return packages


class Android15CollisionResolutionTest(unittest.TestCase):
    def test_platform_source_owned_modules_are_not_selected_as_prebuilts(self) -> None:
        blocks = module_blocks()
        self.assertEqual(sorted(SOURCE_OWNED_MODULES & set(blocks)), [])
        self.assertEqual(sorted(SOURCE_OWNED_PATHS & active_paths()), [])

    def test_source_owned_runtime_modules_stay_packaged(self) -> None:
        packages = product_packages()
        self.assertEqual(sorted(SOURCE_PACKAGES_REQUIRED - packages), [])

    def test_complete_proprietary_location_consumer_closure_remains_selected(self) -> None:
        blocks = module_blocks()
        self.assertEqual(sorted(PROPRIETARY_LOCATION_CONSUMERS - set(blocks)), [])

    def test_pie_media_wrapper_closure_is_not_retained(self) -> None:
        blocks = module_blocks()
        self.assertEqual(sorted(MEDIA_SOURCE_FRONTEND_PREBUILTS & set(blocks)), [])
        self.assertEqual(sorted(MEDIA_SOURCE_FRONTEND_PATHS & active_paths()), [])

    def test_media_omx_source_ownership_is_recorded(self) -> None:
        lock = json.loads((ROOT / "SOURCE_LOCK.json").read_text(encoding="utf-8"))
        android15 = lock["android15_contract"]
        self.assertTrue(android15.get("source_owned_media_omx_stack_pruned"))
        self.assertFalse(android15.get("legacy_vndk28_stagefright_namespaced", True))

    def test_real_red_camera_hal_remains_proprietary_and_wrapper_independent(self) -> None:
        blocks = module_blocks()
        camera = blocks["camera.msm8998"]
        for wrapper in CAMERA_SOURCE_WRAPPERS:
            self.assertNotIn(f'"{wrapper}"', camera)


if __name__ == "__main__":
    unittest.main()
