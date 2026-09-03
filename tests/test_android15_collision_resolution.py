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
PROPRIETARY_LOCATION_CONSUMERS = {
    "libizat_core",
    "liblbs_core",
    "libloc_api_v02",
    "liblocationservice",
    "liblocationservice_glue",
    "vendor.qti.gnss@1.0-impl",
}
SOURCE_OWNED_MODULES = {
    "android.hidl.base@1.0",
    *CAMERA_SOURCE_WRAPPERS,
    *LOCATION_SOURCE_CORE,
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

    def test_proprietary_location_consumers_remain_selected_while_core_is_source_owned(self) -> None:
        blocks = module_blocks()
        self.assertEqual(sorted(PROPRIETARY_LOCATION_CONSUMERS - set(blocks)), [])

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

    def test_real_red_camera_hal_remains_proprietary_and_wrapper_independent(self) -> None:
        blocks = module_blocks()
        camera = blocks["camera.msm8998"]
        for wrapper in CAMERA_SOURCE_WRAPPERS:
            self.assertNotIn(f'"{wrapper}"', camera)


if __name__ == "__main__":
    unittest.main()
