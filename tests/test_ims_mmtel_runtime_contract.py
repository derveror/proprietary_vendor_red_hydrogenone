from __future__ import annotations

import hashlib
import json
import re
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROPRIETARY = ROOT / "proprietary"

EXPECTED_SHA256 = {
    "system_ext/app/QtiTelephonyService/QtiTelephonyService.apk": (
        "f2b0ff541ea2b4ab57606fe7cf5737e0a1f21d29d5fb4f02d830488fefdbff06"
    ),
    "system_ext/etc/permissions/qcrilhook.xml": (
        "30f2d18283025a215e823cd286a89673280077791d22ce5ccabcbb5a6e71bf5f"
    ),
    "system_ext/framework/qcrilhook.jar": (
        "d4ee895698102bc443693beaeb184832c60a1c01da4df5a965af17b068327825"
    ),
    "system_ext/lib64/libimscamera_jni.so": (
        "fff8a5e72e930e7333672ffb6c4c8ee78bdb49d5539d3afd24d2d08c7ec08213"
    ),
    "system_ext/lib64/libimsmedia_jni.so": (
        "6f7a232d43deb578bbf20dc28a20c28b50ecedd451951c3c62cfc401a36e77ec"
    ),
    "system_ext/priv-app/ims/ims.apk": (
        "b4619d79ed14ebfaa5b052d693b22511890acd96213df05af3cb551444939416"
    ),
    "system_ext/priv-app/qcrilmsgtunnel/qcrilmsgtunnel.apk": (
        "e23970ba15b1ab5b82fcb23a48ac3cdff7441b16795b316cc5cdde4054632fbb"
    ),
}


class ImsMmtelRuntimeContractTest(unittest.TestCase):
    def test_fp3_ims_frontend_is_byte_verified(self) -> None:
        for relative, expected in EXPECTED_SHA256.items():
            path = PROPRIETARY / relative
            self.assertTrue(path.is_file(), relative)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), expected)

    def test_ims_apk_declares_mmtel_service_and_required_libraries(self) -> None:
        apk = PROPRIETARY / "system_ext/priv-app/ims/ims.apk"
        self.assertTrue(apk.is_file())
        if not apk.is_file():
            return
        with zipfile.ZipFile(apk) as archive:
            manifest = archive.read("AndroidManifest.xml")
        for value in (
            "org.codeaurora.ims",
            "android.telephony.ims.ImsService",
            "qti-telephony-hidl-wrapper",
            "qti-telephony-utils",
            "ims-ext-common",
        ):
            self.assertIn(value.encode("utf-16le"), manifest, value)
    def test_qti_telephony_service_declares_radio_audio_bridge(self) -> None:
        apk = (
            PROPRIETARY
            / "system_ext/app/QtiTelephonyService/QtiTelephonyService.apk"
        )
        self.assertTrue(apk.is_file())
        if not apk.is_file():
            return
        with zipfile.ZipFile(apk) as archive:
            manifest = archive.read("AndroidManifest.xml")
            classes = archive.read("classes.dex")
        for value in (
            "com.qualcomm.qti.telephonyservice",
            "android.permission.MODIFY_AUDIO_ROUTING",
            "android.permission.MODIFY_AUDIO_SETTINGS",
            "com.qualcomm.permission.USE_QCRIL_MSG_TUNNEL",
            "com.qualcomm.qcrilhook",
            "qti-telephony-hidl-wrapper",
            "qti-telephony-utils",
        ):
            self.assertIn(value.encode("utf-16le"), manifest, value)
        for value in (
            b"QcRilAudio",
            b"vendor.qti.hardware.radio.am@1.0::IQcRilAudio",
            b"setParameters",
            b"setParameters with: ",
        ):
            self.assertIn(value, classes, value.decode())

    def test_qcrilhook_permission_xml_loads_the_bridge_library(self) -> None:
        permission = (
            PROPRIETARY / "system_ext/etc/permissions/qcrilhook.xml"
        ).read_text(encoding="utf-8")
        self.assertIn('name="com.qualcomm.qcrilhook"', permission)
        self.assertIn('file="/system_ext/framework/qcrilhook.jar"', permission)
        self.assertIn(
            'dependency="qti-telephony-utils:qti-telephony-hidl-wrapper"',
            permission,
        )

    def test_ims_modules_and_private_jni_symlinks_are_generated(self) -> None:
        android_bp = (ROOT / "Android.bp").read_text(encoding="utf-8")
        for module in (
            "QtiTelephonyService",
            "ims",
            "libimscamera_jni",
            "libimsmedia_jni",
            "qcrilhook",
            "qcrilmsgtunnel",
        ):
            self.assertRegex(android_bp, rf'name: "{re.escape(module)}"')
        self.assertIn(
            'installed_location: "priv-app/ims/lib/arm64/libimscamera_jni.so"',
            android_bp,
        )
        self.assertIn(
            'installed_location: "priv-app/ims/lib/arm64/libimsmedia_jni.so"',
            android_bp,
        )

        vendor_makefile = (ROOT / "hydrogenone-vendor.mk").read_text(
            encoding="utf-8"
        )
        for module in (
            "QtiTelephonyService",
            "ims",
            "libimscamera_jni",
            "libimsmedia_jni",
            "system_ext_priv-app_ims_lib_arm64_libimscamera_jni_so",
            "system_ext_priv-app_ims_lib_arm64_libimsmedia_jni_so",
            "qcrilhook",
            "qcrilmsgtunnel",
        ):
            self.assertRegex(
                vendor_makefile, rf"(?m)^\s*{re.escape(module)}(?:\s*\\)?$"
            )
        self.assertIn(
            "proprietary/system_ext/etc/permissions/qcrilhook.xml:"
            "$(TARGET_COPY_OUT_SYSTEM_EXT)/etc/permissions/qcrilhook.xml",
            vendor_makefile,
        )

        generator = (ROOT / "tools/generate_elf_contract.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('"install_symlink",', generator)

    def test_source_metadata_pins_the_shared_reference_runtime(self) -> None:
        source_lock = json.loads((ROOT / "SOURCE_LOCK.json").read_text(encoding="utf-8"))
        ims = source_lock["android15_contract"]["ims_mmtel_runtime"]
        self.assertEqual(ims["donor_build"], "FP3 6.A.040.2")
        self.assertEqual(
            set(ims["validated_reference_trees"]),
            {
                "essential/mata",
                "razer/cheryl",
                "oneplus/msm8998-common",
                "nubia/msm8998-common",
            },
        )
        self.assertEqual(set(ims["paths"]), set(EXPECTED_SHA256))

        manifest = json.loads(
            (ROOT / "proprietary-manifest.json").read_text(encoding="utf-8")
        )
        by_path = {entry["path"]: entry for entry in manifest["files"]}
        for relative, expected in EXPECTED_SHA256.items():
            self.assertIn(relative, by_path)
            self.assertEqual(by_path[relative]["sha256"], expected)
            self.assertEqual(by_path[relative]["tier"], "P1")


if __name__ == "__main__":
    unittest.main()
