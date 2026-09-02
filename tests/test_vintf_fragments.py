from __future__ import annotations

import re
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

EXPECTED = {
    "android.hardware.biometrics.fingerprint@2.1-service": {
        "@2.1::IBiometricsFingerprint/default",
        "@1.0::IFingerprintSensorTest/default",
    },
    "android.hardware.bluetooth@1.0-service-qti": {
        "@1.0::IBluetoothHci/default",
        "@1.0::IAntHci/default",
        "@1.0::IFmHci/default",
    },
    "android.hardware.media.omx@1.0-service": {
        "@1.0::IOmx/default",
        "@1.0::IOmxStore/default",
    },
    "wifidisplayhalservice": {
        "@1.0::IDSManager/wifidisplaydshal",
        "@1.0::IHDCPSession/wifidisplayhdcphal",
    },
    "vendor.cm.hardware.thermal3d@1.0-service.cm": {
        "@1.0::IThermal3d/default",
    },
    "vendor.leia.hardware.leiadisp@1.0-service": {
        "@1.0::ILeiadisp/default",
    },
    "vendor.qti.esepowermanager@1.0-service": {
        "@1.0::IEsePowerManager/default",
    },
    "qcrild": {
        "@1.1::IRadio/slot1",
        "@1.1::IRadio/slot2",
        "@1.1::ISap/slot1",
        "@1.1::ISap/slot2",
        "@1.0::IRadioConfig/default",
        "@1.0::ISecureElement/SIM1",
        "@1.0::ISecureElement/SIM2",
        "@1.0::IQcRilAudio/slot1",
        "@1.0::IQcRilAudio/slot2",
        "@1.0::IImsRadio/imsradio0",
        "@1.0::IImsRadio/imsradio1",
        "@1.0::IUimLpa/UimLpa0",
        "@1.0::IUimLpa/UimLpa1",
        "@1.0::IQtiOemHook/oemhook0",
        "@1.0::IQtiOemHook/oemhook1",
        "@1.0::IQtiRadio/slot1",
        "@1.0::IQtiRadio/slot2",
        "@1.1::IUim/Uim0",
        "@1.1::IUim/Uim1",
        "@1.0::IUimRemoteServiceClient/uimRemoteClient0",
        "@1.0::IUimRemoteServiceClient/uimRemoteClient1",
        "@1.0::IUimRemoteServiceServer/uimRemoteServer0",
        "@1.0::IUimRemoteServiceServer/uimRemoteServer1",
    },
}

SOURCE_OWNED_NAMES = {
    "android.hardware.gnss",
    "android.hardware.nfc",
}


def bp_block(module: str) -> str:
    text = (ROOT / "Android.bp").read_text(encoding="utf-8")
    pattern = re.compile(
        r"cc_prebuilt_(?:binary|library_shared)\s*\{(?:(?!\n\}).)*?"
        + r'\bname:\s*"'
        + re.escape(module)
        + r'"(?:(?!\n\}).)*?\n\}',
        re.S,
    )
    match = pattern.search(text)
    if not match:
        raise AssertionError(f"missing Soong module {module}")
    return match.group(0)


def fragment_for_module(module: str) -> Path:
    block = bp_block(module)
    match = re.search(r'vintf_fragments:\s*\[\s*"([^"]+)"\s*\]', block, re.S)
    if not match:
        raise AssertionError(f"{module} has no vintf_fragments property")
    return ROOT / match.group(1)


def fragment_fqnames(path: Path) -> set[str]:
    root = ET.parse(path).getroot()
    return {node.text.strip() for node in root.findall(".//fqname") if node.text}


class ProprietaryVintfContractTest(unittest.TestCase):
    def test_every_retained_proprietary_hal_has_exact_stock_fragment(self) -> None:
        for module, expected in EXPECTED.items():
            fragment = fragment_for_module(module)
            self.assertTrue(fragment.is_file(), f"missing VINTF fragment for {module}: {fragment}")
            self.assertEqual(fragment_fqnames(fragment), expected, module)

    def test_vendor_fragments_do_not_redeclare_source_owned_gnss_or_nfc(self) -> None:
        conflicts: list[str] = []
        for fragment in sorted((ROOT / "vintf").glob("*.xml")):
            root = ET.parse(fragment).getroot()
            for hal in root.findall("hal"):
                name = hal.findtext("name")
                if name in SOURCE_OWNED_NAMES:
                    conflicts.append(f"{fragment.name}: {name}")
        self.assertEqual(conflicts, [], f"source-owned HALs leaked into vendor VINTF: {conflicts}")

    def test_fragments_are_device_manifests_with_hwbinder_transport(self) -> None:
        for module in EXPECTED:
            root = ET.parse(fragment_for_module(module)).getroot()
            self.assertEqual(root.tag, "manifest")
            self.assertEqual(root.attrib.get("type"), "device")
            for hal in root.findall("hal"):
                self.assertEqual(hal.attrib.get("format"), "hidl")
                self.assertEqual(hal.findtext("transport"), "hwbinder")


if __name__ == "__main__":
    unittest.main()
