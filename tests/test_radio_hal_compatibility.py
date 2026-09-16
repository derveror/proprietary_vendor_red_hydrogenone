from __future__ import annotations

import subprocess
import unittest
import xml.etree.ElementTree as ET
import json
import re
from pathlib import Path

from tools import generate_elf_contract


ROOT = Path(__file__).resolve().parents[1]
QCRIL = ROOT / "proprietary/vendor/lib64/libril-qc-hal-qmi.so"
RADIO_MANIFEST = ROOT / "vintf/radio.xml"


def dynamic_dependencies(path: Path) -> set[str]:
    output = subprocess.run(
        ["readelf", "-d", path],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return {
        line.split("[", 1)[1].split("]", 1)[0]
        for line in output.splitlines()
        if "(NEEDED)" in line
    }


class RadioHalCompatibilityTest(unittest.TestCase):
    def test_generator_maps_versioned_protobuf_provider(self) -> None:
        self.assertEqual(
            generate_elf_contract.module_for_soname(
                "libprotobuf-cpp-full-3.9.1.so", {}
            ),
            "libprotobuf-cpp-full-3.9.1-vendorcompat",
        )

    def test_generator_keeps_make_only_radio_shims_out_of_soong_edges(self) -> None:
        helper = getattr(generate_elf_contract, "soong_dependency_modules", None)
        self.assertIsNotNone(helper)
        if helper is None:
            return
        self.assertEqual(
            helper(
                [
                    "android.hardware.radio.c_shim@1.0.so",
                    "android.hardware.radio.c_shim@1.1.so",
                    "android.hardware.radio@1.4.so",
                ],
                {},
            ),
            ["android.hardware.radio@1.4"],
        )

    def test_qcril_has_one_documented_make_soong_checkelf_exception(self) -> None:
        bp = (ROOT / "Android.bp").read_text(encoding="utf-8")
        block = re.search(
            r'cc_prebuilt_library_shared\s*\{(?:(?!\n\}).)*?'
            r'\bname:\s*"libril-qc-hal-qmi"(?:(?!\n\}).)*?\n\}',
            bp,
            re.S,
        )
        self.assertIsNotNone(block)
        if block is None:
            return
        self.assertIn("check_elf_files: false", block.group(0))

        registry = json.loads(
            (ROOT / "ANDROID15_ELF_EXCEPTIONS.json").read_text(encoding="utf-8")
        )["exceptions"]
        self.assertEqual(set(registry), {"libril-qc-hal-qmi"})
        self.assertEqual(
            set(registry["libril-qc-hal-qmi"]["blocking_dependencies"]),
            {
                "android.hardware.radio.c_shim@1.0",
                "android.hardware.radio.c_shim@1.1",
                "android.hardware.radio.c_shim@1.2",
            },
        )

    def test_qcril_exposes_android15_supported_radio_hal(self) -> None:
        needed = dynamic_dependencies(QCRIL)
        self.assertIn("android.hardware.radio@1.4.so", needed)
        self.assertIn("android.hardware.radio@1.5.so", needed)

    def test_qcril_uses_lineage_radio_config_backend(self) -> None:
        needed = dynamic_dependencies(QCRIL)
        for version in ("1.0", "1.1", "1.2"):
            self.assertIn(f"android.hardware.radio.c_shim@{version}.so", needed)
            self.assertNotIn(f"android.hardware.radio.config@{version}.so", needed)

    def test_manifest_advertises_frontend_compatible_radio_services(self) -> None:
        root = ET.parse(RADIO_MANIFEST).getroot()
        hals = {hal.findtext("name"): hal for hal in root.findall("hal")}

        radio = hals["android.hardware.radio"]
        fqnames = {node.text for node in radio.findall("fqname")}
        self.assertIn("@1.4::IRadio/slot1", fqnames)
        self.assertIn("@1.4::IRadio/slot2", fqnames)

        self.assertNotIn("android.hardware.radio.config", hals)
        backend = hals["lineage.hardware.radio.config"]
        self.assertEqual(
            {node.text for node in backend.findall("fqname")},
            {"@1.0::IRadioConfig/default"},
        )

    def test_source_lock_records_reference_radio_override(self) -> None:
        source_lock = json.loads((ROOT / "SOURCE_LOCK.json").read_text(encoding="utf-8"))
        override = source_lock["android15_contract"].get("radio_compatibility")
        self.assertIsNotNone(override)
        if override is None:
            return
        self.assertEqual(override["donor_build"], "FP3 6.A.025.0")
        self.assertEqual(
            override["validated_reference_trees"],
            ["essential/mata", "razer/cheryl", "oneplus/msm8998-common", "nubia/msm8998-common"],
        )
        self.assertIn("vendor/lib64/libril-qc-hal-qmi.so", override["paths"])
        self.assertIn("vendor/bin/hw/qcrild", override["paths"])


if __name__ == "__main__":
    unittest.main()
