from __future__ import annotations

import hashlib
import json
import re
import subprocess
import unittest
from pathlib import Path

from tools.apply_android15_vendor_contract import BASELINE_PIPELINE, POST_CAMERA_PIPELINE


ROOT = Path(__file__).resolve().parents[1]
RELATIVE_PATH = "vendor/bin/qrtr-ns"
EXPECTED_SIZE = 68632
EXPECTED_SHA256 = "294d3d810af39d66db49469917e46fc0537e5122cf54c883344135bfd83bf7dd"


def selected_paths() -> set[str]:
    result: set[str] = set()
    for raw in (ROOT / "proprietary-files.txt").read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        body = line.split(";", 1)[0]
        result.add(body.split(":", 1)[0].lstrip("-"))
    return result


class Red118QrtrNameServiceTest(unittest.TestCase):
    def test_vendor_pipeline_restores_qrtr_before_elf_generation(self) -> None:
        step = "restore_red118_qrtr_name_service.py"
        for pipeline in (BASELINE_PIPELINE, POST_CAMERA_PIPELINE):
            self.assertIn(step, pipeline)
            self.assertLess(pipeline.index(step), pipeline.index("generate_elf_contract.py"))

    def test_exact_stock118_binary_is_retained(self) -> None:
        path = ROOT / "proprietary" / RELATIVE_PATH
        self.assertTrue(path.is_file(), f"missing RED .118 payload: {RELATIVE_PATH}")
        if not path.is_file():
            return

        data = path.read_bytes()
        self.assertEqual(len(data), EXPECTED_SIZE)
        self.assertEqual(hashlib.sha256(data).hexdigest(), EXPECTED_SHA256)

        header = subprocess.run(
            ["readelf", "-h", str(path)],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        self.assertRegex(header, r"(?m)^\s*Class:\s+ELF64$")
        self.assertRegex(header, r"(?m)^\s*Machine:\s+AArch64$")

        dynamic = subprocess.run(
            ["readelf", "-d", str(path)],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        needed = set(re.findall(r"Shared library: \[([^]]+)]", dynamic))
        self.assertIn("libqrtr.so", needed)

    def test_binary_is_selected_pinned_and_packaged(self) -> None:
        self.assertIn(RELATIVE_PATH, selected_paths())

        manifest = json.loads(
            (ROOT / "proprietary-manifest.json").read_text(encoding="utf-8")
        )
        by_path = {entry["path"]: entry for entry in manifest["files"]}
        self.assertEqual(
            by_path.get(RELATIVE_PATH),
            {
                "tier": "P0",
                "path": RELATIVE_PATH,
                "size": EXPECTED_SIZE,
                "sha256": EXPECTED_SHA256,
            },
        )

        bp = (ROOT / "Android.bp").read_text(encoding="utf-8")
        match = re.search(
            r'cc_prebuilt_binary\s*\{(?:(?!\n\}).)*?name:\s*"qrtr-ns"(?:(?!\n\}).)*?\n\}',
            bp,
            re.S,
        )
        self.assertIsNotNone(match, "qrtr-ns prebuilt module is not declared")
        if match is not None:
            self.assertIn('"proprietary/vendor/bin/qrtr-ns"', match.group(0))
            self.assertIn('"libqrtr"', match.group(0))

        mk = (ROOT / "hydrogenone-vendor.mk").read_text(encoding="utf-8")
        self.assertRegex(mk, r"(?m)^\s*qrtr-ns\s*\\?\s*$")

    def test_unproven_qrtr_utilities_are_not_added(self) -> None:
        self.assertTrue(
            {"vendor/bin/qrtr-cfg", "vendor/bin/qrtr-lookup"}.isdisjoint(selected_paths())
        )


if __name__ == "__main__":
    unittest.main()
