from __future__ import annotations

import hashlib
import json
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

# LineageOS 22.2 cheryl uses this Android 11 sld_sprout peripheral-manager
# triplet.  The RED .118 Android 9 pair aborts in Android 15 libutils before it
# can vote the modem WLAN protection domain online.
CHERYL_SLD_PERIPHERAL_MANAGER = {
    "vendor/bin/pm-service": {
        "size": 54888,
        "sha256": "13382d52072aebd899eecc4578802a9a85bc6a4f8e1beea876bcc8f9aebf109f",
        "build_id": "0418cb700f32ed704c56d588f1dcad2f",
    },
    "vendor/bin/pm-proxy": {
        "size": 11672,
        "sha256": "a7b90a7d70f155f0d9f29040b51be2cab44dcbde977f949895ef0e5e5afc714b",
        "build_id": "609eb0a072479411693c079886026116",
    },
    "vendor/lib64/libperipheral_client.so": {
        "size": 55648,
        "sha256": "8cf22edb4c18359ce8f3523352a16e0ef8af3df6cbb40add57fa840351a1bf0f",
        "build_id": "c92710c6c4c5bc5c5a6e20d1d6ff2361",
    },
}


class Android15PeripheralManagerTest(unittest.TestCase):
    def test_cheryl_sld_triplet_replaces_android9_red_binaries(self) -> None:
        failures: list[str] = []
        for relative, expected in CHERYL_SLD_PERIPHERAL_MANAGER.items():
            path = ROOT / "proprietary" / relative
            if not path.is_file():
                failures.append(f"missing {relative}")
                continue

            data = path.read_bytes()
            if len(data) != expected["size"]:
                failures.append(f"{relative}: size {len(data)} != {expected['size']}")
            actual_sha = hashlib.sha256(data).hexdigest()
            if actual_sha != expected["sha256"]:
                failures.append(
                    f"{relative}: sha256 {actual_sha} != {expected['sha256']}"
                )

            notes = subprocess.run(
                ["readelf", "-n", str(path)],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
            if f"Build ID: {expected['build_id']}" not in notes:
                failures.append(f"{relative}: unexpected ELF build ID")

        self.assertEqual(
            failures,
            [],
            "Android 15 peripheral-manager payload mismatch:\n" + "\n".join(failures),
        )

    def test_manifest_pins_cheryl_sld_triplet_as_boot_critical(self) -> None:
        manifest = json.loads(
            (ROOT / "proprietary-manifest.json").read_text(encoding="utf-8")
        )
        by_path = {entry["path"]: entry for entry in manifest["files"]}
        failures: list[str] = []
        for relative, expected in CHERYL_SLD_PERIPHERAL_MANAGER.items():
            wanted = {
                "tier": "P0",
                "path": relative,
                "size": expected["size"],
                "sha256": expected["sha256"],
            }
            if by_path.get(relative) != wanted:
                failures.append(f"{relative}: {by_path.get(relative)} != {wanted}")
        self.assertEqual(failures, [], "manifest mismatch:\n" + "\n".join(failures))

    def test_source_lock_records_the_cross_device_compatibility_override(self) -> None:
        source_lock = json.loads((ROOT / "SOURCE_LOCK.json").read_text(encoding="utf-8"))
        self.assertEqual(
            source_lock["android15_contract"].get("peripheral_manager_compatibility"),
            {
                "reason": "RED .118 Android 9 pm-service and pm-proxy crash on Android 15",
                "reference_device": "razer/cheryl",
                "donor_build": "sld_sprout RKQ1.210607.001/00WW_3_71E",
                "paths": sorted(CHERYL_SLD_PERIPHERAL_MANAGER),
            },
        )


if __name__ == "__main__":
    unittest.main()
