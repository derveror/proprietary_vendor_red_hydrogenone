from __future__ import annotations

import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROPRIETARY = ROOT / "proprietary"

# device/red/hydrogenone deliberately owns these standard HAL services on
# LineageOS 22.2. A retained Android 9 service must not register the same
# default instance in parallel.
SOURCE_OWNED_SERVICE_REGISTRATIONS = {
    "vendor/bin/hw/vendor.qti.gnss@1.0-service": (
        "IGnss17registerAsService",
        "android.hardware.gnss@1.0-service-qti owns IGnss/default",
    ),
    "vendor/bin/hw/vendor.nxp.hardware.nfc@1.1-service": (
        "INfc17registerAsService",
        "android.hardware.nfc@1.2-service owns INfc/default",
    ),
}

MUST_RETAIN_AFTER_SERVICE_PRUNE = {
    # GNSS source service still consumes retained RED/Qualcomm proprietary
    # location payload. libloc_core/liblocation_api themselves are source-owned
    # and are covered by test_android15_collision_resolution.py.
    "vendor/lib64/libizat_core.so",
    # The source NFC service loads the RED NXP legacy nfc_nci implementation.
    "vendor/lib/hw/nfc_nci.nqx.default.so",
    # Vendor-only eSE extension remains independently owned.
    "vendor/bin/hw/vendor.qti.esepowermanager@1.0-service",
    "vendor/etc/init/vendor.qti.esepowermanager@1.0-service.rc",
}


def selected_paths() -> set[str]:
    paths: set[str] = set()
    for raw in (ROOT / "proprietary-files.txt").read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        body = line.split(";", 1)[0]
        paths.add(body.split(":", 1)[0].lstrip("-"))
    return paths


class VintfOwnershipTest(unittest.TestCase):
    def test_source_owned_default_instances_are_not_registered_by_stock_services(self) -> None:
        conflicts: list[str] = []
        for relative, (registration_symbol, owner) in SOURCE_OWNED_SERVICE_REGISTRATIONS.items():
            path = PROPRIETARY / relative
            if not path.exists():
                continue
            output = subprocess.run(
                ["strings", "-a", str(path)],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
            if registration_symbol in output:
                conflicts.append(f"{relative}: {registration_symbol}; {owner}")
        self.assertEqual(
            conflicts,
            [],
            "stock services would double-register source-owned standard HAL instances:\n"
            + "\n".join(conflicts),
        )

    def test_service_prune_keeps_required_hardware_payload(self) -> None:
        selected = selected_paths()
        missing = sorted(MUST_RETAIN_AFTER_SERVICE_PRUNE - selected)
        self.assertEqual(missing, [], f"required GNSS/NFC/eSE payload missing: {missing}")


if __name__ == "__main__":
    unittest.main()
