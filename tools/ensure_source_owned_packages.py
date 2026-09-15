#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

# extract-utils can only regenerate packages backed by proprietary-files.txt.
# These modules deliberately remain selected after their RED .118 prebuilts are
# pruned because LineageOS 22.2 provides the active vendor implementations.
SOURCE_PACKAGES = (
    "camera.device@1.0-impl",
    "camera.device@3.2-impl",
    "camera.device@3.3-impl",
    "camera.device@3.4-external-impl",
    "camera.device@3.4-impl",
    "libaudiopreprocessing",
    "libcld80211",
    "libgps.utils",
    "libhidlbase_shim",
    "libkeystore-engine-wifi-hidl",
    "libkeystore-wifi-hidl",
    "libloc_core",
    "liblocation_api",
    "libwifi-hal",
    "vendor.qti.hardware.camera.device@1.0",
)

SCRIPT_COPIES = {
    "init.qcom.sensors": (
        "vendor/red/hydrogenone/proprietary/vendor/bin/init.qcom.sensors.sh:"
        "$(TARGET_COPY_OUT_VENDOR)/bin/init.qcom.sensors.sh"
    ),
    "init.qti.ims": (
        "vendor/red/hydrogenone/proprietary/vendor/bin/init.qti.ims.sh:"
        "$(TARGET_COPY_OUT_VENDOR)/bin/init.qti.ims.sh"
    ),
}


def selected_packages(text: str) -> set[str]:
    return {
        match.group(1)
        for match in re.finditer(r"(?m)^\s+([^#\s][^\\\n]*?)\s*\\?\s*$", text)
    }


def restore_script_copy_ownership(text: str) -> str:
    for module in SCRIPT_COPIES:
        text = re.sub(
            rf"(?m)^\s*{re.escape(module)}\s*\\?\s*\n",
            "",
            text,
        )

    missing = [rule for rule in SCRIPT_COPIES.values() if rule not in text]
    if missing:
        block = ["", "PRODUCT_COPY_FILES += \\"]
        block.extend(
            f"    {rule}" + (" \\" if index < len(missing) - 1 else "")
            for index, rule in enumerate(missing)
        )
        text = text.rstrip() + "\n" + "\n".join(block) + "\n"
    return text


def ensure_source_packages(vendor_mk: Path) -> list[str]:
    original = vendor_mk.read_text(encoding="utf-8")
    text = restore_script_copy_ownership(original)
    if "PRODUCT_PACKAGES +=" not in text:
        raise SystemExit(f"PRODUCT_PACKAGES block missing from {vendor_mk}")

    missing = sorted(set(SOURCE_PACKAGES) - selected_packages(text))
    if missing:
        block = [
            "",
            "# LineageOS 22.2 source-owned replacements for pruned RED .118 prebuilts",
            "PRODUCT_PACKAGES += \\",
        ]
        block.extend(
            f"    {package}" + (" \\" if index < len(missing) - 1 else "")
            for index, package in enumerate(missing)
        )
        text = text.rstrip() + "\n" + "\n".join(block) + "\n"

    if text != original:
        vendor_mk.write_text(text, encoding="utf-8")
    return missing


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--vendor-mk",
        type=Path,
        default=ROOT / "hydrogenone-vendor.mk",
    )
    args = parser.parse_args()
    added = ensure_source_packages(args.vendor_mk)
    print(f"Ensured source-owned packages: added={len(added)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
