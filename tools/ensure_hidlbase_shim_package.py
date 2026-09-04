#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

from legacy_hidl_shim_consumers import HIDLBASE_SHIM_MODULE

ROOT = Path(__file__).resolve().parents[1]
VENDOR_MK = ROOT / "hydrogenone-vendor.mk"
MARKER = "# Android 15 compatibility for RED Android 9 HIDL prebuilts"


def product_packages(text: str) -> set[str]:
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


def main() -> int:
    text = VENDOR_MK.read_text(encoding="utf-8")
    if HIDLBASE_SHIM_MODULE in product_packages(text):
        print(f"Runtime compatibility package already selected: {HIDLBASE_SHIM_MODULE}")
        return 0

    block = (
        f"\n{MARKER}\n"
        "PRODUCT_PACKAGES += \\\n"
        f"    {HIDLBASE_SHIM_MODULE}\n"
    )
    VENDOR_MK.write_text(text.rstrip() + "\n" + block, encoding="utf-8")
    print(f"Selected runtime compatibility package: {HIDLBASE_SHIM_MODULE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
