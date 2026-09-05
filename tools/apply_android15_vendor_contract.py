#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"

BASELINE_PIPELINE = (
    "generate_elf_contract.py",
    "resolve_android15_source_collisions.py",
    "prune_source_owned_nbaio_mono.py",
    "prune_qti_camera_interface_duplicate.py",
    "prune_source_owned_init_rc_duplicates.py",
    "prune_source_owned_wifi_keystore.py",
    "prune_source_owned_wifi_hal.py",
    "prune_source_owned_camera_wrappers.py",
    "prune_source_owned_location_core.py",
    "prune_obsolete_audio_preprocessing_stack.py",
    "prune_source_owned_media_omx_stack.py",
    "patch_legacy_hidl_shim.py",
    "patch_imsdatadaemon_hwbinder.py",
    # Re-read DT_NEEDED after binary fixups so Android.bp/checkelf metadata
    # names libhidlbase_shim for the exact affected architectures.
    "generate_elf_contract.py",
    # Post-generation ownership guards restore source-owned package decisions
    # after proprietary metadata is rebuilt from the remaining payload.
    "prune_obsolete_audio_preprocessing_stack.py",
    "prune_source_owned_media_omx_stack.py",
    # The exception5 Android 15 build matrix proved both retained RED NXP NFC
    # HAL libraries against the current NFC 1.0/1.1 source providers.
    "promote_verified_nfc_checkelf.py",
    # generate_elf_contract owns proprietary-module metadata; runtime-only
    # Lineage compatibility packages are appended afterwards and kept by this
    # idempotent post-generation step.
    "ensure_hidlbase_shim_package.py",
)

POST_CAMERA_PIPELINE = (
    "prune_source_owned_nbaio_mono.py",
    "prune_source_owned_init_rc_duplicates.py",
    "prune_source_owned_wifi_keystore.py",
    "prune_source_owned_wifi_hal.py",
    "prune_source_owned_camera_wrappers.py",
    "prune_source_owned_location_core.py",
    "prune_obsolete_audio_preprocessing_stack.py",
    "prune_source_owned_media_omx_stack.py",
    "patch_legacy_hidl_shim.py",
    "patch_imsdatadaemon_hwbinder.py",
    "generate_elf_contract.py",
    "prune_obsolete_audio_preprocessing_stack.py",
    "prune_source_owned_media_omx_stack.py",
    "promote_verified_nfc_checkelf.py",
    "ensure_hidlbase_shim_package.py",
)


def run(tool: str) -> None:
    path = TOOLS / tool
    print(f"===== {tool} =====", flush=True)
    subprocess.run(
        [sys.executable, str(path)],
        cwd=ROOT,
        check=True,
    )


def main() -> int:
    camera_blob = (
        ROOT
        / "proprietary/vendor/lib64/vendor.qti.hardware.camera.device@1.0.so"
    )
    pipeline = BASELINE_PIPELINE if camera_blob.is_file() else POST_CAMERA_PIPELINE
    for tool in pipeline:
        run(tool)
    print("Android 15 vendor contract pipeline completed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
