# RED Hydrogen One proprietary vendor tree

Target: LineageOS 22.2 / Android 15 for `hydrogenone`.

This tree is regenerated from the byte-verified RED `.118` Android 9 stock package. It contains one ordinary device-specific repository only: `vendor/red/hydrogenone`; no RED `msm8998-common` tree is used.

Selection: 583 stock files (`P0=137`, `P1=431`, `P2 RED/Leia=15`). See `proprietary-manifest.json` for exact SHA-256 provenance.

The vendor tree is a bring-up candidate: legacy Android 9 prebuilts must still pass LineageOS 22.2 build, VINTF, linker, SELinux, and runtime validation before being considered stable.

## LineageOS 22.2 bring-up state

The Android 15 proprietary contract is developed together with
`device/red/hydrogenone`. The canonical, evidence-qualified project status is
`PROJECT_STATE.md` in that device repository; paired changes use the same
`test/lineage-22.2-bringup` branch name in both repositories. The generated
vendor payload must continue to be validated by the device tree's pinned
cross-tree contract before a build is attempted.
