# RED Hydrogen One proprietary vendor tree

Target: LineageOS 22.2 / Android 15 for `hydrogenone`.

This tree is regenerated from the byte-verified RED `.118` Android 9 stock package. It contains one ordinary device-specific repository only: `vendor/red/hydrogenone`; no RED `msm8998-common` tree is used.

Current Android 15 contract selection: 499 stock-derived files (`P0=108`, `P1=374`, `P2 RED/Leia=17`). `SOURCE_LOCK.json` pins the `.118` archive/build identity and selected-file count; `proprietary-manifest.json` records exact per-file SHA-256 provenance.

Android 9 stock shipped VNDK 28, but LineageOS 22.2 does not provide a v28 snapshot to package. The vendor tree therefore must not request `PRODUCT_EXTRA_VNDK_VERSIONS += 28`; legacy compatibility required by the device product is handled explicitly on the device side.

The vendor tree is a bring-up candidate: legacy Android 9 prebuilts must still pass LineageOS 22.2 build, VINTF, linker, SELinux, and runtime validation before being considered stable.
