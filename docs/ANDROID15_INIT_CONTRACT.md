# RED Hydrogen One Android 15 Init Contract

**Target:** LineageOS 22.2 / Android 15 API 35  
**Stock authority:** RED `.118`, SHA-256 `7277a1accf9595bb727f2189863cf5f6249dd99322e2953432bca6e448365f1e`  
**Vendor branch:** `lineage-22.2-android15-contract`

## Ownership rule

Stock Android 9 init files are evidence, not an Android 15 control plane. A retained proprietary rc file must satisfy both conditions:

1. its service executable is present in the retained RED proprietary tree, or the executable is explicitly platform/source-owned; and
2. its install destination is not already owned by `device/red/hydrogenone`.

The executable closure is enforced by `tests/test_init_contract.py`.

## Device-owned init files

The Android 15 device tree owns these exact vendor destinations and the stock copies are therefore excluded from the proprietary vendor tree:

```text
/vendor/etc/init/hw/init.qcom.rc
/vendor/etc/init/hw/init.qcom.usb.rc
```

`device/red/hydrogenone/rootdir/etc/init/hw/init.qcom.rc` is the Android 15 RED control plane. It performs the measured UFS/fstab setup and RED-specific FPC/SmartPort sysfs ownership instead of carrying the broad Android 9 Qualcomm factory/service graph.

The stock factory fragment is also excluded:

```text
/vendor/etc/init/hw/init.qcom.factory.rc
```

## Stock rc removed as stale/evidence-only

The following `.118` fragments referenced executables that are absent from the complete `.118` vendor image, have a source-owned Android 15 replacement, or are otherwise factory-only. They are intentionally not shipped:

```text
vendor/etc/init/android.hardware.cas@1.0-service.rc
vendor/etc/init/android.hardware.drm@1.0-service.rc
vendor/etc/init/android.hardware.drm@1.1-service.clearkey.rc
vendor/etc/init/android.hardware.drm@1.1-service.widevine.rc
vendor/etc/init/android.hardware.memtrack@1.0-service.rc
vendor/etc/init/android.hardware.power@1.0-service.rc
vendor/etc/init/android.hardware.thermal@1.0-service.rc
vendor/etc/init/android.hardware.vr@1.0-service.rc
vendor/etc/init/hostapd.android.rc
vendor/etc/init/sns_reg.rc
vendor/etc/init/vendor.display.color@1.0-service.rc
vendor/etc/init/vendor.qti.hardware.alarm@1.0-service.rc
vendor/etc/init/vendor.qti.hardware.factory@1.0-service.rc
vendor/etc/init/vendor.qti.hardware.perf@1.0-service.rc
vendor/etc/init/vendor.qti.hardware.qdutils_disp@1.0-service-qti.rc
vendor/etc/init/vendor.qti.hardware.qteeconnector@1.0-service.rc
vendor/etc/init/vendor.qti.hardware.soter@1.0-service.rc
vendor/etc/init/vendor.qti.hardware.tui_comm@1.0-service-qti.rc
```

The earlier source-ownership pruning additionally removed stock rc for source-owned boot/audio/camera/configstore/gatekeeper/graphics/health/keymaster/light/sensors/USB/vibrator/Wi-Fi wrappers.

## Retained proprietary service families

The retained rc set is limited to services whose proprietary executables remain selected. Important families include:

- FPC fingerprint;
- Qualcomm Bluetooth HCI;
- legacy OMX service used by the proprietary codec stack;
- QCRIL/RIL and IMS services;
- NXP NFC/eSE services;
- Qualcomm vendor GNSS extension (`vendor.qti.gnss@1.0`), distinct from the source-owned generic Android GNSS 2.1 wrapper;
- RED `vendor.cm.hardware.thermal3d@1.0`;
- Leia `vendor.leia.hardware.leiadisp@1.0`;
- Qualcomm Wi-Fi Display extension where its proprietary service is retained.

`vendor/etc/init/hw/init.msm.usb.configfs.rc` remains as stock configuration data for the Qualcomm configfs gadget actions. It does not replace the device-owned `init.qcom.usb.rc` service/control file.

## Validation

Static gate:

```bash
python3 -m unittest -v tests.test_init_contract
```

The test fails if:

- vendor reintroduces `init.qcom.rc` or `init.qcom.usb.rc`;
- factory `init.qcom.factory.rc` returns; or
- a retained proprietary rc service points at a missing `/vendor/...` executable.

Runtime validation after a build:

```bash
adb shell getprop init.svc.vendor.qcrild
adb shell getprop init.svc.vendor.ril-daemon
adb shell ps -A -Z
adb shell lshal
adb shell logcat -b all -d | grep -Ei 'init|cannot find|cannot link|CANNOT LINK EXECUTABLE'
```

No missing service is solved by adding an unrelated donor binary. A missing runtime owner must be traced back to the RED `.118` dependency graph or to a documented LineageOS source replacement.
