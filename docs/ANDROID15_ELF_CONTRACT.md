# RED Hydrogen One Android 15 ELF Contract

**Target:** LineageOS 22.2 / Android 15 API 35  
**Stock authority:** RED `.118`, SHA-256 `7277a1accf9595bb727f2189863cf5f6249dd99322e2953432bca6e448365f1e`  
**Vendor branch:** `lineage-22.2-android15-contract`  
**Verified ELF implementation commit:** `841c0c8bd3daf3013afe44237b2007dacee27dfb`

## Purpose

The stock Android 9 vendor used linker/VNDK assumptions that cannot be copied blindly into Android 15. `Android.bp` is therefore generated from the actual retained RED ELF files:

1. `readelf -d` extracts every `DT_NEEDED` edge.
2. A retained RED library is preferred when its SONAME exists in this vendor tree.
3. Otherwise the dependency maps to the corresponding LineageOS/AOSP module name.
4. `shared_libs` is written per architecture.
5. `check_elf_files` remains enabled whenever the dependency-provider mapping is verified.
6. A prebuilt may use `check_elf_files: false` only when it is listed in `ANDROID15_ELF_EXCEPTIONS.json` with the exact blocking dependencies and evidence.

The generator is:

```text
tools/generate_elf_contract.py
```

It is deterministic; running it twice on an unchanged tree produces byte-identical `Android.bp`, `ANDROID15_ELF_AUDIT.json`, and `ANDROID15_ELF_EXCEPTIONS.json`.

## Current result

```text
Selected proprietary files: 501
P0 / P1 / P2:               104 / 380 / 17
ELF modules:                 336
checkelf enabled:            317
explicit exceptions:         19
missing retained files:      0
duplicate retained paths:    0
```

This is intentionally different from the original generated baseline, where all proprietary ELF modules had `check_elf_files: false`.

## Recovered RED dependency omitted from the initial selection

The `.118` dependency graph proved that the proprietary Leia display stack requires:

```text
vendor/lib/libsdm-disp-apis.so
vendor/lib64/libsdm-disp-apis.so
```

Canonical identities:

```text
vendor/lib/libsdm-disp-apis.so
size:    38064
SHA-256: 36d1ce9d762209699cba72a76f24905057d32cabb85b68b39c109c4813e60e1b

vendor/lib64/libsdm-disp-apis.so
size:    69312
SHA-256: 849a8b2db319ad03eaebea51acd998b1652866f2a38bfc545351034a919759d2
```

Both are taken from RED `.118`, not from a donor. The one-shot apply job reconstructed the canonical eight-part stock archive, verified its SHA-256 before extraction, verified both provider hashes, and removed itself after committing the generated contract. They are selected as one multilib module:

```text
libsdm-disp-apis
```

`vendor.leia.hardware.leiadisp@1.0-service` and its implementation can now resolve this RED dependency through the vendor tree.

## Source-owned dependencies

Some proprietary RED binaries legitimately depend on libraries that are now built from LineageOS source rather than retained as Android 9 blobs. Examples include:

```text
libgnsspps
libminijail
```

`libgnsspps` is selected by `device/red/hydrogenone` as part of the source GNSS stack. `libminijail` is present in the current LineageOS VNDK graph, including the Android 9/v28 compatibility list.

These are declared as `shared_libs`; they are not reintroduced as proprietary duplicates.

## Remaining explicit exceptions

The remaining 19 exception modules are not silently accepted. Their exact blockers are machine-readable in:

```text
ANDROID15_ELF_EXCEPTIONS.json
```

They are concentrated in legacy Android 9 interfaces:

- legacy OMX / Stagefright helper dependencies;
- camera-device HIDL / graphics mapper dependencies;
- old UBSan/audio helper dependencies;
- `libgui_vendor` ConfigStore/BufferQueue dependencies;
- old Wi-Fi keystore HIDL dependencies;
- NXP NFC HIDL v1.0/v1.1 interfaces;
- Qualcomm hostapd/supplicant HIDL interfaces.

These exceptions are a **build-gate backlog**, not proof of runtime compatibility. The clean LineageOS 22.2 build decides whether the exact module name can be satisfied by the v28/current source graph, requires a versioned vendor module, or needs a narrow blob fixup/shim.

## Validation

Static contract:

```bash
python3 tools/generate_elf_contract.py
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

Reproducibility check:

```bash
sha256sum Android.bp ANDROID15_ELF_AUDIT.json ANDROID15_ELF_EXCEPTIONS.json
python3 tools/generate_elf_contract.py
sha256sum Android.bp ANDROID15_ELF_AUDIT.json ANDROID15_ELF_EXCEPTIONS.json
```

The two hash sets must be identical.

Build validation follows the project gates:

```bash
source build/envsetup.sh
lunch lineage_hydrogenone-bp1a-userdebug
m nothing
m vendorimage
```

A build-time missing module or checkelf failure is resolved by tracing its exact `DT_NEEDED`/symbol error. It is not solved with a global checkelf disable or an unrelated donor binary.
