# Hydrogen One Vendor Android 15 Contract Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Convert the verified RED Android 9 `.118` proprietary baseline into a reproducible LineageOS 22.2 / Android 15 vendor contract without duplicating source-built HALs or carrying stock debug/runtime debris.

**Architecture:** `vendor/red/hydrogenone` remains the only RED proprietary tree. Stock `.118` is authoritative for proprietary payload, while the device tree owns open Android 15 services/configuration. Migration is subsystem-by-subsystem: first remove source-owned duplicates and debug binaries, then validate ELF closure, init/VINTF ownership, and finally regenerate the vendor package list and audit metadata.

**Tech Stack:** Android Make/Soong, Python 3 contract tests, GitHub Actions, verified RED `.118` SHA-256 manifest, LineageOS 22.2 donor patterns.

**Spec:** `derveror/device_red_hydrogenone:docs/superpowers/specs/2026-09-02-hydrogenone-lineage22.2-design.md`

## Global Constraints

- Target: LineageOS `22.2`, Android 15, API 35.
- Stock authority: `H1A1000.082ho.01.00.10r.118_userdebug_fastboot.rar`, SHA-256 `7277a1accf9595bb727f2189863cf5f6249dd99322e2953432bca6e448365f1e`.
- Never create `device/red/msm8998-common` or `vendor/red/msm8998-common`.
- No donor proprietary blob is accepted only because it comes from MSM8998.
- Android 9 init/HIDL/property/SELinux contracts are evidence, not automatic Android 15 runtime files.
- Source-built Android 15 HALs selected by `device/red/hydrogenone` must not be duplicated by vendor prebuilts or stock rc fragments.
- No unique device data (`persist`, NV, IMEI/MEID, DRM keys, enrollment, Wi-Fi/Bluetooth identity, userdata).
- Broad compatibility bypasses such as blanket `DISABLE_CHECKELF` are not final solutions.
- All changes happen on `lineage-22.2-android15-contract` until verified.

---

### Task 1: Contract Test Gate for Source-Owned HALs and Debug Binaries

**Files:**
- Create: `tests/test_android15_contract.py`
- Create: `.github/workflows/verify-vendor-contract.yml`

**Interfaces:**
- Consumes: `Android.bp`, `hydrogenone-vendor.mk`, `proprietary-files.txt`, `proprietary-manifest.json`.
- Produces: deterministic pass/fail checks used by every later task.

- [ ] **Step 1: Write failing tests** asserting that source-owned Android 15 services and their stock init fragments are absent from the active vendor contract, and that known factory/debug executables are not selected.
- [ ] **Step 2: Run the workflow and verify RED**. Expected failure must name current Android 9 duplicate modules/rc paths or debug binaries.
- [ ] **Step 3: Keep the tests unchanged for Task 2 implementation.**

### Task 2: Remove Source-Owned HAL Duplicates and Debug/Test Payload

**Files:**
- Modify: `Android.bp`
- Modify: `hydrogenone-vendor.mk`
- Modify: `proprietary-files.txt`
- Modify: `proprietary-manifest.json`
- Modify: `GENERATED_VENDOR_AUDIT.json`
- Modify: `VENDOR_TREE_AUDIT.json`
- Delete: corresponding files under `proprietary/vendor/...` only when they have no retained proprietary consumer.

**Interfaces:**
- Consumes: Task 1 forbidden module/path sets and current device-tree source service selections.
- Produces: vendor baseline with one owner per HAL service.

- [ ] **Step 1: Remove source-owned service prebuilts** for camera provider wrapper, sensor wrapper, USB service, GNSS wrapper, Wi-Fi service, and obsolete audio HIDL wrapper where the device tree selects a newer source implementation.
- [ ] **Step 2: Remove stock rc fragments** for source-owned boot/configstore/graphics/health/light/power/sensors/USB/vibrator/Wi-Fi wrappers when their stock executable is not the retained vendor owner.
- [ ] **Step 3: Remove known factory/debug binaries** (`fpc_tee_test`, `mm-*-test`, `mm-qcamera-app`, `qmi_simple_ril_test`, `sensorrdiag`, and equivalent explicit test utilities) from the selected contract.
- [ ] **Step 4: Recompute manifest counts and selected bytes** from the retained proprietary tree.
- [ ] **Step 5: Run Task 1 tests and verify GREEN.**

### Task 3: Init Service Closure

**Files:**
- Create: `tests/test_init_contract.py`
- Create: `docs/ANDROID15_INIT_CONTRACT.md`
- Modify: `hydrogenone-vendor.mk`
- Modify: `proprietary-files.txt`
- Modify: `proprietary-manifest.json`

**Interfaces:**
- Consumes: retained vendor executables and rc files.
- Produces: every retained rc `service` maps to an installed executable or a documented source-built owner.

- [ ] **Step 1: Add a failing test** that parses retained rc files and flags service executables absent from the final source/vendor ownership map.
- [ ] **Step 2: Classify failures** as retained proprietary service, source-owned replacement, or obsolete stock reference.
- [ ] **Step 3: Remove obsolete rc fragments and keep only executable-closed services.**
- [ ] **Step 4: Document source/proprietary owner and Android 15 validation command per retained service family.**
- [ ] **Step 5: Verify all init tests pass.**

### Task 4: ELF Dependency and Linker-Namespace Gate

**Files:**
- Create: `tests/test_elf_contract.py`
- Create: `docs/ANDROID15_ELF_CONTRACT.md`
- Modify: `Android.bp`

**Interfaces:**
- Consumes: `.118` ELF dependency evidence plus retained module list.
- Produces: explicit per-module checkelf status and a finite exception list.

- [ ] **Step 1: Add tests** that forbid blanket unchecked ELF generation and require every retained `check_elf_files: false` module to appear in an explicit exception registry with a reason.
- [ ] **Step 2: Enable ELF checking where dependency closure already resolves under Android 15.**
- [ ] **Step 3: Record only narrow unresolved exceptions** with exact missing SONAME/symbol/namespace reason.
- [ ] **Step 4: Verify no global checkelf bypass exists.**

### Task 5: VINTF/HAL Ownership Matrix

**Files:**
- Create: `docs/ANDROID15_HAL_OWNERSHIP.md`
- Create: `tests/test_hal_ownership.py`

**Interfaces:**
- Consumes: final vendor services, device-tree product packages, stock `.118` VINTF evidence.
- Produces: one owner and one instance map for every HAL intended for first boot.

- [ ] **Step 1: Define P0/P1 HAL owner matrix** for source vs proprietary services.
- [ ] **Step 2: Add tests preventing duplicate source/vendor service ownership.**
- [ ] **Step 3: Flag stock HALs that remain evidence-only until device VINTF integration.**
- [ ] **Step 4: Verify ownership matrix matches selected modules.**

### Task 6: Reproducibility and Source Lock

**Files:**
- Modify: `SOURCE_LOCK.json`
- Modify: `GENERATED_VENDOR_AUDIT.json`
- Modify: `VENDOR_TREE_AUDIT.json`
- Create: `tests/test_vendor_manifest.py`

**Interfaces:**
- Consumes: retained `proprietary-manifest.json` and filesystem.
- Produces: exact count/hash/size equality and no sensitive paths.

- [ ] **Step 1: Add tests** for manifest/filesystem one-to-one equality, SHA-256, size, duplicates, and sensitive-path exclusion.
- [ ] **Step 2: Recompute audit data from the actual retained tree.**
- [ ] **Step 3: Verify all manifest hashes and counts.**

### Task 7: Device/Vendor Integration Gate

**Files:**
- Modify only after Tasks 1–6 are green: `derveror/device_red_hydrogenone` integration branch files as required.
- Create: `docs/DEVICE_VENDOR_INTEGRATION.md` in the vendor branch.

**Interfaces:**
- Consumes: verified vendor ownership matrix.
- Produces: non-duplicated product package/copy-file contract ready for a real LineageOS tree.

- [ ] **Step 1: Compare final vendor `PRODUCT_PACKAGES` against device `PRODUCT_PACKAGES`.**
- [ ] **Step 2: Compare vendor copy destinations against device copy destinations.**
- [ ] **Step 3: Update device extraction/vendor hooks only after conflicts are zero.**
- [ ] **Step 4: Run existing device static tests plus vendor contract tests.**

### Task 8: Build Gate and First-Boot Candidate

**Files:**
- No speculative file changes before build evidence.

**Interfaces:**
- Consumes: clean device/vendor trees.
- Produces: actual build logs and next fixes.

- [ ] **Step 1: In a clean LineageOS 22.2 checkout run `lunch lineage_hydrogenone-bp1a-userdebug` and `m nothing`.**
- [ ] **Step 2: Run `m vendorimage`, `m bootimage`, and `m systemimage`.**
- [ ] **Step 3: Resolve failures using systematic-debugging; never patch by guess.**
- [ ] **Step 4: Only after clean image builds proceed to target-files/OTA and physical first-boot validation.**
