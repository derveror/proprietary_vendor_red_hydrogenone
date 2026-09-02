# RED Hydrogen One Android 15 proprietary VINTF contract

**Stock authority:** RED `.118` (`7277a1accf9595bb727f2189863cf5f6249dd99322e2953432bca6e448365f1e`)  
**Target:** LineageOS 22.2 / Android 15 API 35

This contract declares only proprietary HAL instances that still have a retained RED service owner after Android 15 pruning. Source-owned standard GNSS (`android.hardware.gnss`) and NFC (`android.hardware.nfc`) are deliberately excluded because `device/red/hydrogenone` selects the LineageOS/QTI source services.

The retained proprietary contract contains **35 exact stock fqnames** across fingerprint, Bluetooth/FM/ANT, OMX, Wi-Fi display, RED thermal3d/Leia display, eSE, and radio/IMS/UIM services. `VINTF_PROPRIETARY_CONTRACT.json` is the machine-readable source of the module → fragment → HAL mapping.

Each fragment is attached to the service module through `vintf_fragments` in the generated `Android.bp`; `tools/generate_elf_contract.py` owns that mapping so ELF regeneration cannot silently drop VINTF metadata.

The radio fragment records the exact `.118` versions/instances implemented by the retained Qualcomm radio stack. It does not invent linked-but-undeclared interfaces such as `vendor.qti.hardware.data.connection`. Runtime startup/trigger validation remains a separate radio bring-up gate.
