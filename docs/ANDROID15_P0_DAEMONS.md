# RED Hydrogen One Android 15 P0 daemon completion

Stock authority: RED `.118`, SHA-256 `7277a1accf9595bb727f2189863cf5f6249dd99322e2953432bca6e448365f1e`.

The Android 15 rootdir contract requires three RED/Qualcomm daemons that were omitted from the first vendor selection: `spdaemon`, `hvdcp_opti`, and `energy-awareness`. `spdaemon` also has a direct RED `.118` DT_NEEDED dependency on `libspcom.so`, so the matching 64-bit provider is retained with it.

All four files are pinned by exact size and SHA-256 in `proprietary-manifest.json` and validated by `tests/test_p0_daemon_completion.py`. They are RED stock files, not donor blobs.

`tools/generate_elf_contract.py` derives their `shared_libs` from the real `DT_NEEDED` records; the normal checkelf policy applies and no blanket exception is introduced.
