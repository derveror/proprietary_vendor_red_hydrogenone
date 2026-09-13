# RED Hydrogen One Android 15 P0 daemon completion

Stock authority: RED `.118`, SHA-256 `7277a1accf9595bb727f2189863cf5f6249dd99322e2953432bca6e448365f1e`.

The Android 15 rootdir contract requires three RED/Qualcomm daemons that were omitted from the first vendor selection: `spdaemon`, `hvdcp_opti`, and `energy-awareness`. `spdaemon` also has a direct RED `.118` DT_NEEDED dependency on `libspcom.so`, so the matching 64-bit provider is retained with it.

All four files are pinned by exact size and SHA-256 in `proprietary-manifest.json` and validated by `tests/test_p0_daemon_completion.py`. They are RED stock files, not donor blobs.

`tools/generate_elf_contract.py` derives their `shared_libs` from the real `DT_NEEDED` records; the normal checkelf policy applies and no blanket exception is introduced.

## QSEE listener closure

`qseecomd` loads its listeners with `dlopen`, so they are not visible in the
daemon's `DT_NEEDED` list. A durable normal-boot trace showed the daemon exiting
with status 255 before publishing `vendor.sys.listeners.registered`. The stock
binary's control flow makes the RPMB and SSD listener initializers mandatory,
and the generated vendor image contained `librpmb.so` but not `libssd.so`.

The exact RED `.118` 64-bit `libssd.so` is therefore retained as P0 (68,208
bytes, SHA-256
`9a6b9bee2d010fb6156f2931a6cbea72c0bbab26b565e49524fee10c93024c74`).
Its ELF dependencies pass the normal Android 15 checkelf contract. The device
rootdir separately mounts the stock `cmlog` securefs partition at
`/mnt/vendor/persist/data` before `post-fs` starts `qseecomd`.
