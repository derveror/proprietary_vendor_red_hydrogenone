#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

EXPECTED_SHA256 = {
    "system_ext/bin/dpmd": "7a5379734f6cbd23adfb8e3729087beb19ef584303425e0bf298e15c7fcb0263",
    "system_ext/etc/dpm/dpm.conf": "87f839379ce8f1882e2f287f83d4abc84b3b749873f7ffa6ae2303936352c7a7",
    "system_ext/etc/init/dpmd.rc": "977c0d6987108d4a8a5952efadbbf66892ff4efaef3414b6e95e347229a77b24",
    "system_ext/etc/permissions/com.qti.dpmframework.xml": "f0f06e0ffbe31064be2639ca338f0f944df96835e934ba60778a62d6ef9142c9",
    "system_ext/etc/permissions/dpmapi.xml": "03dc2d5f62228102224eea64ff7bf98a4416146123497750e1a6bdb77b10d520",
    "system_ext/framework/com.qti.dpmframework.jar": "160f4818af5ae8bff97373e31d11b97af6be9e330c24bcd20a83986ac3ece2cf",
    "system_ext/framework/dpmapi.jar": "5b57736888c16de41f99264cfb980a41b470737b9b222f4c7ea9e2cd6ed9fe96",
    "system_ext/lib64/com.qualcomm.qti.dpm.api@1.0.so": "07634cb2cc208c90e395b182c761d66dc41d84c7da831c3f4e747054f2f78037",
    "system_ext/lib64/libdpmctmgr.so": "256d54e25d860c049d263f53ff5d214b3aff02af2d7cebb7fd307fd8948bbe32",
    "system_ext/lib64/libdpmfdmgr.so": "b0af4f9c6ff59cbc88a3af6852b1e34c4a97094bd052048e6ae1aad9859be3b7",
    "system_ext/lib64/libdpmframework.so": "a57ca3847cdd619c424c4e0dedfe603a0400f50fde44d5797ad21d27faf5662b",
    "system_ext/lib64/libdpmtcm.so": "d7356f33ec0cfd7b72cc1a8d5424b67ce0aa37ba6c6e9f9edded0fbe28ac39e4",
    "system_ext/lib64/libdiag_system.so": "9d2cba558f3382c6f88e8acab4a82f899fa6d0a3b01d7398fdd2482c7de2bdc4",
    "system_ext/lib64/vendor.qti.diaghal@1.0.so": "21050415b2af475f36e90058b913a12f366fb9782d9bfc7a5e154494661a6b20",
    "system_ext/priv-app/dpmserviceapp/dpmserviceapp.apk": "bcadad9924174bab6fef54b95f69aeecf2a1f36d3e90495364cf63a62f29e580",
    "vendor/bin/dpmQmiMgr": "00a56585d294769d65addf61d0be73b0513ab74897ddb2d1bc34def7723ccecb",
    "vendor/bin/netmgrd": "48a8aaf29aa52220b9071fcd0edef8d75bc93da7738b208eea1adefe8607c1f3",
    "vendor/etc/data/dsi_config.xml": "063cefcd27bf4acf88f5f9deecf9a50cf358ef49ac225d165d8d7e8a344ff4b4",
    "vendor/etc/data/netmgr_config.xml": "68218668d7d7e0edd6972762322d3516588dc764b04d75a75ff58804544b0568",
    "vendor/etc/init/dpmQmiMgr.rc": "525fba1911f28e3ee37bebc84033d94ea5c15ed89ce91c8ddeb02919ff8805dc",
    "vendor/etc/init/netmgrd.rc": "568143f3edf386dda7a13503cea2df6cc03904cfa798e14dfab5487aa8e6403b",
    "vendor/lib64/com.qualcomm.qti.dpm.api@1.0.so": "9c758d219a5ac3f34a92d95eb7ebb6d422abc3104bc218625257cf2a07f40fc9",
    "vendor/lib64/libdpmqmihal.so": "0c18eba12d4d4e14b234e8c71abba99b260318f72b6b30f4db86c39e3c2b6ebe",
    "vendor/lib64/libnetmgr.so": "3a89fb2746fdb7268b20015effe6edb40ddd5bc87c0622ad40bd7663a2ce9734",
    "vendor/lib64/libnetmgr_common.so": "ef9e8fbd56651bf6004d0d3deadd975656e468a66dfe7699f2d06c72fc57036e",
    "vendor/lib64/libnetmgr_nr_fusion.so": "b2579c20a31c02bbd58175723ceb91c548159061806f8cbab6216e4a84be0c47",
    "vendor/lib64/libnetmgr_rmnet_ext.so": "462881e7fa7a378c2952171c04ff7fc7be811f731c108ec6237ab1ad2566afd8",
    "vendor/lib64/libnlnetmgr.so": "e1f5a382194342e7991f5ed81d450ec0129b2a7680a7640b7f58e2f3dc5e2c69",
}


def load_json(name: str) -> dict:
    return json.loads((ROOT / name).read_text(encoding="utf-8"))


def write_json(name: str, value: dict) -> None:
    (ROOT / name).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    verified: dict[str, dict] = {}
    for relative, expected in EXPECTED_SHA256.items():
        payload = ROOT / "proprietary" / relative
        if not payload.is_file():
            raise SystemExit(f"missing FP3 radio data-plane payload: {relative}")
        digest = hashlib.sha256(payload.read_bytes()).hexdigest()
        if digest != expected:
            raise SystemExit(f"FP3 radio data-plane SHA-256 mismatch: {relative}: {digest}")
        verified[relative] = {
            "tier": "P1",
            "path": relative,
            "size": payload.stat().st_size,
            "sha256": digest,
        }

    manifest = load_json("proprietary-manifest.json")
    by_path = {entry["path"]: entry for entry in manifest["files"]}
    by_path.update(verified)
    manifest["files"] = sorted(by_path.values(), key=lambda entry: (entry["tier"], entry["path"]))
    counts = Counter(entry["tier"] for entry in manifest["files"])
    manifest["counts"] = {
        "P0": counts.get("P0", 0),
        "P1": counts.get("P1", 0),
        "P2": counts.get("P2", 0),
        "total": len(manifest["files"]),
    }
    write_json("proprietary-manifest.json", manifest)

    selected_bytes = sum(int(entry["size"]) for entry in manifest["files"])
    generated = load_json("GENERATED_VENDOR_AUDIT.json")
    generated.update(
        {
            "selected_files": len(manifest["files"]),
            "p0": counts.get("P0", 0),
            "p1": counts.get("P1", 0),
            "p2": counts.get("P2", 0),
            "selected_bytes": selected_bytes,
        }
    )
    write_json("GENERATED_VENDOR_AUDIT.json", generated)

    source_lock = load_json("SOURCE_LOCK.json")
    source_lock["selected_files"] = len(manifest["files"])
    radio = source_lock.setdefault("android15_contract", {}).setdefault(
        "radio_compatibility", {}
    )
    radio["paths"] = sorted(set(radio.get("paths", ())) | set(EXPECTED_SHA256))
    radio["data_plane_complete"] = True
    radio["dpm_system_side_complete"] = True
    write_json("SOURCE_LOCK.json", source_lock)

    tree_audit = load_json("VENDOR_TREE_AUDIT.json")
    tree_audit["counts"] = manifest["counts"]
    notes = list(tree_audit.get("notes", []))
    note = (
        "The FP3 QCRIL generation is paired with its byte-verified netmgr/DPM "
        "mobile-data plane; the older RED .118 netmgr generation is not mixed in."
    )
    if note not in notes:
        notes.append(note)
    tree_audit["notes"] = notes
    write_json("VENDOR_TREE_AUDIT.json", tree_audit)

    print(
        "Recorded FP3 radio data-plane closure: "
        f"files={len(EXPECTED_SHA256)}, selected total={len(manifest['files'])}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
