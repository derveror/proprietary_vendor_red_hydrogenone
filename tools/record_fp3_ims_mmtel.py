#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

EXPECTED_SHA256 = {
    "system_ext/app/QtiTelephonyService/QtiTelephonyService.apk": (
        "f2b0ff541ea2b4ab57606fe7cf5737e0a1f21d29d5fb4f02d830488fefdbff06"
    ),
    "system_ext/etc/permissions/qcrilhook.xml": (
        "30f2d18283025a215e823cd286a89673280077791d22ce5ccabcbb5a6e71bf5f"
    ),
    "system_ext/framework/qcrilhook.jar": (
        "d4ee895698102bc443693beaeb184832c60a1c01da4df5a965af17b068327825"
    ),
    "system_ext/lib64/libimscamera_jni.so": (
        "fff8a5e72e930e7333672ffb6c4c8ee78bdb49d5539d3afd24d2d08c7ec08213"
    ),
    "system_ext/lib64/libimsmedia_jni.so": (
        "6f7a232d43deb578bbf20dc28a20c28b50ecedd451951c3c62cfc401a36e77ec"
    ),
    "system_ext/priv-app/ims/ims.apk": (
        "b4619d79ed14ebfaa5b052d693b22511890acd96213df05af3cb551444939416"
    ),
    "system_ext/priv-app/qcrilmsgtunnel/qcrilmsgtunnel.apk": (
        "e23970ba15b1ab5b82fcb23a48ac3cdff7441b16795b316cc5cdde4054632fbb"
    ),
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
            raise SystemExit(f"missing FP3 IMS MMTEL payload: {relative}")
        digest = hashlib.sha256(payload.read_bytes()).hexdigest()
        if digest != expected:
            raise SystemExit(f"FP3 IMS MMTEL SHA-256 mismatch: {relative}: {digest}")
        verified[relative] = {
            "tier": "P1",
            "path": relative,
            "size": payload.stat().st_size,
            "sha256": digest,
        }

    manifest = load_json("proprietary-manifest.json")
    by_path = {entry["path"]: entry for entry in manifest["files"]}
    by_path.update(verified)
    manifest["files"] = sorted(
        by_path.values(), key=lambda entry: (entry["tier"], entry["path"])
    )
    counts = Counter(entry["tier"] for entry in manifest["files"])
    manifest["counts"] = {
        "P0": counts.get("P0", 0),
        "P1": counts.get("P1", 0),
        "P2": counts.get("P2", 0),
        "total": len(manifest["files"]),
    }
    write_json("proprietary-manifest.json", manifest)

    generated = load_json("GENERATED_VENDOR_AUDIT.json")
    generated.update(
        {
            "selected_files": len(manifest["files"]),
            "p0": counts.get("P0", 0),
            "p1": counts.get("P1", 0),
            "p2": counts.get("P2", 0),
            "selected_bytes": sum(int(entry["size"]) for entry in manifest["files"]),
        }
    )
    write_json("GENERATED_VENDOR_AUDIT.json", generated)

    source_lock = load_json("SOURCE_LOCK.json")
    source_lock["selected_files"] = len(manifest["files"])
    source_lock.setdefault("android15_contract", {})["ims_mmtel_runtime"] = {
        "reason": (
            "Android 15 requires a framework-visible ImsService; RED stock 118 "
            "supplies only an Android 9 frontend and radio-audio bridge, while "
            "all maintained MSM8998 LineageOS 22.2 references share this "
            "compatible Qualcomm runtime"
        ),
        "donor_build": "FP3 6.A.040.2",
        "validated_reference_trees": [
            "essential/mata",
            "razer/cheryl",
            "oneplus/msm8998-common",
            "nubia/msm8998-common",
        ],
        "paths": sorted(EXPECTED_SHA256),
        "stock118_feature_policy_preserved": True,
    }
    write_json("SOURCE_LOCK.json", source_lock)

    tree_audit = load_json("VENDOR_TREE_AUDIT.json")
    tree_audit["counts"] = manifest["counts"]
    note = (
        "The Android 15 Qualcomm IMS MMTEL frontend, private JNI libraries, "
        "and radio-audio call-state bridge are byte-identical across the "
        "maintained mata, cheryl, Nubia, and OnePlus MSM8998 reference trees; "
        "RED .118 remains the feature-policy authority."
    )
    obsolete_note = (
        "The Android 15 Qualcomm IMS MMTEL frontend and its two private JNI "
        "libraries are byte-identical across the maintained mata, cheryl, "
        "Nubia, and OnePlus MSM8998 reference trees; RED .118 remains the "
        "feature-policy authority."
    )
    notes = [
        existing
        for existing in tree_audit.get("notes", [])
        if existing != obsolete_note
    ]
    if note not in notes:
        notes.append(note)
    tree_audit["notes"] = notes
    write_json("VENDOR_TREE_AUDIT.json", tree_audit)

    print(
        "Recorded FP3 IMS MMTEL and radio-audio runtime: "
        f"files={len(EXPECTED_SHA256)}, selected total={len(manifest['files'])}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
