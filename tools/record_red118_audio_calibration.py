#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STOCK_SHA256 = "7277a1accf9595bb727f2189863cf5f6249dd99322e2953432bca6e448365f1e"
EXPECTED_SHA256 = {
    "vendor/etc/audio_tuning_mixer.txt": "c09d6e8fdb0e367e132064a23bac781318be1313b7454712b43feae5e8f09f28",
    "vendor/etc/acdbdata/MTP/MTP_Bluetooth_cal.acdb": "0c46a904c6c262248a5e0ef7ccb4f8e5131b28232ec71e19a78850f71961260a",
    "vendor/etc/acdbdata/MTP/MTP_General_cal.acdb": "09631f20c7d55738b833b570b79a83a35d5bf86f46a7a787de92433d1868d31a",
    "vendor/etc/acdbdata/MTP/MTP_Global_cal.acdb": "8dd3d326ecd0ce07c8e5a818189033683e923948fe655a865b7e5de89a6a4bdd",
    "vendor/etc/acdbdata/MTP/MTP_Handset_cal.acdb": "a70ad69f8483139c1f468967eae30ea45590957a6e5af4e68212235c46eeeb67",
    "vendor/etc/acdbdata/MTP/MTP_Hdmi_cal.acdb": "114c3045e91a383dc27a9d85c332131b9229371310fd498de7664a4ccf5b6ed0",
    "vendor/etc/acdbdata/MTP/MTP_Headset_cal.acdb": "af9e08c497bff64be90d1ee47d197814e19a6bf0970b3d87a0038ac4047ee781",
    "vendor/etc/acdbdata/MTP/MTP_Speaker_cal.acdb": "3aa79fd5505166cbce6afda67b2d3d3a18090b95892b14ece29072831750ac9a",
    "vendor/etc/acdbdata/MTP/MTP_workspaceFile.qwsp": "17385208d13d3d70e8b2c5649a076f4243c7a580a14a830e21cacf6f1607521e",
    "vendor/lib/libacdb-fts.so": "9d5b7fc1618bf3f63fea4ef87799c3b8f9701b3472bfee01019287e1f98eb8ea",
    "vendor/lib/libacdbloader.so": "93f8bebc7c3b057745f7dddb7f073007c3f619ac0435cf35411bae344dc1a648",
    "vendor/lib/libacdbrtac.so": "390f0255b4f8aab3076de4aa266fa51b00c54f1d1722796bd8579150900610f9",
    "vendor/lib/libadiertac.so": "09af96612bac9a615cc08f7934ba09b0d00d24d13fb5e1ed4bf5017e45a15d51",
    "vendor/lib/libaudcal.so": "d035a7cfde4e2959d7aa58442f30bf1e9e75a10176caad36f462a2fc22289d0e",
    "vendor/lib64/libacdb-fts.so": "51730e0e9f9d7c9ad3261e894672350d3816975a4a83b7cab7524589a1cda082",
    "vendor/lib64/libacdbloader.so": "5ce12163b8e8ea2cd2e75babbdfd9fa398ec39c97b6656a9250a76d1a6b91eaf",
    "vendor/lib64/libacdbrtac.so": "f69f4d134e8759ba39bb07d0d0487319172f1f5e1e299588f42a56cf5b5356ed",
    "vendor/lib64/libadiertac.so": "c949030b2da1191aebb79a93e368fdc1a0d1d57eaaad681ada2214c04bc29a40",
    "vendor/lib64/libaudcal.so": "0e81c904a1c49fa829c82288048ecc597e161b229be17de615150ee2dac0a153",
}


def load_json(name: str) -> dict:
    return json.loads((ROOT / name).read_text(encoding="utf-8"))


def write_json(name: str, value: dict) -> None:
    (ROOT / name).write_text(
        json.dumps(value, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )


def verified_entries() -> dict[str, dict]:
    verified: dict[str, dict] = {}
    for relative, expected_sha256 in EXPECTED_SHA256.items():
        payload = ROOT / "proprietary" / relative
        if not payload.is_file():
            raise SystemExit(f"missing RED .118 audio calibration payload: {relative}")
        digest = hashlib.sha256(payload.read_bytes()).hexdigest()
        if digest != expected_sha256:
            raise SystemExit(
                f"RED .118 audio calibration SHA-256 mismatch: {relative}: {digest}"
            )
        verified[relative] = {
            "tier": "P0",
            "path": relative,
            "size": payload.stat().st_size,
            "sha256": digest,
        }
    return verified


def record_proprietary_list(paths: set[str]) -> None:
    list_path = ROOT / "proprietary-files.txt"
    lines = list_path.read_text(encoding="utf-8").splitlines()
    selected = {
        line.strip().lstrip("-").split("|", 1)[0].split(";", 1)[0].split(":", 1)[0]
        for line in lines
        if line.strip() and not line.lstrip().startswith("#")
    }
    missing = sorted(paths - selected)
    if missing:
        lines.extend(("", "# RED .118 MTP audio calibration runtime", *missing))
        list_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def main() -> int:
    verified = verified_entries()
    manifest = load_json("proprietary-manifest.json")
    if manifest["canonical_stock"]["sha256"] != STOCK_SHA256:
        raise SystemExit("audio calibration source authority is not RED stock .118")

    by_path = {entry["path"]: entry for entry in manifest["files"]}
    for relative, expected in verified.items():
        current = by_path.get(relative)
        if current is not None and current != expected:
            raise SystemExit(f"audio calibration manifest mismatch: {relative}")
        by_path[relative] = expected
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
    record_proprietary_list(set(verified))

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
    source_lock.setdefault("android15_contract", {})[
        "red118_mtp_audio_calibration_files"
    ] = len(verified)
    write_json("SOURCE_LOCK.json", source_lock)

    tree_audit = load_json("VENDOR_TREE_AUDIT.json")
    tree_audit["counts"] = manifest["counts"]
    prefix = "RED .118 MTP audio calibration runtime retains"
    notes = [
        note
        for note in tree_audit.get("notes", [])
        if not note.startswith(prefix)
    ]
    notes.append(
        f"{prefix} {len(verified)} exact stock files: the 32/64-bit ACDB loader "
        "dependency closure, MTP calibration database, and mixer tuning used by "
        "the msm8998-tasha-snd-card."
    )
    tree_audit["notes"] = notes
    write_json("VENDOR_TREE_AUDIT.json", tree_audit)

    print(
        "Recorded RED .118 MTP audio calibration runtime: "
        f"files={len(verified)}, selected total={len(manifest['files'])}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
