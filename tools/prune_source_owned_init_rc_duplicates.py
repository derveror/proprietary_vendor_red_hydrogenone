#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SOURCE_OWNED_INIT_RC = (
    {
        "tier": "P0",
        "path": "vendor/etc/init/android.hardware.biometrics.fingerprint@2.1-service.rc",
        "size": 321,
        "sha256": "c45a07fb91845794ec2889d1c63e3826ee017da573c9a845d2b0ce027b3c9594",
        "owner": "hardware/interfaces biometrics fingerprint@2.1 init_rc",
    },
    {
        "tier": "P0",
        "path": "vendor/etc/init/android.hardware.media.omx@1.0-service.rc",
        "size": 211,
        "sha256": "92327bd0cbccbed25e25d68a67d3db0b06ee8763d474740a0deaaefc9e6e509f",
        "owner": "frameworks/av mediacodec android.hardware.media.omx@1.0-service init_rc",
    },
)


def load_json(name: str) -> dict:
    return json.loads((ROOT / name).read_text(encoding="utf-8"))


def write_json(name: str, value: dict) -> None:
    (ROOT / name).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def selected_path(raw: str) -> str | None:
    line = raw.strip()
    if not line or line.startswith("#"):
        return None
    body = line.split(";", 1)[0]
    return body.split(":", 1)[0].lstrip("-")


def verify_payload(expected: dict, payload: Path) -> None:
    if payload.stat().st_size != expected["size"]:
        raise SystemExit(
            f"size mismatch for source-owned init rc {expected['path']}: "
            f"{payload.stat().st_size} != {expected['size']}"
        )
    digest = hashlib.sha256(payload.read_bytes()).hexdigest()
    if digest != expected["sha256"]:
        raise SystemExit(
            f"SHA-256 mismatch for source-owned init rc {expected['path']}: {digest}"
        )


def prune_manifest_and_payload() -> dict:
    manifest = load_json("proprietary-manifest.json")
    by_path = {entry["path"]: entry for entry in manifest["files"]}
    prune_paths = {entry["path"] for entry in SOURCE_OWNED_INIT_RC}

    for expected in SOURCE_OWNED_INIT_RC:
        metadata = {
            key: expected[key]
            for key in ("tier", "path", "size", "sha256")
        }
        current = by_path.get(expected["path"])
        if current is not None and current != metadata:
            raise SystemExit(
                f"manifest identity mismatch for {expected['path']}: {current}"
            )

        payload = ROOT / "proprietary" / expected["path"]
        if payload.is_file():
            verify_payload(expected, payload)
            payload.unlink()

    manifest["files"] = [
        entry for entry in manifest["files"] if entry["path"] not in prune_paths
    ]
    manifest["files"].sort(key=lambda entry: (entry["tier"], entry["path"]))
    counts = Counter(entry["tier"] for entry in manifest["files"])
    manifest["counts"] = {
        "P0": counts.get("P0", 0),
        "P1": counts.get("P1", 0),
        "P2": counts.get("P2", 0),
        "total": len(manifest["files"]),
    }
    write_json("proprietary-manifest.json", manifest)
    return manifest


def prune_proprietary_files() -> None:
    path = ROOT / "proprietary-files.txt"
    prune_paths = {entry["path"] for entry in SOURCE_OWNED_INIT_RC}
    lines = path.read_text(encoding="utf-8").splitlines()
    lines = [raw for raw in lines if selected_path(raw) not in prune_paths]
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def prune_product_copy_files() -> None:
    path = ROOT / "hydrogenone-vendor.mk"
    text = path.read_text(encoding="utf-8")
    for expected in SOURCE_OWNED_INIT_RC:
        source = f"vendor/red/hydrogenone/proprietary/{expected['path']}"
        kept = [line for line in text.splitlines() if source not in line]
        text = "\n".join(kept).rstrip() + "\n"
    path.write_text(text, encoding="utf-8")


def update_project_metadata(manifest: dict) -> None:
    counts = manifest["counts"]
    selected_bytes = sum(int(entry["size"]) for entry in manifest["files"])

    generated = load_json("GENERATED_VENDOR_AUDIT.json")
    generated.update(
        {
            "selected_files": len(manifest["files"]),
            "p0": counts["P0"],
            "p1": counts["P1"],
            "p2": counts["P2"],
            "selected_bytes": selected_bytes,
        }
    )
    write_json("GENERATED_VENDOR_AUDIT.json", generated)

    lock = load_json("SOURCE_LOCK.json")
    lock["selected_files"] = len(manifest["files"])
    android15 = lock.setdefault("android15_contract", {})
    android15["source_owned_init_rc_duplicates_pruned"] = True
    android15["source_owned_init_rc"] = [
        {
            "path": entry["path"],
            "owner": entry["owner"],
        }
        for entry in SOURCE_OWNED_INIT_RC
    ]
    write_json("SOURCE_LOCK.json", lock)

    tree = load_json("VENDOR_TREE_AUDIT.json")
    tree["counts"] = counts
    notes = list(tree.get("notes", []))
    note = (
        "Fingerprint@2.1 and media OMX proprietary executables remain selected, "
        "but their RED .118 init rc copies are pruned because the corresponding "
        "LineageOS source modules already install equivalent init_rc destinations; "
        "this prevents ckati duplicate-install rules."
    )
    if note not in notes:
        notes.append(note)
    tree["notes"] = notes
    write_json("VENDOR_TREE_AUDIT.json", tree)


def main() -> int:
    manifest = prune_manifest_and_payload()
    prune_proprietary_files()
    prune_product_copy_files()
    update_project_metadata(manifest)
    print(
        "Pruned source-owned init rc duplicates: "
        f"P0={manifest['counts']['P0']}, total={manifest['counts']['total']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
