#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BP = ROOT / "Android.bp"

SOURCE_OWNED_AUDIO_EFFECTS = (
    {
        "tier": "P1",
        "path": "vendor/lib/libeffects.so",
        "module": "libeffects",
        "size": 19684,
        "sha256": "94608d1099e71fd037c40bd9d8c4e97ad85c1fb7ef0306b6203c56be0ff4b139",
    },
    {
        "tier": "P1",
        "path": "vendor/lib64/libeffects.so",
        "module": "libeffects",
        "size": 40880,
        "sha256": "adbb734331b71bbf9ae7469df35b36c53a615275dbd91cef2a9e2b7788b53ecc",
    },
    {
        "tier": "P1",
        "path": "vendor/lib/libeffectsconfig.so",
        "module": "libeffectsconfig",
        "size": 19284,
        "sha256": "fcbc5ab5d8003a40d6d2c67d498d9b264df8cb23c6b1d456ec6c7b5f4b1ff557",
    },
    {
        "tier": "P1",
        "path": "vendor/lib64/libeffectsconfig.so",
        "module": "libeffectsconfig",
        "size": 49136,
        "sha256": "c190df3ea67e1675981e4dd2d65bce4bfb3df4050f2eb47fbdeb0db76e390999",
    },
)
SOURCE_OWNED_MODULES = {entry["module"] for entry in SOURCE_OWNED_AUDIO_EFFECTS}


def load_json(name: str) -> dict:
    return json.loads((ROOT / name).read_text(encoding="utf-8"))


def write_json(name: str, data: dict) -> None:
    (ROOT / name).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def proprietary_entry_path(raw: str) -> str | None:
    line = raw.strip()
    if not line or line.startswith("#"):
        return None
    body = line.split(";", 1)[0]
    return body.split(":", 1)[0].lstrip("-")


def verify_and_remove_payload(manifest: dict) -> None:
    by_path = {entry["path"]: entry for entry in manifest["files"]}
    for expected in SOURCE_OWNED_AUDIO_EFFECTS:
        current = by_path.get(expected["path"])
        metadata = {
            key: expected[key]
            for key in ("tier", "path", "size", "sha256")
        }
        if current is not None and current != metadata:
            raise SystemExit(
                f"manifest identity mismatch for {expected['path']}: {current}"
            )

        path = ROOT / "proprietary" / expected["path"]
        if not path.is_file():
            continue
        if path.stat().st_size != expected["size"]:
            raise SystemExit(
                f"size mismatch for source-owned audio effect {expected['path']}"
            )
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != expected["sha256"]:
            raise SystemExit(
                f"SHA-256 mismatch for source-owned audio effect "
                f"{expected['path']}: {digest}"
            )
        path.unlink()


def remove_bp_modules() -> None:
    text = BP.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    output: list[str] = []
    i = 0
    while i < len(lines):
        if not re.match(
            r"^cc_prebuilt_(?:binary|library_shared)\s*\{\s*$", lines[i]
        ):
            output.append(lines[i])
            i += 1
            continue

        start = i
        depth = lines[i].count("{") - lines[i].count("}")
        i += 1
        while i < len(lines) and depth > 0:
            depth += lines[i].count("{") - lines[i].count("}")
            i += 1
        block = "".join(lines[start:i])
        match = re.search(r'(?m)^\s*name:\s*"([^"]+)"', block)
        if match and match.group(1) in SOURCE_OWNED_MODULES:
            while output and output[-1].strip() == "":
                output.pop()
            continue
        output.append(block)

    BP.write_text("".join(output).rstrip() + "\n", encoding="utf-8")


def update_selection_metadata() -> tuple[dict, Counter]:
    manifest = load_json("proprietary-manifest.json")
    verify_and_remove_payload(manifest)

    pruned_paths = {entry["path"] for entry in SOURCE_OWNED_AUDIO_EFFECTS}
    manifest["files"] = [
        entry for entry in manifest["files"] if entry["path"] not in pruned_paths
    ]
    counts = Counter(entry["tier"] for entry in manifest["files"])
    manifest["counts"] = {
        "P0": counts.get("P0", 0),
        "P1": counts.get("P1", 0),
        "P2": counts.get("P2", 0),
        "total": len(manifest["files"]),
    }
    write_json("proprietary-manifest.json", manifest)

    proprietary_files = ROOT / "proprietary-files.txt"
    lines = proprietary_files.read_text(encoding="utf-8").splitlines()
    lines = [
        raw for raw in lines if proprietary_entry_path(raw) not in pruned_paths
    ]
    proprietary_files.write_text(
        "\n".join(lines).rstrip() + "\n", encoding="utf-8"
    )

    vendor_mk = ROOT / "hydrogenone-vendor.mk"
    mk = vendor_mk.read_text(encoding="utf-8")
    for module in SOURCE_OWNED_MODULES:
        mk = re.sub(
            rf"(?m)^\s*{re.escape(module)}\s*\\\s*\n",
            "",
            mk,
        )
    vendor_mk.write_text(mk, encoding="utf-8")

    selected_bytes = sum(int(entry["size"]) for entry in manifest["files"])

    lock = load_json("SOURCE_LOCK.json")
    lock["selected_files"] = len(manifest["files"])
    lock.setdefault("android15_contract", {})[
        "source_owned_audio_effects_pruned"
    ] = True
    write_json("SOURCE_LOCK.json", lock)

    audit = load_json("GENERATED_VENDOR_AUDIT.json")
    audit.update(
        {
            "selected_files": len(manifest["files"]),
            "p0": counts.get("P0", 0),
            "p1": counts.get("P1", 0),
            "p2": counts.get("P2", 0),
            "selected_bytes": selected_bytes,
        }
    )
    write_json("GENERATED_VENDOR_AUDIT.json", audit)

    tree = load_json("VENDOR_TREE_AUDIT.json")
    tree["counts"] = manifest["counts"]
    notes = list(tree.get("notes", []))
    note = (
        "LineageOS 22.2 builds libeffects for vendor and libeffectsconfig as "
        "vendor_available from frameworks/av; the duplicate RED .118 "
        "platform-built copies are pruned."
    )
    if note not in notes:
        notes.append(note)
    tree["notes"] = notes
    write_json("VENDOR_TREE_AUDIT.json", tree)

    return manifest, counts


def main() -> int:
    manifest, counts = update_selection_metadata()
    remove_bp_modules()
    print(
        "Pruned Android 15 source-owned audio effects: "
        f"P1={counts.get('P1', 0)}, total={len(manifest['files'])}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
