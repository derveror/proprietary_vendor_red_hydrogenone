#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

DISPLAY_COLOR_FILES = (
    {
        "tier": "P2",
        "path": "vendor/lib/vendor.display.color@1.0.so",
        "size": 172520,
        "sha256": "4f6f8116cc4b88c7ca8b3e993052fe1fc7e774379b8d701f5b2f3a41ed412e75",
    },
    {
        "tier": "P2",
        "path": "vendor/lib64/vendor.display.color@1.0.so",
        "size": 269304,
        "sha256": "b5ba1f85adc4dfe87fdaa65545c4b46b8d4229e68f922b41b1e35b48875b79fe",
    },
)


def load_json(name: str) -> dict:
    return json.loads((ROOT / name).read_text(encoding="utf-8"))


def write_json(name: str, data: dict) -> None:
    (ROOT / name).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def verify_stock_payload() -> None:
    for entry in DISPLAY_COLOR_FILES:
        path = ROOT / "proprietary" / entry["path"]
        if not path.is_file():
            raise SystemExit(f"missing RED .118 display-color provider: {entry['path']}")
        size = path.stat().st_size
        if size != entry["size"]:
            raise SystemExit(f"size mismatch for {entry['path']}: {size} != {entry['size']}")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != entry["sha256"]:
            raise SystemExit(
                f"SHA-256 mismatch for {entry['path']}: {digest} != {entry['sha256']}"
            )


def update_manifest() -> tuple[dict, Counter]:
    manifest = load_json("proprietary-manifest.json")
    by_path = {entry["path"]: entry for entry in manifest["files"]}
    for required in DISPLAY_COLOR_FILES:
        current = by_path.get(required["path"])
        if current is not None and current != required:
            raise SystemExit(
                f"manifest identity mismatch for {required['path']}: {current}"
            )
        if current is None:
            manifest["files"].append(dict(required))

    manifest["files"].sort(key=lambda entry: (entry["tier"], entry["path"]))
    counts = Counter(entry["tier"] for entry in manifest["files"])
    manifest["counts"] = {
        "P0": counts.get("P0", 0),
        "P1": counts.get("P1", 0),
        "P2": counts.get("P2", 0),
        "total": len(manifest["files"]),
    }
    write_json("proprietary-manifest.json", manifest)
    return manifest, counts


def update_proprietary_files() -> None:
    path = ROOT / "proprietary-files.txt"
    text = path.read_text(encoding="utf-8")
    selected = {
        raw.strip().split(";", 1)[0].split(":", 1)[0].lstrip("-")
        for raw in text.splitlines()
        if raw.strip() and not raw.strip().startswith("#")
    }
    missing = [entry["path"] for entry in DISPLAY_COLOR_FILES if entry["path"] not in selected]
    if not missing:
        return

    anchor = "vendor/lib64/libsdm-disp-apis.so\n"
    if anchor not in text:
        raise SystemExit("cannot locate RED/Leia libsdm-disp-apis anchor in proprietary-files.txt")
    addition = "".join(f"{item}\n" for item in missing)
    path.write_text(text.replace(anchor, anchor + addition, 1), encoding="utf-8")


def update_vendor_mk() -> None:
    path = ROOT / "hydrogenone-vendor.mk"
    text = path.read_text(encoding="utf-8")
    if re.search(r"(?m)^\s*vendor\.display\.color@1\.0\s*\\?\s*$", text):
        return
    anchor = "    libsdm-disp-apis \\\n"
    if anchor not in text:
        raise SystemExit("cannot locate libsdm-disp-apis PRODUCT_PACKAGES anchor")
    path.write_text(
        text.replace(anchor, anchor + "    vendor.display.color@1.0 \\\n", 1),
        encoding="utf-8",
    )


def update_metadata(manifest: dict, counts: Counter) -> None:
    selected_bytes = sum(int(entry["size"]) for entry in manifest["files"])

    lock = load_json("SOURCE_LOCK.json")
    lock["selected_files"] = len(manifest["files"])
    lock.setdefault("android15_contract", {})[
        "red_display_color_dependency_recovered"
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
    tree["counts"] = {
        "P0": counts.get("P0", 0),
        "P1": counts.get("P1", 0),
        "P2": counts.get("P2", 0),
        "total": len(manifest["files"]),
    }
    notes = list(tree.get("notes", []))
    note = (
        "RED .118 vendor.display.color@1.0.so (32/64) is retained because "
        "libsdm-disp-apis.so DT_NEEDED requires that exact HIDL interface provider."
    )
    if note not in notes:
        notes.append(note)
    tree["notes"] = notes
    write_json("VENDOR_TREE_AUDIT.json", tree)


def main() -> int:
    verify_stock_payload()
    manifest, counts = update_manifest()
    update_proprietary_files()
    update_vendor_mk()
    update_metadata(manifest, counts)
    print(
        "Recovered RED .118 display-color provider: "
        f"P2={counts.get('P2', 0)}, total={len(manifest['files'])}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
