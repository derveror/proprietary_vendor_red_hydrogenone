#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PATH = "vendor/lib64/librmnetctl.so"
MODULE = "librmnetctl"
STOCK_SIZE = 70640
STOCK_SHA256 = "ad42b64ecbd587028eb91323c11c1e3ef9f7e3a2638f1349dfa9d64e52de52d2"


def load_json(name: str) -> dict:
    return json.loads((ROOT / name).read_text(encoding="utf-8"))


def write_json(name: str, value: dict) -> None:
    (ROOT / name).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def selected_path(raw: str) -> str | None:
    line = raw.strip()
    if not line or line.startswith("#"):
        return None
    return line.split(";", 1)[0].split(":", 1)[0].lstrip("-").split("|", 1)[0]


def remove_soong_module(text: str) -> str:
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    index = 0
    while index < len(lines):
        if not re.match(r"^cc_prebuilt_\w+\s*\{\s*$", lines[index]):
            out.append(lines[index])
            index += 1
            continue
        start = index
        depth = 0
        while index < len(lines):
            depth += lines[index].count("{") - lines[index].count("}")
            index += 1
            if depth == 0:
                break
        block = "".join(lines[start:index])
        if re.search(rf'(?m)^\s*name:\s*"{re.escape(MODULE)}",\s*$', block):
            while index < len(lines) and not lines[index].strip():
                index += 1
            continue
        out.append(block)
    return "".join(out)


def main() -> int:
    payload = ROOT / "proprietary" / PATH
    if payload.is_file():
        digest = hashlib.sha256(payload.read_bytes()).hexdigest()
        if payload.stat().st_size != STOCK_SIZE or digest != STOCK_SHA256:
            raise SystemExit(f"unexpected librmnetctl prebuilt identity: {digest}")
        payload.unlink()

    proprietary_files = ROOT / "proprietary-files.txt"
    lines = proprietary_files.read_text(encoding="utf-8").splitlines()
    proprietary_files.write_text(
        "\n".join(raw for raw in lines if selected_path(raw) != PATH).rstrip() + "\n",
        encoding="utf-8",
    )

    manifest = load_json("proprietary-manifest.json")
    manifest["files"] = [entry for entry in manifest["files"] if entry["path"] != PATH]
    counts = Counter(entry["tier"] for entry in manifest["files"])
    manifest["counts"] = {
        "P0": counts.get("P0", 0),
        "P1": counts.get("P1", 0),
        "P2": counts.get("P2", 0),
        "total": len(manifest["files"]),
    }
    write_json("proprietary-manifest.json", manifest)

    bp = ROOT / "Android.bp"
    bp.write_text(remove_soong_module(bp.read_text(encoding="utf-8")), encoding="utf-8")

    vendor_mk = ROOT / "hydrogenone-vendor.mk"
    mk_lines = vendor_mk.read_text(encoding="utf-8").splitlines()
    vendor_mk.write_text(
        "\n".join(
            raw for raw in mk_lines if not re.match(r"^\s*librmnetctl\s*\\?\s*$", raw)
        ).rstrip()
        + "\n",
        encoding="utf-8",
    )

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
        "source_owned_rmnetctl_pruned"
    ] = True
    write_json("SOURCE_LOCK.json", source_lock)

    tree_audit = load_json("VENDOR_TREE_AUDIT.json")
    tree_audit["counts"] = manifest["counts"]
    notes = list(tree_audit.get("notes", []))
    note = (
        "RED .118 librmnetctl is pruned in favor of the LineageOS dataservices "
        "source provider required by the FP3 netmgrd rtrmnet ABI."
    )
    if note not in notes:
        notes.append(note)
    tree_audit["notes"] = notes
    write_json("VENDOR_TREE_AUDIT.json", tree_audit)

    print(f"Pruned source-owned librmnetctl: selected total={len(manifest['files'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
