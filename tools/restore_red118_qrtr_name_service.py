#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUIRED = {
    "tier": "P0",
    "path": "vendor/bin/qrtr-ns",
    "size": 68632,
    "sha256": "294d3d810af39d66db49469917e46fc0537e5122cf54c883344135bfd83bf7dd",
    "module": "qrtr-ns",
}


def load_json(path: str) -> dict:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def write_json(path: str, value: dict) -> None:
    (ROOT / path).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def verify_payload() -> None:
    path = ROOT / "proprietary" / REQUIRED["path"]
    if not path.is_file():
        raise SystemExit(f"missing RED .118 QRTR name service: {REQUIRED['path']}")
    data = path.read_bytes()
    if len(data) != REQUIRED["size"]:
        raise SystemExit(
            f"size mismatch for {REQUIRED['path']}: {len(data)} != {REQUIRED['size']}"
        )
    digest = hashlib.sha256(data).hexdigest()
    if digest != REQUIRED["sha256"]:
        raise SystemExit(
            f"SHA-256 mismatch for {REQUIRED['path']}: {digest} != {REQUIRED['sha256']}"
        )


def update_manifest() -> dict:
    manifest = load_json("proprietary-manifest.json")
    identity = {
        key: REQUIRED[key] for key in ("tier", "path", "size", "sha256")
    }
    by_path = {entry["path"]: entry for entry in manifest["files"]}
    current = by_path.get(REQUIRED["path"])
    if current is not None and current != identity:
        raise SystemExit(
            f"manifest identity mismatch for {REQUIRED['path']}: {current}"
        )
    if current is None:
        manifest["files"].append(identity)
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


def update_proprietary_files() -> None:
    path = ROOT / "proprietary-files.txt"
    lines = path.read_text(encoding="utf-8").rstrip().splitlines()
    selected = {
        raw.strip().split(";", 1)[0].split(":", 1)[0].lstrip("-")
        for raw in lines
        if raw.strip() and not raw.strip().startswith("#")
    }
    if REQUIRED["path"] not in selected:
        try:
            anchor = lines.index("vendor/bin/tftp_server")
        except ValueError:
            lines.append(REQUIRED["path"])
        else:
            lines.insert(anchor, REQUIRED["path"])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def seed_android_bp() -> None:
    path = ROOT / "Android.bp"
    text = path.read_text(encoding="utf-8")
    modules = set(re.findall(r'(?m)^\s*name:\s*"([^"]+)"\s*,?$', text))
    if REQUIRED["module"] in modules:
        return

    payload = ROOT / "proprietary" / REQUIRED["path"]
    header = subprocess.check_output(["readelf", "-h", str(payload)], text=True)
    if "ELF64" not in header or "AArch64" not in header:
        raise SystemExit(f"unexpected ELF target for {REQUIRED['path']}")

    block = f'''cc_prebuilt_binary {{
    name: "{REQUIRED['module']}",
    owner: "red",
    strip: {{
        none: true,
    }},
    target: {{
        android_arm64: {{
            srcs: [
                "proprietary/{REQUIRED['path']}",
            ],
        }},
    }},
    compile_multilib: "64",
    prefer: true,
    soc_specific: true,
}}'''
    path.write_text(text.rstrip() + "\n\n" + block + "\n", encoding="utf-8")


def update_vendor_mk() -> None:
    path = ROOT / "hydrogenone-vendor.mk"
    text = path.read_text(encoding="utf-8")
    if re.search(r"(?m)^\s*qrtr-ns\s*\\?\s*$", text):
        return
    anchor = "    tftp_server \\\n"
    if anchor not in text:
        raise SystemExit("cannot locate tftp_server package anchor")
    path.write_text(text.replace(anchor, "    qrtr-ns \\\n" + anchor, 1), encoding="utf-8")


def update_metadata(manifest: dict) -> None:
    counts = Counter(entry["tier"] for entry in manifest["files"])
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

    lock = load_json("SOURCE_LOCK.json")
    lock["selected_files"] = len(manifest["files"])
    lock.setdefault("android15_contract", {})[
        "qrtr_name_service_restored_from_red_118"
    ] = True
    write_json("SOURCE_LOCK.json", lock)

    audit = load_json("VENDOR_TREE_AUDIT.json")
    audit["counts"] = manifest["counts"]
    notes = list(audit.get("notes", []))
    note = (
        "RED .118 qrtr-ns is retained so the modem can publish the WLAN QMI "
        "service before tftp_server supplies wlanmdsp.mbn to ICNSS."
    )
    if note not in notes:
        notes.append(note)
    audit["notes"] = notes
    write_json("VENDOR_TREE_AUDIT.json", audit)


def main() -> int:
    verify_payload()
    manifest = update_manifest()
    update_proprietary_files()
    seed_android_bp()
    update_vendor_mk()
    update_metadata(manifest)
    print("RED .118 QRTR name service restored")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
