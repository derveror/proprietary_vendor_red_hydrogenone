#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED = (
    {
        "tier": "P0",
        "path": "vendor/bin/spdaemon",
        "size": 68656,
        "sha256": "a157a177f899ad1783945b88fbe3cb2ddae35ea480d8595b5ddcac91ea16886d",
        "module": "spdaemon",
        "kind": "cc_prebuilt_binary",
    },
    {
        "tier": "P0",
        "path": "vendor/lib64/libspcom.so",
        "size": 68464,
        "sha256": "3f9e7b0ecd2ffd999ef58077a15fffa780754dd0f4fb0ae2d8eb49adbe924c4c",
        "module": "libspcom",
        "kind": "cc_prebuilt_library_shared",
    },
    {
        "tier": "P0",
        "path": "vendor/bin/hvdcp_opti",
        "size": 202720,
        "sha256": "4d1d5a97f2da8840912ffdb8351a20b278905ebd4f471cfdee81c4052cc80a03",
        "module": "hvdcp_opti",
        "kind": "cc_prebuilt_binary",
    },
    {
        "tier": "P0",
        "path": "vendor/bin/energy-awareness",
        "size": 70120,
        "sha256": "2b1ae7f5ef59b9a7518b3eabd4823eac5cce51330069f75bd120bcfc30767158",
        "module": "energy-awareness",
        "kind": "cc_prebuilt_binary",
    },
)


def load_json(path: str) -> dict:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def write_json(path: str, value: dict) -> None:
    (ROOT / path).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def verify_payload() -> None:
    failures: list[str] = []
    for item in REQUIRED:
        path = ROOT / "proprietary" / item["path"]
        if not path.is_file():
            failures.append(f"missing {item['path']}")
            continue
        data = path.read_bytes()
        if len(data) != item["size"]:
            failures.append(f"{item['path']}: size {len(data)} != {item['size']}")
        digest = hashlib.sha256(data).hexdigest()
        if digest != item["sha256"]:
            failures.append(f"{item['path']}: sha256 {digest} != {item['sha256']}")
    if failures:
        raise SystemExit("RED .118 P0 payload verification failed:\n" + "\n".join(failures))


def update_manifest() -> dict:
    manifest = load_json("proprietary-manifest.json")
    by_path = {entry["path"]: entry for entry in manifest["files"]}
    for item in REQUIRED:
        identity = {key: item[key] for key in ("tier", "path", "size", "sha256")}
        current = by_path.get(item["path"])
        if current is not None and current != identity:
            raise SystemExit(f"manifest identity mismatch for {item['path']}: {current}")
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
    for item in REQUIRED:
        if item["path"] not in selected:
            lines.append(item["path"])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def elf_target(path: Path) -> tuple[str, str]:
    header = subprocess.check_output(["readelf", "-h", str(path)], text=True)
    if "ELF64" in header:
        return "android_arm64", "64"
    if "ELF32" in header:
        return "android_arm", "32"
    raise SystemExit(f"unknown ELF class for {path}")


def render_seed_block(item: dict) -> str:
    arch, multilib = elf_target(ROOT / "proprietary" / item["path"])
    return "\n".join(
        (
            f"{item['kind']} {{",
            f"    name: \"{item['module']}\",",
            '    owner: "red",',
            "    strip: {",
            "        none: true,",
            "    },",
            "    target: {",
            f"        {arch}: {{",
            "            srcs: [",
            f"                \"proprietary/{item['path']}\",",
            "            ],",
            "        },",
            "    },",
            f"    compile_multilib: \"{multilib}\",",
            "    prefer: true,",
            "    soc_specific: true,",
            "}",
        )
    )


def seed_android_bp() -> None:
    path = ROOT / "Android.bp"
    text = path.read_text(encoding="utf-8")
    modules = set(re.findall(r'(?m)^\s*name:\s*"([^"]+)"\s*,?$', text))
    additions = [render_seed_block(item) for item in REQUIRED if item["module"] not in modules]
    if additions:
        path.write_text(text.rstrip() + "\n\n" + "\n\n".join(additions) + "\n", encoding="utf-8")


def update_vendor_mk() -> None:
    path = ROOT / "hydrogenone-vendor.mk"
    text = path.read_text(encoding="utf-8").rstrip()
    missing = [
        item["module"]
        for item in REQUIRED
        if not re.search(rf"(?m)^\s*{re.escape(item['module'])}\s*\\?\s*$", text)
    ]
    if missing:
        section = ["", "", "# RED .118 P0 daemon completion", "PRODUCT_PACKAGES += \\"]
        for index, module in enumerate(sorted(missing)):
            suffix = " \\" if index < len(missing) - 1 else ""
            section.append(f"    {module}{suffix}")
        text += "\n".join(section)
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


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
        "p0_rootdir_daemon_payload_completed_from_red_118"
    ] = True
    write_json("SOURCE_LOCK.json", lock)

    audit = load_json("VENDOR_TREE_AUDIT.json")
    audit["counts"] = manifest["counts"]
    notes = list(audit.get("notes", []))
    note = (
        "RED .118 spdaemon/libspcom, hvdcp_opti, and energy-awareness are retained "
        "because the Android 15 rootdir contract and MSM8998 runtime dependency graph require them."
    )
    if note not in notes:
        notes.append(note)
    audit["notes"] = notes
    write_json("VENDOR_TREE_AUDIT.json", audit)

    (ROOT / "docs/ANDROID15_P0_DAEMONS.md").write_text(
        """# RED Hydrogen One Android 15 P0 daemon completion

Stock authority: RED `.118`, SHA-256 `7277a1accf9595bb727f2189863cf5f6249dd99322e2953432bca6e448365f1e`.

The Android 15 rootdir contract requires three RED/Qualcomm daemons that were omitted from the first vendor selection: `spdaemon`, `hvdcp_opti`, and `energy-awareness`. `spdaemon` also has a direct RED `.118` DT_NEEDED dependency on `libspcom.so`, so the matching 64-bit provider is retained with it.

All four files are pinned by exact size and SHA-256 in `proprietary-manifest.json` and validated by `tests/test_p0_daemon_completion.py`. They are RED stock files, not donor blobs.

`tools/generate_elf_contract.py` derives their `shared_libs` from the real `DT_NEEDED` records; the normal checkelf policy applies and no blanket exception is introduced.
""",
        encoding="utf-8",
    )


def main() -> int:
    verify_payload()
    manifest = update_manifest()
    update_proprietary_files()
    seed_android_bp()
    update_vendor_mk()
    update_metadata(manifest)
    print(f"P0 daemon completion prepared: {len(REQUIRED)} verified RED .118 files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
