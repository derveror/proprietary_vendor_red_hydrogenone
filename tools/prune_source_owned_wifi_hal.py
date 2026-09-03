#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BP = ROOT / "Android.bp"

# These RED .118 libraries collide by module name with the Android 15 Wi-Fi
# source stack.  The source modules carry compile-time header contracts that a
# cc_prebuilt_library_shared cannot reproduce:
#   - libwifi-hal exports wifi_legacy_headers (hardware_legacy/wifi_hal.h)
#   - libcld80211 exports cld80211_lib.h to libwifi-hal-qcom
# Keep the package names selected, but remove the stock prebuilt owners.
SOURCE_OWNED = (
    {
        "tier": "P1",
        "path": "vendor/lib64/libcld80211.so",
        "module": "libcld80211",
        "size": 68216,
        "sha256": "5fe4c8eab9b90ead61783e97058eae0eac2047baa88fdb55f15cd8ae0652d5b6",
    },
    {
        "tier": "P1",
        "path": "vendor/lib64/libwifi-hal.so",
        "module": "libwifi-hal",
        "size": 369808,
        "sha256": "2716e3961b030fa21e8ac2d53d5990f8d22439dd6373acb726ce2fe007088dfb",
    },
)
SOURCE_MODULES = {entry["module"] for entry in SOURCE_OWNED}
SOURCE_PATHS = {entry["path"] for entry in SOURCE_OWNED}


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


def prune_payload() -> dict:
    manifest = load_json("proprietary-manifest.json")
    by_path = {entry["path"]: entry for entry in manifest["files"]}

    for expected in SOURCE_OWNED:
        current = by_path.get(expected["path"])
        metadata = {
            key: expected[key]
            for key in ("tier", "path", "size", "sha256")
        }
        if current is not None and current != metadata:
            raise SystemExit(
                f"manifest identity mismatch for {expected['path']}: {current}"
            )

        payload = ROOT / "proprietary" / expected["path"]
        if payload.is_file():
            if payload.stat().st_size != expected["size"]:
                raise SystemExit(f"size mismatch for {expected['path']}")
            digest = hashlib.sha256(payload.read_bytes()).hexdigest()
            if digest != expected["sha256"]:
                raise SystemExit(
                    f"SHA-256 mismatch for {expected['path']}: {digest}"
                )
            payload.unlink()

    manifest["files"] = [
        entry for entry in manifest["files"] if entry["path"] not in SOURCE_PATHS
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

    path = ROOT / "proprietary-files.txt"
    lines = path.read_text(encoding="utf-8").splitlines()
    lines = [raw for raw in lines if selected_path(raw) not in SOURCE_PATHS]
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return manifest


def prebuilt_blocks(text: str) -> list[tuple[int, int, str]]:
    lines = text.splitlines(keepends=True)
    blocks: list[tuple[int, int, str]] = []
    i = 0
    while i < len(lines):
        if not re.match(r"^cc_prebuilt_(?:binary|library_shared)\s*\{\s*$", lines[i]):
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
        if match:
            blocks.append((start, i, match.group(1)))
    return blocks


def prune_prebuilt_modules() -> None:
    text = BP.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    removals = [
        (start, end)
        for start, end, name in prebuilt_blocks(text)
        if name in SOURCE_MODULES
    ]
    for start, end in sorted(removals, reverse=True):
        lines[start:end] = []
    BP.write_text(
        re.sub(r"\n{3,}", "\n\n", "".join(lines)).rstrip() + "\n",
        encoding="utf-8",
    )


def assert_source_packages_retained() -> None:
    text = (ROOT / "hydrogenone-vendor.mk").read_text(encoding="utf-8")
    for module in sorted(SOURCE_MODULES):
        if not re.search(rf"(?m)^\s*{re.escape(module)}\s*\\?\s*$", text):
            raise SystemExit(
                f"source-owned Wi-Fi HAL package must stay selected: {module}"
            )


def update_elf_metadata() -> tuple[int, int]:
    exceptions_doc = load_json("ANDROID15_ELF_EXCEPTIONS.json")
    exceptions = exceptions_doc.get("exceptions", {})
    for module in SOURCE_MODULES:
        exceptions.pop(module, None)
    exceptions_doc["exceptions"] = exceptions
    write_json("ANDROID15_ELF_EXCEPTIONS.json", exceptions_doc)

    audit = load_json("ANDROID15_ELF_AUDIT.json")
    modules = audit.get("modules", {})
    for module in SOURCE_MODULES:
        modules.pop(module, None)
    audit["modules"] = modules
    total = len(modules)
    exception_count = len(exceptions)
    audit["summary"] = {
        **audit.get("summary", {}),
        "total_modules": total,
        "checkelf_enabled": total - exception_count,
        "checkelf_exceptions": exception_count,
    }
    write_json("ANDROID15_ELF_AUDIT.json", audit)
    return total, exception_count


def update_project_metadata(manifest: dict, modules: int, exceptions: int) -> None:
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
            "elf_modules": modules,
            "checkelf_enabled": modules - exceptions,
            "checkelf_exceptions": exceptions,
        }
    )
    write_json("GENERATED_VENDOR_AUDIT.json", generated)

    lock = load_json("SOURCE_LOCK.json")
    lock["selected_files"] = len(manifest["files"])
    android15 = lock.setdefault("android15_contract", {})
    android15["source_owned_wifi_hal_pruned"] = True
    android15["source_owned_wifi_hal_packages_retained"] = sorted(SOURCE_MODULES)
    android15["checkelf_enabled_modules"] = modules - exceptions
    android15["checkelf_exception_modules"] = exceptions
    write_json("SOURCE_LOCK.json", lock)

    tree = load_json("VENDOR_TREE_AUDIT.json")
    tree["counts"] = counts
    notes = list(tree.get("notes", []))
    note = (
        "RED .118 libwifi-hal/libcld80211 prebuilts are pruned because they shadow "
        "LineageOS 22.2 source modules that export compile-time Wi-Fi legacy headers. "
        "The package names remain selected so android.hardware.wifi-service receives "
        "wifi_legacy_headers and libwifi-hal-qcom receives cld80211_lib.h."
    )
    if note not in notes:
        notes.append(note)
    tree["notes"] = notes
    write_json("VENDOR_TREE_AUDIT.json", tree)


def main() -> int:
    manifest = prune_payload()
    prune_prebuilt_modules()
    assert_source_packages_retained()
    modules, exceptions = update_elf_metadata()
    update_project_metadata(manifest, modules, exceptions)
    print(
        "Pruned source-owned Wi-Fi HAL prebuilts: "
        f"total={manifest['counts']['total']}, modules={modules}, "
        f"checkelf={modules - exceptions}, exceptions={exceptions}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
