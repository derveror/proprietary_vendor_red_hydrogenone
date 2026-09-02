#!/usr/bin/env python3
from __future__ import annotations

import fnmatch
import json
import os
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

FORBIDDEN_MODULES = {
    "android.hardware.audio.effect@2.0-impl",
    "android.hardware.audio.effect@4.0-impl",
    "android.hardware.audio@2.0-impl",
    "android.hardware.audio@4.0-impl",
    "android.hardware.audio@2.0-service",
    "android.hardware.camera.provider@2.4-impl",
    "android.hardware.camera.provider@2.4-service",
    "android.hardware.gnss@1.0-impl-qti",
    "android.hardware.sensors@1.0-impl",
    "android.hardware.sensors@1.0-service",
    "android.hardware.soundtrigger@2.1-impl",
    "android.hardware.usb@1.0-service",
    "android.hardware.wifi@1.0-service",
    "audio.primary.msm8998",
    "audio.r_submix.default",
    "audio.usb.default",
    "libgnss",
    "libgnsspps",
    "libwifi-hal-qcom",
    "libwpa_client",
    "vendor.qti.gnss@1.0-service",
    "vendor.nxp.hardware.nfc@1.1-service",
}

FORBIDDEN_RC = {
    "vendor/etc/init/android.hardware.audio@2.0-service.rc",
    "vendor/etc/init/android.hardware.boot@1.0-service.rc",
    "vendor/etc/init/android.hardware.camera.provider@2.4-service.rc",
    "vendor/etc/init/android.hardware.configstore@1.1-service.rc",
    "vendor/etc/init/android.hardware.gatekeeper@1.0-service-qti.rc",
    "vendor/etc/init/android.hardware.graphics.allocator@2.0-service.rc",
    "vendor/etc/init/android.hardware.graphics.composer@2.1-service.rc",
    "vendor/etc/init/android.hardware.health@2.0-service.rc",
    "vendor/etc/init/android.hardware.keymaster@3.0-service-qti.rc",
    "vendor/etc/init/android.hardware.light@2.0-service.rc",
    "vendor/etc/init/android.hardware.sensors@1.0-service.rc",
    "vendor/etc/init/android.hardware.usb@1.0-service.rc",
    "vendor/etc/init/android.hardware.vibrator@1.0-service.rc",
    "vendor/etc/init/android.hardware.wifi@1.0-service.rc",
    "vendor/etc/init/vendor.qti.gnss@1.0-service.rc",
    "vendor/etc/init/vendor.nxp.hardware.nfc@1.1-service.rc",
}

# Stock .118 init contains references that are stale even in the complete
# factory vendor image. The generic qcom rc files also collide with the exact
# Android 15 control-plane destinations owned by device/red/hydrogenone.
STALE_INIT_RC = {
    "vendor/etc/init/android.hardware.cas@1.0-service.rc",
    "vendor/etc/init/android.hardware.drm@1.0-service.rc",
    "vendor/etc/init/android.hardware.drm@1.1-service.clearkey.rc",
    "vendor/etc/init/android.hardware.drm@1.1-service.widevine.rc",
    "vendor/etc/init/android.hardware.memtrack@1.0-service.rc",
    "vendor/etc/init/android.hardware.power@1.0-service.rc",
    "vendor/etc/init/android.hardware.thermal@1.0-service.rc",
    "vendor/etc/init/android.hardware.vr@1.0-service.rc",
    "vendor/etc/init/hostapd.android.rc",
    "vendor/etc/init/hw/init.qcom.factory.rc",
    "vendor/etc/init/hw/init.qcom.rc",
    "vendor/etc/init/hw/init.qcom.usb.rc",
    "vendor/etc/init/sns_reg.rc",
    "vendor/etc/init/vendor.display.color@1.0-service.rc",
    "vendor/etc/init/vendor.qti.hardware.alarm@1.0-service.rc",
    "vendor/etc/init/vendor.qti.hardware.factory@1.0-service.rc",
    "vendor/etc/init/vendor.qti.hardware.perf@1.0-service.rc",
    "vendor/etc/init/vendor.qti.hardware.qdutils_disp@1.0-service-qti.rc",
    "vendor/etc/init/vendor.qti.hardware.qteeconnector@1.0-service.rc",
    "vendor/etc/init/vendor.qti.hardware.soter@1.0-service.rc",
    "vendor/etc/init/vendor.qti.hardware.tui_comm@1.0-service-qti.rc",
}

DEBUG_GLOBS = (
    "vendor/bin/audioflacapp",
    "vendor/bin/fpc_tee_test",
    "vendor/bin/mm-*-test",
    "vendor/bin/mm-audio-ftm",
    "vendor/bin/mm-qcamera-app",
    "vendor/bin/qmi_simple_ril_test",
    "vendor/bin/sensorrdiag",
)


def load_json(path: str) -> dict:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def write_json(path: str, data: dict) -> None:
    (ROOT / path).write_text(json.dumps(data, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def parse_bp_blocks(text: str) -> list[dict]:
    lines = text.splitlines(keepends=True)
    blocks: list[dict] = []
    i = 0
    while i < len(lines):
        match = re.match(r"^([A-Za-z0-9_]+)\s*\{\s*$", lines[i])
        if not match:
            i += 1
            continue
        start = i
        depth = lines[i].count("{") - lines[i].count("}")
        i += 1
        while i < len(lines) and depth > 0:
            depth += lines[i].count("{") - lines[i].count("}")
            i += 1
        end = i
        block_text = "".join(lines[start:end])
        name_match = re.search(r'(?m)^\s*name:\s*"([^"]+)"\s*,?\s*$', block_text)
        srcs = re.findall(r'"proprietary/([^"]+)"', block_text)
        blocks.append(
            {
                "kind": match.group(1),
                "start": start,
                "end": end,
                "name": name_match.group(1) if name_match else None,
                "srcs": srcs,
            }
        )
    return blocks


def render_android_bp(remove_paths: set[str]) -> tuple[set[str], int]:
    path = ROOT / "Android.bp"
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    blocks = parse_bp_blocks(text)

    removed_modules: set[str] = set()
    removed_ranges: list[tuple[int, int]] = []

    changed = True
    while changed:
        changed = False
        for block in blocks:
            if (block["start"], block["end"]) in removed_ranges:
                continue
            name = block["name"]
            srcs = set(block["srcs"])
            if (name and name in FORBIDDEN_MODULES) or (srcs & remove_paths):
                removed_ranges.append((block["start"], block["end"]))
                if name:
                    removed_modules.add(name)
                before = len(remove_paths)
                remove_paths.update(srcs)
                changed = changed or len(remove_paths) != before

    skip: set[int] = set()
    for start, end in removed_ranges:
        skip.update(range(start, end))

    output = "".join(line for idx, line in enumerate(lines) if idx not in skip)
    output = re.sub(r"\n{3,}", "\n\n", output).rstrip() + "\n"
    path.write_text(output, encoding="utf-8")

    remaining_elf = sum(
        1
        for block in parse_bp_blocks(output)
        if block["kind"] in {"cc_prebuilt_binary", "cc_prebuilt_library_shared"}
    )
    return removed_modules, remaining_elf


def selected_path_from_line(line: str) -> str | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    body = stripped.split(";", 1)[0]
    return body.split(":", 1)[0].lstrip("-")


def filter_proprietary_files(remove_paths: set[str]) -> None:
    path = ROOT / "proprietary-files.txt"
    lines = path.read_text(encoding="utf-8").splitlines()
    kept: list[str] = []
    for line in lines:
        selected = selected_path_from_line(line)
        if selected and selected in remove_paths:
            continue
        kept.append(line)
    path.write_text("\n".join(kept).rstrip() + "\n", encoding="utf-8")


def parse_make_copy_entries(text: str) -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []
    prefix = "vendor/red/hydrogenone/proprietary/"
    for raw in text.splitlines():
        stripped = raw.strip().rstrip("\\").rstrip()
        if not stripped.startswith(prefix) or ":" not in stripped:
            continue
        source_with_prefix, destination = stripped.split(":", 1)
        entries.append((source_with_prefix[len(prefix) :], f"{source_with_prefix}:{destination}"))
    return entries


def parse_make_packages(text: str) -> list[str]:
    match = re.search(
        r"PRODUCT_PACKAGES\s*\+=\s*\\\n(.*?)(?=\n\n|\n[A-Z_]+\s*[:+]?=|\Z)",
        text,
        re.S,
    )
    if not match:
        return []
    return re.findall(r"(?m)^\s*([A-Za-z0-9_.@+:-]+)\s*\\?\s*$", match.group(1))


def render_make_list(name: str, items: list[str]) -> str:
    if not items:
        return f"{name} +=\n"
    lines = [f"{name} += \\"]
    for index, item in enumerate(items):
        suffix = " \\" if index < len(items) - 1 else ""
        lines.append(f"    {item}{suffix}")
    return "\n".join(lines)


def render_vendor_mk(remove_paths: set[str], removed_modules: set[str]) -> int:
    path = ROOT / "hydrogenone-vendor.mk"
    text = path.read_text(encoding="utf-8")
    copy_entries = [entry for source, entry in parse_make_copy_entries(text) if source not in remove_paths]
    packages = [package for package in parse_make_packages(text) if package not in removed_modules]

    output = (
        "# Automatically generated from verified RED .118 stock.\n"
        "# Android 15 contract: source-owned HAL wrappers, stale stock init, and factory/debug payload are pruned.\n\n"
        "PRODUCT_SOONG_NAMESPACES += \\\n"
        "    vendor/red/hydrogenone\n\n"
        + render_make_list("PRODUCT_COPY_FILES", copy_entries)
        + "\n\n"
        + render_make_list("PRODUCT_PACKAGES", packages)
        + "\n"
    )
    path.write_text(output, encoding="utf-8")
    return len(copy_entries)


def delete_payload(remove_paths: set[str]) -> list[str]:
    deleted: list[str] = []
    for relative in sorted(remove_paths):
        path = ROOT / "proprietary" / relative
        if path.is_symlink() or path.exists():
            path.unlink()
            deleted.append(relative)
    return deleted


def main() -> int:
    manifest = load_json("proprietary-manifest.json")
    original_files = manifest["files"]
    original_by_path = {entry["path"]: entry for entry in original_files}

    remove_paths = set(FORBIDDEN_RC) | set(STALE_INIT_RC)
    for path in original_by_path:
        if any(fnmatch.fnmatch(path, pattern) for pattern in DEBUG_GLOBS):
            remove_paths.add(path)

    removed_modules, elf_modules = render_android_bp(remove_paths)
    filter_proprietary_files(remove_paths)
    copy_files = render_vendor_mk(remove_paths, removed_modules)
    deleted = delete_payload(remove_paths)

    retained_files = [entry for entry in original_files if entry["path"] not in remove_paths]
    retained_paths = [entry["path"] for entry in retained_files]
    tier_counts = Counter(entry["tier"] for entry in retained_files)
    selected_bytes = sum(int(entry["size"]) for entry in retained_files)

    missing = [
        path
        for path in retained_paths
        if not os.path.lexists(ROOT / "proprietary" / path)
    ]
    duplicates = len(retained_paths) - len(set(retained_paths))

    manifest["files"] = retained_files
    manifest["counts"] = {
        "P0": tier_counts.get("P0", 0),
        "P1": tier_counts.get("P1", 0),
        "P2": tier_counts.get("P2", 0),
        "total": len(retained_files),
    }
    manifest["android15_contract"] = {
        "source_owned_modules_pruned": sorted(removed_modules & FORBIDDEN_MODULES),
        "stale_init_paths_pruned": sorted(path for path in STALE_INIT_RC if path in original_by_path),
        "removed_path_count": len([path for path in original_by_path if path in remove_paths]),
        "policy": "Retain RED hardware payload; replace source-owned Android 9 HAL wrappers with LineageOS 22.2 implementations and remove stock init fragments whose executable owner is absent or whose destination is device-owned.",
    }
    write_json("proprietary-manifest.json", manifest)

    source_lock = load_json("SOURCE_LOCK.json")
    source_lock["selected_files"] = len(retained_files)
    source_lock["android15_contract"] = {
        "branch": "lineage-22.2-android15-contract",
        "source_owned_wrappers_pruned": True,
        "debug_factory_payload_pruned": True,
        "stale_init_pruned": True,
    }
    write_json("SOURCE_LOCK.json", source_lock)

    generated = load_json("GENERATED_VENDOR_AUDIT.json")
    generated.update(
        {
            "selected_files": len(retained_files),
            "p0": tier_counts.get("P0", 0),
            "p1": tier_counts.get("P1", 0),
            "p2": tier_counts.get("P2", 0),
            "selected_bytes": selected_bytes,
            "elf_modules": elf_modules,
            "copy_files": copy_files,
            "missing_files": missing,
            "duplicate_paths": duplicates,
        }
    )
    write_json("GENERATED_VENDOR_AUDIT.json", generated)

    tree_audit = load_json("VENDOR_TREE_AUDIT.json")
    tree_audit["counts"] = {
        "P0": tier_counts.get("P0", 0),
        "P1": tier_counts.get("P1", 0),
        "P2": tier_counts.get("P2", 0),
        "total": len(retained_files),
    }
    notes = list(tree_audit.get("notes", []))
    for note in (
        "Android 9 source-owned HAL wrappers and explicit factory/debug executables are pruned on the Android 15 contract branch.",
        "Stock init fragments are retained only when their service executable has an owner; device-owned init.qcom.rc/init.qcom.usb.rc are not duplicated by vendor.",
    ):
        if note not in notes:
            notes.append(note)
    tree_audit["notes"] = notes
    write_json("VENDOR_TREE_AUDIT.json", tree_audit)

    removed_manifest_paths = sorted(path for path in original_by_path if path in remove_paths)
    report = {
        "schema_version": 1,
        "stock_archive_sha256": source_lock["stock_archive_sha256"],
        "before": {
            "selected_files": len(original_files),
            "selected_bytes": sum(int(entry["size"]) for entry in original_files),
        },
        "after": {
            "selected_files": len(retained_files),
            "selected_bytes": selected_bytes,
            "elf_modules": elf_modules,
            "copy_files": copy_files,
        },
        "removed_modules": sorted(removed_modules),
        "removed_manifest_paths": removed_manifest_paths,
        "deleted_payload_paths": deleted,
        "stale_init_candidates": sorted(STALE_INIT_RC),
        "missing_retained_paths": missing,
        "duplicate_retained_paths": duplicates,
    }
    write_json("ANDROID15_PRUNE_REPORT.json", report)

    if missing:
        raise SystemExit(f"retained manifest paths missing from proprietary tree: {missing[:10]}")
    if duplicates:
        raise SystemExit(f"duplicate retained manifest paths: {duplicates}")

    print(
        "android15 pruning complete: "
        f"{len(original_files)} -> {len(retained_files)} files, "
        f"removed {len(removed_manifest_paths)} selected paths, "
        f"{len(removed_modules)} Soong modules"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
