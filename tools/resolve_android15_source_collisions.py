#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BP = ROOT / "Android.bp"

SOURCE_OWNED = (
    {
        "tier": "P1",
        "path": "vendor/lib/android.hidl.base@1.0.so",
        "module": "android.hidl.base@1.0",
        "size": 62416,
        "sha256": "215d9cebf8d33286876bbe7243e2f86f99074a99a522c9c9b74244dd351bb43a",
    },
    {
        "tier": "P1",
        "path": "vendor/lib/libalsautils.so",
        "module": "libalsautils",
        "size": 19336,
        "sha256": "e032216be21df4d9719cc6d73f8272f95e8686cd74a172bc6314642d13a2e06c",
    },
    {
        "tier": "P1",
        "path": "vendor/lib64/libalsautils.so",
        "module": "libalsautils",
        "size": 68256,
        "sha256": "abd7a6c75cef012e09962ec09796344dc3d0dfe19d0e00cf6be193f8a5921166",
    },
)
SOURCE_MODULES = {entry["module"] for entry in SOURCE_OWNED}

LEGACY_VNDK = {
    "libstagefright_foundation": {
        "module": "libstagefright_foundation-v28",
        "stem": "libstagefright_foundation",
        "src": "proprietary/vendor/lib/vndk/libstagefright_foundation.so",
    },
    "libstagefright_omx": {
        "module": "libstagefright_omx-v28",
        "stem": "libstagefright_omx",
        "src": "proprietary/vendor/lib/vndk/libstagefright_omx.so",
    },
}


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


def verify_and_prune_source_payload() -> dict:
    manifest = load_json("proprietary-manifest.json")
    by_path = {entry["path"]: entry for entry in manifest["files"]}
    pruned = {entry["path"] for entry in SOURCE_OWNED}

    for expected in SOURCE_OWNED:
        metadata = {key: expected[key] for key in ("tier", "path", "size", "sha256")}
        current = by_path.get(expected["path"])
        if current is not None and current != metadata:
            raise SystemExit(f"manifest identity mismatch for {expected['path']}: {current}")

        payload = ROOT / "proprietary" / expected["path"]
        if payload.is_file():
            if payload.stat().st_size != expected["size"]:
                raise SystemExit(f"size mismatch for {expected['path']}")
            digest = hashlib.sha256(payload.read_bytes()).hexdigest()
            if digest != expected["sha256"]:
                raise SystemExit(f"SHA-256 mismatch for {expected['path']}: {digest}")
            payload.unlink()

    manifest["files"] = [entry for entry in manifest["files"] if entry["path"] not in pruned]
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
    lines = [raw for raw in lines if selected_path(raw) not in pruned]
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return manifest


def parse_prebuilt_blocks(text: str) -> list[tuple[int, int, str, str]]:
    lines = text.splitlines(keepends=True)
    blocks: list[tuple[int, int, str, str]] = []
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
        if not match:
            raise SystemExit("prebuilt block without name")
        blocks.append((start, i, match.group(1), block))
    return blocks


def add_or_replace_stem(block: str, stem: str) -> str:
    if re.search(r'(?m)^\s*stem:\s*"[^"]+"', block):
        return re.sub(r'(?m)^(\s*)stem:\s*"[^"]+"', rf'\1stem: "{stem}"', block, count=1)
    marker = re.search(r'(?m)^(\s*)compile_multilib:\s*"[^"]+",\s*$', block)
    if not marker:
        raise SystemExit(f"cannot add stem for {stem}: compile_multilib missing")
    insertion = marker.group(0) + f'\n{marker.group(1)}stem: "{stem}",'
    return block[:marker.start()] + insertion + block[marker.end():]


def rewrite_android_bp() -> None:
    text = BP.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    blocks = parse_prebuilt_blocks(text)
    replacements: list[tuple[int, int, str]] = []

    by_name = {name: (start, end, block) for start, end, name, block in blocks}
    for module in SOURCE_MODULES:
        item = by_name.get(module)
        if item:
            replacements.append((item[0], item[1], ""))

    for original, spec in LEGACY_VNDK.items():
        item = by_name.get(original) or by_name.get(spec["module"])
        if item is None:
            raise SystemExit(f"missing RED API28 VNDK module {original}")
        start, end, block = item
        if spec["src"] not in block:
            raise SystemExit(f"unexpected RED API28 VNDK source for {original}")
        block = re.sub(
            r'(?m)^(\s*)name:\s*"(?:' + re.escape(original) + '|' + re.escape(spec["module"]) + r')",',
            rf'\1name: "{spec["module"]}",',
            block,
            count=1,
        )
        block = add_or_replace_stem(block, spec["stem"])
        replacements.append((start, end, block))

    for start, end, replacement in sorted(replacements, reverse=True):
        lines[start:end] = [replacement + ("\n" if replacement and not replacement.endswith("\n") else "")]

    out = "".join(lines)
    for original, spec in LEGACY_VNDK.items():
        out = re.sub(
            rf'(?m)^(\s*)"{re.escape(original)}",(\s*)$',
            rf'\1"{spec["module"]}",\2',
            out,
        )
    out = re.sub(r"\n{3,}", "\n\n", out).rstrip() + "\n"
    BP.write_text(out, encoding="utf-8")


def update_vendor_mk() -> None:
    path = ROOT / "hydrogenone-vendor.mk"
    text = path.read_text(encoding="utf-8")
    for module in SOURCE_MODULES:
        text = re.sub(rf"(?m)^\s*{re.escape(module)}\s*\\\s*\n", "", text)
    for original, spec in LEGACY_VNDK.items():
        text = re.sub(
            rf"(?m)^(\s*){re.escape(original)}(\s*\\\s*)$",
            rf"\1{spec['module']}\2",
            text,
        )
        if not re.search(rf"(?m)^\s*{re.escape(spec['module'])}\s*\\?\s*$", text):
            raise SystemExit(f"missing PRODUCT_PACKAGES owner for {spec['module']}")
    path.write_text(text, encoding="utf-8")


def rewrite_value(value):
    if isinstance(value, str):
        for original, spec in LEGACY_VNDK.items():
            value = re.sub(
                re.escape(original) + r"(?!-v28)",
                spec["module"],
                value,
            )
        return value
    if isinstance(value, list):
        return [rewrite_value(item) for item in value]
    if isinstance(value, dict):
        return {key: rewrite_value(item) for key, item in value.items()}
    return value


def update_elf_metadata() -> tuple[int, int]:
    exceptions_doc = load_json("ANDROID15_ELF_EXCEPTIONS.json")
    exceptions = exceptions_doc.get("exceptions", {})
    for module in SOURCE_MODULES:
        exceptions.pop(module, None)
    for original, spec in LEGACY_VNDK.items():
        if original in exceptions:
            exceptions[spec["module"]] = exceptions.pop(original)
    exceptions_doc["exceptions"] = rewrite_value(exceptions)
    write_json("ANDROID15_ELF_EXCEPTIONS.json", exceptions_doc)

    audit = load_json("ANDROID15_ELF_AUDIT.json")
    modules = audit.get("modules", {})
    for module in SOURCE_MODULES:
        modules.pop(module, None)
    for original, spec in LEGACY_VNDK.items():
        if original in modules:
            modules[spec["module"]] = modules.pop(original)
    audit["modules"] = rewrite_value(modules)
    total = len(audit["modules"])
    exception_count = len(exceptions_doc["exceptions"])
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
    android15["source_owned_hidl_base_pruned"] = True
    android15["source_owned_alsautils_pruned"] = True
    android15["legacy_vndk28_stagefright_namespaced"] = True
    android15["checkelf_enabled_modules"] = modules - exceptions
    android15["checkelf_exception_modules"] = exceptions
    write_json("SOURCE_LOCK.json", lock)

    tree = load_json("VENDOR_TREE_AUDIT.json")
    tree["counts"] = counts
    notes = list(tree.get("notes", []))
    for note in (
        "LineageOS 22.2 supplies android.hidl.base@1.0 from hardware/lineage/compat and libalsautils as a vendor_available source module; duplicate RED .118 prebuilts are pruned.",
        "RED .118 API28 libstagefright_foundation/libstagefright_omx remain in /vendor/lib/vndk with their stock SONAMEs, but use unique -v28 Soong module names to avoid Android 15 source-module shadowing.",
    ):
        if note not in notes:
            notes.append(note)
    tree["notes"] = notes
    write_json("VENDOR_TREE_AUDIT.json", tree)


def main() -> int:
    manifest = verify_and_prune_source_payload()
    rewrite_android_bp()
    update_vendor_mk()
    modules, exceptions = update_elf_metadata()
    update_project_metadata(manifest, modules, exceptions)
    print(
        "Resolved Android 15 source/prebuilt collisions: "
        f"total={manifest['counts']['total']}, modules={modules}, "
        f"checkelf={modules - exceptions}, exceptions={exceptions}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
