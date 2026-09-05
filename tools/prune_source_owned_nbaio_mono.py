#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BP = ROOT / "Android.bp"
MODULE = "libnbaio_mono"
SOURCE_OWNED = (
    {
        "tier": "P1",
        "path": "vendor/lib/libnbaio_mono.so",
        "module": MODULE,
        "size": 15256,
        "sha256": "077f22cf0d830196186a3549fe3108f8a4f5c9b8954e69a5993ce302b1943c49",
    },
    {
        "tier": "P1",
        "path": "vendor/lib64/libnbaio_mono.so",
        "module": MODULE,
        "size": 37424,
        "sha256": "4e95ffa4f61239ebe3ff67615072265c360258d35f72a203b18765ef85f38d9c",
    },
)
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


def module_shared_libs(record: dict) -> set[str]:
    result: set[str] = set()
    for arch in record.get("architectures", {}).values():
        result.update(arch.get("shared_libs", []))
    return result


def assert_no_proprietary_consumers() -> None:
    audit = load_json("ANDROID15_ELF_AUDIT.json")
    violations = []
    for name, record in audit.get("modules", {}).items():
        if name == MODULE:
            continue
        if MODULE in module_shared_libs(record):
            violations.append(name)
    if violations:
        raise SystemExit(
            "cannot prune source-owned libnbaio_mono; retained proprietary consumers: "
            + ", ".join(sorted(violations))
        )


def prune_payload() -> dict:
    manifest = load_json("proprietary-manifest.json")
    by_path = {entry["path"]: entry for entry in manifest["files"]}

    for expected in SOURCE_OWNED:
        current = by_path.get(expected["path"])
        metadata = {key: expected[key] for key in ("tier", "path", "size", "sha256")}
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


def prune_prebuilt_module() -> None:
    text = BP.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    removals = [
        (start, end)
        for start, end, name in prebuilt_blocks(text)
        if name == MODULE
    ]
    for start, end in sorted(removals, reverse=True):
        lines[start:end] = []
    BP.write_text(
        re.sub(r"\n{3,}", "\n\n", "".join(lines)).rstrip() + "\n",
        encoding="utf-8",
    )


def update_vendor_packages() -> None:
    path = ROOT / "hydrogenone-vendor.mk"
    text = path.read_text(encoding="utf-8")
    text = re.sub(rf"(?m)^\s*{re.escape(MODULE)}\s*\\?\s*\n", "", text)
    path.write_text(text, encoding="utf-8")


def update_elf_metadata() -> tuple[int, int]:
    exceptions_doc = load_json("ANDROID15_ELF_EXCEPTIONS.json")
    exceptions = exceptions_doc.get("exceptions", {})
    exceptions.pop(MODULE, None)
    exceptions_doc["exceptions"] = exceptions
    write_json("ANDROID15_ELF_EXCEPTIONS.json", exceptions_doc)

    audit = load_json("ANDROID15_ELF_AUDIT.json")
    modules = audit.get("modules", {})
    modules.pop(MODULE, None)
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
    android15["source_owned_nbaio_mono_pruned"] = True
    android15["source_owned_nbaio_mono_paths"] = sorted(SOURCE_PATHS)
    android15["checkelf_enabled_modules"] = modules - exceptions
    android15["checkelf_exception_modules"] = exceptions
    write_json("SOURCE_LOCK.json", lock)

    tree = load_json("VENDOR_TREE_AUDIT.json")
    tree["counts"] = counts
    notes = list(tree.get("notes", []))
    note = (
        "RED .118 libnbaio_mono is pruned in favor of the LineageOS 22.2 "
        "source vendor library: the stock Android 9 blob has no retained proprietary "
        "DT_NEEDED consumers and shadows the source module needed by audio.r_submix.default."
    )
    if note not in notes:
        notes.append(note)
    tree["notes"] = notes
    write_json("VENDOR_TREE_AUDIT.json", tree)


def main() -> int:
    assert_no_proprietary_consumers()
    manifest = prune_payload()
    prune_prebuilt_module()
    update_vendor_packages()
    modules, exceptions = update_elf_metadata()
    update_project_metadata(manifest, modules, exceptions)
    print(
        "Pruned source-owned RED libnbaio_mono: "
        f"total={manifest['counts']['total']}, modules={modules}, "
        f"checkelf={modules - exceptions}, exceptions={exceptions}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
