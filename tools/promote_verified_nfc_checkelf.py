#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BP = ROOT / "Android.bp"

NFC_MODULES = {
    "nfc_nci.nqx.default",
    "nfc_nci.nqx.default.hw",
}
PROVEN_SOURCE_DEPENDENCIES = {
    "android.hardware.nfc@1.0",
    "android.hardware.nfc@1.1",
}


def load_json(name: str) -> dict:
    return json.loads((ROOT / name).read_text(encoding="utf-8"))


def write_json(name: str, value: dict) -> None:
    (ROOT / name).write_text(
        json.dumps(value, indent=2) + "\n",
        encoding="utf-8",
    )


def enable_bp_checkelf() -> None:
    lines = BP.read_text(encoding="utf-8").splitlines(keepends=True)
    out: list[str] = []
    found: set[str] = set()
    i = 0

    while i < len(lines):
        if not re.match(
            r"^cc_prebuilt_(?:binary|library_shared)\s*\{\s*$",
            lines[i],
        ):
            out.append(lines[i])
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
        name = match.group(1) if match else None

        if name in NFC_MODULES:
            block = block.replace("    check_elf_files: false,\n", "")
            found.add(name)

        out.append(block)

    missing = NFC_MODULES - found
    if missing:
        raise SystemExit(
            "missing retained NXP NFC modules: "
            + ", ".join(sorted(missing))
        )

    BP.write_text("".join(out), encoding="utf-8")


def update_metadata() -> None:
    exceptions_doc = load_json("ANDROID15_ELF_EXCEPTIONS.json")
    exceptions = exceptions_doc.get("exceptions", {})
    for module in NFC_MODULES:
        exceptions.pop(module, None)
    exceptions_doc["exceptions"] = exceptions
    write_json("ANDROID15_ELF_EXCEPTIONS.json", exceptions_doc)

    audit = load_json("ANDROID15_ELF_AUDIT.json")
    modules = audit.get("modules", {})
    for module in NFC_MODULES:
        record = modules.get(module)
        if record is None:
            raise SystemExit(f"missing retained NXP NFC audit module: {module}")
        record["check_elf_files"] = True
        record["blocking_dependencies"] = []
    exception_count = len(exceptions)
    total = len(modules)
    audit["summary"] = {
        **audit.get("summary", {}),
        "total_modules": total,
        "checkelf_enabled": total - exception_count,
        "checkelf_exceptions": exception_count,
    }
    write_json("ANDROID15_ELF_AUDIT.json", audit)

    lock = load_json("SOURCE_LOCK.json")
    android15 = lock.setdefault("android15_contract", {})
    android15["nfc_legacy_hal_checkelf_verified"] = True
    android15["nfc_legacy_hal_source_dependencies_verified"] = sorted(
        PROVEN_SOURCE_DEPENDENCIES
    )
    android15["checkelf_enabled_modules"] = total - exception_count
    android15["checkelf_exception_modules"] = exception_count
    write_json("SOURCE_LOCK.json", lock)

    generated = load_json("GENERATED_VENDOR_AUDIT.json")
    generated["elf_modules"] = total
    generated["checkelf_enabled"] = total - exception_count
    generated["checkelf_exceptions"] = exception_count
    write_json("GENERATED_VENDOR_AUDIT.json", generated)


def main() -> int:
    enable_bp_checkelf()
    update_metadata()
    print(
        "Promoted verified RED NXP NFC HALs to checkelf: "
        + ", ".join(sorted(NFC_MODULES))
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
