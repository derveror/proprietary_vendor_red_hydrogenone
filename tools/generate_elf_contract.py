#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BP = ROOT / "Android.bp"

STOCK_SHA256 = "7277a1accf9595bb727f2189863cf5f6249dd99322e2953432bca6e448365f1e"

REQUIRED_RED_PROVIDER_FILES = (
    {
        "tier": "P2",
        "path": "vendor/lib/libsdm-disp-apis.so",
        "size": 38064,
        "sha256": "36d1ce9d762209699cba72a76f24905057d32cabb85b68b39c109c4813e60e1b",
    },
    {
        "tier": "P2",
        "path": "vendor/lib64/libsdm-disp-apis.so",
        "size": 69312,
        "sha256": "849a8b2db319ad03eaebea51acd998b1652866f2a38bfc545351034a919759d2",
    },
)

UNVERIFIED_EXTERNAL_DEPENDENCIES = {
    "android.hardware.configstore-utils",
    "android.hardware.configstore@1.0",
    "android.hardware.graphics.allocator@2.0",
    "android.hardware.graphics.bufferqueue@1.0",
    "android.hardware.graphics.common@1.0",
    "android.hardware.graphics.common@1.1",
    "android.hardware.graphics.mapper@2.0",
    "android.hardware.nfc@1.0",
    "android.hardware.nfc@1.1",
    "android.hardware.wifi.hostapd@1.0",
    "android.hardware.wifi.supplicant@1.0",
    "android.hardware.wifi.supplicant@1.1",
    "android.hidl.token@1.0-utils",
    "android.system.wifi.keystore@1.0",
    "libexif",
    "libjpeg",
    "libspeexresampler",
    "libstagefright_bufferqueue_helper",
    "libstagefright_xmlparser",
    "libtinyxml2",
    "libyuv",
}

SOURCE_VERIFIED_DEPENDENCIES = {
    "libclang_rt.ubsan_standalone",
    "libgnsspps",
    "libminijail",
}

VINTF_FRAGMENT_BY_MODULE = {
    "android.hardware.biometrics.fingerprint@2.1-service": "vintf/fingerprint.xml",
    "android.hardware.bluetooth@1.0-service-qti": "vintf/bluetooth.xml",
    "android.hardware.media.omx@1.0-service": "vintf/media-omx.xml",
    "wifidisplayhalservice": "vintf/wifidisplay.xml",
    "vendor.cm.hardware.thermal3d@1.0-service.cm": "vintf/thermal3d.xml",
    "vendor.leia.hardware.leiadisp@1.0-service": "vintf/leia.xml",
    "vendor.qti.esepowermanager@1.0-service": "vintf/esepowermanager.xml",
    "qcrild": "vintf/radio.xml",
}


def load_json(path: str) -> dict:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def write_json(path: str, data: dict) -> None:
    (ROOT / path).write_text(
        json.dumps(data, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )


def verify_required_red_provider_payload() -> None:
    for entry in REQUIRED_RED_PROVIDER_FILES:
        path = ROOT / "proprietary" / entry["path"]
        if not path.is_file():
            raise SystemExit(f"missing required RED provider: {entry['path']}")
        if path.stat().st_size != entry["size"]:
            raise SystemExit(
                f"size mismatch for {entry['path']}: "
                f"{path.stat().st_size} != {entry['size']}"
            )
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != entry["sha256"]:
            raise SystemExit(f"SHA-256 mismatch for {entry['path']}: {digest}")


def ensure_required_red_provider_metadata() -> None:
    verify_required_red_provider_payload()

    manifest = load_json("proprietary-manifest.json")
    by_path = {entry["path"]: entry for entry in manifest["files"]}
    for required in REQUIRED_RED_PROVIDER_FILES:
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

    proprietary_files = ROOT / "proprietary-files.txt"
    text = proprietary_files.read_text(encoding="utf-8").rstrip()
    selected = {
        raw.strip().split(";", 1)[0].split(":", 1)[0].lstrip("-")
        for raw in text.splitlines()
        if raw.strip() and not raw.strip().startswith("#")
    }
    for required in REQUIRED_RED_PROVIDER_FILES:
        if required["path"] not in selected:
            text += "\n" + required["path"]
    proprietary_files.write_text(text + "\n", encoding="utf-8")

    vendor_mk = ROOT / "hydrogenone-vendor.mk"
    mk = vendor_mk.read_text(encoding="utf-8")
    if not re.search(r"(?m)^\s*libsdm-disp-apis\s*\\?\s*$", mk):
        marker = "    libsdm-disp-vndapis"
        position = mk.find(marker)
        if position < 0:
            raise SystemExit("cannot locate libsdm-disp-vndapis package anchor")
        mk = mk[:position] + "    libsdm-disp-apis \\\n" + mk[position:]
        vendor_mk.write_text(mk, encoding="utf-8")

    selected_bytes = sum(int(entry["size"]) for entry in manifest["files"])

    source_lock = load_json("SOURCE_LOCK.json")
    source_lock["selected_files"] = len(manifest["files"])
    android15 = source_lock.setdefault("android15_contract", {})
    android15["red_leia_display_dependency_recovered"] = True
    write_json("SOURCE_LOCK.json", source_lock)

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

    tree_audit = load_json("VENDOR_TREE_AUDIT.json")
    tree_audit["counts"] = {
        "P0": counts.get("P0", 0),
        "P1": counts.get("P1", 0),
        "P2": counts.get("P2", 0),
        "total": len(manifest["files"]),
    }
    notes = list(tree_audit.get("notes", []))
    note = (
        "RED .118 libsdm-disp-apis.so (32/64) is retained because the "
        "Leia display service DT_NEEDED graph requires it."
    )
    if note not in notes:
        notes.append(note)
    tree_audit["notes"] = notes
    write_json("VENDOR_TREE_AUDIT.json", tree_audit)


def parse_blocks(text: str) -> list[dict]:
    lines = text.splitlines(keepends=True)
    blocks: list[dict] = []
    i = 0
    while i < len(lines):
        match = re.match(
            r"^(cc_prebuilt_(?:binary|library_shared))\s*\{\s*$", lines[i]
        )
        if not match:
            i += 1
            continue
        start = i
        depth = lines[i].count("{") - lines[i].count("}")
        i += 1
        while i < len(lines) and depth > 0:
            depth += lines[i].count("{") - lines[i].count("}")
            i += 1
        block_text = "".join(lines[start:i])
        name = re.search(r'(?m)^\s*name:\s*"([^"]+)"', block_text)
        rel = re.search(r'(?m)^\s*relative_install_path:\s*"([^"]+)"', block_text)
        multilib = re.search(r'(?m)^\s*compile_multilib:\s*"([^"]+)"', block_text)
        arch_srcs: dict[str, list[str]] = {}
        for arch in ("android_arm", "android_arm64"):
            arm = re.search(rf"{arch}:\s*\{{(.*?)\n\s*\}},", block_text, re.S)
            if arm:
                arch_srcs[arch] = re.findall(
                    r'"(proprietary/[^"]+)"', arm.group(1)
                )
        blocks.append(
            {
                "kind": match.group(1),
                "name": name.group(1) if name else None,
                "relative_install_path": rel.group(1) if rel else None,
                "compile_multilib": multilib.group(1) if multilib else None,
                "arch_srcs": arch_srcs,
            }
        )
    return blocks


def ensure_required_provider_module(blocks: list[dict]) -> None:
    names = {block["name"] for block in blocks}

    if "libsdm-disp-apis" not in names:
        blocks.append(
            {
                "kind": "cc_prebuilt_library_shared",
                "name": "libsdm-disp-apis",
                "relative_install_path": None,
                "compile_multilib": "both",
                "arch_srcs": {
                    "android_arm": ["proprietary/vendor/lib/libsdm-disp-apis.so"],
                    "android_arm64": ["proprietary/vendor/lib64/libsdm-disp-apis.so"],
                },
            }
        )
        names.add("libsdm-disp-apis")

    color_srcs = {
        "android_arm": "proprietary/vendor/lib/vendor.display.color@1.0.so",
        "android_arm64": "proprietary/vendor/lib64/vendor.display.color@1.0.so",
    }
    if (
        "vendor.display.color@1.0" not in names
        and all((ROOT / src).is_file() for src in color_srcs.values())
    ):
        blocks.append(
            {
                "kind": "cc_prebuilt_library_shared",
                "name": "vendor.display.color@1.0",
                "relative_install_path": None,
                "compile_multilib": "both",
                "arch_srcs": {
                    arch: [src] for arch, src in color_srcs.items()
                },
            }
        )

    blocks.sort(key=lambda block: block["name"])


def elf_dynamic(path: Path) -> tuple[list[str], str | None]:
    result = subprocess.run(
        ["readelf", "-d", str(path)],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    needed = re.findall(
        r"\(NEEDED\).*Shared library: \[([^\]]+)\]", result.stdout
    )
    soname = re.search(
        r"\(SONAME\).*Library soname: \[([^\]]+)\]", result.stdout
    )
    return needed, soname.group(1) if soname else None


def module_for_soname(soname: str, providers: dict[str, str]) -> str:
    if soname in providers:
        return providers[soname]

    module = soname[:-3] if soname.endswith(".so") else soname
    # Match LineageOS 22.2 extract-utils: legacy stock ELF DT_NEEDED entries
    # name the UBSan runtime by architecture, while Soong exposes one generic
    # module whose per-arch outputs retain those SONAMEs.
    for suffix in ("-arm-android", "-aarch64-android"):
        if module == f"libclang_rt.ubsan_standalone{suffix}":
            return "libclang_rt.ubsan_standalone"
    return module


def render_list(name: str, values: list[str], indent: int = 12) -> list[str]:
    pad = " " * indent
    output = [f"{pad}{name}: ["]
    output.extend(f'{pad}    "{value}",' for value in values)
    output.append(f"{pad}],")
    return output


def render_block(block: dict, providers: dict[str, str], exceptions: dict, audit: dict) -> str:
    arch_info: dict[str, dict] = {}
    blocking: set[str] = set()
    for arch, srcs in block["arch_srcs"].items():
        shared: set[str] = set()
        needed_evidence: dict[str, list[str]] = {}
        for src in srcs:
            path = ROOT / src
            needed, _ = elf_dynamic(path)
            mapped = [module_for_soname(name, providers) for name in needed]
            shared.update(mapped)
            needed_evidence[src] = mapped
            for dep in mapped:
                if (
                    dep in UNVERIFIED_EXTERNAL_DEPENDENCIES
                    and dep not in providers.values()
                    and dep not in SOURCE_VERIFIED_DEPENDENCIES
                ):
                    blocking.add(dep)
        arch_info[arch] = {
            "srcs": srcs,
            "shared_libs": sorted(shared),
            "needed": needed_evidence,
        }

    is_exception = bool(blocking)
    if is_exception:
        exceptions[block["name"]] = {
            "reason": (
                "DT_NEEDED includes provider modules not yet proven vendor-compatible "
                "in the pinned LineageOS 22.2 product graph; defer checkelf until the clean build gate."
            ),
            "blocking_dependencies": sorted(blocking),
            "evidence": [
                f"{src}: DT_NEEDED -> {', '.join(deps)}"
                for info in arch_info.values()
                for src, deps in info["needed"].items()
            ],
        }

    audit["modules"][block["name"]] = {
        "kind": block["kind"],
        "check_elf_files": not is_exception,
        "blocking_dependencies": sorted(blocking),
        "architectures": arch_info,
    }

    out = [
        f'{block["kind"]} {{',
        f'    name: "{block["name"]}",',
        '    owner: "red",',
        "    strip: {",
        "        none: true,",
        "    },",
    ]
    if is_exception:
        out.append("    check_elf_files: false,")
    fragment = VINTF_FRAGMENT_BY_MODULE.get(block["name"])
    if fragment:
        out.append("    vintf_fragments: [")
        out.append(f'        "{fragment}",')
        out.append("    ],")
    out.append("    target: {")
    for arch in ("android_arm", "android_arm64"):
        if arch not in arch_info:
            continue
        out.append(f"        {arch}: {{")
        out.extend(render_list("srcs", arch_info[arch]["srcs"], 12))
        if arch_info[arch]["shared_libs"]:
            out.extend(render_list("shared_libs", arch_info[arch]["shared_libs"], 12))
        out.append("        },")
    out.append("    },")
    out.append(f'    compile_multilib: "{block["compile_multilib"]}",')
    out.append("    prefer: true,")
    if block["relative_install_path"]:
        out.append(f'    relative_install_path: "{block["relative_install_path"]}",')
    out.append("    soc_specific: true,")
    out.append("}")
    return "\n".join(out)


def update_audit_metadata(total_modules: int, exception_count: int) -> None:
    generated = load_json("GENERATED_VENDOR_AUDIT.json")
    generated["elf_modules"] = total_modules
    generated["checkelf_enabled"] = total_modules - exception_count
    generated["checkelf_exceptions"] = exception_count
    write_json("GENERATED_VENDOR_AUDIT.json", generated)

    source_lock = load_json("SOURCE_LOCK.json")
    android15 = source_lock.setdefault("android15_contract", {})
    android15["elf_dependency_graph_generated_from_dt_needed"] = True
    android15["checkelf_enabled_modules"] = total_modules - exception_count
    android15["checkelf_exception_modules"] = exception_count
    write_json("SOURCE_LOCK.json", source_lock)

    tree_audit = load_json("VENDOR_TREE_AUDIT.json")
    notes = list(tree_audit.get("notes", []))
    for note in (
        "Android.bp shared_libs are generated from the retained .118 ELF DT_NEEDED graph.",
        f"{total_modules - exception_count} of {total_modules} proprietary ELF modules have check_elf_files enabled; the remaining {exception_count} are explicit dependency-mapping exceptions tracked in ANDROID15_ELF_EXCEPTIONS.json.",
    ):
        if note not in notes:
            notes.append(note)
    tree_audit["notes"] = notes
    write_json("VENDOR_TREE_AUDIT.json", tree_audit)


def main() -> int:
    ensure_required_red_provider_metadata()
    blocks = parse_blocks(BP.read_text(encoding="utf-8"))
    ensure_required_provider_module(blocks)

    providers: dict[str, str] = {}
    for block in blocks:
        if block["kind"] != "cc_prebuilt_library_shared":
            continue
        for srcs in block["arch_srcs"].values():
            for src in srcs:
                path = ROOT / src
                _, soname = elf_dynamic(path)
                for key in (soname, path.name):
                    if not key:
                        continue
                    existing = providers.get(key)
                    if existing and existing != block["name"]:
                        raise SystemExit(
                            f"ambiguous ELF provider for {key}: {existing}, {block['name']}"
                        )
                    providers[key] = block["name"]

    exceptions: dict[str, dict] = {}
    audit = {"schema_version": 1, "stock_archive_sha256": STOCK_SHA256, "modules": {}}
    rendered = [render_block(block, providers, exceptions, audit) for block in blocks]

    BP.write_text(
        "// Automatically generated from verified RED .118 proprietary ELF payload.\n"
        "// shared_libs are derived from readelf DT_NEEDED; unresolved provider mappings remain explicit exceptions.\n\n"
        + "\n\n".join(rendered)
        + "\n",
        encoding="utf-8",
    )

    write_json(
        "ANDROID15_ELF_EXCEPTIONS.json",
        {
            "schema_version": 1,
            "policy": (
                "check_elf_files is disabled only when at least one DT_NEEDED provider has not yet been proven vendor-compatible in the pinned LineageOS 22.2 product graph."
            ),
            "exceptions": exceptions,
        },
    )

    audit["summary"] = {
        "total_modules": len(blocks),
        "checkelf_enabled": len(blocks) - len(exceptions),
        "checkelf_exceptions": len(exceptions),
        "provider_sonames": len(providers),
    }
    write_json("ANDROID15_ELF_AUDIT.json", audit)
    update_audit_metadata(len(blocks), len(exceptions))

    print(
        f"ELF contract generated: {len(blocks)} modules, "
        f"{len(blocks) - len(exceptions)} checkelf enabled, "
        f"{len(exceptions)} explicit exceptions"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
