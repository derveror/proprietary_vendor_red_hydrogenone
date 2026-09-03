#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

MODULE_START_RE = re.compile(r'(?m)^\s*([A-Za-z0-9_]+)\s*\{')
NAME_RE = re.compile(r'(?m)^\s*name\s*:\s*"([^"]+)"\s*,?\s*$')
DEFAULTS_RE = re.compile(r'(?ms)^\s*defaults\s*:\s*\[(.*?)\]\s*,?')
STR_RE = re.compile(r'"([^"]+)"')

SKIP_DIRS = {'.git', '.repo', 'out'}
VENDOR_ONLY_KEYS = ('vendor', 'soc_specific', 'proprietary', 'device_specific', 'odm')
NON_SYSTEM_SPECIFIC_KEYS = ('product_specific', 'system_ext_specific')


def bool_re(key: str) -> re.Pattern[str]:
    return re.compile(
        rf'(?m)^\s*{re.escape(key)}\s*:\s*(true|false)\s*,?\s*$'
    )


def brace_blocks(text: str):
    for match in MODULE_START_RE.finditer(text):
        start = match.start()
        brace = text.find('{', match.start(), match.end())
        depth = 0
        in_string = False
        escape = False
        i = brace
        while i < len(text):
            char = text[i]
            if in_string:
                if escape:
                    escape = False
                elif char == '\\':
                    escape = True
                elif char == '"':
                    in_string = False
            else:
                if char == '"':
                    in_string = True
                elif char == '{':
                    depth += 1
                elif char == '}':
                    depth -= 1
                    if depth == 0:
                        yield match.group(1), text[start:i + 1], start
                        break
            i += 1


def scan_android_bp(
    top: Path,
    vendor_root: Path,
) -> tuple[list[dict], dict[str, list[dict]]]:
    modules: list[dict] = []
    defaults_by_name: dict[str, list[dict]] = defaultdict(list)
    vendor_root = vendor_root.resolve()

    for root, dirs, files in os.walk(top):
        root_path = Path(root)
        dirs[:] = [
            directory
            for directory in dirs
            if directory not in SKIP_DIRS and not directory.startswith('.git')
        ]
        try:
            resolved = root_path.resolve()
        except OSError:
            continue
        if resolved == vendor_root or vendor_root in resolved.parents:
            dirs[:] = []
            continue
        if 'Android.bp' not in files:
            continue

        path = root_path / 'Android.bp'
        try:
            text = path.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue

        for module_type, block, offset in brace_blocks(text):
            name = NAME_RE.search(block)
            if not name:
                continue
            flags = {}
            for key in (
                *VENDOR_ONLY_KEYS,
                *NON_SYSTEM_SPECIFIC_KEYS,
                'vendor_available',
            ):
                match = bool_re(key).search(block)
                flags[key] = None if not match else (match.group(1) == 'true')
            defaults_match = DEFAULTS_RE.search(block)
            defaults = (
                STR_RE.findall(defaults_match.group(1)) if defaults_match else []
            )
            record = {
                'type': module_type,
                'name': name.group(1),
                'path': str(path.relative_to(top)),
                'line': text[:offset + name.start()].count('\n') + 1,
                'flags': flags,
                'defaults': defaults,
            }
            modules.append(record)
            if module_type.endswith('_defaults') or module_type in {
                'cc_defaults',
                'java_defaults',
                'rust_defaults',
                'aidl_interface_defaults',
            }:
                defaults_by_name[record['name']].append(record)

    return modules, defaults_by_name


def parse_vendor_prebuilts(vendor_root: Path) -> list[dict]:
    bp = vendor_root / 'Android.bp'
    text = bp.read_text(encoding='utf-8', errors='replace')
    prebuilts = []
    for module_type, block, offset in brace_blocks(text):
        if module_type not in {
            'cc_prebuilt_library_shared',
            'cc_prebuilt_binary',
        }:
            continue
        name = NAME_RE.search(block)
        if not name:
            continue
        prebuilts.append(
            {
                'name': name.group(1),
                'type': module_type,
                'path': str(bp),
                'line': text[:offset + name.start()].count('\n') + 1,
            }
        )
    return prebuilts


def effective_flags(
    record: dict,
    defaults_by_name: dict[str, list[dict]],
    seen: set[str] | None = None,
) -> dict[str, bool | None]:
    if seen is None:
        seen = set()
    flags = dict(record['flags'])
    for default_name in record.get('defaults', []):
        if default_name in seen:
            continue
        next_seen = set(seen)
        next_seen.add(default_name)
        for default in defaults_by_name.get(default_name, []):
            parent = effective_flags(default, defaults_by_name, next_seen)
            for key, value in parent.items():
                if flags.get(key) is None and value is not None:
                    flags[key] = value
    return flags


def classify_source(
    record: dict,
    defaults_by_name: dict[str, list[dict]],
) -> tuple[str, dict]:
    flags = effective_flags(record, defaults_by_name)
    vendor_only = any(flags.get(key) is True for key in VENDOR_ONLY_KEYS)
    other_partition = any(
        flags.get(key) is True for key in NON_SYSTEM_SPECIFIC_KEYS
    )
    vendor_available = flags.get('vendor_available') is True

    if vendor_only:
        return 'same_vendor_partition', flags
    if vendor_available:
        return 'high_risk_system_plus_vendor', flags
    if other_partition:
        return 'other_partition', flags
    return 'system_only_or_unknown', flags


def audit(top: Path, vendor_root: Path) -> dict:
    top = top.resolve()
    vendor_root = vendor_root.resolve()
    prebuilts = parse_vendor_prebuilts(vendor_root)
    source_modules, defaults_by_name = scan_android_bp(top, vendor_root)

    by_name: dict[str, list[dict]] = defaultdict(list)
    for record in source_modules:
        by_name[record['name']].append(record)

    high_risk = []
    same_name = []
    for prebuilt in prebuilts:
        for source in by_name.get(prebuilt['name'], []):
            if source['type'].endswith('_defaults') or source['type'] in {
                'cc_defaults',
                'java_defaults',
                'rust_defaults',
            }:
                continue
            classification, flags = classify_source(source, defaults_by_name)
            item = {
                'name': prebuilt['name'],
                'prebuilt_type': prebuilt['type'],
                'source_type': source['type'],
                'source_path': source['path'],
                'source_line': source['line'],
                'classification': classification,
                'effective_flags': flags,
                'defaults': source.get('defaults', []),
            }
            same_name.append(item)
            if classification == 'high_risk_system_plus_vendor':
                high_risk.append(item)

    high_risk.sort(
        key=lambda item: (
            item['name'],
            item['source_path'],
            item['source_line'],
        )
    )
    same_name.sort(
        key=lambda item: (
            item['name'],
            item['source_path'],
            item['source_line'],
        )
    )
    return {
        'vendor_prebuilt_count': len(prebuilts),
        'source_module_count': len(source_modules),
        'same_name_count': len(same_name),
        'high_risk_count': len(high_risk),
        'high_risk': high_risk,
        'same_name': same_name,
    }


def main(argv: list[str]) -> int:
    vendor_root = Path(__file__).resolve().parents[1]
    top = (
        Path(argv[1]).resolve()
        if len(argv) > 1
        else vendor_root.parents[2]
    )
    report = audit(top, vendor_root)

    print('===== ANDROID 15 SOURCE/PREBUILT COLLISION AUDIT =====')
    print(f'TOP: {top}')
    print(f'VENDOR TREE: {vendor_root}')
    print(f'VENDOR PREBUILTS: {report["vendor_prebuilt_count"]}')
    print(f'SOURCE MODULES SCANNED: {report["source_module_count"]}')
    print(f'SAME-NAME SOURCE MODULES: {report["same_name_count"]}')
    print(
        'HIGH-RISK SYSTEM+VENDOR COLLISIONS: '
        f'{report["high_risk_count"]}'
    )
    print()
    for item in report['high_risk']:
        print(
            f'HIGH {item["name"]} :: {item["source_type"]} '
            f'{item["source_path"]}:{item["source_line"]} '
            f'defaults={item["defaults"]} '
            f'flags={item["effective_flags"]}'
        )

    print()
    print('===== JSON =====')
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
