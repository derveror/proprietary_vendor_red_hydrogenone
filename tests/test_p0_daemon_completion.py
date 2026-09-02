from __future__ import annotations

import hashlib
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED = {
    "vendor/bin/spdaemon": {
        "size": 68656,
        "sha256": "a157a177f899ad1783945b88fbe3cb2ddae35ea480d8595b5ddcac91ea16886d",
        "module": "spdaemon",
    },
    "vendor/lib64/libspcom.so": {
        "size": 68464,
        "sha256": "3f9e7b0ecd2ffd999ef58077a15fffa780754dd0f4fb0ae2d8eb49adbe924c4c",
        "module": "libspcom",
    },
    "vendor/bin/hvdcp_opti": {
        "size": 202720,
        "sha256": "4d1d5a97f2da8840912ffdb8351a20b278905ebd4f471cfdee81c4052cc80a03",
        "module": "hvdcp_opti",
    },
    "vendor/bin/energy-awareness": {
        "size": 70120,
        "sha256": "2b1ae7f5ef59b9a7518b3eabd4823eac5cce51330069f75bd120bcfc30767158",
        "module": "energy-awareness",
    },
}


def selected_paths() -> set[str]:
    result: set[str] = set()
    for raw in (ROOT / "proprietary-files.txt").read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        body = line.split(";", 1)[0]
        result.add(body.split(":", 1)[0].lstrip("-"))
    return result


def bp_modules() -> set[str]:
    text = (ROOT / "Android.bp").read_text(encoding="utf-8")
    return set(re.findall(r'(?m)^\s*name:\s*"([^"]+)"\s*,?$', text))


class P0DaemonCompletionTest(unittest.TestCase):
    def test_required_red_stock_payload_exists_with_exact_identity(self) -> None:
        failures: list[str] = []
        for relative, expected in REQUIRED.items():
            path = ROOT / "proprietary" / relative
            if not path.is_file():
                failures.append(f"missing {relative}")
                continue
            data = path.read_bytes()
            actual_hash = hashlib.sha256(data).hexdigest()
            if len(data) != expected["size"]:
                failures.append(f"{relative}: size {len(data)} != {expected['size']}")
            if actual_hash != expected["sha256"]:
                failures.append(f"{relative}: sha256 {actual_hash} != {expected['sha256']}")
        self.assertEqual(failures, [], "RED .118 daemon payload mismatch:\n" + "\n".join(failures))

    def test_required_payload_is_selected_and_declared_as_modules(self) -> None:
        selected = selected_paths()
        modules = bp_modules()
        missing_paths = sorted(set(REQUIRED) - selected)
        missing_modules = sorted({item["module"] for item in REQUIRED.values()} - modules)
        self.assertEqual(missing_paths, [], f"required P0 paths not selected: {missing_paths}")
        self.assertEqual(missing_modules, [], f"required P0 modules not declared: {missing_modules}")

    def test_spdaemon_dependency_provider_is_retained(self) -> None:
        text = (ROOT / "Android.bp").read_text(encoding="utf-8")
        match = re.search(
            r'cc_prebuilt_binary\s*\{(?:(?!\n\}).)*?name:\s*"spdaemon"(?:(?!\n\}).)*?\n\}',
            text,
            re.S,
        )
        self.assertIsNotNone(match, "spdaemon module missing")
        self.assertIn('"libspcom"', match.group(0), "spdaemon must declare libspcom from RED .118")

    def test_added_payload_is_not_hidden_behind_checkelf_disable_without_registry(self) -> None:
        text = (ROOT / "ANDROID15_ELF_EXCEPTIONS.json").read_text(encoding="utf-8")
        for module in ("spdaemon", "libspcom", "hvdcp_opti", "energy-awareness"):
            if f'"{module}"' in text:
                self.fail(f"{module} unexpectedly entered the checkelf exception registry")


if __name__ == "__main__":
    unittest.main()
