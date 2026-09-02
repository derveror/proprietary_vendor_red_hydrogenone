from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INIT_ROOT = ROOT / "proprietary/vendor/etc/init"

# Executables supplied by Android/LineageOS rather than this proprietary tree.
SOURCE_OR_PLATFORM_EXECUTABLES = {
    "/system/bin/sh",
    "/vendor/bin/sh",
    "/system/bin/logwrapper",
    "/system/bin/toybox",
}

SERVICE_RE = re.compile(r"(?m)^\s*service\s+(\S+)\s+(\S+)")


def vendor_path_for_executable(executable: str) -> Path | None:
    if executable.startswith("/vendor/"):
        return ROOT / "proprietary" / executable.lstrip("/")
    return None


class InitContractTest(unittest.TestCase):
    def test_retained_vendor_services_have_executable_owners(self) -> None:
        unresolved: list[str] = []
        for rc in sorted(INIT_ROOT.rglob("*.rc")):
            text = rc.read_text(encoding="utf-8", errors="replace")
            for match in SERVICE_RE.finditer(text):
                service, executable = match.groups()
                if executable in SOURCE_OR_PLATFORM_EXECUTABLES:
                    continue
                vendor_path = vendor_path_for_executable(executable)
                if vendor_path is None:
                    # /system and other partition executables are not owned by this vendor tree.
                    continue
                if not (vendor_path.exists() or vendor_path.is_symlink()):
                    unresolved.append(f"{rc.relative_to(ROOT)}: {service} -> {executable}")
        self.assertEqual(unresolved, [], "retained rc references missing vendor executables:\n" + "\n".join(unresolved))

    def test_no_factory_init_fragment_is_retained(self) -> None:
        factory = INIT_ROOT / "hw/init.qcom.factory.rc"
        self.assertFalse(factory.exists(), "factory-only init.qcom.factory.rc must not ship in Android 15 vendor")


if __name__ == "__main__":
    unittest.main()
