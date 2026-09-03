#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"

PIPELINE = (
    "generate_elf_contract.py",
    "resolve_android15_source_collisions.py",
    "prune_qti_camera_interface_duplicate.py",
)


def main() -> int:
    for tool in PIPELINE:
        path = TOOLS / tool
        print(f"===== {tool} =====", flush=True)
        subprocess.run(
            [sys.executable, str(path)],
            cwd=ROOT,
            check=True,
        )
    print("Android 15 vendor contract pipeline completed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
