#!/usr/bin/env python3
"""Dependency-light smoke checks for the frozen D-MASH prototype."""

from __future__ import annotations

import ast
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PYTHON_ROOT = ROOT / "D-MASH" / "client"
PWA_ROOT = ROOT / "D-MASH PWA" / "not_messenger"

REQUIRED_FILES = (
    PYTHON_ROOT / "backend" / "main.py",
    PYTHON_ROOT / "backend" / "network.py",
    PYTHON_ROOT / "backend" / "dsp.py",
    PWA_ROOT / "index.html",
    PWA_ROOT / "manifest.json",
    PWA_ROOT / "sw.js",
    PWA_ROOT / "js" / "core_engine.js",
    PWA_ROOT / "js" / "storage.js",
    PWA_ROOT / "js" / "ui_logic.js",
)


def run(command: list[str]) -> None:
    result = subprocess.run(command, cwd=ROOT, check=False)
    if result.returncode:
        raise SystemExit(result.returncode)


def main() -> int:
    missing = [str(path.relative_to(ROOT)) for path in REQUIRED_FILES if not path.is_file()]
    if missing:
        print("FAIL required files missing: " + ", ".join(missing), file=sys.stderr)
        return 1
    print("PASS required prototype files")

    python_files = sorted((PYTHON_ROOT / "backend").glob("*.py"))
    python_files.append(PYTHON_ROOT.parent / "stress_test.py")
    try:
        for path in python_files:
            ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, SyntaxError) as error:
        print(f"FAIL Python syntax: {error}", file=sys.stderr)
        return 1
    print("PASS Python syntax")

    node = shutil.which("node")
    if node:
        for relative in ("sw.js", "js/core_engine.js", "js/storage.js", "js/ui_logic.js"):
            run([node, "--check", str(PWA_ROOT / relative)])
        print("PASS JavaScript syntax")
    else:
        print("SKIP JavaScript syntax (node not installed)")

    php = shutil.which("php")
    if php:
        for relative in ("api/pidorskiy_api.php", "api/tg_webhook.php"):
            run([php, "-l", str(ROOT / "D-MASH PWA" / relative)])
        print("PASS PHP syntax")
    else:
        print("SKIP PHP syntax (php not installed)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
