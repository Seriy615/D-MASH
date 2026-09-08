#!/usr/bin/env python3
"""Run every repository suite, retaining failures instead of stopping early."""
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main():
    commands = [
        ("Node", ROOT / "D-MASH/client", [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"]),
        ("Origin", ROOT / "origin", [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"]),
    ]
    commands.extend((p.name, ROOT, ["node", str(p)]) for p in sorted(
        (ROOT / "D-MASH PWA/not_messenger/tests").glob("*.test.js")))
    results = []
    for name, cwd, command in commands:
        print(f"\nRunning {name}", flush=True)
        result = subprocess.run(command, cwd=cwd, check=False)
        results.append((name, result.returncode))
    for name, code in results:
        print(f"{'PASS' if code == 0 else 'FAIL'} {name}")
    return int(any(code for _, code in results))


if __name__ == "__main__":
    raise SystemExit(main())
