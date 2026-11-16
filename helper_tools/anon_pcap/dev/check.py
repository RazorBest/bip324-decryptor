"""Run all checks in one shot.

Usage:

    uv run dev/check.py          # check only -- same as CI
    uv run dev/check.py --fix    # auto-fix what black/ruff can, then check

You can also you something else than uv. You just need to make sure you have
the tools installed with the right versions (pyproject.toml).
"""

import subprocess
import sys

CHECK_CMDS = [
    ["black", "--check", "--diff", "."],
    ["ruff", "check", "."],
    ["mypy", "."],
]

FIX_CMDS = [
    ["black", "."],
    ["ruff", "check", "--fix", "."],
]


def run(cmd: list[str]) -> int:
    print(f"\n\033[1m→ {' '.join(cmd)}\033[0m")
    return subprocess.run(cmd).returncode


def main() -> int:
    if "--fix" in sys.argv:
        for cmd in FIX_CMDS:
            run(cmd)
        print("\nRe-checking after fixes...")

    for cmd in CHECK_CMDS:
        if run(cmd) != 0:
            print(f"\n\033[31m✗ Failed: {' '.join(cmd)}\033[0m", file=sys.stderr)
            return 1

    print("\n\033[32m✓ All checks passed\033[0m")
    return 0


if __name__ == "__main__":
    sys.exit(main())
