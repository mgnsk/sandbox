"""Shared test infra.

Every test runs the programs in src/ as programs - see launcher.py for the
launcher's harness (its terminal and popups included) and guards.py for the
guards' and sandbox-init's - so another implementation can be put in their
place. Nothing here imports them.
"""

import os
import shlex
from pathlib import Path

BIN_DIR = Path(__file__).resolve().parent.parent / "src"


def pytest_report_header():
    """Which implementation runs: with $SANDBOX_GUARD_CMD, the programs it
    has (see guards.guard_argv); the rest are src/'s."""
    lines = [
        f"{var}={os.environ[var]}"
        for var in ("SANDBOX_LAUNCHER", "SANDBOX_GUARD_CMD")
        if os.environ.get(var)
    ]
    cmd = os.environ.get("SANDBOX_GUARD_CMD")
    if cmd:
        names = sorted(
            p.name
            for p in BIN_DIR.iterdir()
            if p.is_file()
            and p.suffix != ".py"
            and os.path.exists(shlex.split(cmd.format(name=p.name))[0])
        )
        lines.append(f"$SANDBOX_GUARD_CMD runs: {', '.join(names) or 'nothing'}")
    return lines
