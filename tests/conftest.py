"""Shared test infra.

Every test runs the programs as programs - see launcher.py for the
launcher's harness (its terminal and popups included) and guards.py for the
guards' and sandbox-init's. They're the one binary, under each program's
name, in $SANDBOX_BIN_DIR: the package's bin/ (as the nix check runs them),
else what `make build` leaves in .build/go/bin.
"""

import os
from pathlib import Path

import pytest

BIN_DIR = Path(
    os.environ.get("SANDBOX_BIN_DIR")
    or Path(__file__).resolve().parent.parent / ".build/go/bin"
)


def pytest_report_header():
    return [f"programs from {BIN_DIR}"]


def pytest_sessionstart(session):
    if not (BIN_DIR / "sandbox").exists():
        raise pytest.UsageError(
            f"no sandbox binary in {BIN_DIR}: run `make build` or set $SANDBOX_BIN_DIR"
        )
