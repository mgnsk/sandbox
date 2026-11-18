"""Shared test infra.

Every test runs the programs in src/ as programs - see launcher.py for the
launcher's harness (its terminal and popups included) and guards.py for the
guards' and sandbox-init's - so another implementation can be put in their
place. Nothing here imports them.
"""

from pathlib import Path

BIN_DIR = Path(__file__).resolve().parent.parent / "src"
