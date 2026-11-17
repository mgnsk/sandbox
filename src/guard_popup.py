"""The tmux popup the sandbox's guards ask for approval in.

Each guard runs on the host, one process per sandbox, for as long as that
sandbox does. So an Approvals held in a guard's memory is what "always in this
sandbox" means: nothing is written down, and the next sandbox asks again.
"""

import os
import shlex
import subprocess
import tempfile
import threading
import uuid

PROMPT = "y = once, A = always in this sandbox, N = no "


def ask(name, text, show_cmd, width, height=None):
    """Show text in a popup and block for the answer: "once", "always", or
    None for no / no tmux / popup failure.

    show_cmd is the shell command displaying the text, with {} for its file.
    The text itself is only ever in that file, never interpolated into the
    popup's shell command: that command runs on the host, outside the sandbox,
    so request-derived text must never be treated as shell syntax there.
    """
    if "TMUX" not in os.environ:
        return None

    channel = f"{name}-{uuid.uuid4().hex}"
    marker = info_path = None
    try:
        marker_fd, marker = tempfile.mkstemp(prefix=f"{name}-marker-")
        os.close(marker_fd)
        info_fd, info_path = tempfile.mkstemp(prefix=f"{name}-info-")
        with os.fdopen(info_fd, "w", encoding="utf-8") as f:
            f.write(text)

        popup_cmd = (
            f"{show_cmd.format(shlex.quote(info_path))}; "
            f'read -p "{PROMPT}" a; '
            f'case "$a" in [yY]) echo once > {shlex.quote(marker)};; '
            f"[aA]) echo always > {shlex.quote(marker)};; esac; "
            f"tmux wait-for -S {channel}"
        )
        size = ["-w", str(width)] + (["-h", str(height)] if height else [])
        with subprocess.Popen(["tmux", "display-popup", "-E", *size, popup_cmd]) as popup:

            def watch_popup():
                # A popup that fails to launch (e.g. no attached client) never
                # runs popup_cmd, so nothing else would signal the channel.
                if popup.wait() != 0:
                    subprocess.run(["tmux", "wait-for", "-S", channel], check=False)

            threading.Thread(target=watch_popup, daemon=True).start()
            subprocess.run(["tmux", "wait-for", channel], check=False)
        with open(marker, encoding="utf-8") as f:
            answer = f.read().strip()
        return answer if answer in ("once", "always") else None
    finally:
        if marker:
            os.unlink(marker)
        if info_path:
            os.unlink(info_path)


class Approvals:
    """One guard's approvals for the life of its process."""

    def __init__(self):
        self._always = False
        self._lock = threading.Lock()

    def approve(self, ask_user):
        """Whether to let a request through, calling ask_user for its answer
        unless the user has already answered "always".

        The lock is held across the popup: one at a time, and requests queued
        behind an "always" answer see it instead of popping up themselves.
        """
        with self._lock:
            if self._always:
                return True
            answer = ask_user()
            if answer == "always":
                self._always = True
            return answer in ("once", "always")
