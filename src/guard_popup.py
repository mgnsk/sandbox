"""The guards' side of the approval popup the launcher shows.

The launcher (`sandbox`, see popup_relay) owns the terminal the sandbox runs
on and listens on a socket only the guards know: $SANDBOX_POPUP_SOCKET, in a
private temp dir that's never bound in. A guard sends the text to show and
gets the user's answer back.

Each guard runs on the host, one process per sandbox, for as long as that
sandbox does. So an Approvals held in a guard's memory is what "always in this
sandbox" means: nothing is written down, and the next sandbox asks again.
"""

import json
import os
import socket
import threading

ENV = "SANDBOX_POPUP_SOCKET"


def ask(name, text):
    """Show text in a popup and block for the answer: "once", "always", or
    None for no / no terminal to ask on / any failure.

    The text is only ever drawn by the launcher, never run: it's sent as
    data over the socket, and the launcher replaces anything non-printable.
    """
    path = os.environ.get(ENV)
    if not path:
        return None
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(path)
            sock.sendall(json.dumps({"name": name, "text": text}).encode())
            sock.shutdown(socket.SHUT_WR)
            answer = b""
            while chunk := sock.recv(64):
                answer += chunk
                if len(answer) > 64:
                    return None
    except OSError:
        return None
    answer = answer.decode("ascii", "replace")
    return answer if answer in ("once", "always") else None


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
