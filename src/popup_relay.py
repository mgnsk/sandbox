"""The launcher's terminal: the sandbox runs behind a pty of its own, and the
guards' approval popups are drawn on the real terminal in between.

Only the launcher holds the real terminal. The sandbox gets the slave side
of a fresh pty, and the launcher copies bytes both ways - except while a
popup is up: then keys go to the popup alone and the sandbox's output is
held back. So nothing in the sandbox can type into a popup, draw over it or
read what's typed there, and it works wherever a terminal does (over ssh
too), with nothing to install.

A popup takes over the whole screen. When the sandbox is on the main screen
it's drawn on the alternate one, and switching back restores the sandbox's
screen as it was. When the sandbox is on the alternate screen itself (vim,
less, ...), it's drawn there, and afterwards the pty is resized away and
back, which has a full-screen program redraw.

Guards ask over a unix socket in a private temp dir (see guard_popup): a
JSON {"name", "text"} request, answered with "once", "always" or "no".
Requests are shown one at a time, in order. Without a usable terminal there
is no socket, and guard_popup.ask answers no.
"""

import collections
import fcntl
import json
import os
import re
import selectors
import signal
import socket
import struct
import subprocess
import termios
import time
import tty
import unicodedata

PROMPT = "y = once, A = always in this sandbox, N = no: "
# Keys typed in this long after a popup appears are dropped: they were meant
# for the sandbox, typed before the popup could be seen. Otherwise a sandbox
# could time a request to catch a "y<Enter>" typed into its own prompt.
GRACE = 0.5
MAX_REQUEST = 1 << 20
# Sandbox output held while a popup is up, past which the pty is no longer
# read (the sandbox blocks on writing).
MAX_PENDING = 1 << 20
# How long the pty stays at the other size when nudging a redraw.
NUDGE = 0.05


def usable(fd=0, out=1):
    """Whether there's a terminal to relay and show popups on."""
    return os.isatty(fd) and os.isatty(out)


def listen(path):
    """The socket the guards ask on, for the launcher's private temp dir."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(path)
    os.chmod(path, 0o600)
    sock.listen(16)
    return sock


# -- text ----------------------------------------------------------------------


def sanitize(s):
    """Anything non-printable (escape sequences, bidi overrides, line
    separators) becomes "?": popup text is drawn on the terminal as is."""
    return "".join(c if c.isprintable() else "?" for c in s.replace("\t", "    "))


def char_width(c):
    if unicodedata.combining(c):
        return 0
    return 2 if unicodedata.east_asian_width(c) in "WF" else 1


def fit(s, width):
    """s cut to width columns, and padded to it."""
    out, used = "", 0
    for c in s:
        w = char_width(c)
        if used + w > width:
            break
        out += c
        used += w
    return out + " " * (width - used)


def wrap(text, width):
    """Lines of text, sanitized and hard-wrapped at width columns - not cut:
    a request is approved for exactly what's shown."""
    lines = []
    for raw in text.split("\n"):
        line, used = "", 0
        for c in sanitize(raw):
            w = char_width(c)
            if used + w > width and line:
                lines.append(line)
                line, used = "", 0
            line += c
            used += w
        lines.append(line)
    while lines and not lines[-1]:
        lines.pop()
    return lines


# -- the popup -----------------------------------------------------------------

KEY_RE = re.compile(rb"\x1b\[[0-?]*[ -/]*[@-~]|\x1bO.|.", re.S)
UP = {b"\x1b[A", b"\x1bOA"}
DOWN = {b"\x1b[B", b"\x1bOB"}
PAGE_UP = {b"\x1b[5~"}
PAGE_DOWN = {b"\x1b[6~"}
HOME = {b"\x1b[H", b"\x1bOH", b"\x1b[1~"}
END = {b"\x1b[F", b"\x1bOF", b"\x1b[4~"}


class Popup:
    """One request on screen: the text, scrollable, and a y/A/N prompt read
    as a line like `read` would (Enter alone is no)."""

    def __init__(self, name, text, rows, cols, now, grace=GRACE):
        self.name = sanitize(name)
        self.text = text
        self.ready_at = now + grace
        self.typed = ""
        self.top = 0
        self.resize(rows, cols)

    def resize(self, rows, cols):
        self.rows, self.cols = max(rows, 4), max(cols, 10)
        self.lines = wrap(self.text, self.cols)
        self.top = min(self.top, self.max_top())

    def body_rows(self):
        return self.rows - 3

    def max_top(self):
        return max(len(self.lines) - self.body_rows(), 0)

    def scroll(self, by):
        self.top = min(max(self.top + by, 0), self.max_top())

    def feed(self, data, now):
        """Handle typed bytes; the answer ("once", "always", "no") once
        there is one, else None."""
        if now < self.ready_at:
            return None
        for key in KEY_RE.findall(data):
            if key in (b"\r", b"\n"):
                return {"y": "once", "a": "always"}.get(self.typed.lower(), "no")
            if key in (b"\x03", b"\x04"):
                return "no"
            if key in (b"\x7f", b"\x08"):
                self.typed = self.typed[:-1]
            elif key == b"\x15":
                self.typed = ""
            elif key in UP:
                self.scroll(-1)
            elif key in DOWN:
                self.scroll(1)
            elif key in PAGE_UP:
                self.scroll(-self.body_rows())
            elif key in PAGE_DOWN:
                self.scroll(self.body_rows())
            elif key in HOME:
                self.top = 0
            elif key in END:
                self.top = self.max_top()
            elif len(key) == 1 and 0x20 <= key[0] < 0x7F and len(self.typed) < 16:
                self.typed += key.decode()
        return None

    def render(self, now):
        """The whole screen, as bytes for the terminal."""
        out = ["\x1b[0m\x1b(B\x1b[?25l\x1b[H\x1b[2J"]

        def at(row, s):
            out.append(f"\x1b[{row};1H{s}")

        title = f" sandbox: {self.name} asks for approval"
        at(1, "\x1b[7m" + fit(title, self.cols) + "\x1b[0m")
        body = self.lines[self.top : self.top + self.body_rows()]
        for i, line in enumerate(body):
            at(2 + i, line)
        if self.max_top():
            status = (
                f" lines {self.top + 1}-{self.top + len(body)} of {len(self.lines)}"
                " - Up/Down/PgUp/PgDn to read it all"
            )
            at(self.rows - 1, "\x1b[7m" + fit(status, self.cols) + "\x1b[0m")
        prompt = fit(PROMPT + self.typed, self.cols - 1).rstrip()
        if now < self.ready_at:
            at(self.rows, "\x1b[2m" + prompt + "\x1b[0m")
        else:
            at(self.rows, prompt + "\x1b[?25h")
        return "".join(out).encode()


# -- the relay -----------------------------------------------------------------


class Modes:
    """The few terminal modes of the sandbox's that a popup has to restore,
    tracked from its output."""

    RE = re.compile(rb"\x1b\[\?([0-9;]*)([hl])|\x1bc")

    def __init__(self):
        self.alt = False
        self.cursor = True
        self._tail = b""

    def feed(self, data):
        # The tail of the last chunk again, for a sequence split across two:
        # matched twice, but in order, so the last one still wins.
        buf = self._tail + data
        for m in self.RE.finditer(buf):
            if m.group(0) == b"\x1bc":
                self.alt, self.cursor = False, True
                continue
            on = m.group(2) == b"h"
            for mode in m.group(1).split(b";"):
                if mode in (b"1049", b"1047", b"47"):
                    self.alt = on
                elif mode == b"25":
                    self.cursor = on
        self._tail = buf[-32:]


def take_ctty():
    """In the child, after setsid: the pty on stdin as controlling terminal."""
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)


def get_size(fd):
    rows, cols, xpix, ypix = struct.unpack(
        "HHHH", fcntl.ioctl(fd, termios.TIOCGWINSZ, b"\0" * 8)
    )
    return rows, cols, xpix, ypix


def set_size(fd, size):
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", *size))


def read_request(conn):
    """(name, text) from a guard's connection, None if it's malformed."""
    conn.settimeout(2.0)
    data = b""
    try:
        while chunk := conn.recv(65536):
            data += chunk
            if len(data) > MAX_REQUEST:
                return None
        req = json.loads(data)
        return str(req["name"]), str(req["text"])
    except (OSError, ValueError, KeyError, TypeError):
        return None


def reply(conn, answer):
    try:
        conn.sendall(answer.encode())
    except OSError:
        pass
    conn.close()


class Relay:
    def __init__(self, listener, fd=0, out=1, grace=GRACE):
        self.listener = listener
        self.fd, self.out = fd, out
        self.grace = grace
        self.tty_ok = True
        self.master_eof = False
        self.modes = Modes()
        self.to_child = bytearray()
        self.pending = bytearray()
        self.queue = collections.deque()
        self.popup = None
        self.conn = None
        self.screen_open = False
        self.drew_on_alt = False
        self.resized = False
        self.timers = {}

    def run(self, argv):
        """Run argv on a pty, relaying the terminal; return its exit status."""
        attrs = termios.tcgetattr(self.fd)
        master, slave = os.openpty()
        termios.tcsetattr(slave, termios.TCSANOW, attrs)
        set_size(slave, get_size(self.fd))
        proc = subprocess.Popen(
            argv,
            stdin=slave,
            stdout=slave,
            stderr=slave,
            start_new_session=True,
            preexec_fn=take_ctty,
        )
        os.close(slave)
        self.master, self.proc = master, proc
        os.set_blocking(master, False)

        wake_r, wake_w = os.pipe()
        os.set_blocking(wake_r, False)
        os.set_blocking(wake_w, False)
        old_wakeup = signal.set_wakeup_fd(wake_w)

        def forward(signum, _frame):
            if proc.poll() is None:
                proc.send_signal(signum)

        old_handlers = {
            signum: signal.signal(signum, handler)
            for signum, handler in (
                (signal.SIGWINCH, lambda *_: None),
                (signal.SIGINT, lambda *_: None),
                (signal.SIGTERM, forward),
                (signal.SIGHUP, forward),
            )
        }
        pidfd = os.pidfd_open(proc.pid)
        self.sel = selectors.DefaultSelector()
        self.sel.register(self.fd, selectors.EVENT_READ, "tty")
        self.sel.register(master, selectors.EVENT_READ, "master")
        self.sel.register(self.listener, selectors.EVENT_READ, "listener")
        self.sel.register(wake_r, selectors.EVENT_READ, "signal")
        self.sel.register(pidfd, selectors.EVENT_READ, "exit")
        tty.setraw(self.fd, termios.TCSANOW)
        try:
            self.loop(wake_r)
            self.drain()
        finally:
            for conn in [self.conn] + [c for c, _, _ in self.queue]:
                if conn:
                    reply(conn, "no")
            self.popup = self.conn = None
            self.queue.clear()
            if self.screen_open:
                self.close_screen()
            try:
                termios.tcsetattr(self.fd, termios.TCSADRAIN, attrs)
            except termios.error:
                pass
            self.sel.close()
            signal.set_wakeup_fd(old_wakeup)
            for signum, handler in old_handlers.items():
                signal.signal(signum, handler)
            for fd in (pidfd, wake_r, wake_w, master):
                os.close(fd)
        return proc.wait()

    def loop(self, wake_r):
        while True:
            now = time.monotonic()
            timeout = None
            if self.timers:
                timeout = max(min(self.timers.values()) - now, 0)
            for key, events in self.sel.select(timeout):
                what = key.data
                if what == "exit":
                    return
                if what == "tty":
                    self.on_tty()
                elif what == "master":
                    if events & selectors.EVENT_WRITE:
                        self.write_child()
                    if events & selectors.EVENT_READ:
                        self.read_child()
                elif what == "listener":
                    self.on_request()
                elif what == "signal":
                    if signal.SIGWINCH in os.read(wake_r, 512):
                        self.on_resize()
            now = time.monotonic()
            for name, at in list(self.timers.items()):
                if at <= now:
                    del self.timers[name]
                    if name == "unnudge":
                        set_size(self.master, get_size(self.fd))
                    elif name == "ready" and self.popup:
                        self.draw()

    # -- the sandbox's side --

    def update_master(self):
        """Watch the pty for what there's room for: reading unless the held
        output is full, writing while there's input for it."""
        if self.master_eof:
            return
        events = 0
        if len(self.pending) < MAX_PENDING:
            events |= selectors.EVENT_READ
        if self.to_child:
            events |= selectors.EVENT_WRITE
        registered = self.master in self.sel.get_map()
        if events and registered:
            self.sel.modify(self.master, events, "master")
        elif events:
            self.sel.register(self.master, events, "master")
        elif registered:
            self.sel.unregister(self.master)

    def write_child(self):
        try:
            n = os.write(self.master, self.to_child)
        except BlockingIOError:
            return
        except OSError:
            n = len(self.to_child)
        del self.to_child[:n]
        self.update_master()

    def read_child(self):
        try:
            data = os.read(self.master, 65536)
        except BlockingIOError:
            return
        except OSError:
            data = b""
        if not data:
            # Every slave fd closed; the exit follows.
            self.master_eof = True
            self.sel.unregister(self.master)
            return
        if self.screen_open:
            self.pending += data
            self.update_master()
        else:
            self.show(data)

    def drain(self):
        """What the sandbox wrote before it exited."""
        while True:
            try:
                data = os.read(self.master, 65536)
            except OSError:
                break
            if not data:
                break
            if self.screen_open:
                self.pending += data
            else:
                self.show(data)

    # -- the terminal's side --

    def write(self, data):
        if not self.tty_ok:
            return
        view = memoryview(data)
        try:
            while view:
                n = os.write(self.out, view)
                view = view[n:]
        except OSError:
            self.tty_ok = False

    def show(self, data):
        """Sandbox output, onto the terminal."""
        self.modes.feed(data)
        self.write(data)

    def on_tty(self):
        try:
            data = os.read(self.fd, 4096)
        except OSError:
            data = b""
        if not data:
            # Hung up: nothing more to relay, and no one to answer popups.
            self.tty_ok = False
            self.sel.unregister(self.fd)
            if self.popup:
                self.answer("no")
            return
        if self.popup:
            answer = self.popup.feed(data, time.monotonic())
            if answer:
                self.answer(answer)
            else:
                self.draw()
        else:
            self.to_child += data
            self.update_master()

    def on_resize(self):
        try:
            size = get_size(self.fd)
        except OSError:
            return
        if self.screen_open:
            self.resized = True
            if self.popup:
                self.popup.resize(size[0], size[1])
                self.draw()
        else:
            set_size(self.master, size)

    # -- popups --

    def on_request(self):
        try:
            conn, _ = self.listener.accept()
        except OSError:
            return
        request = read_request(conn)
        if request is None:
            conn.close()
            return
        self.queue.append((conn, *request))
        if not self.popup:
            self.next_popup()

    def next_popup(self):
        while self.queue:
            conn, name, text = self.queue.popleft()
            if not self.tty_ok:
                reply(conn, "no")
                continue
            if not self.screen_open:
                self.open_screen()
            rows, cols, _, _ = get_size(self.fd)
            now = time.monotonic()
            self.popup = Popup(name, text, rows, cols, now, self.grace)
            self.conn = conn
            self.timers["ready"] = self.popup.ready_at
            self.draw()
            return
        if self.screen_open:
            self.close_screen()

    def answer(self, answer):
        reply(self.conn, answer)
        self.popup = self.conn = None
        self.timers.pop("ready", None)
        self.next_popup()

    def draw(self):
        self.write(self.popup.render(time.monotonic()))

    def open_screen(self):
        self.drew_on_alt = self.modes.alt
        self.resized = False
        # 1049 saves the cursor and attributes on the way in and restores
        # them on the way out; on the alternate screen already, \e7 does.
        self.write(b"\x1b7" if self.drew_on_alt else b"\x1b[?1049h")
        self.screen_open = True

    def close_screen(self):
        if self.drew_on_alt:
            self.write(b"\x1b[0m\x1b[H\x1b[2J\x1b8")
        else:
            self.write(b"\x1b[0m\x1b[?1049l")
        self.write(b"\x1b[?25h" if self.modes.cursor else b"\x1b[?25l")
        self.screen_open = False
        if self.pending:
            self.show(bytes(self.pending))
            self.pending.clear()
        self.update_master()
        try:
            size = get_size(self.fd)
        except OSError:
            return
        if self.resized:
            set_size(self.master, size)
        elif self.drew_on_alt:
            # The same size again wouldn't signal; a column less, briefly,
            # has the program inside redraw what the popup covered.
            rows, cols, xpix, ypix = size
            set_size(self.master, (rows, cols - 1 if cols > 1 else 2, xpix, ypix))
            self.timers["unnudge"] = time.monotonic() + NUDGE
