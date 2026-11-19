"""Black-box harness for the launcher (src/sandbox).

The launcher is run as a program - `LAUNCHER CONFIG.json [OPTIONS] [--]
[COMMAND...]`, as the nix wrapper runs it - and judged only by what it does
from the outside: its exit status and output, the files it leaves in the
state dir, what it asks on the terminal, and the command line it hands to
pasta. Nothing here imports it, so the same tests run against any
implementation: $SANDBOX_LAUNCHER (shell words) replaces the Python one.

Everything the config names is a stand-in from a per-test tools dir:

- pasta records its argv and, instead of making a namespace, runs the
  command given to the sandbox (or nothing, for a login shell) with the
  --setenv variables and --chdir of the bwrap args. Binds whose destination
  is under the test's $XDG_RUNTIME_DIR become symlinks there, so a client
  inside finds a guard's socket where it would in a real sandbox.
- ip prints the "host addresses" in $FAKE_IP_ADDRS.
- nix (inside, for sandbox.nix) and nix-build (on the host, for
  config.nix) record their argv and print $FAKE_NIX_OUT/$FAKE_NIX_BUILD_OUT.

The guards are the real ones (they're tested on their own too).
"""

import errno
import fcntl
import json
import os
import pty
import select
import shlex
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time
from pathlib import Path

from conftest import BIN_DIR

LAUNCHER = (
    shlex.split(os.environ["SANDBOX_LAUNCHER"])
    if os.environ.get("SANDBOX_LAUNCHER")
    else [sys.executable, "-E", "-s", str(BIN_DIR / "sandbox")]
)

FAKE_PASTA = """
import json, os, signal, stat, subprocess, sys

argv = sys.argv[1:]
bwrap = argv[argv.index("--seccomp") + 2:]
env, chdir, files, i = dict(os.environ), None, {}, 0
runtime = os.environ.get("XDG_RUNTIME_DIR", "/nonexistent")
while i < len(bwrap):
    a = bwrap[i]
    if a == "--setenv":
        env[bwrap[i + 1]] = bwrap[i + 2]
        i += 3
    elif a in ("--bind", "--ro-bind", "--bind-try", "--ro-bind-try"):
        src, dst = bwrap[i + 1], bwrap[i + 2]
        # Files the launcher writes for inside (resolv.conf, the CA bundle)
        # are gone with it; keep what they said.
        try:
            if stat.S_ISREG(os.stat(src).st_mode) and os.path.getsize(src) < 1 << 16:
                files[src] = open(src, encoding="utf-8", errors="replace").read()
        except OSError:
            pass
        if dst.startswith(runtime + "/") and not os.path.lexists(dst):
            os.symlink(src, dst)
        i += 3
    elif a == "--chdir":
        chdir = bwrap[i + 1]
        break
    else:
        i += 1
with open(os.environ["FAKE_LOG"], "a") as f:
    entry = {"tool": "pasta", "argv": argv, "tty": os.isatty(0), "files": files}
    f.write(json.dumps(entry) + "\\n")
# What's run inside is the host's PATH here, not the profile's.
env["PATH"] = os.environ["PATH"]
marker = 'exec "$@"'
if marker not in bwrap:
    sys.exit(int(os.environ.get("FAKE_PASTA_EXIT", "0")))
command = bwrap[bwrap.index(marker) + 2:]
try:
    proc = subprocess.Popen(command, cwd=chdir, env=env)
except FileNotFoundError:
    sys.exit(127)
for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
    signal.signal(signum, lambda signum, _: proc.send_signal(signum))
code = proc.wait()
sys.exit(code if code >= 0 else 128 - code)
"""

FAKE_IP = """
import os
for i, addr in enumerate(os.environ.get("FAKE_IP_ADDRS", "").split()):
    print(f"{i + 2}: eth{i}    inet {addr}/24 brd 10.255.255.255 scope global eth{i}")
"""

FAKE_NIX = """
import json, os, sys

name = os.path.basename(sys.argv[0])
with open(os.environ["FAKE_LOG"], "a") as f:
    f.write(json.dumps({"tool": name, "argv": sys.argv[1:]}) + "\\n")
var = "FAKE_NIX_BUILD_OUT" if name == "nix-build" else "FAKE_NIX_OUT"
print("some noise from a shell startup file")
print(os.environ.get(var, ""))
sys.exit(int(os.environ.get(var.replace("_OUT", "_EXIT"), "0")))
"""


def _script(path, body):
    path.write_text(f"#!{sys.executable}\n{body}")
    path.chmod(0o755)
    return str(path)


def store_file(path, value, raw=False):
    """value as JSON (or as it is, raw) in a store path, which is all the
    launcher takes for a built config or manifest; skips without a nix to
    add it."""
    path = Path(path)
    path.write_text(value if raw else json.dumps(value))
    nix_store = shutil.which("nix-store")
    if nix_store:
        result = subprocess.run(
            [nix_store, "--add", str(path)], capture_output=True, text=True, check=False
        )
        if result.returncode == 0:
            return result.stdout.strip()
    import pytest

    pytest.skip("needs nix-store --add (no nix daemon here)")


class Invocation:
    """One pasta command line, taken apart."""

    def __init__(self, argv):
        self.argv = argv
        sep = argv.index("--")
        self.pasta = argv[:sep]
        inner = argv[sep + 1 :]
        # bash -c SCRIPT bash IP SECCOMP N ADDR... BWRAP --seccomp 10 ARGS...
        self.bash, self.script = inner[0], inner[2]
        self.ip, self.seccomp, n = inner[4], inner[5], int(inner[6])
        self.addrs = inner[7 : 7 + n]
        self.bwrap = inner[7 + n]
        assert inner[8 + n : 10 + n] == ["--seccomp", "10"], inner
        self.args = inner[10 + n :]
        chdir = self.args.index("--chdir")
        self.mount_args = self.args[:chdir]
        self.chdir = self.args[chdir + 1]
        # sandbox-init (however it's started) PROFILE GENERATION SHELL --login ...
        self.init = self.args[chdir + 2 :]
        login = self.init.index("--login")
        self.init_program = self.init[: login - 3]
        self.init_paths = self.init[login - 3 : login - 1]
        self.shell = self.init[login - 1 :]

    def pasta_opt(self, flag):
        return self.pasta[self.pasta.index(flag) + 1]

    @property
    def setenv(self):
        out, a = {}, self.mount_args
        for i, arg in enumerate(a):
            if arg == "--setenv":
                out[a[i + 1]] = a[i + 2]
        return out

    @property
    def mounts(self):
        """(flag, src, dst) for every bind, in order; (flag, dst) for the rest."""
        out, a, i = [], self.mount_args, 0
        while i < len(a):
            if a[i] in ("--bind", "--ro-bind", "--bind-try", "--ro-bind-try"):
                out.append(tuple(a[i : i + 3]))
                i += 3
            elif a[i] in ("--tmpfs", "--dev", "--proc"):
                out.append(tuple(a[i : i + 2]))
                i += 2
            elif a[i] in ("--setenv", "--uid", "--gid", "--cap-drop"):
                i += 3 if a[i] == "--setenv" else 2
            else:
                i += 1
        return out

    def bind(self, dst):
        """The bind source for dst."""
        [src] = [m[1] for m in self.mounts if len(m) == 3 and m[2] == dst]
        return src

    @property
    def command(self):
        """The command after the login shell's exec trick, or None for a
        login shell."""
        if 'exec "$@"' not in self.init:
            return None
        return self.init[self.init.index('exec "$@"') + 2 :]


class Result:
    def __init__(self, returncode, stdout, stderr, log):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr
        self.log = log

    def calls(self, tool):
        return [e["argv"] for e in self.log if e["tool"] == tool]

    @property
    def files(self):
        """{source: content} of the regular files bound in by the last pasta run."""
        return [e for e in self.log if e["tool"] == "pasta"][-1]["files"]

    @property
    def pasta(self):
        """The (only) pasta invocation of the outermost launcher: the last."""
        calls = self.calls("pasta")
        assert calls, f"pasta never ran:\n{self.stderr}"
        return Invocation(calls[-1])


class Launcher:
    """A home, a project, a state dir and a config to run the launcher with."""

    def __init__(self, tmp_path):
        # Physical, as the launcher sees it.
        tmp_path = Path(os.path.realpath(tmp_path))
        self.tmp = tmp_path
        self.home = tmp_path / "home"
        self.project = self.home / "p"
        (self.project / ".git").mkdir(parents=True)
        self.state = tmp_path / "state"
        self.runtime = tmp_path / "run"
        self.runtime.mkdir()
        # Where the launcher's temp dirs go, all removed when it's done.
        # Short, for the guards' sockets (108 bytes at most); close() removes it.
        self.tmpdir = Path(tempfile.mkdtemp(prefix="sbt-"))
        self.log_path = tmp_path / "log.jsonl"
        tools = tmp_path / "tools"
        tools.mkdir()
        self.tools = tools
        ssl = tmp_path / "ssl"
        (ssl / "certs").mkdir(parents=True)
        (ssl / "certs/ca-bundle.crt").write_text("SYSTEM CA BUNDLE\n")
        self.resolv_conf = tmp_path / "resolv.conf"
        self.resolv_conf.write_text("nameserver 192.0.2.53\n")
        self.seccomp = tmp_path / "seccomp.bpf"
        self.seccomp.write_bytes(b"\0" * 8)
        host_bin = tmp_path / "host-bin"
        host_bin.mkdir()
        self.host_bin = host_bin
        self.config = {
            "stateDir": str(self.state),
            "released": None,
            "upgradeNoticeDays": 30,
            "userConfig": None,
            "hostPorts": [],
            "passEnv": ["TERM", "LANG"],
            "hostEtc": ["/etc/hosts"],
            "guards": {
                "sshAgent": {
                    "enable": False,
                    "socket": None,
                    "path": "$XDG_RUNTIME_DIR/ssh-agent.sock",
                },
                "secretService": False,
                "github": False,
                "forgejo": False,
                "openUrl": False,
            },
            "default": self.profile("default"),
            "profiles": [],
            "seccomp": str(self.seccomp),
            "resolvConf": str(self.resolv_conf),
            "fhs": {
                "bin": "/store/fhs/bin",
                "usrBin": "/store/fhs/usr/bin",
                "nixLd": "/store/nix-ld",
                "ldPath": "/lib64/ld-linux-x86-64.so.2",
                "ssl": str(ssl),
            },
            "tools": {
                "pasta": _script(tools / "pasta", FAKE_PASTA),
                "ip": _script(tools / "ip", FAKE_IP),
                "bash": shutil.which("bash"),
                "bwrap": "/store/bwrap",
                "shell": "/store/bash",
            },
            "init": {"script": "/store/sandbox-init", "nixProfile": False, "homeManager": False},
            "python": sys.executable,
            "src": str(BIN_DIR),
            "hostPath": str(host_bin),
            "dbusDaemon": shutil.which("dbus-daemon") or "/nonexistent/dbus-daemon",
            "project": {"eval": "/store/project.nix", "nixpkgs": "/store/nixpkgs", "system": "x86_64-linux"},
        }  # fmt: skip
        _script(tools / "nix", FAKE_NIX)
        _script(tools / "nix-build", FAKE_NIX)
        self.env = {
            "HOME": str(self.home),
            "USER": "u",
            "PATH": f"{tools}:{os.environ['PATH']}",
            "XDG_RUNTIME_DIR": str(self.runtime),
            "FAKE_LOG": str(self.log_path),
            "TERM": "xterm",
            "TMPDIR": str(self.tmpdir),
            # Leaks the launcher must keep out.
            "GH_TOKEN": "host-gh-token",
            # Coverage of the launcher and the guards, when measured.
            **{
                k: v
                for k, v in os.environ.items()
                if k.startswith("COVERAGE_") or k == "GOCOVERDIR"
            },
        }

    def close(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    @staticmethod
    def profile(name, **kw):
        return {
            "name": name,
            "env": {"PATH": "/store/env/bin", "PROFILE": name},
            "binds": [],
            "claudeDir": None,
            "claudeApiKey": False,
            "paths": [],
            "projectFiles": [],
            "priority": 0,
            **kw,
        }

    @property
    def config_path(self):
        path = self.tmp / "config.json"
        path.write_text(json.dumps(self.config))
        return path

    def volume(self, project=None):
        """The project's volume dir: the one dir the launcher made in the state dir."""
        dirs = [d for d in self.state.iterdir() if d.is_dir()]
        if project is not None:
            dirs = [
                d
                for d in dirs
                if d.name.startswith(str(project).replace("/", "_") + "-")
            ]
        [d] = dirs
        return d

    def _log(self):
        try:
            text = self.log_path.read_text()
        except FileNotFoundError:
            return []
        self.log_path.unlink()
        return [json.loads(line) for line in text.splitlines()]

    def argv(self, args, config):
        return [*LAUNCHER, str(config or self.config_path), *args]

    def run(self, *args, cwd=None, env=None, input="", timeout=60, config=None):
        """Run without a terminal: no controlling tty, stdin from input."""
        proc = subprocess.run(
            self.argv(args, config),
            cwd=cwd or self.project,
            env={**self.env, **(env or {})},
            input=input,
            capture_output=True,
            text=True,
            timeout=timeout,
            start_new_session=True,
            check=False,
        )
        return Result(proc.returncode, proc.stdout, proc.stderr, self._log())

    def pty(self, *args, cwd=None, env=None, config=None):
        """Start on a terminal of its own, as its controlling one."""
        return PtyRun(
            self.argv(args, config),
            cwd or self.project,
            {**self.env, **(env or {})},
            self,
        )


def descendants(pid):
    """pid's descendant processes."""
    children = {}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            stat = Path(f"/proc/{entry}/stat").read_text()
        except OSError:
            continue
        ppid = int(stat.rsplit(")", 1)[1].split()[1])
        children.setdefault(ppid, []).append(int(entry))
    out, todo = [], [pid]
    while todo:
        for child in children.get(todo.pop(), []):
            out.append(child)
            todo.append(child)
    return out


class PtyRun:
    """The launcher on a pty: read what it shows, type at it."""

    def __init__(self, argv, cwd, env, launcher):
        self.launcher = launcher
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, b"\x18\x00\x50\x00" + b"\0" * 4)
        self.master = master
        self.output = b""
        # Everything shown, and whatever else wants to see it (a terminal
        # emulator's feed).
        self.raw = b""
        self.watchers = []

        def ctty():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)

        self.proc = subprocess.Popen(
            argv,
            cwd=cwd,
            env=env,
            stdin=slave,
            stdout=slave,
            stderr=slave,
            preexec_fn=ctty,  # noqa: PLW1509 - the test's own child
        )
        os.close(slave)

    def _read(self, timeout):
        ready, _, _ = select.select([self.master], [], [], timeout)
        if not ready:
            return False
        try:
            data = os.read(self.master, 65536)
        except OSError as e:
            if e.errno != errno.EIO:
                raise
            data = b""
        if not data:
            return None
        self.output += data
        self.raw += data
        for watch in self.watchers:
            watch(data)
        return True

    def read_for(self, seconds):
        """Read what's shown for this long."""
        deadline = time.monotonic() + seconds
        while (left := deadline - time.monotonic()) > 0:
            if self._read(left) is None:
                return

    def until(self, condition, timeout=20, what="condition"):
        """Read until condition() holds."""
        deadline = time.monotonic() + timeout
        while not condition():
            left = deadline - time.monotonic()
            if left <= 0 or self._read(min(left, 0.1)) is None and not condition():
                raise AssertionError(
                    f"{what} never met; got:\n{self.raw.decode(errors='replace')}"
                )

    def expect(self, text, timeout=20):
        """Wait for text (str) to appear in the output after what earlier
        expects consumed; returns everything up to and including it."""
        needle = text.encode()
        deadline = time.monotonic() + timeout
        while needle not in self.output:
            left = deadline - time.monotonic()
            if left <= 0 or self._read(left) is None:
                raise AssertionError(
                    f"{text!r} not shown; got:\n{self.output.decode(errors='replace')}"
                )
        before, _, self.output = self.output.partition(needle)
        return (before + needle).decode(errors="replace")

    def send(self, text):
        os.write(self.master, text if isinstance(text, bytes) else text.encode())

    def resize(self, rows, cols):
        """As a terminal window does: the launcher gets SIGWINCH."""
        fcntl.ioctl(
            self.master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0)
        )

    def hang_up(self):
        os.close(self.master)
        self.master = None

    def popup_socket(self, timeout=10):
        """Where the guards ask: $SANDBOX_POPUP_SOCKET in the environment of
        the launcher's descendants (its guards)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for pid in descendants(self.proc.pid):
                try:
                    environ = Path(f"/proc/{pid}/environ").read_bytes().split(b"\0")
                except OSError:
                    continue
                for entry in environ:
                    if entry.startswith(b"SANDBOX_POPUP_SOCKET="):
                        return entry.split(b"=", 1)[1].decode()
            time.sleep(0.05)
        raise AssertionError("no guard with a popup socket")

    def wait(self, timeout=30):
        """Read to the end; the exit status and the remaining output."""
        deadline = time.monotonic() + timeout
        while self.master is not None and (
            self.proc.poll() is None or self._read(0) is True
        ):
            if time.monotonic() > deadline:
                self.proc.kill()
                raise AssertionError(
                    f"still running; output:\n{self.output.decode(errors='replace')}"
                )
            self._read(0.05)
        if self.master is None:
            self.proc.wait(timeout)
        else:
            os.close(self.master)
        return Result(
            self.proc.returncode,
            self.output.decode(errors="replace"),
            "",
            self.launcher._log(),
        )

    def signal(self, signum=signal.SIGTERM):
        self.proc.send_signal(signum)
