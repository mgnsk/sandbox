"""Tests that launch a real sandbox - pasta, bwrap, every guard - and check
what the sandboxed process actually sees.

A flag on a command line can't tell you bwrap honored it, that a nested
namespace didn't reintroduce root, or that pasta's netns is actually
reachable - that gap is how the sandbox once ran the sandboxed process as
uid 0 without any test catching it. (The command line itself is
test_sandbox_launcher.py's.) They run the `sandbox` built from this flake:
$SANDBOX_BIN, else `sandbox` on PATH, e.g.

    SANDBOX_BIN=$(nix build --print-out-paths)/bin/sandbox pytest tests

and need a real host: unprivileged user namespaces are unavailable inside a
running sandbox (`--disable-userns` blocks exactly that), so they skip
themselves there. Each gets its own $SANDBOX_STATE_DIR.
"""

import contextlib
import hashlib
import json
import os
import shutil
import signal
import socket
import subprocess
import threading
import time
import uuid
from pathlib import Path

import pytest

SANDBOX = os.environ.get("SANDBOX_BIN") or shutil.which("sandbox")


def volume_name(project):
    digest = hashlib.sha256(project.encode()).hexdigest()[:8]
    return project.replace("/", "_") + f"-{digest}"


# -- real sandbox ----------------------------------------------------------------


def _userns_usable():
    bwrap = shutil.which("bwrap") or "/nix/var/nix/profiles/default/bin/bwrap"
    if SANDBOX is None:
        return False
    try:
        probe = subprocess.run(
            [
                bwrap,
                "--unshare-all",
                "--unshare-user",
                "--disable-userns",
                "--ro-bind",
                "/",
                "/",
                "true",
            ],
            capture_output=True,
            timeout=10,
            check=False,
        )
    except OSError:
        # No bwrap to probe with; let the sandbox itself fail loudly.
        return True
    return probe.returncode == 0


@pytest.fixture
def state_dir(tmp_path):
    d = tmp_path / "state"
    d.mkdir()
    return d


def run_sandbox(script, *, cwd, state_dir=None, extra_env=None, timeout=60, args=()):
    """Feed `script` to the sandboxed bash's stdin, return the CompletedProcess.

    With no command the sandbox runs `bash --login`; with stdin not a tty,
    that reads and runs commands from it non-interactively and exits at EOF.
    """
    env = os.environ.copy()
    # Next to the project, as the state_dir fixture makes it.
    env["SANDBOX_STATE_DIR"] = str(state_dir or Path(cwd).parent / "state")
    env.update(extra_env or {})
    return subprocess.run(
        [SANDBOX, *args],
        input=script,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


@pytest.fixture
def project_dir(tmp_path, state_dir):
    """A throwaway git repo."""
    if not _userns_usable():
        pytest.skip(
            "needs a built sandbox ($SANDBOX_BIN) and a real host: unprivileged user "
            "namespaces are unavailable here (e.g. this pytest run is itself inside a sandbox)"
        )
    repo = tmp_path / "project"
    (repo / ".git").mkdir(parents=True)
    return repo


@pytest.fixture
def run_in(project_dir, state_dir):
    def run(script, **kw):
        return run_sandbox(script, cwd=project_dir, state_dir=state_dir, **kw)

    return run


def test_refuses_to_run_in_home_through_a_symlink(tmp_path):
    """The check must see the physical path, not a link's logical one."""
    if SANDBOX is None:
        pytest.skip("no built sandbox")
    link = tmp_path / "home-link"
    link.symlink_to(Path.home())
    result = subprocess.run(
        ["bash", "-c", f'cd "{link}" && exec "{SANDBOX}" true'],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert "refusing" in result.stderr


def test_sandboxed_process_is_not_root(run_in):
    """pasta's own user namespace maps the invoking user to uid 0 in it -
    without bwrap's --uid/--gid pinning it back, the sandboxed process looks
    like real root."""
    result = run_in("id -u; id -g\n")
    assert result.returncode == 0, result.stderr
    assert result.stdout.split() == [str(os.getuid()), str(os.getgid())]


def test_args_are_run_as_the_command(project_dir, state_dir):
    result = run_sandbox(
        "", cwd=project_dir, state_dir=state_dir, args=["echo", "hello there"]
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "hello there"


def test_subdirectory_gets_the_whole_work_tree(project_dir, state_dir):
    """Started in a subdirectory, the repo root and .git are there, read-write."""
    sub = project_dir / "sub"
    sub.mkdir()
    result = run_sandbox(
        "test -d ../.git && touch ../top && echo ok\n", cwd=sub, state_dir=state_dir
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"
    assert (project_dir / "top").exists()


def test_project_sandbox_nix_is_applied(project_dir, state_dir):
    """Evaluated in a nested sandbox, its default command applies."""
    (project_dir / "sandbox.nix").write_text(
        '{ ... }: { command = [ "sh" "-c" "echo from-project" ]; }\n'
    )
    result = run_sandbox("", cwd=project_dir, state_dir=state_dir, timeout=600)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().splitlines()[-1] == "from-project"


def test_environment_is_cleared_and_reallowlisted(run_in):
    result = run_in(
        'echo "GH_TOKEN=[$GH_TOKEN]"; echo "SOME_HOST_VAR=[$SOME_HOST_VAR]"\n'
        'echo "HOME=[$HOME]"; echo "TERM=[$TERM]"\n',
        extra_env={
            "GH_TOKEN": "leaked-token",
            "SOME_HOST_VAR": "should-not-cross",
            "TERM": "xterm-256color",
        },
    )
    assert result.returncode == 0, result.stderr
    assert "leaked-token" not in result.stdout, (
        "a host GH_TOKEN must never reach the sandbox"
    )
    assert "SOME_HOST_VAR=[]" in result.stdout
    assert f"HOME=[{os.environ['HOME']}]" in result.stdout
    assert "TERM=[xterm-256color]" in result.stdout


def test_no_host_userland(run_in):
    """/usr/bin, /bin and the dynamic loader are the store's, not the host's."""
    result = run_in(
        "readlink -f /usr/bin/env /bin/sh; ls /usr/bin; ls /lib 2>&1 | head -1\n"
        "command -v bash git claude\n"
    )
    assert result.returncode == 0, result.stderr
    lines = result.stdout.splitlines()
    assert lines[0].startswith("/nix/store/") and lines[1].startswith("/nix/store/")
    assert sorted(lines[2:4]) == ["env", "xdg-open"]
    for path in lines[-3:]:
        assert path.startswith("/nix/store/"), path


def test_store_and_claude_config_are_read_only(run_in):
    result = run_in('echo x > "$(command -v gh)"\n')
    assert result.returncode != 0
    assert "Read-only file system" in result.stderr

    result = run_in(
        "cat /etc/claude-code/managed-settings.json; echo x > /etc/claude-code/CLAUDE.md\n"
    )
    assert json.loads(result.stdout)["env"]["DISABLE_AUTOUPDATER"] == 1
    assert "Read-only file system" in result.stderr


def test_volume_is_per_project(run_in, state_dir, project_dir):
    result = run_in('echo kept > "$HOME/kept"\n')
    assert result.returncode == 0, result.stderr
    volume = state_dir / volume_name(str(project_dir.resolve()))
    assert (volume / str(Path.home()).lstrip("/") / "kept").read_text() == "kept\n"
    assert (
        not (Path.home() / "kept").exists()
        or (Path.home() / "kept").read_text() != "kept\n"
    )


def test_exchange_dir_is_read_only(run_in):
    result = run_in('ln -s "$HOME/.bashrc" "$SANDBOX_EXCHANGE/foo.txt"\n')
    assert result.returncode != 0
    assert "Read-only file system" in result.stderr


def test_gh_and_xdg_open_talk_to_their_guards(run_in):
    result = run_in(
        '[ -n "$SANDBOX_GH_PROXY" ] && [ -r "$SANDBOX_CA_FILE" ] && echo gh-proxy\n'
        '[ -S "$XDG_RUNTIME_DIR/open-url.sock" ] && echo url-socket\n'
        'echo "browser=[$BROWSER]"\n'
        "xdg-open file:///etc/passwd; echo rc=$?\n"
    )
    assert result.returncode == 0, result.stderr
    assert "url-socket" in result.stdout
    assert "browser=[/usr/bin/xdg-open]" in result.stdout
    assert "rc=4" in result.stdout


def test_go_is_a_per_project_volume_not_the_host_dir(run_in):
    """All of $HOME/go is a single per-project volume, so neither $HOME/go/pkg
    (module cache) nor $HOME/go/bin is the real host directory. go/bin sits on
    the *host's* PATH; go/pkg is trusted by the host's `go` toolchain, which
    extracts a module once and never re-verifies the extracted source per build
    - so sandboxed code that could rewrite a cached dependency there would be
    executed by the next `go build` on the host or in another project. For both
    subpaths: a file the sandbox writes must never reach the real one, and a
    file the host already has in the real one must not be visible inside.
    """
    home = Path.home()
    pkg_dir = home / "go" / "pkg"
    bin_dir = home / "go" / "bin"
    pkg_dir.mkdir(parents=True, exist_ok=True)
    bin_dir.mkdir(parents=True, exist_ok=True)

    pkg_host_marker = f"test-host-pkg-{uuid.uuid4().hex}"
    bin_host_marker = f"test-host-bin-{uuid.uuid4().hex}"
    pkg_written_marker = f"test-from-sandbox-pkg-{uuid.uuid4().hex}"
    bin_written_marker = f"test-from-sandbox-bin-{uuid.uuid4().hex}"
    (pkg_dir / pkg_host_marker).write_text("from host\n")
    (bin_dir / bin_host_marker).write_text("from host\n")
    try:
        result = run_in(
            f'test -e "$HOME/go/pkg/{pkg_host_marker}" && echo PKG_LEAKED || echo PKG_NOT_LEAKED\n'
            f'test -e "$HOME/go/bin/{bin_host_marker}" && echo BIN_LEAKED || echo BIN_NOT_LEAKED\n'
            # The per-project go/ volume starts empty - go itself mkdir -p's
            # into it as needed, a plain `echo >` doesn't, so do that first
            # rather than assuming pkg/bin already exist in it.
            f'mkdir -p "$(dirname "$HOME/go/pkg/{pkg_written_marker}")"\n'
            f'mkdir -p "$(dirname "$HOME/go/bin/{bin_written_marker}")"\n'
            f'echo from sandbox > "$HOME/go/pkg/{pkg_written_marker}"\n'
            f'echo from sandbox > "$HOME/go/bin/{bin_written_marker}"\n',
        )
        assert result.returncode == 0, result.stderr
        assert "PKG_NOT_LEAKED" in result.stdout, (
            "$HOME/go/pkg must be a per-project volume, not the real host module cache - "
            "sharing it read-write is a module-cache-poisoning path to host code execution"
        )
        assert "BIN_NOT_LEAKED" in result.stdout, (
            "$HOME/go/bin must be a per-project volume, not the real host directory"
        )
        assert not (pkg_dir / pkg_written_marker).exists(), (
            "a file the sandbox wrote to $HOME/go/pkg reached the real host module cache"
        )
        assert not (bin_dir / bin_written_marker).exists(), (
            "a file the sandbox wrote to $HOME/go/bin reached the real host directory"
        )
    finally:
        (pkg_dir / pkg_host_marker).unlink(missing_ok=True)
        (bin_dir / bin_host_marker).unlink(missing_ok=True)


# -- networking --------------------------------------------------------


def test_network_is_reachable_through_pasta(project_dir):
    result = run_sandbox("getent hosts github.com\n", cwd=project_dir, timeout=30)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip(), (
        "pasta should still provide working DNS/outbound connectivity"
    )


def _free_non_ephemeral_port(family, addr):
    """Where real dev servers sit (3000, 5173, 8000, ...), below the kernel's
    ephemeral range."""
    ephemeral_low = int(
        Path("/proc/sys/net/ipv4/ip_local_port_range").read_text().split()[0]
    )
    for port in range(18000, min(ephemeral_low, 19000)):
        try:
            with socket.socket(family, socket.SOCK_STREAM) as probe:
                probe.bind((addr, port))
        except OSError:
            continue
        return port
    return None


def _free_ephemeral_port(family, addr):
    """Where an OAuth login's callback listener sits, from bind(0). A bare
    `-t auto` skips this range."""
    with socket.socket(family, socket.SOCK_STREAM) as probe:
        probe.bind((addr, 0))
        return probe.getsockname()[1]


def _http_get(addr, port):
    """The first bytes of a reply to GET /, or an OSError."""
    with socket.create_connection((addr, port), timeout=2) as conn:
        conn.sendall(b"GET / HTTP/1.0\r\n\r\n")
        return conn.recv(64)


@pytest.mark.parametrize("free_port", [_free_non_ephemeral_port, _free_ephemeral_port])
def test_loopback_server_in_sandbox_is_reachable_from_host(
    project_dir, tmp_path, free_port
):
    """A server bound to 127.0.0.1 inside the sandbox (vite, an OAuth login's
    callback listener) must answer a host browser opening http://localhost:port.

    pasta forwards ports bound in its netns (`-t auto`) on its own, but delivers
    the connection to the netns's public address unless --host-lo-to-ns-lo is
    set - so a loopback-only listener accepted nothing and the browser said
    "problem loading site". A `0.0.0.0` listener would have passed either way,
    which is why this binds loopback specifically.

    A browser tries localhost's ::1 first and only falls back to 127.0.0.1 if
    ::1 is refused. pasta's auto scan doesn't tell tcp from tcp6 listeners, so
    without a host address it also listened on [::1]:port, accepted there and
    reset - claude's login callback page never loaded. ::1 must be refused.
    """
    addr = "127.0.0.1"
    port = free_port(socket.AF_INET, addr)
    if port is None:
        pytest.skip(f"no free non-ephemeral port on {addr} on this host")

    # The sandboxed bash reads this from stdin; `read` then holds the sandbox
    # open until the test closes stdin, so it exits normally and cleanup() runs.
    script = f"python3 -m http.server {port} --bind {addr} >/dev/null &\nread -r _\n"
    log = tmp_path / "sandbox.log"
    v6 = "not tried"
    with log.open("w") as stderr:
        proc = subprocess.Popen(
            [SANDBOX],
            env={**os.environ, "SANDBOX_STATE_DIR": str(project_dir.parent / "state")},
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=stderr,
            cwd=project_dir,
            text=True,
            start_new_session=True,
        )
        try:
            proc.stdin.write(script)
            proc.stdin.flush()

            # pasta rescans the netns for new listeners once a second, on top of
            # the sandbox's own startup - refused/reset until then is expected.
            reply = b""
            last = "no attempt made"
            deadline = time.monotonic() + 30
            while not reply.startswith(b"HTTP/") and time.monotonic() < deadline:
                assert proc.poll() is None, f"sandbox exited early:\n{log.read_text()}"
                try:
                    reply = _http_get(addr, port)
                    last = f"connected, then got {reply!r}"
                except OSError as e:
                    reply = b""
                    last = f"{type(e).__name__}: {e}"
                if not reply:
                    time.sleep(0.5)

            if reply.startswith(b"HTTP/"):
                try:
                    v6 = f"connected, then got {_http_get('::1', port)!r}"
                except ConnectionRefusedError:
                    v6 = "refused"
                except OSError as e:
                    v6 = f"{type(e).__name__}: {e}"
        finally:
            proc.stdin.close()
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()

    assert reply.startswith(b"HTTP/"), (
        f"a server bound to {addr}:{port} inside the sandbox never answered on the host - "
        f"pasta needs --host-lo-to-ns-lo to deliver loopback connections to the netns's loopback\n"
        f"last attempt: {last} (refused = pasta never forwarded the port; "
        f"connected-then-empty = forwarded but not delivered)\n"
        f"sandbox stderr:\n{log.read_text()}"
    )
    assert v6 == "refused" or v6.startswith("connected, then got b'HTTP/"), (
        f"[::1]:{port} on the host gave: {v6} - a browser opening localhost tries ::1 "
        f"first and only falls back to 127.0.0.1 when refused; pasta's -t needs the "
        f"127.0.0.1/ host address"
    )


HOST_REPLY = b"host-service"


@contextlib.contextmanager
def _host_server(addr):
    """A TCP listener on the host at addr, answering every connection with
    HOST_REPLY; yields its port."""
    port = _free_non_ephemeral_port(socket.AF_INET, addr)
    if port is None:
        pytest.skip(f"no free non-ephemeral port on {addr} on this host")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((addr, port))
    server.listen()
    server.settimeout(0.2)
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                conn, _ = server.accept()
            except OSError:
                continue
            with conn:
                conn.sendall(HOST_REPLY)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        stop.set()
        thread.join()
        server.close()


def _probe_from_sandbox(project_dir, targets, extra_env=None):
    """Connect to each (addr, port) from inside the sandbox; return
    {addr: what came back} - the reply, or the error name."""
    code = (
        "import socket, sys\n"
        "for target in sys.argv[1:]:\n"
        "    addr, port = target.rsplit(':', 1)\n"
        "    try:\n"
        "        with socket.create_connection((addr, int(port)), timeout=3) as c:\n"
        "            got = c.recv(64).decode(errors='replace') or 'empty'\n"
        "    except OSError as e:\n"
        "        got = type(e).__name__\n"
        "    print(addr, got)\n"
    )
    args = " ".join(f"'{addr}:{port}'" for addr, port in targets)
    script = f"python3 -c \"$(cat <<'EOF'\n{code}EOF\n)\" {args}\n"
    result = run_sandbox(script, cwd=project_dir, extra_env=extra_env, timeout=60)
    assert result.returncode == 0, result.stderr
    return dict(
        line.split(" ", 1) for line in result.stdout.splitlines() if " " in line
    )


def _host_global_addrs():
    out = subprocess.run(
        ["ip", "-o", "addr", "show", "scope", "global"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [line.split()[3].split("/")[0] for line in out.splitlines()]


def test_host_loopback_port_is_not_reachable_by_default(project_dir):
    """pasta's default -T auto mirrored every host loopback listener into the
    netns - a host adb server on 127.0.0.1:5037 was usable from inside."""
    with _host_server("127.0.0.1") as port:
        got = _probe_from_sandbox(
            project_dir, [("127.0.0.1", port)], {"SANDBOX_HOST_PORTS": ""}
        )
    assert got["127.0.0.1"] != HOST_REPLY.decode(), (
        "host loopback port reachable without SANDBOX_HOST_PORTS"
    )


def test_listed_host_port_is_reachable(project_dir):
    with _host_server("127.0.0.1") as port:
        got = _probe_from_sandbox(
            project_dir, [("127.0.0.1", port)], {"SANDBOX_HOST_PORTS": f"1, {port}/tcp"}
        )
    assert got["127.0.0.1"] == HOST_REPLY.decode(), (
        f"listed port {port} not forwarded: {got}"
    )


def test_host_loopback_is_not_reachable_via_gateway(project_dir):
    """pasta's default --map-host-loopback translated the gateway address to
    the host's loopback, any port."""
    gateway = run_sandbox(
        "ip -4 route show default | awk '{print $3; exit}'\n", cwd=project_dir
    )
    assert gateway.returncode == 0, gateway.stderr
    gw = gateway.stdout.strip()
    if not gw:
        pytest.skip("no IPv4 default route in the sandbox")
    with _host_server("127.0.0.1") as port:
        got = _probe_from_sandbox(project_dir, [(gw, port)], {"SANDBOX_HOST_PORTS": ""})
    assert got[gw] != HOST_REPLY.decode(), f"host loopback reachable via gateway {gw}"


def test_host_addresses_are_not_reachable(project_dir):
    """A host service on all interfaces must not be reachable through any of
    the host's own addresses (tailscale, docker bridges, ...)."""
    addrs = [a for a in _host_global_addrs() if ":" not in a]
    if not addrs:
        pytest.skip("no global IPv4 address on this host")
    with _host_server("0.0.0.0") as port:
        got = _probe_from_sandbox(
            project_dir, [(a, port) for a in addrs], {"SANDBOX_HOST_PORTS": ""}
        )
    reached = [a for a in addrs if got.get(a) == HOST_REPLY.decode()]
    assert not reached, f"host service reachable via host address(es) {reached}: {got}"


SANDBOX_REPLY = b"sandbox-service"


@contextlib.contextmanager
def _sandbox_service(project_dir, tmp_path, port, extra_env=None):
    """A sandbox of project_dir running a TCP listener on 127.0.0.1:port inside
    that answers every connection with SANDBOX_REPLY, like a service from
    `devenv up`. Yields once the host's 127.0.0.1:port reaches it (pasta's
    `-t auto` forward); the sandbox stops on exit."""
    code = (
        "import socket\n"
        "s = socket.socket()\n"
        "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
        f"s.bind(('127.0.0.1', {port}))\n"
        "s.listen()\n"
        "while True:\n"
        "    c, _ = s.accept()\n"
        f"    c.sendall({SANDBOX_REPLY!r})\n"
        "    c.close()\n"
    )
    # `read` holds the sandbox open until stdin closes, as in
    # test_loopback_server_in_sandbox_is_reachable_from_host.
    script = f"python3 -c \"$(cat <<'EOF'\n{code}EOF\n)\" &\nread -r _\n"
    log = tmp_path / f"sandbox-service-{port}.log"
    with log.open("w") as stderr:
        proc = subprocess.Popen(
            [SANDBOX],
            env={
                **os.environ,
                "SANDBOX_STATE_DIR": str(project_dir.parent / "state"),
                **(extra_env or {}),
            },
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=stderr,
            cwd=project_dir,
            text=True,
            start_new_session=True,
        )
        try:
            proc.stdin.write(script)
            proc.stdin.flush()
            last = "no attempt made"
            deadline = time.monotonic() + 30
            while True:
                assert proc.poll() is None, f"sandbox exited early:\n{log.read_text()}"
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=2) as c:
                        got = c.recv(64)
                    if got == SANDBOX_REPLY:
                        break
                    last = f"connected, then got {got!r}"
                except OSError as e:
                    last = f"{type(e).__name__}: {e}"
                assert time.monotonic() < deadline, (
                    f"the service in the sandbox never answered on the host's "
                    f"127.0.0.1:{port}; last attempt: {last}\n"
                    f"sandbox stderr:\n{log.read_text()}"
                )
                time.sleep(0.5)
            yield
        finally:
            proc.stdin.close()
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()


def test_service_in_one_sandbox_is_reachable_from_another_through_the_host(
    project_dir, tmp_path
):
    """The README's devenv section: services from `devenv up` in one sandbox
    aren't on another sandbox's 127.0.0.1 (each has its own netns), but the
    second reaches them through the host when given the port in
    SANDBOX_HOST_PORTS."""
    port = _free_non_ephemeral_port(socket.AF_INET, "127.0.0.1")
    if port is None:
        pytest.skip("no free non-ephemeral port on 127.0.0.1 on this host")
    with _sandbox_service(project_dir, tmp_path, port):
        unlisted = _probe_from_sandbox(
            project_dir, [("127.0.0.1", port)], {"SANDBOX_HOST_PORTS": ""}
        )
        listed = _probe_from_sandbox(
            project_dir, [("127.0.0.1", port)], {"SANDBOX_HOST_PORTS": str(port)}
        )
    assert unlisted["127.0.0.1"] != SANDBOX_REPLY.decode(), (
        "a second sandbox reached the first's service without SANDBOX_HOST_PORTS - "
        "sandboxes of a project are expected to have separate netns"
    )
    assert listed["127.0.0.1"] == SANDBOX_REPLY.decode(), (
        f"a second sandbox with SANDBOX_HOST_PORTS={port} didn't reach the first's "
        f"service through the host: {listed}"
    )


def test_listed_host_port_cannot_be_bound_inside(project_dir):
    """The README's devenv section warns against `hostPorts` for a port a
    service in the same sandbox listens on: pasta holds a listed port inside
    to forward it to the host, so the service gets "address in use"."""
    port = _free_non_ephemeral_port(socket.AF_INET, "127.0.0.1")
    if port is None:
        pytest.skip("no free non-ephemeral port on 127.0.0.1 on this host")
    script = (
        "python3 - <<'PYEOF'\n"
        "import socket\n"
        "s = socket.socket()\n"
        "try:\n"
        f"    s.bind(('127.0.0.1', {port}))\n"
        "    print('BOUND')\n"
        "except OSError as e:\n"
        "    print('FAILED', e.errno == __import__('errno').EADDRINUSE)\n"
        "PYEOF\n"
    )
    result = run_sandbox(
        script, cwd=project_dir, extra_env={"SANDBOX_HOST_PORTS": str(port)}
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "FAILED True", (
        f"binding listed host port {port} inside gave {result.stdout.strip()!r}, "
        f"expected address in use - the README's hostPorts warning is wrong"
    )


@pytest.mark.parametrize("bad", ["0", "70000", "10-5", "abc", "22/sctp"])
def test_bad_host_ports_stop_the_sandbox(project_dir, bad):
    result = run_sandbox(
        "echo started\n", cwd=project_dir, extra_env={"SANDBOX_HOST_PORTS": bad}
    )
    assert result.returncode != 0
    assert "started" not in result.stdout
    assert "SANDBOX_HOST_PORTS" in result.stderr


def test_host_abstract_sockets_are_not_reachable(project_dir):
    """The old --share-net exposed the host's abstract @/tmp/.X11-unix/X<n>
    socket to anything in the sandbox - Xwayland accepts unauthenticated local
    connections on it, so that was enough to drive XTEST against every X
    client on the desktop. The abstract namespace belongs to the netns, and
    pasta's own must not have the host's sockets: one bound here, standing in
    for X11's, must be out of reach inside.
    """
    if shutil.which("python3") is None:
        pytest.skip("no python3 on this host to run the probe with")

    name = f"\0/tmp/.X11-unix/sandbox-test-{os.getpid()}"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(name)
        listener.listen(1)
        # Reachable outside, so the check inside means something.
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(name)

        probe = (
            "python3 - <<'PYEOF'\n"
            "import socket\n"
            "s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"
            "s.settimeout(2)\n"
            "try:\n"
            f"    s.connect({name!r})\n"
            "    print('CONNECTED')\n"
            "except OSError as e:\n"
            "    print('REFUSED', e)\n"
            "PYEOF\n"
        )
        result = run_sandbox(probe, cwd=project_dir)
    assert result.returncode == 0, result.stderr
    assert "CONNECTED" not in result.stdout, (
        "the sandbox can still reach the host's abstract sockets - "
        "--share-net is retaining the host's netns instead of pasta's"
    )


# -- seccomp --------------------------------------------------------


SECCOMP_PROBE = """python3 - <<'PYEOF'
import ctypes, errno, os, socket, termios

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long

def outcome(fn):
    try:
        fn()
        return "ok"
    except OSError as e:
        return errno.errorcode[e.errno]

def raw(nr, *args):
    if libc.syscall(ctypes.c_long(nr), *[ctypes.c_ulong(a) for a in args]) == -1:
        return errno.errorcode[ctypes.get_errno()]
    return "ok"

def tiocsti():
    _, pty = os.openpty()
    if libc.ioctl(pty, termios.TIOCSTI, ctypes.c_char_p(b"x")) == -1:
        return errno.errorcode[ctypes.get_errno()]
    return "ok"

print([l.split()[1] for l in open("/proc/self/status") if l.startswith("Seccomp:")][0])
print(outcome(lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM).close()))
print(outcome(lambda: socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET).close()))
print(raw(425, 1, 0))  # io_uring_setup
print(raw(250, 0, 0))  # keyctl
print(tiocsti())
PYEOF
"""


def test_seccomp_filter_is_applied(project_dir):
    """Each rule class in nix/seccomp.py, as the sandboxed process sees
    it - proves bwrap actually received the fd through pasta, not just that
    `--seccomp` is on the command line. TIOCSTI is EIO without the filter
    under dev.tty.legacy_tiocsti=0, so EPERM shows the filter itself is
    what stops it.
    """
    if shutil.which("python3") is None:
        pytest.skip("no python3 on this host to run the probe with")
    result = run_sandbox(SECCOMP_PROBE, cwd=project_dir)
    assert result.returncode == 0, result.stderr
    mode, inet, alg, io_uring, keyctl, tiocsti = result.stdout.split()
    assert mode == "2", "no seccomp filter is installed in the sandbox"
    assert inet == "ok", "the filter must not break ordinary networking"
    assert alg == "EAFNOSUPPORT"
    assert io_uring == "ENOSYS", (
        "io_uring should look absent so runtimes fall back to epoll"
    )
    assert keyctl == "EPERM"
    assert tiocsti == "EPERM"


# -- cleanup --------------------------------------------------------


def _guard_pids():
    out = subprocess.run(
        [
            "pgrep",
            "-f",
            "ssh-agent-guard|gh-api-proxy|forgejo-api-proxy|claude-api-proxy|secret-service-guard|open-url-guard",
        ],
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    return set(out.split())


def test_guards_do_not_survive_the_sandbox_exiting(project_dir):
    """Guards.close() waits for each guard, but give stragglers a few seconds
    instead of asserting on a single snapshot."""
    before = _guard_pids()
    result = run_sandbox("true\n", cwd=project_dir)
    assert result.returncode == 0, result.stderr
    leaked = _guard_pids() - before
    for _ in range(50):
        if not leaked:
            break
        time.sleep(0.1)
        leaked = _guard_pids() - before
    assert not leaked, f"guard process(es) survived sandbox exit: {leaked}"
