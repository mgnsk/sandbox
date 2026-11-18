"""Black-box tests for src/ssh-agent-guard, run as a program between a client
and a stand-in for the user's real agent: what reaches the agent, what's
answered, and what the popup shows."""

import os
import socket
import struct
import subprocess
import sys
import threading
import time

import pytest
from guards import FakePopups, Guard, base_env, short_dir

REQUEST_IDENTITIES, IDENTITIES_ANSWER, SIGN_REQUEST, FAILURE = 11, 12, 13, 5
SIGNATURE = bytes([14]) + b"signature-bytes"
FAIL = bytes([FAILURE])
MAX_MESSAGE_SIZE = 256 * 1024


def string(b):
    return struct.pack(">I", len(b)) + b


def frame(payload):
    return struct.pack(">I", len(payload)) + payload


def recv_frame(sock):
    """One frame, or None at EOF."""
    head = b""
    while len(head) < 4:
        chunk = sock.recv(4 - len(head))
        if not chunk:
            return None
        head += chunk
    (length,) = struct.unpack(">I", head)
    body = b""
    while len(body) < length:
        chunk = sock.recv(length - len(body))
        if not chunk:
            return None
        body += chunk
    return body


def identities_answer(pairs):
    body = struct.pack(">I", len(pairs))
    for key_blob, comment in pairs:
        body += string(key_blob) + string(comment)
    return bytes([IDENTITIES_ANSWER]) + body


def sign_request(key_blob=b"fake-key", data=None):
    payload = bytes([SIGN_REQUEST]) + string(key_blob)
    if data is not None:
        payload += string(data)
    return payload


def sshsig(namespace):
    """Signed data as `ssh-keygen -Y sign -n <namespace>` hands it to the agent."""
    return (
        b"SSHSIG"
        + string(namespace)
        + string(b"")
        + string(b"sha512")
        + string(b"h" * 64)
    )


class FakeAgent:
    """The user's real agent: records every frame it gets, answers
    identities with .identities and anything else with SIGNATURE."""

    def __init__(self, path):
        self.seen = []
        self.connections = 0
        self.identities = identities_answer([(b"fake-key", b"me@laptop")])
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.bind(str(path))
        self.sock.listen(8)
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            self.connections += 1
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        with conn:
            while (payload := recv_frame(conn)) is not None:
                self.seen.append(payload)
                if payload[:1] == bytes([REQUEST_IDENTITIES]):
                    conn.sendall(frame(self.identities))
                else:
                    conn.sendall(frame(SIGNATURE))

    def close(self):
        self.sock.close()


@pytest.fixture
def world():
    d = short_dir()
    agent = FakeAgent(d / "agent.sock")
    popups = FakePopups(d / "popup.sock")
    guards = []

    def start(popup=True, upstream=None):
        listen = d / f"guard{len(guards)}.sock"
        env = base_env(SANDBOX_POPUP_SOCKET=popups.path if popup else None)
        guard = Guard(
            "ssh-agent-guard",
            upstream or d / "agent.sock",
            listen,
            env=env,
            ready=listen,
        )
        guards.append(guard)
        return str(listen)

    yield start, agent, popups
    for guard in guards:
        guard.stop()
    popups.close()
    agent.close()


@pytest.fixture
def guard(world):
    start, agent, popups = world
    return start(), agent, popups


def exchange(path, *payloads):
    """Send each payload on one connection, reading the answer to each."""
    with socket.socket(socket.AF_UNIX) as sock:
        sock.connect(path)
        sock.settimeout(10)
        answers = []
        for payload in payloads:
            sock.sendall(frame(payload))
            answers.append(recv_frame(sock))
        return answers


# -- forwarding ------------------------------------------------------------------


def test_identities_are_forwarded(guard):
    path, agent, popups = guard
    assert exchange(path, bytes([REQUEST_IDENTITIES])) == [agent.identities]
    assert agent.seen == [bytes([REQUEST_IDENTITIES])]
    assert popups.requests == []


def test_sign_request_approved_in_the_popup_is_forwarded(guard):
    path, agent, popups = guard
    popups.answer = b"once"
    request = sign_request(data=b"session-id-and-packet-bytes")
    assert exchange(path, request) == [SIGNATURE]
    assert agent.seen == [request]
    [asked] = popups.requests
    assert asked["name"] == "ssh-agent-guard"
    assert asked["text"].startswith("Allow SSH agent to sign?\n\n")


def test_declined_sign_request_never_reaches_the_agent(guard):
    path, agent, _ = guard
    assert exchange(path, sign_request()) == [FAIL]
    assert agent.seen == []


def test_once_asks_again_and_always_stops_asking_for_this_guard(world):
    start, agent, popups = world
    popups.answer = b"once"
    path = start()
    assert exchange(path, sign_request(), sign_request()) == [SIGNATURE] * 2
    assert len(popups.requests) == 2
    popups.answer = b"always"
    # Across connections: "always" outlives the one that answered it.
    assert exchange(path, sign_request()) == [SIGNATURE]
    popups.answer = b"no"
    assert exchange(path, sign_request()) == [SIGNATURE]
    assert len(popups.requests) == 3
    # A new sandbox's guard asks again.
    assert exchange(start(), sign_request()) == [FAIL]
    assert len(popups.requests) == 4


@pytest.mark.parametrize("answer", [b"no", b"", b"garbage", b"once" * 100])
def test_anything_but_once_or_always_is_no(guard, answer):
    path, agent, popups = guard
    popups.answer = answer
    assert exchange(path, sign_request()) == [FAIL]
    assert agent.seen == []


def test_without_a_popup_socket_sign_requests_are_refused(world):
    start, agent, _ = world
    assert exchange(start(popup=False), sign_request()) == [FAIL]
    assert agent.seen == []


def test_commit_signature_skips_the_popup(guard):
    """A sign request whose data is an SSHSIG blob in git's namespace (commit
    and tag signing via `ssh-keygen -Y sign`) is forwarded without asking."""
    path, agent, popups = guard
    request = sign_request(data=sshsig(b"git"))
    assert exchange(path, request) == [SIGNATURE]
    assert agent.seen == [request]
    assert popups.requests == []


@pytest.mark.parametrize(
    "data",
    [sshsig(b"file"), sshsig(b"gitx"), b"SSHSIG", b"SSHSIG\xff\xff\xff\xffgit", None],
    ids=["file-namespace", "other-namespace", "truncated", "bad-length", "no-data"],
)
def test_other_sign_requests_ask(guard, data):
    """Only git's namespace skips the popup; other or malformed SSHSIG blobs
    are asked about (here: declined) like any other sign request."""
    path, agent, popups = guard
    assert exchange(path, sign_request(data=data)) == [FAIL]
    assert len(popups.requests) == 1
    assert agent.seen == []


@pytest.mark.parametrize(
    "msg_type",
    [
        17,  # ADD_IDENTITY
        18,  # REMOVE_IDENTITY
        19,  # REMOVE_ALL_IDENTITIES
        20,  # ADD_SMARTCARD_KEY
        21,  # REMOVE_SMARTCARD_KEY
        22,  # LOCK
        23,  # UNLOCK
        25,  # ADD_ID_CONSTRAINED
        26,  # ADD_SMARTCARD_KEY_CONSTRAINED
        27,  # EXTENSION
    ],
)
def test_message_types_outside_the_allowlist_are_refused(guard, msg_type):
    """Only identity listing and (gated) signing may reach the real agent.
    Everything else mutates agent state the sandbox has no business
    touching - LOCK in particular would wedge the user's agent."""
    path, agent, popups = guard
    popups.answer = b"always"
    assert exchange(path, bytes([msg_type]) + b"payload") == [FAIL]
    assert agent.seen == []
    assert popups.requests == []


# -- what the popup shows ------------------------------------------------------------


def test_popup_names_the_requester_and_the_key(guard, tmp_path):
    path, _, popups = guard
    # The comment comes from an identities answer earlier on any connection.
    exchange(path, bytes([REQUEST_IDENTITIES]))
    client = tmp_path / "client.py"
    client.write_text(
        "import socket, sys\n"
        "s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[2])\n"
        f"s.sendall({frame(sign_request(data=b'session'))!r}); s.recv(64)\n"
    )
    subprocess.run(
        [sys.executable, client, "marker-arg", path], cwd=tmp_path, check=True
    )
    [text] = popups.texts
    assert f"  cwd:      {tmp_path}\n" in text
    assert f"  command:  {sys.executable} {client} marker-arg " in text
    assert "  comment:  me@laptop\n" in text


def test_popup_says_unknown_for_a_key_never_listed(guard):
    path, _, popups = guard
    exchange(path, bytes([REQUEST_IDENTITIES]), sign_request(b"other-key", b"session"))
    assert "  comment:  unknown\n" in popups.texts[0]


def test_popup_strips_escapes_and_truncates(guard):
    path, agent, popups = guard
    agent.identities = identities_answer([(b"fake-key", b"\x1b[31mred" + b"a" * 300)])
    exchange(path, bytes([REQUEST_IDENTITIES]), sign_request(data=b"session"))
    [text] = popups.texts
    assert "\x1b" not in text
    comment = text.split("  comment:  ", 1)[1].rstrip("\n")
    assert comment == "?[31mred" + "a" * 192 + "…"


def test_malformed_identities_answer_is_relayed_and_ignored(guard):
    path, agent, popups = guard
    # Claims 5 keys but has no key/comment data to back that up.
    agent.identities = bytes([IDENTITIES_ANSWER]) + struct.pack(">I", 5)
    assert exchange(path, bytes([REQUEST_IDENTITIES])) == [agent.identities]
    exchange(path, sign_request(data=b"session"))
    assert "  comment:  unknown\n" in popups.texts[0]


def test_peer_is_sampled_once_at_connect(guard, tmp_path):
    """The popup describes the process that connected, even when what sends
    the request is something else by then - otherwise a peer that exited
    could have its pid reused by an unrelated host process, which the popup
    would then blame. Here the connecting process execs into another."""
    path, _, popups = guard
    sender = tmp_path / "sender.py"
    sender.write_text(
        "import socket, sys\n"
        "s = socket.socket(fileno=int(sys.argv[2]))\n"
        f"s.sendall({frame(sign_request(data=b'session'))!r}); s.recv(64)\n"
    )
    connector = tmp_path / "connector.py"
    connector.write_text(
        "import os, socket, sys, time\n"
        "s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[2])\n"
        "time.sleep(0.3)\n"
        "os.set_inheritable(s.fileno(), True)\n"
        f"os.execv(sys.executable, [sys.executable, {str(sender)!r}, 'after-exec', str(s.fileno())])\n"
    )
    subprocess.run(
        [sys.executable, connector, "before-exec", path], check=True, timeout=20
    )
    [text] = popups.texts
    assert "before-exec" in text
    assert "after-exec" not in text


# -- framing ------------------------------------------------------------------------


def test_oversized_length_closes_the_connection_unread(guard):
    path, agent, _ = guard
    with socket.socket(socket.AF_UNIX) as sock:
        sock.connect(path)
        sock.settimeout(10)
        sock.sendall(struct.pack(">I", MAX_MESSAGE_SIZE + 1))
        assert sock.recv(1) == b""
    assert agent.seen == []


def test_a_message_at_the_size_limit_is_forwarded(guard):
    path, agent, _ = guard
    payload = bytes([REQUEST_IDENTITIES]) + b"x" * (MAX_MESSAGE_SIZE - 1)
    assert exchange(path, payload) == [agent.identities]
    assert agent.seen == [payload]


def test_close_mid_message_forwards_nothing(guard):
    path, agent, _ = guard
    with socket.socket(socket.AF_UNIX) as sock:
        sock.connect(path)
        sock.sendall(struct.pack(">I", 10) + b"abc")
    time.sleep(0.3)
    assert agent.seen == []


def test_empty_messages_are_skipped(guard):
    path, agent, _ = guard
    with socket.socket(socket.AF_UNIX) as sock:
        sock.connect(path)
        sock.settimeout(10)
        sock.sendall(frame(b"") + frame(bytes([REQUEST_IDENTITIES])))
        assert recv_frame(sock) == agent.identities


def test_unreachable_agent_closes_the_client(world):
    start, _, _ = world
    path = start(upstream=short_dir() / "nope.sock")
    with socket.socket(socket.AF_UNIX) as sock:
        sock.connect(path)
        sock.settimeout(10)
        assert sock.recv(1) == b""


def test_an_agent_that_hangs_up_closes_the_client(world):
    start, _, _ = world
    d = short_dir()
    server = socket.socket(socket.AF_UNIX)
    server.bind(str(d / "a.sock"))
    server.listen(1)

    def hang_up():
        conn, _ = server.accept()
        recv_frame(conn)
        conn.close()

    threading.Thread(target=hang_up, daemon=True).start()
    path = start(upstream=d / "a.sock")
    assert exchange(path, bytes([REQUEST_IDENTITIES])) == [None]
    server.close()


def test_a_stale_socket_is_replaced(world):
    start, agent, _ = world
    d = short_dir()
    (d / "listen.sock").write_text("left over")
    guard = Guard(
        "ssh-agent-guard", agent.sock.getsockname(), d / "listen.sock", env=base_env()
    )
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                assert exchange(str(d / "listen.sock"), bytes([REQUEST_IDENTITIES]))
                break
            except OSError:
                time.sleep(0.05)
        else:
            pytest.fail("never listened")
    finally:
        guard.stop()
    assert os.path.exists(d / "listen.sock")
