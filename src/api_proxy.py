"""The HTTP-over-unix-socket proxy behind the sandbox's API guards
(gh-api-proxy, forgejo-api-proxy).

Each guard runs on the host, listening on a private socket that the sandbox launcher
binds in. A patched client inside sends its API requests there as plain HTTP,
with the real host in Host. The proxy holds the real token, which never enters
the sandbox, and per request:

  - refuses malformed requests and hosts the guard doesn't allow;
  - forwards reads as-is, and holds writes for the user's approval in a tmux
    popup (the guard decides what counts as a write);
  - drops the client's Authorization and adds the guard's own, then relays
    the request to the real host over HTTPS.

ProxyServer's policy methods are what a guard overrides.
"""

import http.client
import json
import shlex
import socket
import socketserver
import ssl
import struct
from http.server import BaseHTTPRequestHandler
from pathlib import Path

import guard_popup

CHUNK = 64 * 1024

# Hop-by-hop headers (RFC 9110 7.6.1) plus the ones this proxy sets itself.
# Expect is answered locally by http.server before the request reaches us.
DROP_REQUEST_HEADERS = frozenset(
    {
        "host",
        "authorization",
        "connection",
        "keep-alive",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "expect",
    }
)
DROP_RESPONSE_HEADERS = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-connection",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)


def clean(s):
    """Strip non-printable chars (e.g. terminal escapes) for safe display,
    keeping line breaks. Never truncates: a write is approved for exactly
    what's shown."""
    return "\n".join(
        "".join(c if c.isprintable() else "?" for c in line) for line in s.split("\n")
    )


def peer_pid(sock):
    """PID of the process on the other end of a connected AF_UNIX socket."""
    creds = sock.getsockopt(
        socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
    )
    pid, _uid, _gid = struct.unpack("3i", creds)
    return pid


def peer_cmdline(pid):
    """Best-effort command line of pid, read from the host's /proc."""
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return "unknown"
    parts = [p.decode("utf-8", "replace") for p in raw.split(b"\0") if p]
    return shlex.join(parts) if parts else "unknown"


def open_upstream(host):
    """A TLS connection to the real host ("name" or "name:port")."""
    return http.client.HTTPSConnection(
        host, timeout=300, context=ssl.create_default_context()
    )


class Handler(BaseHTTPRequestHandler):
    """One request per connection: validate, classify, approve, forward."""

    protocol_version = "HTTP/1.1"
    timeout = 60  # For reading the request.

    def log_message(self, format, *args):  # pylint: disable=redefined-builtin
        pass

    def do_GET(self):  # pylint: disable=invalid-name
        """Every method goes through proxy()."""
        self.proxy()

    do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_GET

    def refuse(self, status, message):
        """Answer with an error the client shows as its message."""
        body = json.dumps({"message": f"{self.server.name}: {message}"}).encode()
        try:
            self.send_response_only(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
        except OSError:
            pass  # Client already gone.

    def check_request(self):
        """(host, body length) of a well-formed request to an allowed host,
        else None after refusing it. One Host and at most one Content-Length:
        this proxy and upstream must agree on both."""
        hosts = self.headers.get_all("Host") or []
        lengths = self.headers.get_all("Content-Length") or ["0"]
        host = hosts[0].lower().removesuffix(":443") if len(hosts) == 1 else ""
        if not self.path.startswith("/"):
            self.refuse(400, "expected an origin-form request target")
        elif not self.server.host_allowed(host):
            self.refuse(403, self.server.host_refusal(clean(host)))
        elif "Transfer-Encoding" in self.headers:
            self.refuse(411, "chunked request bodies are not supported")
        elif len(lengths) != 1 or not lengths[0].isdigit():
            self.refuse(400, "bad Content-Length")
        else:
            return host, int(lengths[0])
        return None

    def proxy(self):
        """Forward the request, after approval if it writes."""
        self.close_connection = True  # pylint: disable=attribute-defined-outside-init
        checked = self.check_request()
        if checked is None:
            return None
        host, length = checked

        body = None
        limit = self.server.body_limit(host, self.path)
        if limit is not None:
            if length > limit:
                return self.refuse(413, "request body too large to classify")
            body = self.rfile.read(length)
            if len(body) != length:
                return None

        description = self.server.describe_write(self.command, host, self.path, body)
        if description is not None and not self.server.approve(
            self.connection, description
        ):
            return self.refuse(403, "declined by user")
        return self.forward(host, length, body)

    def forward(self, host, length, body):
        """Send the request upstream and stream the response back."""
        conn = self.server.open_upstream(host)
        try:
            try:
                self.send_upstream(conn, host, length, body)
                response = conn.getresponse()
            except (OSError, http.client.HTTPException) as e:
                return self.refuse(502, f"upstream error: {e}")
            self.relay_response(response)
        finally:
            conn.close()
        return None

    def send_upstream(self, conn, host, length, body):
        """Request line, the client's headers minus DROP_REQUEST_HEADERS, the
        guard's Authorization if any, then the body - already read, or
        streamed from the client."""
        conn.putrequest(
            self.command, self.path, skip_host=True, skip_accept_encoding=True
        )
        conn.putheader("Host", host)
        for name, value in self.headers.items():
            if name.lower() not in DROP_REQUEST_HEADERS:
                conn.putheader(name, value)
        authorization = self.server.authorization(host)
        if authorization is not None:
            conn.putheader("Authorization", authorization)
        conn.endheaders()
        if body is not None:
            conn.send(body)
            return
        remaining = length
        while remaining:
            chunk = self.rfile.read(min(CHUNK, remaining))
            if not chunk:
                raise OSError("client closed the connection mid-body")
            conn.send(chunk)
            remaining -= len(chunk)

    def relay_response(self, response):
        """Upstream's status, headers minus DROP_RESPONSE_HEADERS, and body."""
        try:
            self.send_response_only(response.status, response.reason)
            for name, value in response.getheaders():
                if name.lower() not in DROP_RESPONSE_HEADERS:
                    self.send_header(name, value)
            # Close-delimited when upstream was chunked (no Content-Length).
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                while chunk := response.read(CHUNK):
                    self.wfile.write(chunk)
        except (OSError, http.client.HTTPException):
            pass  # Client or upstream went away mid-response.


class ProxyServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    """A guard's socket server. upstream and confirm are injectable for
    tests; a guard overrides name, popup_title and the policy methods."""

    daemon_threads = True

    name = "api-proxy"
    popup_title = "Allow sandboxed API write?"

    def __init__(self, path, upstream=open_upstream, confirm=None):
        super().__init__(path, Handler)
        self.open_upstream = upstream
        self.confirm = confirm or self.confirm_via_tmux
        self._approvals = guard_popup.Approvals()

    # -- policy ---------------------------------------------------------------

    def host_allowed(self, host):
        """Whether requests to host are forwarded at all."""
        raise NotImplementedError

    def host_refusal(self, host):
        """The message refusing a host that isn't allowed."""
        return f"host not allowed: {host}"

    def body_limit(self, host, path):
        """None to stream the request body, else read it in full (up to this
        many bytes) and hand it to describe_write."""
        return None

    def describe_write(self, method, host, path, body):
        """None if the request only reads, else a description of the write
        for the approval popup."""
        target = f"{method} {host}{path}"
        return None if method in ("GET", "HEAD") else target

    def authorization(self, host):
        """The Authorization header to send to host, or None for none."""
        raise NotImplementedError

    # -- approval -------------------------------------------------------------

    def confirm_via_tmux(self, description, cmdline):
        """Ask in a tmux popup whether to allow a write - see guard_popup.ask
        for the answers."""
        text = f"{self.popup_title}\n\n  process:  {clean(cmdline)}\n\n{clean(description)}\n"
        return guard_popup.ask(self.name, text, "less -FRX {}", "90%", "80%")

    def approve(self, sock, description):
        """Whether to let a write through, per the popup or an earlier
        "always" answer."""
        try:
            pid = peer_pid(sock)
        except OSError:
            pid = None
        return self._approvals.approve(
            lambda: self.confirm(description, peer_cmdline(pid) if pid else "unknown")
        )
