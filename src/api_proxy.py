"""The proxies behind the sandbox's API guards (gh-api-proxy,
forgejo-api-proxy, claude-api-proxy). Each guard runs on the host and holds
the real token, which never enters the sandbox. Clients inside reach it one
of two ways:

  - ProxyServer: plain HTTP over a private unix socket the launcher binds
    in, with the real host in Host (Claude Code's ANTHROPIC_UNIX_SOCKET).
  - HttpsProxyServer: an HTTPS_PROXY on the host's loopback, which pasta
    maps into the sandbox. A client CONNECTs (with the per-launch secret in
    Proxy-Authorization), the proxy answers the TLS handshake itself with a
    certificate from its own throwaway CA (mitm_ca), which only the sandbox's
    gh and fj wrappers trust, and reads the request inside.

Either way, per request, the proxy:

  - refuses malformed requests, and hosts and paths the guard doesn't allow;
  - forwards reads as-is, and holds writes for the user's approval in a popup
    (the guard decides what counts as a write);
  - drops the client's Authorization (and any other credential header the
    guard names) and adds the guard's own, then relays the request to the
    real host over HTTPS.

ProxyServer's policy methods are what a guard overrides.
"""

import base64
import hmac
import http.client
import json
import os
import re
import secrets
import shlex
import socket
import socketserver
import ssl
import struct
import threading
from http.server import BaseHTTPRequestHandler
from pathlib import Path

import guard_popup
import mitm_ca

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


# What `sandbox --gh-token` / `--fj-token` accept: no whitespace or control
# characters, so a token can't smuggle a header into a request.
TOKEN_RE = re.compile(r"^[A-Za-z0-9_.~+/=-]{8,1024}$")


def read_token(path):
    """The project token in the file at path (written by the launcher, out of
    the sandbox's reach), or None if it's missing or malformed. Read per
    request, so setting one reaches running sandboxes."""
    try:
        token = Path(path).read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError):
        return None
    return token if TOKEN_RE.match(token) else None


def read_tokens(path):
    """{host: token} from the JSON file at path, keeping only well-formed
    entries; empty if it's missing or unreadable."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {
        host.lower(): token
        for host, token in data.items()
        if isinstance(host, str) and isinstance(token, str) and TOKEN_RE.match(token)
    }


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


def open_tunnel(name, port):
    """A TCP connection to the real host, for a tunnel left alone."""
    return socket.create_connection((name, port), timeout=300)


def relay(client, upstream):
    """Copy bytes both ways until both sides are done."""

    def pump(src, dst):
        try:
            while data := src.recv(CHUNK):
                dst.sendall(data)
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    back = threading.Thread(target=pump, args=(upstream, client), daemon=True)
    back.start()
    pump(client, upstream)
    back.join()


class RefusingHandler(BaseHTTPRequestHandler):
    """Quiet, and refuses with a message the client shows."""

    protocol_version = "HTTP/1.1"
    timeout = 60  # For reading the request.

    def log_message(self, format, *args):  # pylint: disable=redefined-builtin
        pass

    def refuse(self, status, message, headers=()):
        """Answer with an error the client shows as its message."""
        body = json.dumps({"message": f"{self.server.name}: {message}"}).encode()
        try:
            self.send_response_only(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            for name, value in headers:
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)
        except OSError:
            pass  # Client already gone.


class Handler(RefusingHandler):
    """One request per connection: validate, classify, approve, forward.

    tunnel_host is the CONNECT target ("host" or "host:port") for a request
    read inside a tunnel; its Host must name the same."""

    tunnel_host = None

    def do_GET(self):  # pylint: disable=invalid-name
        """Every method goes through proxy()."""
        self.proxy()

    do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_GET

    def check_request(self):
        """(host, body length) of a well-formed request to an allowed host,
        else None after refusing it. One Host and at most one Content-Length:
        this proxy and upstream must agree on both."""
        hosts = self.headers.get_all("Host") or []
        lengths = self.headers.get_all("Content-Length") or ["0"]
        host = hosts[0].lower().removesuffix(":443") if len(hosts) == 1 else ""
        if not self.path.startswith("/"):
            self.refuse(400, "expected an origin-form request target")
        elif self.tunnel_host is not None and host != self.tunnel_host:
            self.refuse(421, f"Host {clean(host)} isn't the CONNECT target")
        elif not self.server.host_allowed(host):
            self.refuse(403, self.server.host_refusal(clean(host)))
        elif not self.server.path_allowed(host, self.path):
            self.refuse(403, f"path not allowed: {clean(self.path)}")
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
        host = self.server.upstream_host(host)
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
        guard's credentials, then the body - already read, or
        streamed from the client."""
        conn.putrequest(
            self.command, self.path, skip_host=True, skip_accept_encoding=True
        )
        conn.putheader("Host", host)
        drop = DROP_REQUEST_HEADERS | self.server.credential_headers
        for name, value in self.headers.items():
            if name.lower() not in drop:
                conn.putheader(name, value)
        for name, value in self.server.credentials(host):
            conn.putheader(name, value)
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
                # read1: whatever has arrived, so event streams aren't held
                # back until CHUNK bytes pile up.
                while chunk := response.read1(CHUNK):
                    self.wfile.write(chunk)
        except (OSError, http.client.HTTPException):
            pass  # Client or upstream went away mid-response.


class TunnelHandler(Handler):
    """Handler for the one request inside a CONNECT tunnel."""

    def __init__(self, request, client_address, server, tunnel_host):
        self.tunnel_host = tunnel_host
        super().__init__(request, client_address, server)


# host:port, as a client CONNECTs to it. No IPv6 literals.
CONNECT_RE = re.compile(r"^([a-z0-9.-]+):([0-9]{1,5})$")


class ConnectHandler(RefusingHandler):
    """Answers a CONNECT, then the TLS handshake inside it with a
    certificate for the target, and hands the tunnel to TunnelHandler."""

    def do_CONNECT(self):  # pylint: disable=invalid-name
        """Authenticate, open the tunnel, intercept it."""
        self.close_connection = True  # pylint: disable=attribute-defined-outside-init
        if not self.server.authorized(self.headers.get_all("Proxy-Authorization")):
            return self.refuse(
                407,
                "proxy authentication required",
                [("Proxy-Authenticate", 'Basic realm="sandbox"')],
            )
        match = CONNECT_RE.match(self.path.lower())
        if not match or not 0 < int(match[2]) < 65536:
            return self.refuse(400, f"bad CONNECT target: {clean(self.path)}")
        name, port = match[1], match[2]
        host = name if port == "443" else f"{name}:{port}"
        if self.server.tunnel_allowed(host):
            return self.tunnel(name, int(port))
        try:
            self.send_response_only(200, "Connection Established")
            self.end_headers()
            tls = self.server.ca.context(name).wrap_socket(
                self.connection, server_side=True
            )
        except (OSError, ssl.SSLError):
            return None  # Client gone, or didn't trust the certificate.
        try:
            TunnelHandler(tls, self.client_address, self.server, host)
        except (OSError, ssl.SSLError):
            pass
        finally:
            close_tls(tls)
        return None

    def tunnel(self, name, port):
        """Connect the client to the real host, without looking inside."""
        try:
            upstream = self.server.open_tunnel(name, port)
        except OSError as e:
            return self.refuse(502, f"upstream error: {e}")
        with upstream:
            try:
                self.send_response_only(200, "Connection Established")
                self.end_headers()
            except OSError:
                return None
            self.connection.settimeout(300)
            relay(self.connection, upstream)
        return None

    def do_GET(self):  # pylint: disable=invalid-name
        """Plain-HTTP proxying isn't offered: everything goes over CONNECT."""
        self.close_connection = True  # pylint: disable=attribute-defined-outside-init
        self.refuse(405, "only CONNECT")

    do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_GET


def close_tls(tls):
    """Close with a close_notify: responses here are close-delimited, and
    rustls (fj) takes an EOF without one as a truncated body."""
    try:
        tls.settimeout(2)
        tls.unwrap()
    except (OSError, ValueError, ssl.SSLError):
        pass
    finally:
        tls.close()


class Policy:
    """What a guard decides, shared by both transports. upstream and confirm
    are injectable for tests; a guard overrides name, popup_title and the
    policy methods."""

    name = "api-proxy"
    popup_title = "Allow sandboxed API write?"

    def __init__(self, upstream=open_upstream, confirm=None, tunnel=open_tunnel):
        self.open_upstream = upstream
        self.open_tunnel = tunnel
        self.confirm = confirm or self.confirm_via_popup
        self._approvals = guard_popup.Approvals()

    # -- policy ---------------------------------------------------------------

    def host_allowed(self, host):
        """Whether requests to host are forwarded at all."""
        raise NotImplementedError

    def tunnel_allowed(self, host):
        """Whether a CONNECT to host ("name" or "name:port") is passed
        through as it is, unread: hosts that get no credentials, which the
        client's children (git under gh) may reach too."""
        return False

    def path_allowed(self, host, path):
        """Whether requests for path (with its query) on host are forwarded."""
        return True

    def upstream_host(self, host):
        """The host to forward an allowed request for host to."""
        return host

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

    # Client headers dropped besides Authorization (lower case): ones that
    # carry credentials the guard replaces.
    credential_headers = frozenset()

    def authorization(self, host):
        """The Authorization header to send to host, or None for none."""
        raise NotImplementedError

    def credentials(self, host):
        """[(name, value)] credential headers to send to host."""
        authorization = self.authorization(host)
        return [] if authorization is None else [("Authorization", authorization)]

    # -- approval -------------------------------------------------------------

    def peer_cmdline(self, sock):
        """The requesting process's command line, or None if unknowable."""
        return None

    def confirm_via_popup(self, description, cmdline):
        """Ask in a popup whether to allow a write - see guard_popup.ask
        for the answers."""
        process = f"  process:  {clean(cmdline)}\n\n" if cmdline else ""
        text = f"{self.popup_title}\n\n{process}{clean(description)}\n"
        return guard_popup.ask(self.name, text)

    def approve(self, sock, description):
        """Whether to let a write through, per the popup or an earlier
        "always" answer."""
        return self._approvals.approve(
            lambda: self.confirm(description, self.peer_cmdline(sock))
        )


class ProxyServer(Policy, socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    """A guard on a unix socket, taking plain HTTP."""

    daemon_threads = True

    def __init__(self, path, upstream=open_upstream, confirm=None):
        Policy.__init__(self, upstream=upstream, confirm=confirm)
        socketserver.UnixStreamServer.__init__(self, path, Handler)

    def peer_cmdline(self, sock):
        try:
            pid = peer_pid(sock)
        except OSError:
            return "unknown"
        return peer_cmdline(pid) if pid else "unknown"


class HttpsProxyServer(Policy, socketserver.ThreadingMixIn, socketserver.TCPServer):
    """A guard as an intercepting HTTPS_PROXY on address. The peer is pasta,
    so the popup can't name the requesting process."""

    daemon_threads = True
    allow_reuse_address = False

    def __init__(
        self,
        address=("127.0.0.1", 0),
        secret=None,
        ca=None,
        upstream=open_upstream,
        confirm=None,
        tunnel=open_tunnel,
    ):
        Policy.__init__(self, upstream=upstream, confirm=confirm, tunnel=tunnel)
        socketserver.TCPServer.__init__(self, address, ConnectHandler)
        self.ca = ca or mitm_ca.CA(f"sandbox {self.name}")
        self.secret = secret or secrets.token_urlsafe(32)
        token = base64.b64encode(f"sandbox:{self.secret}".encode()).decode()
        self._expected_auth = f"Basic {token}".encode()

    @property
    def proxy_url(self):
        """HTTPS_PROXY for a client, the secret included."""
        host, port = self.server_address[:2]
        return f"http://sandbox:{self.secret}@{host}:{port}"

    def authorized(self, values):
        """Whether Proxy-Authorization (all its values) carries the secret."""
        return (
            values is not None
            and len(values) == 1
            and hmac.compare_digest(values[0].strip().encode(), self._expected_auth)
        )

    def announce(self, state_dir):
        """Write ca.pem, then proxy.json ({"port", "secret"}) - the launcher
        waits for the latter. state_dir is private to the launcher's user."""
        Path(state_dir, "ca.pem").write_bytes(self.ca.pem())
        info = json.dumps({"port": self.server_address[1], "secret": self.secret})
        tmp = Path(state_dir, ".proxy.json")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(info)
        os.replace(tmp, Path(state_dir, "proxy.json"))
