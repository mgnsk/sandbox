"""A throwaway certificate authority for an HTTPS-intercepting guard proxy.

Each proxy makes its own at startup. The key lives only in that process's
memory and dies with it; only the certificate leaves it, into the bundle the
sandbox's gh and fj wrappers trust. Leaf certificates are minted on demand,
one per host the proxy is asked to CONNECT to.
"""

import datetime
import ipaddress
import os
import ssl
import tempfile
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

# Leaves outlive any sandbox session; the CA itself dies with the proxy.
LEAF_VALIDITY = datetime.timedelta(days=30)
CA_VALIDITY = datetime.timedelta(days=365)
# Some slack for clock differences between host and clients.
BACKDATE = datetime.timedelta(hours=1)


def _name(common_name):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _san(host):
    try:
        return x509.IPAddress(ipaddress.ip_address(host))
    except ValueError:
        return x509.DNSName(host)


class CA:
    """A CA key and certificate, and an SSLContext per host signed by it."""

    def __init__(self, name):
        now = datetime.datetime.now(datetime.UTC)
        self._key = ec.generate_private_key(ec.SECP256R1())
        public = self._key.public_key()
        self.cert = (
            x509.CertificateBuilder()
            .subject_name(_name(name))
            .issuer_name(_name(name))
            .public_key(public)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - BACKDATE)
            .not_valid_after(now + CA_VALIDITY)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(public), critical=False
            )
            .sign(self._key, hashes.SHA256())
        )
        self._contexts = {}
        self._lock = threading.Lock()

    def pem(self):
        """The CA certificate, PEM-encoded."""
        return self.cert.public_bytes(serialization.Encoding.PEM)

    def context(self, host):
        """A server-side SSLContext presenting a certificate for host
        (a DNS name or IP address, without a port)."""
        with self._lock:
            ctx = self._contexts.get(host)
            if ctx is None:
                ctx = self._contexts[host] = self._make_context(host)
            return ctx

    def _leaf(self, host):
        now = datetime.datetime.now(datetime.UTC)
        key = ec.generate_private_key(ec.SECP256R1())
        cert = (
            x509.CertificateBuilder()
            .subject_name(_name(host))
            .issuer_name(self.cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - BACKDATE)
            .not_valid_after(now + LEAF_VALIDITY)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
            )
            .add_extension(x509.SubjectAlternativeName([_san(host)]), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self._key.public_key()
                ),
                critical=False,
            )
            .sign(self._key, hashes.SHA256())
        )
        return cert, key

    def _make_context(self, host):
        cert, key = self._leaf(host)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        # One request per connection, over HTTP/1.1 - no h2.
        ctx.set_alpn_protocols(["http/1.1"])
        # load_cert_chain only takes files: a private dir, gone right after.
        with tempfile.TemporaryDirectory(prefix="mitm-ca-") as tmp:
            path = os.path.join(tmp, "leaf.pem")
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
                f.write(self.pem())
                f.write(
                    key.private_bytes(
                        serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption(),
                    )
                )
            ctx.load_cert_chain(path)
        return ctx
