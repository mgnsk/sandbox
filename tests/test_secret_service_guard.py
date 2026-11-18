"""Black-box tests for src/secret-service-guard, run as a program on a
private D-Bus bus, as the launcher runs it, and spoken to over D-Bus like
libsecret clients (gh's go-keyring, Python keyring, ...) do."""

import asyncio
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import time

import pytest
from dbus_fast import Message, MessageType, Variant
from dbus_fast.aio import MessageBus
from guards import Guard, base_env, short_dir

DBUS_DAEMON = shutil.which("dbus-daemon")
pytestmark = pytest.mark.skipif(DBUS_DAEMON is None, reason="needs dbus-daemon")

SERVICE = "org.freedesktop.secrets"
SERVICE_PATH = "/org/freedesktop/secrets"
COLLECTION = "/org/freedesktop/secrets/aliases/default"
ITEM = "org.freedesktop.Secret.Item"

BUS_CONF = """<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:path={sock}</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>
"""


class World:
    """A private bus, and the guard on it with its database."""

    def __init__(self):
        self.dir = short_dir()
        self.sock = self.dir / "bus.sock"
        (self.dir / "bus.conf").write_text(BUS_CONF.format(sock=self.sock))
        self.daemon = subprocess.Popen(
            [
                DBUS_DAEMON,
                f"--config-file={self.dir / 'bus.conf'}",
                "--nofork",
                "--nopidfile",
            ]
        )
        deadline = time.monotonic() + 10
        while not self.sock.exists():
            assert time.monotonic() < deadline and self.daemon.poll() is None
            time.sleep(0.02)
        self.db = self.dir / "secrets.sqlite3"
        self.guard = None

    def start(self):
        ready = self.dir / "ready"
        if ready.exists():
            ready.unlink()
        self.guard = Guard(
            "secret-service-guard",
            f"unix:path={self.sock}",
            self.db,
            ready,
            env=base_env(),
            ready=ready,
        )

    def restart(self):
        self.guard.stop()
        self.start()

    def close(self):
        if self.guard:
            self.guard.stop()
        self.daemon.terminate()
        self.daemon.wait()

    def call(self, path, interface, member, signature="", body=()):
        return asyncio.run(self._call(path, interface, member, signature, list(body)))

    async def _call(self, path, interface, member, signature, body):
        bus = await MessageBus(bus_address=f"unix:path={self.sock}").connect()
        try:
            reply = await bus.call(
                Message(
                    destination=SERVICE,
                    path=path,
                    interface=interface,
                    member=member,
                    signature=signature,
                    body=body,
                )
            )
        finally:
            bus.disconnect()
        if reply.message_type == MessageType.ERROR:
            raise RuntimeError(reply.error_name)
        return reply.body

    # -- the Secret Service API, as a client sees it ----------------------------

    def open_session(self):
        return self.call(
            SERVICE_PATH,
            "org.freedesktop.Secret.Service",
            "OpenSession",
            "sv",
            ["plain", Variant("s", "")],
        )

    def create(
        self, label, attributes, secret, replace=True, content_type="text/plain"
    ):
        properties = {
            f"{ITEM}.Label": Variant("s", label),
            f"{ITEM}.Attributes": Variant("a{ss}", attributes),
        }
        item, prompt = self.call(
            COLLECTION, "org.freedesktop.Secret.Collection", "CreateItem", "a{sv}(oayays)b",
            [properties, ["/org/freedesktop/secrets/session/s1", b"", secret, content_type], replace],
        )  # fmt: skip
        assert prompt == "/"
        return item

    def search(self, attributes):
        return self.call(COLLECTION, "org.freedesktop.Secret.Collection", "SearchItems", "a{ss}", [attributes])[0]  # fmt: skip

    def get(self, item):
        session, params, value, content_type = self.call(
            item, ITEM, "GetSecret", "o", ["/s"]
        )[0]
        assert (session, params) == ("/s", b"")
        return bytes(value), content_type

    def delete(self, item):
        assert self.call(item, ITEM, "Delete") == ["/"]


@pytest.fixture
def world():
    w = World()
    w.start()
    yield w
    w.close()


def mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def test_store_search_and_get(world):
    item = world.create("label", {"service": "gh", "account": "me"}, b"secret1")
    assert world.search({"service": "gh"}) == [item]
    assert world.search({"service": "gh", "account": "me"}) == [item]
    assert world.search({"service": "gh", "account": "someone-else"}) == []
    assert world.search({}) == [item]
    assert world.get(item) == (b"secret1", "text/plain")


def test_replace_updates_an_item_with_the_same_attributes_only(world):
    attrs = {"service": "gh"}
    first = world.create("label1", attrs, b"old")
    assert world.create("label2", attrs, b"new") == first
    assert world.get(first) == (b"new", "text/plain")
    assert world.search(attrs) == [first]
    # Exactly the same attributes: a superset is another item.
    other = world.create("label3", {"service": "gh", "account": "me"}, b"x")
    assert other != first
    assert world.get(first) == (b"new", "text/plain")


def test_without_replace_a_duplicate_is_added(world):
    attrs = {"service": "gh"}
    a = world.create("label1", attrs, b"old", replace=False)
    b = world.create("label2", attrs, b"new", replace=False)
    assert a != b
    assert sorted(world.search(attrs)) == sorted([a, b])


def test_secrets_are_bytes_and_keep_their_content_type(world):
    item = world.create(
        "bin", {"k": "v"}, bytes(range(256)), content_type="application/octet-stream"
    )
    assert world.get(item) == (bytes(range(256)), "application/octet-stream")


def test_delete(world):
    item = world.create("label", {"service": "gh"}, b"x")
    world.delete(item)
    assert world.search({"service": "gh"}) == []
    with pytest.raises(RuntimeError):
        world.get(item)


def test_secrets_persist_across_sandboxes(world):
    """A new sandbox starts a new guard on the same database."""
    item = world.create("label", {"service": "gh"}, b"kept")
    world.restart()
    # Exported again at start, before any search.
    assert world.get(item) == (b"kept", "text/plain")
    assert world.search({"service": "gh"}) == [item]


def test_sessions_are_plain_and_numbered(world):
    first = world.open_session()
    second = world.open_session()
    assert first[0].value == "" and second[0].value == ""
    assert first[1] == "/org/freedesktop/secrets/session/s1"
    assert second[1] == "/org/freedesktop/secrets/session/s2"


def test_everything_is_unlocked_without_a_prompt(world):
    assert world.call(SERVICE_PATH, "org.freedesktop.Secret.Service", "Unlock", "ao", [["/some/obj"]]) == [["/some/obj"], "/"]  # fmt: skip


def test_collections_are_empty(world):
    """So go-keyring falls back to aliases/default directly."""
    [value] = world.call(SERVICE_PATH, "org.freedesktop.DBus.Properties", "Get", "ss",
                         ["org.freedesktop.Secret.Service", "Collections"])  # fmt: skip
    assert value.value == []


def test_database_and_its_sidecars_are_owner_only(world):
    """It holds credentials in plaintext; the default umask would make it 0644."""
    world.create("label", {"service": "gh"}, b"topsecret")
    assert mode(world.db) == 0o600
    assert mode(f"{world.db}-wal") == 0o600


def test_a_preexisting_database_is_tightened(world):
    world.guard.stop()
    world.db.unlink()
    world.db.touch()
    os.chmod(world.db, 0o644)
    world.start()
    assert mode(world.db) == 0o600


# -- the database, as earlier versions left it -------------------------------------

SCHEMA = """CREATE TABLE items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    label TEXT NOT NULL,
    attributes TEXT NOT NULL,
    content_type TEXT NOT NULL,
    secret BLOB NOT NULL
)"""


def test_an_existing_database_carries_over(world):
    """A project's secrets.sqlite3 from an earlier version: its items are
    there, replaced in place and added to."""
    world.guard.stop()
    world.db.unlink()
    with sqlite3.connect(world.db) as db:
        db.execute(SCHEMA)
        db.execute(
            "INSERT INTO items (label, attributes, content_type, secret) VALUES (?, ?, ?, ?)",
            ("old", '{"account": "me", "service": "gh"}', "text/plain", b"kept"),
        )
    db.close()
    world.start()
    item = "/org/freedesktop/secrets/item/1"
    assert world.search({"service": "gh"}) == [item]
    assert world.get(item) == (b"kept", "text/plain")
    assert world.create("new", {"service": "gh", "account": "me"}, b"v2") == item
    assert world.get(item) == (b"v2", "text/plain")
    assert (
        world.create("x", {"service": "other"}, b"x")
        == "/org/freedesktop/secrets/item/2"
    )


@pytest.mark.parametrize(
    "attributes",
    [
        {},
        {"service": "gh", "account": "me"},
        {"b": "1", "a": "2", "B": "3", "_": "4"},
        {
            "ü": "日本",
            "emoji": "\U0001f511",
            "quote": '"\\',
            "ctl": "\n\t\r\b\f\x01\x7f/",
            "ab": "",
            "a": "",
        },
    ],
)
def test_attributes_are_stored_as_sorted_ascii_json(world, attributes):
    """The format every version writes, so a database reads the same
    whichever wrote it."""
    world.create("label", attributes, b"x")
    with sqlite3.connect(world.db) as db:
        [(stored,)] = db.execute("SELECT attributes FROM items").fetchall()
    db.close()
    assert stored == json.dumps(attributes, sort_keys=True)
    assert world.search(attributes) == ["/org/freedesktop/secrets/item/1"]


# -- what a client gets wrong ------------------------------------------------------


def test_an_item_without_a_label_or_attributes_is_refused(world):
    for properties in (
        {f"{ITEM}.Attributes": Variant("a{ss}", {"k": "v"})},
        {f"{ITEM}.Label": Variant("s", "label")},
    ):
        with pytest.raises(RuntimeError):
            world.call(
                COLLECTION, "org.freedesktop.Secret.Collection", "CreateItem", "a{sv}(oayays)b",
                [properties, ["/s", b"", b"x", "text/plain"], True],
            )  # fmt: skip
    assert world.search({}) == []


def test_an_item_never_stored_does_not_exist(world):
    with pytest.raises(RuntimeError):
        world.get("/org/freedesktop/secrets/item/42")


def test_objects_can_be_introspected(world):
    """GDBus-based clients (libsecret) may look before they call."""
    item = world.create("label", {"k": "v"}, b"x")
    for path, member in (
        (SERVICE_PATH, "OpenSession"),
        (COLLECTION, "SearchItems"),
        (item, "GetSecret"),
    ):
        [xml] = world.call(path, "org.freedesktop.DBus.Introspectable", "Introspect")
        assert f'name="{member}"' in xml
