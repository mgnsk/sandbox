"""Tests for src/sandbox, the launcher.

The unit tests load the launcher as a module and check its pure parts -
cwd refusal, project/volume naming, host ports, profiles, bind arguments.

The rest launch the real thing - pasta, bwrap, every guard - and check what
the sandboxed process actually sees. A flag on a command line can't tell you
bwrap honored it, that a nested namespace didn't reintroduce root, or that
pasta's netns is actually reachable - that gap is how the sandbox once ran
the sandboxed process as uid 0 without any test catching it. They run the
`sandbox` built from this flake: $SANDBOX_BIN, else `sandbox` on PATH, e.g.

    SANDBOX_BIN=$(nix build --print-out-paths)/bin/sandbox pytest tests

and need a real host: unprivileged user namespaces are unavailable inside a
running sandbox (`--disable-userns` blocks exactly that), so they skip
themselves there. Each gets its own $SANDBOX_STATE_DIR.
"""

import contextlib
import io
import json
import os
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

import pytest
from conftest import BIN_DIR, load_module

sandbox = load_module("sandbox")
SANDBOX = os.environ.get("SANDBOX_BIN") or shutil.which("sandbox")


# -- unit: cwd, project, volume ------------------------------------------------


@pytest.mark.parametrize("cwd", ["/", "/home", "/home/u"])
def test_refuses_home_and_above(cwd):
    with pytest.raises(sandbox.SandboxError, match="contains \\$HOME"):
        sandbox.check_cwd(cwd, "/home/u")


@pytest.mark.parametrize(
    "cwd", ["/home/u/.config", "/home/u/.ssh/x", "/home/u/.local/share/sandbox"]
)
def test_refuses_home_dot_directories(cwd):
    """The dot directories hold host state: ssh keys, the gh token, every
    sandbox's volume and secrets, ..."""
    with pytest.raises(sandbox.SandboxError, match="host state"):
        sandbox.check_cwd(cwd, "/home/u")


@pytest.mark.parametrize("cwd", ["/home/u/src/p", "/home/user2", "/srv/p"])
def test_accepts_projects(cwd):
    sandbox.check_cwd(cwd, "/home/u")


@pytest.mark.parametrize("cwd", ["/data/state", "/data/state/vol", "/data"])
def test_refuses_the_state_dir(cwd):
    with pytest.raises(sandbox.SandboxError, match="state dir"):
        sandbox.check_outside(cwd, "/data/state")


def test_project_root_is_the_git_top_level(tmp_path):
    (tmp_path / "repo/.git").mkdir(parents=True)
    (tmp_path / "repo/a/b").mkdir(parents=True)
    assert sandbox.project_root(str(tmp_path / "repo/a/b")) == str(tmp_path / "repo")
    # A worktree's .git is a file.
    (tmp_path / "wt/sub").mkdir(parents=True)
    (tmp_path / "wt/.git").write_text("gitdir: elsewhere\n")
    assert sandbox.project_root(str(tmp_path / "wt/sub")) == str(tmp_path / "wt")


def test_project_root_outside_a_repo_is_cwd(tmp_path):
    assert sandbox.project_root(str(tmp_path)) == str(tmp_path)


def test_refuses_a_work_tree_that_contains_home(tmp_path, monkeypatch):
    """The whole work tree is bound read-write, so a git repo in ~ must not
    make a project under it bind all of the host home."""
    home = tmp_path / "home"
    (home / ".git").mkdir(parents=True)
    (home / "src/p").mkdir(parents=True)
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"stateDir": str(tmp_path / "state")}))
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(home / "src/p")
    with pytest.raises(sandbox.SandboxError, match="git work tree .*contains \\$HOME"):
        sandbox.main(["sandbox", str(config)])


def test_volume_name_is_unchanged_from_the_bash_launcher():
    """Existing volumes stay in use."""
    assert (
        sandbox.volume_name("/home/u/p")
        == "_home_u_p-" + __import__("hashlib").sha256(b"/home/u/p").hexdigest()[:8]
    )


def test_expand():
    v = {"HOME": "/home/u", "USER": "u"}
    assert sandbox.expand("~/x", v) == "/home/u/x"
    assert sandbox.expand("~", v) == "/home/u"
    assert sandbox.expand("/a/~b", v) == "/a/~b"
    assert sandbox.expand("$HOME/${USER}/$NOPE", v) == "/home/u/u/$NOPE"


# -- unit: host ports ----------------------------------------------------------


def test_host_ports_parse():
    assert sandbox.parse_host_ports(["5037", "8080/udp", "9000-9010", "22/tcp"]) == (
        ["5037", "9000-9010", "22"],
        ["8080"],
    )


@pytest.mark.parametrize("bad", ["0", "70000", "10-5", "abc", "22/sctp", "-1"])
def test_bad_host_ports_are_refused(bad):
    with pytest.raises(sandbox.SandboxError, match="SANDBOX_HOST_PORTS"):
        sandbox.parse_host_ports([bad])


def test_host_ports_combine_config_and_environment():
    assert sandbox.host_port_specs(["1"], {"SANDBOX_HOST_PORTS": "2, 3/udp"}) == [
        "1",
        "2",
        "3/udp",
    ]
    assert sandbox.host_port_specs([], {}) == []


# -- unit: profiles and binds --------------------------------------------------


def _profile(name, paths=(), files=(), priority=0):
    return {
        "name": name,
        "paths": list(paths),
        "projectFiles": list(files),
        "priority": priority,
    }


def test_profile_selection(tmp_path):
    (tmp_path / "flake.nix").write_text("")
    config = {
        "default": {"name": "default"},
        "profiles": [
            _profile("flake", files=["flake.nix"], priority=10),
            _profile("audio", paths=["~/dotfiles/nix/audio"], priority=20),
            _profile("never"),
        ],
    }
    v = {"HOME": "/home/u"}

    def pick(cwd, project):
        return sandbox.select_profile(config, cwd, project, v)["name"]

    assert pick("/home/u/p", "/home/u/p") == "default"
    assert pick(str(tmp_path), str(tmp_path)) == "flake"
    assert pick("/home/u/dotfiles/nix/audio/x", str(tmp_path)) == "audio"
    # A prefix of a path component isn't a match.
    assert pick("/home/u/dotfiles/nix/audiox", "/nonexistent") == "default"


def _bind(src, **kw):
    return {
        "src": src,
        "dst": None,
        "mode": "ro",
        "optional": False,
        "hideGit": False,
        **kw,
    }


def test_binds_end_with_the_whole_project(tmp_path):
    """The work tree's top level, not just $PWD, so a subdirectory still gets .git."""
    args = sandbox.bind_args([_bind(str(tmp_path), optional=True)], {}, "/p")
    assert args == ["--ro-bind-try", str(tmp_path), str(tmp_path), "--bind", "/p", "/p"]


def test_hide_git_outside_its_own_project(tmp_path):
    (tmp_path / ".git").mkdir()
    b = _bind(str(tmp_path), hideGit=True)
    args = sandbox.bind_args([b], {}, "/p")
    assert args == [
        "--ro-bind",
        str(tmp_path),
        str(tmp_path),
        "--tmpfs",
        f"{tmp_path}/.git",
        "--bind",
        "/p",
        "/p",
    ]


def test_bind_of_the_project_gives_way_to_it(tmp_path):
    """A repo bound for reference is read-write with .git when it is the project."""
    (tmp_path / ".git").mkdir()
    b = _bind(str(tmp_path), hideGit=True)
    args = sandbox.bind_args([b], {}, str(tmp_path))
    assert args == ["--bind", str(tmp_path), str(tmp_path)]


def test_bind_of_the_project_elsewhere_is_kept(tmp_path):
    b = _bind(str(tmp_path), dst="/elsewhere")
    args = sandbox.bind_args([b], {}, str(tmp_path))
    assert args == [
        "--ro-bind",
        str(tmp_path),
        "/elsewhere",
        "--bind",
        str(tmp_path),
        str(tmp_path),
    ]


def test_bind_paths_are_expanded(tmp_path):
    args = sandbox.bind_args(
        [_bind("~/x", dst="$HOME/y", mode="rw")], {"HOME": str(tmp_path)}, "/p"
    )
    assert args[:3] == ["--bind", str(tmp_path / "x"), str(tmp_path / "y")]


# -- unit: sandbox.nix ----------------------------------------------------------

STORE = "/nix/store/" + "a" * 32


def _manifest(**kw):
    return {
        "claudeDir": None,
        "binds": [],
        "hostPorts": [],
        "command": None,
        **kw,
    }


def test_options_before_the_command():
    none = {"claudeApiKey": False, "ghToken": False, "fjToken": None}
    assert sandbox.parse_options(["--reload", "ls", "--reload"]) == (
        {"reload": True, "projectConfig": True, **none},
        ["ls", "--reload"],
    )
    assert sandbox.parse_options(["--no-project-config", "--", "--weird"]) == (
        {"reload": False, "projectConfig": False, **none},
        ["--weird"],
    )
    assert sandbox.parse_options(["--claude-api-key"])[0]["claudeApiKey"] is True
    assert sandbox.parse_options(["--gh-token"])[0]["ghToken"] is True
    assert sandbox.parse_options(["--fj-token", "https://Code.example/x/"]) == (
        {"reload": False, "projectConfig": True, **none, "fjToken": "code.example"},
        [],
    )
    for bad in (["--fj-token"], ["--fj-token", "--reload"]):
        with pytest.raises(sandbox.SandboxError, match="needs the Forgejo host"):
            sandbox.parse_options(bad)
    with pytest.raises(sandbox.SandboxError, match="not a Forgejo host"):
        sandbox.parse_options(["--fj-token", "a b"])
    with pytest.raises(sandbox.SandboxError, match="unknown option"):
        sandbox.parse_options(["--nope"])


def test_store_paths():
    assert sandbox.is_store_path(f"{STORE}-env/bin")
    for bad in [
        "/etc/passwd",
        f"{STORE}-env/../../etc",
        "/nix/store/short-x",
        f"{STORE}-env/",
        3,
    ]:
        assert not sandbox.is_store_path(bad)


def test_reads_a_manifest(tmp_path):
    m = _manifest(claudeDir=f"{STORE}-claude", hostPorts=["5432"], command=["nix", "develop"],
                  binds=[{"src": "~/x", "dst": None, "mode": "rw", "optional": False, "hideGit": False}])  # fmt: skip
    (tmp_path / "m.json").write_text(json.dumps(m))
    assert sandbox.read_manifest(tmp_path / "m.json") == m


@pytest.mark.parametrize(
    "bad",
    [
        {"claudeDir": "/etc/claude-code"},
        {"env": {"A": "b"}},
        {
            "binds": [
                {
                    "src": "~/x",
                    "dst": None,
                    "mode": "rwx",
                    "optional": False,
                    "hideGit": False,
                }
            ]
        },
        {"binds": [{"src": "~/x"}]},
        {"hostPorts": [5432]},
        {"command": []},
        {"extra": True},
    ],
)
def test_refuses_a_bad_manifest(tmp_path, bad):
    """It comes out of a sandbox; nothing in it is taken on trust."""
    (tmp_path / "m.json").write_text(json.dumps(_manifest(**bad)))
    with pytest.raises(sandbox.SandboxError, match="bad sandbox.nix result"):
        sandbox.read_manifest(tmp_path / "m.json")


def _project(tmp_path, content="{ ... }: { }\n"):
    project, volume = tmp_path / "p", tmp_path / "vol"
    project.mkdir()
    volume.mkdir()
    (project / "sandbox.nix").write_text(content)
    config = tmp_path / "config.json"
    config.write_text("{}")
    out = tmp_path / "manifest.json"
    out.write_text(json.dumps(_manifest(command=["n1"])))
    calls = []

    def evaluate(_config, config_path, project_file, base):
        calls.append((config_path, project_file, base))
        return str(out)

    def manifest(reload=False, base=None):
        return sandbox.project_manifest(
            {}, str(config), str(project), str(volume), base, reload, evaluate
        )

    return project, out, calls, manifest


def test_project_manifest_is_cached(tmp_path, monkeypatch):
    project, out, calls, manifest = _project(tmp_path)
    # The cache only takes store paths.
    monkeypatch.setattr(sandbox, "is_store_path", lambda v: v == str(out))
    assert manifest()["command"] == ["n1"]
    assert manifest()["command"] == ["n1"]
    assert len(calls) == 1
    # Changed, reloaded or with another profile Claude config, it's evaluated again.
    (project / "sandbox.nix").write_text('{ ... }: { command = [ "n2" ]; }\n')
    manifest()
    manifest(reload=True)
    manifest(base=f"{STORE}-claude")
    assert len(calls) == 4
    assert calls[-1][1:] == (str(project / "sandbox.nix"), f"{STORE}-claude")


def test_project_file_must_not_be_a_symlink(tmp_path):
    """The launcher reads it on the host; a link would let the sandbox pick
    which host file."""
    project, _, calls, manifest = _project(tmp_path)
    (project / "sandbox.nix").unlink()
    (project / "sandbox.nix").symlink_to(tmp_path / "config.json")
    with pytest.raises(sandbox.SandboxError, match="regular file"):
        manifest()
    assert not calls


class _Tty:
    def __init__(self, answer):
        self.answer, self.written = answer, ""

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def write(self, s):
        self.written += s

    def flush(self):
        pass

    def readline(self):
        return self.answer

    def fileno(self):
        raise io.UnsupportedOperation("not a terminal")


ACCESS = _manifest(
    hostPorts=["5432"],
    binds=[
        {"src": "~/d", "dst": None, "mode": "rw", "optional": False, "hideGit": False}
    ],
)


def test_project_without_host_access_needs_no_approval(tmp_path):
    def no_tty():
        raise AssertionError("asked")

    sandbox.approve_project(
        _manifest(command=["nix", "develop"], claudeDir=f"{STORE}-claude"),
        str(tmp_path),
        "p/sandbox.nix",
        no_tty,
    )


def test_host_access_is_asked_once_until_it_changes(tmp_path):
    tty = _Tty("y\n")
    sandbox.approve_project(ACCESS, str(tmp_path), "p/sandbox.nix", lambda: tty)
    assert "bind ~/d (read-write)" in tty.written and "host port 5432" in tty.written

    def no_tty():
        raise AssertionError("asked again")

    sandbox.approve_project(ACCESS, str(tmp_path), "p/sandbox.nix", no_tty)

    widened = {**ACCESS, "hostPorts": ["5432", "22"]}
    tty = _Tty("n\n")
    with pytest.raises(sandbox.SandboxError, match="not approved"):
        sandbox.approve_project(widened, str(tmp_path), "p/sandbox.nix", lambda: tty)
    assert "host port 22" in tty.written


def test_host_access_without_a_terminal_is_refused(tmp_path):
    def no_tty():
        raise OSError("no tty")

    with pytest.raises(sandbox.SandboxError, match="from a terminal"):
        sandbox.approve_project(ACCESS, str(tmp_path), "p/sandbox.nix", no_tty)


KEY = "sk-ant-api03-" + "k" * 40


def test_claude_api_key_is_asked_once_and_kept_out_of_the_home(tmp_path):
    tty = _Tty(KEY + "\n")
    key_file = sandbox.claude_api_key(str(tmp_path), False, lambda: tty)

    assert key_file == str(tmp_path / "claude-api-key")
    assert Path(key_file).read_text() == KEY + "\n"
    assert stat.S_IMODE(os.stat(key_file).st_mode) == 0o600
    assert "API key" in tty.written and KEY not in tty.written

    def no_tty():
        raise AssertionError("asked again")

    assert sandbox.claude_api_key(str(tmp_path), False, no_tty) == key_file


TOKEN = "github_pat_" + "t" * 40


def test_github_token_is_kept_out_of_the_home(tmp_path):
    tty = _Tty(TOKEN + "\n")
    sandbox.set_github_token(str(tmp_path), lambda: tty)

    token_file = tmp_path / "github-token"
    assert token_file.read_text() == TOKEN + "\n"
    assert stat.S_IMODE(os.stat(token_file).st_mode) == 0o600
    assert TOKEN not in tty.written

    sandbox.set_github_token(str(tmp_path), lambda: _Tty("\n"))  # Kept.
    sandbox.set_github_token(str(tmp_path), lambda: _Tty("has space\n"))  # Refused.
    assert token_file.read_text() == TOKEN + "\n"


def test_token_needs_a_terminal(tmp_path):
    def no_tty():
        raise OSError("no tty")

    with pytest.raises(sandbox.SandboxError, match="needs a terminal"):
        sandbox.set_github_token(str(tmp_path), no_tty)


def test_forgejo_tokens_are_kept_per_host(tmp_path):
    sandbox.set_forgejo_token(str(tmp_path), "a.example", lambda: _Tty("aaaaaaaa\n"))
    sandbox.set_forgejo_token(str(tmp_path), "b.example", lambda: _Tty("bbbbbbbb\n"))
    sandbox.set_forgejo_token(str(tmp_path), "a.example", lambda: _Tty("cccccccc\n"))

    tokens_file = tmp_path / "forgejo-tokens.json"
    assert json.loads(tokens_file.read_text()) == {
        "a.example": "cccccccc",
        "b.example": "bbbbbbbb",
    }
    assert stat.S_IMODE(os.stat(tokens_file).st_mode) == 0o600


def test_claude_api_key_can_be_replaced_or_kept(tmp_path):
    key_file = sandbox.claude_api_key(str(tmp_path), False, lambda: _Tty(KEY + "\n"))
    sandbox.claude_api_key(str(tmp_path), True, lambda: _Tty("\n"))
    assert Path(key_file).read_text() == KEY + "\n"

    other = "sk-ant-api03-" + "o" * 40
    sandbox.claude_api_key(str(tmp_path), True, lambda: _Tty(other + "\n"))
    assert Path(key_file).read_text() == other + "\n"


@pytest.mark.parametrize("answer", ["\n", "not a key\n"])
def test_claude_api_key_skipped_or_malformed_is_not_saved(tmp_path, answer):
    tty = _Tty(answer)
    key_file = sandbox.claude_api_key(str(tmp_path), False, lambda: tty)

    assert not os.path.exists(key_file)
    assert "sandbox --claude-api-key" in tty.written


def test_claude_api_key_without_a_terminal_starts_anyway(tmp_path, capsys):
    def no_tty():
        raise OSError("no tty")

    key_file = sandbox.claude_api_key(str(tmp_path), False, no_tty)
    assert not os.path.exists(key_file)
    assert "sandbox --claude-api-key" in capsys.readouterr().err


def _api_key_config(tmp_path, project):
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            {
                "stateDir": str(tmp_path / "state"),
                "default": {"name": "default", "claudeApiKey": False},
                "profiles": [
                    {
                        "name": "api",
                        "paths": [str(project)],
                        "projectFiles": [],
                        "priority": 0,
                        "claudeApiKey": True,
                    }
                ],
            }
        )
    )
    return config


def test_claude_api_key_option_follows_the_profile(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / "api").mkdir(parents=True)
    (home / "sub").mkdir()
    config = _api_key_config(tmp_path, home / "api")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(sandbox, "open_tty", lambda: _Tty(KEY + "\n"))

    monkeypatch.chdir(home / "sub")
    with pytest.raises(sandbox.SandboxError, match="profile \\(default\\)"):
        sandbox.main(["sandbox", str(config), "--claude-api-key"])

    monkeypatch.chdir(home / "api")
    assert sandbox.main(["sandbox", str(config), "--claude-api-key"]) == 0
    [key_file] = (tmp_path / "state").glob("*/claude-api-key")
    assert key_file.read_text() == KEY + "\n"


def test_project_adds_to_the_profile():
    profile = {
        "env": {"PATH": "/env/bin", "A": "1"},
        "binds": [{"src": "~/x"}],
        "claudeDir": f"{STORE}-claude-default",
    }
    m = _manifest(binds=[{"src": "~/y"}], claudeDir=f"{STORE}-claude-project")
    p = sandbox.apply_project(profile, m)
    assert p["env"] == profile["env"]
    assert p["binds"] == [{"src": "~/x"}, {"src": "~/y"}]
    assert p["claudeDir"] == f"{STORE}-claude-project"
    # Without Claude Code in the profile, none comes in through the project.
    assert sandbox.apply_project({**profile, "claudeDir": None}, m)["claudeDir"] is None


def test_inside_env_is_an_allowlist():
    """A host GH_TOKEN would let gh inside reach the API directly, around the
    write popups; only passEnv and the profile's own variables get in."""
    config = {"passEnv": ["TERM", "MISSING"]}
    profile = {"env": {"PATH": "/env/bin:$HOME/.nix-profile/bin"}}
    v = {"HOME": "/home/u", "USER": "u", "XDG_RUNTIME_DIR": "/run/user/1"}
    env = sandbox.inside_env(config, profile, v, {"TERM": "xterm", "GH_TOKEN": "leak"})
    assert env == {
        "HOME": "/home/u",
        "USER": "u",
        "LOGNAME": "u",
        "XDG_RUNTIME_DIR": "/run/user/1",
        "TERM": "xterm",
        "PATH": "/env/bin:/home/u/.nix-profile/bin",
    }


def test_exchange_links_are_dropped(tmp_path):
    """The host tees into it; a link planted there would aim that write at
    any host file."""
    volume = tmp_path / "vol"
    (volume / "exchange/sub").mkdir(parents=True)
    target = tmp_path / "host-file"
    target.write_text("untouched")
    (volume / "exchange/foo.txt").symlink_to(target)
    (volume / "exchange/sub/bar").symlink_to(target)
    (volume / "exchange/kept.txt").write_text("host output")
    args = sandbox.exchange_args(str(volume))
    assert args[:3] == ["--ro-bind", str(volume / "exchange"), str(volume / "exchange")]
    assert sorted(p.name for p in (volume / "exchange").rglob("*")) == [
        "kept.txt",
        "sub",
    ]
    assert target.read_text() == "untouched"
    assert (volume / "exchange").stat().st_mode & 0o777 == 0o700


# -- unit: pasta ---------------------------------------------------------------


def _pasta(tcp=(), udp=(), addrs=()):
    config = {
        "tools": {"pasta": "PASTA", "bash": "BASH", "ip": "IP", "bwrap": "BWRAP"},
        "seccomp": "BPF",
    }
    return sandbox.pasta_argv(config, list(tcp), list(udp), list(addrs), ["--x"])


def test_dns_forward_replaces_a_loopback_resolver():
    """systemd-resolved's stub: unreachable inside, so forwarded."""
    resolver, text = sandbox.dns_forward(
        "# generated\nnameserver 127.0.0.53\nnameserver ::1\n"
        "nameserver 127.0.0.1\noptions edns0\nsearch lan\n"
    )
    assert resolver == "127.0.0.53"
    assert text == (
        f"# generated\nnameserver {sandbox.DNS_FORWARD_ADDR}\n"
        "options edns0\nsearch lan\n"
    )


@pytest.mark.parametrize(
    "conf",
    [
        "nameserver 100.100.100.100\nnameserver fd7a:115c:a1e0::53\n",
        # glibc tries the first one first; leave a working one in front.
        "nameserver 192.168.1.1\nnameserver 127.0.0.53\n",
        # IPv6 loopback isn't forwarded.
        "nameserver ::1\n",
        "",
    ],
)
def test_dns_forward_leaves_reachable_or_unsupported_resolvers(conf):
    assert sandbox.dns_forward(conf) == (None, None)


def test_dns_forward_only_with_a_loopback_resolver_in_pasta_args():
    assert "--dns-forward" not in _pasta()
    config = {
        "tools": {"pasta": "PASTA", "bash": "BASH", "ip": "IP", "bwrap": "BWRAP"},
        "seccomp": "BPF",
    }
    argv = sandbox.pasta_argv(config, [], [], [], ["--x"], "127.0.0.53")
    i = argv.index("--dns-forward")
    assert argv[i : i + 4] == [
        "--dns-forward",
        sandbox.DNS_FORWARD_ADDR,
        "--dns-host",
        "127.0.0.53",
    ]
    assert i < argv.index("--")


def test_host_access_is_restricted_in_pasta_args():
    """No pasta defaults that reach host services: -T/-U auto, the gateway and
    guest-address mappings."""
    argv = _pasta()
    for flag, value in (("-T", "none"), ("-U", "none"), ("--map-host-loopback", "none"),
                        ("--map-guest-addr", "none"), ("-t", "127.0.0.1/1-65535,auto")):  # fmt: skip
        assert argv[argv.index(flag) + 1] == value, flag
    argv = _pasta(["1", "5-6"], ["7"])
    assert argv[argv.index("-T") + 1] == "1,5-6"
    assert argv[argv.index("-U") + 1] == "7"


def test_seccomp_fd_is_opened_inside_pasta():
    """pasta closes inherited fds past stdio before running its command, so
    the filter is opened by the command itself."""
    argv = _pasta(addrs=["10.0.0.1", "100.1.2.3"])
    sep = argv.index("--")
    assert argv[sep + 1 : sep + 3] == ["BASH", "-c"]
    assert 'exec 10<"$seccomp"' in argv[sep + 3]
    assert argv[sep + 4 :] == [
        "bash",
        "IP",
        "BPF",
        "2",
        "10.0.0.1",
        "100.1.2.3",
        "BWRAP",
        "--seccomp",
        "10",
        "--x",
    ]


def test_pasta_inner_script_adds_prohibit_routes(tmp_path):
    """Run the inner script with stand-ins for ip and bwrap."""
    log = tmp_path / "log"
    ip = tmp_path / "ip"
    ip.write_text(f'#!/bin/sh\necho "ip $*" >> {log}\n')
    ip.chmod(0o755)
    bpf = tmp_path / "bpf"
    bpf.write_text("")
    subprocess.run(
        [
            "bash",
            "-c",
            sandbox.PASTA_INNER,
            "bash",
            str(ip),
            str(bpf),
            "2",
            "1.2.3.4",
            "5.6.7.8",
            "sh",
            "-c",
            f'echo "run $*" >> {log}; test -e /proc/self/fd/10',
            "sh",
            "a",
        ],
        check=True,
    )
    assert log.read_text().splitlines() == [
        "ip route replace prohibit 1.2.3.4",
        "ip route replace prohibit 5.6.7.8",
        "run a",
    ]


# -- unit: guards --------------------------------------------------------------


def test_guards_are_stopped_and_their_dirs_removed(tmp_path):
    guards = sandbox.Guards(
        {"hostPath": "/x", "python": "python3", "src": str(BIN_DIR)}
    )
    proc = guards.start(["sleep", "60"])
    d = guards.tempdir()
    guards.close()
    assert proc.poll() is not None
    assert not os.path.exists(d)


def test_wait_for_names_a_guard_that_exited():
    guards = sandbox.Guards(
        {"hostPath": "/x", "python": "python3", "src": str(BIN_DIR)}
    )
    proc = guards.start(["false"])
    with pytest.raises(sandbox.SandboxError, match="g exited"):
        guards.wait_for("/nonexistent", proc, "g")
    guards.close()


def test_guards_get_store_tools_first_on_path(monkeypatch):
    monkeypatch.setenv("PATH", "/host/bin")
    monkeypatch.setenv("PYTHONPATH", "/project")
    guards = sandbox.Guards(
        {"hostPath": "/store/bin", "python": "python3", "src": str(BIN_DIR)}
    )
    assert guards.env["PATH"] == "/store/bin:/host/bin"
    assert "PYTHONPATH" not in guards.env


def test_https_proxy_guard_gives_its_url_port_and_ca(tmp_path):
    guards = sandbox.Guards(
        {"hostPath": "/x", "python": sys.executable, "src": str(BIN_DIR)}
    )
    try:
        url = sandbox.https_proxy(
            guards, "forgejo-api-proxy", str(tmp_path / "forgejo-tokens.json")
        )
        match = re.fullmatch(r"http://sandbox:([^@:]+)@127\.0\.0\.1:([0-9]+)", url)
        assert match, url
        assert guards.tcp_ports == [match[2]]
        [ca] = guards.ca_certs
        assert ca.startswith("-----BEGIN CERTIFICATE-----")

        ssl_dir = tmp_path / "ssl"
        (ssl_dir / "certs").mkdir(parents=True)
        (ssl_dir / "certs" / "ca-bundle.crt").write_text("SYSTEM\n")
        args = sandbox.ca_bundle_args(guards, {"fhs": {"ssl": str(ssl_dir)}}, "/run/u")
        assert args[0] == "--ro-bind"
        assert args[2:] == [
            "/run/u/sandbox-ca.pem", "--setenv", "SANDBOX_CA_FILE", "/run/u/sandbox-ca.pem"
        ]  # fmt: skip
        assert Path(args[1]).read_text() == "SYSTEM\n" + ca
    finally:
        guards.close()


def test_no_ca_bundle_without_intercepting_guards():
    guards = sandbox.Guards({"hostPath": "/x", "python": "python3", "src": "/x"})
    assert sandbox.ca_bundle_args(guards, {}, "/run/u") == []


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
    volume = state_dir / sandbox.volume_name(str(project_dir.resolve()))
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
