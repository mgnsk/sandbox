"""Black-box tests for the launcher (src/sandbox): run as a program against
stand-in tools, see tests/launcher.py. What a real sandbox then makes of the
command line is test_sandbox.py's business."""

import hashlib
import json
import os
import re
import shutil
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from conftest import BIN_DIR
from launcher import Invocation, Launcher, store_file


@pytest.fixture
def launcher(tmp_path):
    launcher = Launcher(tmp_path)
    yield launcher
    launcher.close()


def volume_name(project):
    """How volume dirs are named, which must never change: existing volumes
    stay in use."""
    digest = hashlib.sha256(project.encode()).hexdigest()[:8]
    return project.replace("/", "_") + f"-{digest}"


def bind(src, **kw):
    return {"src": src, "dst": None, "mode": "ro", "optional": False, "hideGit": False, **kw}  # fmt: skip


def manifest(**kw):
    return {"claudeDir": None, "binds": [], "hostPorts": [], "command": None, **kw}


def py(code):
    """A command running Python code inside."""
    return [sys.executable, "-c", code]


def refused(result, message):
    assert result.returncode == 1, result.stderr
    assert re.search(message, result.stderr), result.stderr
    assert result.stderr.startswith("sandbox: "), result.stderr
    assert not result.calls("pasta"), "started anyway"


# -- where it runs --------------------------------------------------------------


@pytest.mark.parametrize("where", ["home", "above", "root"])
def test_refuses_home_and_above(launcher, where):
    """$PWD is bound read-write: in ~ or above, that's the host home."""
    cwd = {"home": launcher.home, "above": launcher.tmp, "root": Path("/")}[where]
    refused(launcher.run(cwd=cwd), r"refusing to run in .*, it contains \$HOME")


def test_refuses_home_through_a_symlink(launcher):
    """The check sees the physical path, not a link's logical one."""
    link = launcher.tmp / "link"
    link.symlink_to(launcher.home)
    result = launcher.run(cwd=link, env={"PWD": str(link)})
    refused(result, "contains \\$HOME")


@pytest.mark.parametrize("sub", [".config", ".ssh/x", ".local/share/sandbox"])
def test_refuses_home_dot_directories(launcher, sub):
    """The dot directories hold host state: ssh keys, the gh token, every
    sandbox's volume and secrets, ..."""
    cwd = launcher.home / sub
    cwd.mkdir(parents=True)
    refused(launcher.run(cwd=cwd), "it is host state under \\$HOME")


@pytest.mark.parametrize("where", ["home/src/p", "home2", "srv/p"])
def test_accepts_projects(launcher, where):
    cwd = launcher.tmp / where
    cwd.mkdir(parents=True)
    result = launcher.run(cwd=cwd)
    assert result.returncode == 0, result.stderr
    assert result.pasta.chdir == str(cwd)


@pytest.mark.parametrize("where", ["data/state", "data/state/vol", "data"])
def test_refuses_the_state_dir(launcher, where):
    (launcher.tmp / "data/state/vol").mkdir(parents=True)
    result = launcher.run(
        cwd=launcher.tmp / where,
        env={"SANDBOX_STATE_DIR": str(launcher.tmp / "data/state")},
    )
    refused(result, "overlaps the sandbox state dir")


def test_refuses_a_work_tree_that_contains_the_state_dir(launcher):
    repo = launcher.tmp / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / "sub").mkdir()
    result = launcher.run(
        cwd=repo / "sub", env={"SANDBOX_STATE_DIR": str(repo / "state")}
    )
    refused(result, "is in the git work tree .*overlaps the sandbox state dir")


def test_refuses_a_work_tree_that_contains_home(launcher):
    """The whole work tree is bound read-write, so a git repo in ~ must not
    make a project under it bind all of the host home."""
    (launcher.home / ".git").mkdir()
    cwd = launcher.home / "src/q"
    cwd.mkdir(parents=True)
    refused(launcher.run(cwd=cwd), "git work tree .*contains \\$HOME")


# -- project and volume ---------------------------------------------------------


def test_project_root_is_the_git_top_level(launcher):
    """The work tree's top level, not just $PWD, so a subdirectory still gets .git."""
    sub = launcher.project / "a/b"
    sub.mkdir(parents=True)
    result = launcher.run(cwd=sub)
    project = str(launcher.project)
    assert result.pasta.chdir == str(sub)
    assert result.pasta.mounts[-1] == ("--bind", project, project)
    assert launcher.volume().name == volume_name(project)


def test_project_root_of_a_worktree(launcher):
    """A worktree's .git is a file."""
    wt = launcher.tmp / "wt"
    (wt / "sub").mkdir(parents=True)
    (wt / ".git").write_text("gitdir: elsewhere\n")
    result = launcher.run(cwd=wt / "sub")
    assert result.pasta.mounts[-1] == ("--bind", str(wt), str(wt))


def test_project_root_outside_a_repo_is_cwd(launcher):
    cwd = launcher.tmp / "srv/p"
    cwd.mkdir(parents=True)
    result = launcher.run(cwd=cwd)
    assert result.pasta.mounts[-1] == ("--bind", str(cwd), str(cwd))
    assert launcher.volume().name == volume_name(str(cwd))


def test_home_is_a_per_project_volume(launcher):
    """Nested at $HOME's own path in the volume dir, and bound before every
    mount under $HOME, which bwrap layers on top of it."""
    launcher.config["default"]["binds"] = [bind("~/x")]
    result = launcher.run()
    volume = launcher.state / volume_name(str(launcher.project))
    home = str(launcher.home)
    mounts = result.pasta.mounts
    i = mounts.index(("--bind", f"{volume}{home}", home))
    assert (volume / home.lstrip("/")).is_dir()
    assert i < mounts.index(("--ro-bind", f"{home}/x", f"{home}/x"))
    assert i < mounts.index(("--bind", str(launcher.project), str(launcher.project)))


def test_state_dir_from_the_environment_and_xdg(launcher):
    other = launcher.tmp / "elsewhere"
    launcher.run(env={"SANDBOX_STATE_DIR": "$HOME/../elsewhere"})
    assert (other / volume_name(str(launcher.project))).is_dir()
    launcher.config["stateDir"] = None
    launcher.run(env={"XDG_DATA_HOME": str(launcher.tmp / "data")})
    assert (launcher.tmp / "data/sandbox" / volume_name(str(launcher.project))).is_dir()
    launcher.run()
    assert (launcher.home / ".local/share/sandbox").is_dir()


# -- what it starts --------------------------------------------------------------


def test_namespaces_and_the_base_filesystem(launcher):
    result = launcher.run()
    inv, config = result.pasta, launcher.config
    a = inv.args
    for flag in ("--unshare-all", "--unshare-user", "--disable-userns", "--share-net",
                 "--die-with-parent", "--clearenv"):  # fmt: skip
        assert flag in a, flag
    assert a[a.index("--uid") + 1] == str(os.getuid())
    assert a[a.index("--gid") + 1] == str(os.getgid())
    assert a[a.index("--cap-drop") + 1] == "ALL"
    # Nothing is set before the environment is cleared.
    assert a.index("--clearenv") < a.index("--setenv")
    fhs = config["fhs"]
    for mount in [
        ("--dev", "/dev"),
        ("--proc", "/proc"),
        ("--tmpfs", "/tmp"),
        ("--tmpfs", str(launcher.runtime)),
        ("--ro-bind", "/nix", "/nix"),
        ("--ro-bind", fhs["bin"], "/bin"),
        ("--ro-bind", fhs["usrBin"], "/usr/bin"),
        ("--ro-bind", fhs["nixLd"], fhs["ldPath"]),
        ("--ro-bind", fhs["ssl"], "/etc/ssl"),
        ("--ro-bind-try", "/etc/hosts", "/etc/hosts"),
    ]:
        assert mount in inv.mounts, mount
    assert inv.bwrap == "/store/bwrap"
    assert inv.bash == config["tools"]["bash"]
    assert inv.ip == config["tools"]["ip"]
    assert inv.seccomp == config["seccomp"]
    assert not result.calls("nix")


def test_inside_env_is_an_allowlist(launcher):
    """A host GH_TOKEN would let gh inside reach the API directly, around the
    write popups; only passEnv and the profile's own variables get in, with
    ~, $HOME, $USER and $XDG_RUNTIME_DIR expanded."""
    launcher.config["default"]["env"] = {
        "PATH": "/env/bin:$HOME/.nix-profile/bin",
        "A": "$HOME/${USER}/$NOPE",
        "B": "~/x",
        "C": "~",
        "D": "/a/~b",
        "E": "$XDG_RUNTIME_DIR/e",
    }
    result = launcher.run(env={"LANG": "C.UTF-8", "SOME_HOST_VAR": "x"})
    home, run = str(launcher.home), str(launcher.runtime)
    exchange = str(launcher.volume() / "exchange")
    assert result.pasta.setenv == {
        "HOME": home,
        "USER": "u",
        "LOGNAME": "u",
        "XDG_RUNTIME_DIR": run,
        "TERM": "xterm",
        "LANG": "C.UTF-8",
        "PATH": f"/env/bin:{home}/.nix-profile/bin",
        "A": f"{home}/u/$NOPE",
        "B": f"{home}/x",
        "C": home,
        "D": "/a/~b",
        "E": f"{run}/e",
        "SANDBOX_EXCHANGE": exchange,
    }


def test_user_and_runtime_dir_fallbacks(launcher):
    env = {
        k: v for k, v in launcher.env.items() if k not in ("USER", "XDG_RUNTIME_DIR")
    }
    launcher.env = env
    result = launcher.run(env={"LOGNAME": "logname"})
    assert result.pasta.setenv["USER"] == "logname"
    assert result.pasta.setenv["XDG_RUNTIME_DIR"] == f"/run/user/{os.getuid()}"


def test_login_shell_or_command(launcher):
    """sandbox-init first, then a login shell, which runs a given command
    after its startup files."""
    init = launcher.config["init"]["script"]
    inv = launcher.run().pasta
    assert inv.command is None
    assert inv.init[inv.init.index(init) + 3 :] == ["/store/bash", "--login"]
    result = launcher.run("echo", "hello there")
    assert result.pasta.command == ["echo", "hello there"]
    assert result.stdout == "hello there\n"


def test_init_gets_the_nix_profile_and_home_manager_generation(launcher):
    target = launcher.tmp / "profile-gen"
    target.mkdir()
    (launcher.home / ".nix-profile").symlink_to(target)
    launcher.config["init"].update(nixProfile=True, homeManager=True)
    init = launcher.run().pasta.init
    i = init.index(launcher.config["init"]["script"])
    # The home-manager one doesn't exist.
    assert init[i + 1 : i + 3] == [str(target), ""]
    launcher.config["init"].update(nixProfile=False)
    init = launcher.run().pasta.init
    assert init[i + 1 : i + 3] == ["", ""]


def test_exit_status_is_the_sandbox_s(launcher):
    assert launcher.run(env={"FAKE_PASTA_EXIT": "7"}).returncode == 7
    assert launcher.run("sh", "-c", "exit 3").returncode == 3


def test_missing_seccomp_filter(launcher):
    launcher.config["seccomp"] = str(launcher.tmp / "nope.bpf")
    refused(launcher.run(), "missing seccomp filter")


# -- options ----------------------------------------------------------------------


def test_options_end_at_the_command(launcher):
    result = launcher.run("--reload", "echo", "--reload")
    assert result.pasta.command == ["echo", "--reload"]
    assert result.stdout == "--reload\n"
    result = launcher.run("--no-project-config", "--", "--weird")
    assert result.pasta.command == ["--weird"]


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["--nope"], "unknown option --nope \\(put -- before"),
        (["--fj-token"], "--fj-token needs the Forgejo host"),
        (["--fj-token", "--reload"], "--fj-token needs the Forgejo host"),
        (["--fj-token", "a b"], "not a Forgejo host: a b"),
    ],
)
def test_bad_options(launcher, args, message):
    launcher.config["guards"]["forgejo"] = True
    refused(launcher.run(*args), message)


# -- host ports and network --------------------------------------------------------


def test_host_access_is_restricted_in_pasta_args(launcher):
    """No pasta defaults that reach host services: -T/-U auto, the gateway and
    guest-address mappings."""
    inv = launcher.run().pasta
    for flag, value in (("-T", "none"), ("-U", "none"), ("--map-host-loopback", "none"),
                        ("--map-guest-addr", "none"), ("-t", "127.0.0.1/1-65535,auto")):  # fmt: skip
        assert inv.pasta_opt(flag) == value, flag
    assert "--config-net" in inv.pasta and "--host-lo-to-ns-lo" in inv.pasta
    assert "--dns-forward" not in inv.pasta


def test_host_ports_combine_config_and_environment(launcher):
    launcher.config["hostPorts"] = ["5037", "9000-9010"]
    inv = launcher.run(env={"SANDBOX_HOST_PORTS": "8080/udp, 22/tcp 7"}).pasta
    assert inv.pasta_opt("-T") == "5037,9000-9010,22,7"
    assert inv.pasta_opt("-U") == "8080"


@pytest.mark.parametrize("bad", ["0", "70000", "10-5", "abc", "22/sctp", "-1"])
def test_bad_host_ports_are_refused(launcher, bad):
    refused(launcher.run(env={"SANDBOX_HOST_PORTS": bad}), "SANDBOX_HOST_PORTS")


def test_host_addresses_get_prohibit_routes(launcher, tmp_path):
    """pasta closes inherited fds past stdio before running its command, so
    the seccomp filter is opened by the command itself, which first adds the
    prohibit routes. The script is run here with stand-ins for ip and bwrap."""
    inv = launcher.run(env={"FAKE_IP_ADDRS": "10.0.0.1 100.1.2.3"}).pasta
    assert inv.addrs == ["10.0.0.1", "100.1.2.3"]
    log = tmp_path / "inner.log"
    ip = tmp_path / "ip-standin"
    ip.write_text(f'#!/bin/sh\necho "ip $*" >> {log}\n')
    ip.chmod(0o755)
    subprocess.run(
        [inv.bash, "-c", inv.script, "bash", str(ip), inv.seccomp, "2", *inv.addrs,
         "sh", "-c", f'echo "run $*" >> {log}; test -e /proc/self/fd/10', "sh", "a"],
        check=True,
    )  # fmt: skip
    assert log.read_text().splitlines() == [
        "ip route replace prohibit 10.0.0.1",
        "ip route replace prohibit 100.1.2.3",
        "run a",
    ]


def test_dns_forward_replaces_a_loopback_resolver(launcher):
    """systemd-resolved's stub: unreachable inside, so forwarded."""
    launcher.resolv_conf.write_text(
        "# generated\nnameserver 127.0.0.53\nnameserver ::1\n"
        "nameserver 127.0.0.1\noptions edns0\nsearch lan\n"
    )
    result = launcher.run()
    inv = result.pasta
    i = inv.pasta.index("--dns-forward")
    assert inv.pasta[i : i + 4] == [
        "--dns-forward",
        "169.254.1.53",
        "--dns-host",
        "127.0.0.53",
    ]
    assert result.files[inv.bind("/etc/resolv.conf")] == (
        "# generated\nnameserver 169.254.1.53\noptions edns0\nsearch lan\n"
    )
    # Over the host's, which hostEtc binds.
    launcher.config["hostEtc"] = ["/etc/resolv.conf"]
    mounts = launcher.run().pasta.mounts
    host = mounts.index(("--ro-bind-try", "/etc/resolv.conf", "/etc/resolv.conf"))
    assert host < [m[2] if len(m) == 3 else None for m in mounts].index(
        "/etc/resolv.conf", host + 1
    )


@pytest.mark.parametrize(
    "conf",
    [
        "nameserver 100.100.100.100\nnameserver fd7a:115c:a1e0::53\n",
        # glibc tries the first one first; leave a working one in front.
        "nameserver 192.168.1.1\nnameserver 127.0.0.53\n",
        # IPv6 loopback isn't forwarded.
        "nameserver ::1\n",
        "nameserver not-an-address\n",
        "",
        None,
    ],
)
def test_dns_forward_leaves_reachable_or_unsupported_resolvers(launcher, conf):
    if conf is None:
        launcher.resolv_conf.unlink()
    else:
        launcher.resolv_conf.write_text(conf)
    inv = launcher.run().pasta
    assert "--dns-forward" not in inv.pasta
    assert all(len(m) < 3 or m[2] != "/etc/resolv.conf" for m in inv.mounts)


# -- profiles and binds --------------------------------------------------------------


def test_profile_selection(launcher):
    p = Launcher.profile
    launcher.config["profiles"] = [
        p("flake", projectFiles=["flake.nix"], priority=10),
        p("audio", paths=["~/dotfiles/nix/audio"], priority=20),
        p("never"),
    ]
    dotfiles = launcher.home / "dotfiles"
    (dotfiles / ".git").mkdir(parents=True)
    for d in ("nix/audio/x", "nix/audiox"):
        (dotfiles / d).mkdir(parents=True)

    def pick(cwd):
        result = launcher.run(cwd=cwd)
        assert result.returncode == 0, result.stderr
        return result.pasta.setenv["PROFILE"]

    assert pick(launcher.project) == "default"
    (launcher.project / "flake.nix").write_text("")
    assert pick(launcher.project) == "flake"
    assert pick(dotfiles / "nix/audio/x") == "audio"
    # A prefix of a path component isn't a match.
    assert pick(dotfiles / "nix/audiox") == "default"
    # Both match: the higher priority wins.
    (dotfiles / "flake.nix").write_text("")
    assert pick(dotfiles / "nix/audio/x") == "audio"
    assert pick(dotfiles / "nix/audiox") == "flake"


def test_binds(launcher):
    other = launcher.tmp / "other"
    (other / ".git").mkdir(parents=True)
    ref = launcher.tmp / "ref"
    home, project = str(launcher.home), str(launcher.project)
    (launcher.project / "sub").mkdir()
    launcher.config["default"]["binds"] = [
        bind(str(ref), optional=True),
        # Its history is none of another project's business.
        bind(str(other), hideGit=True),
        # No .git there to hide.
        bind(str(ref), dst="/ref2", hideGit=True),
        bind("~/x", dst="$HOME/y", mode="rw"),
        bind("~/z", mode="rw", optional=True),
        # A repo bound for reference is read-write with .git when it is the
        # project - and the one at the end covers it.
        bind(project, hideGit=True),
        bind(project, dst="/elsewhere"),
    ]
    mounts = launcher.run(cwd=launcher.project / "sub").pasta.mounts
    i = mounts.index(("--ro-bind-try", str(ref), str(ref)))
    assert mounts[i:] == [
        ("--ro-bind-try", str(ref), str(ref)),
        ("--ro-bind", str(other), str(other)),
        ("--tmpfs", f"{other}/.git"),
        ("--ro-bind", str(ref), "/ref2"),
        ("--bind", f"{home}/x", f"{home}/y"),
        ("--bind-try", f"{home}/z", f"{home}/z"),
        ("--ro-bind", project, "/elsewhere"),
        ("--bind", project, project),
    ]


def test_bind_sources_are_resolved(launcher):
    real = launcher.tmp / "real"
    real.mkdir()
    (launcher.home / "link").symlink_to(real)
    launcher.config["default"]["binds"] = [bind("~/link")]
    mounts = launcher.run().pasta.mounts
    assert ("--ro-bind", str(real), str(real)) in mounts


def test_claude_dir_is_the_managed_settings(launcher):
    launcher.config["default"]["claudeDir"] = "/store/claude"
    assert (
        "--ro-bind",
        "/store/claude",
        "/etc/claude-code",
    ) in launcher.run().pasta.mounts


# -- exchange dir --------------------------------------------------------------------


def test_exchange_dir(launcher):
    """The host tees into it; a link planted there would aim that write at
    any host file."""
    volume = launcher.state / volume_name(str(launcher.project))
    exchange = volume / "exchange"
    (exchange / "sub").mkdir(parents=True)
    target = launcher.tmp / "host-file"
    target.write_text("untouched")
    (exchange / "foo.txt").symlink_to(target)
    (exchange / "sub/bar").symlink_to(target)
    (exchange / "kept.txt").write_text("host output")
    inv = launcher.run().pasta
    assert ("--ro-bind", str(exchange), str(exchange)) in inv.mounts
    assert inv.setenv["SANDBOX_EXCHANGE"] == str(exchange)
    assert sorted(p.name for p in exchange.rglob("*")) == ["kept.txt", "sub"]
    assert target.read_text() == "untouched"
    assert exchange.stat().st_mode & 0o777 == 0o700


# -- upgrade notice -----------------------------------------------------------------

DAY = 86400


@pytest.mark.parametrize(
    ("released_days_ago", "days", "shown"),
    [(40.5, 30, True), (29, 30, False), (900, 0, False), (None, 30, False)],
)
def test_upgrade_notice(launcher, released_days_ago, days, shown):
    launcher.config["upgradeNoticeDays"] = days
    if released_days_ago is not None:
        launcher.config["released"] = int(time.time() - released_days_ago * DAY)
    err = launcher.run().stderr
    assert ("`nix profile upgrade sandbox`" in err) == shown, err
    if shown:
        assert "this sandbox is 40 days old" in err
        assert "SANDBOX_NO_UPGRADE_NOTICE" not in err
        assert (
            "nix profile upgrade"
            not in launcher.run(env={"SANDBOX_NO_UPGRADE_NOTICE": "1"}).stderr
        )


# -- sandbox.nix ----------------------------------------------------------------------


def with_project(launcher, value, content="{ ... }: { }\n", name="manifest.json"):
    """A sandbox.nix whose evaluation (by the stand-in nix) gives value."""
    (launcher.project / "sandbox.nix").write_text(content)
    out = store_file(launcher.tmp / name, value)
    launcher.env["FAKE_NIX_OUT"] = out
    return out


def test_project_is_evaluated_in_a_sandbox_of_itself(launcher):
    """Without its own sandbox.nix, with the profile's Claude config as the
    base its Claude settings merge into."""
    launcher.config["default"]["claudeDir"] = "/store/claude"
    launcher.config["released"] = int(time.time() - 100 * DAY)
    with_project(launcher, manifest())
    result = launcher.run()
    assert result.returncode == 0, result.stderr
    project = launcher.config["project"]
    assert result.calls("nix") == [
        ["build", "--no-link", "--print-out-paths", "--file", project["eval"],
         "--argstr", "nixpkgs", project["nixpkgs"],
         "--argstr", "system", project["system"],
         "--argstr", "file", str(launcher.project / "sandbox.nix"),
         "--argstr", "base", "/store/claude"],
    ]  # fmt: skip
    inner, outer = (Invocation(argv) for argv in result.calls("pasta"))
    assert inner.command[:2] == ["nix", "build"]
    assert inner.chdir == str(launcher.project)
    assert outer.command is None
    assert f"evaluating {launcher.project}/sandbox.nix" in result.stderr
    # Not again from the launcher that evaluates sandbox.nix.
    assert result.stderr.count("nix profile upgrade sandbox") == 1


def test_project_evaluation_is_cached(launcher):
    out = with_project(launcher, manifest(command=["echo", "n1"]))

    def evaluations(*args):
        result = launcher.run(*args)
        assert result.returncode == 0, result.stderr
        return len(result.calls("nix"))

    assert evaluations() == 1
    assert evaluations() == 0
    cache = json.loads((launcher.volume() / "project.json").read_text())
    assert cache["manifest"] == out
    # Changed, reloaded, or with another profile Claude config, or another
    # sandbox, it's evaluated again.
    (launcher.project / "sandbox.nix").write_text('{ ... }: { command = [ "n2" ]; }\n')
    assert evaluations() == 1
    assert evaluations() == 0
    assert evaluations("--reload") == 1
    launcher.config["default"]["claudeDir"] = "/store/claude"
    assert evaluations() == 1
    other = launcher.tmp / "other-config.json"
    other.write_text(json.dumps(launcher.config))
    assert len(launcher.run(config=other).calls("nix")) == 1
    # A cache that doesn't name a store path is ignored.
    (launcher.volume() / "project.json").write_text(json.dumps({"key": cache["key"], "manifest": "/etc/passwd"}))  # fmt: skip
    assert evaluations() == 1


def test_project_adds_to_the_profile(launcher):
    launcher.config["default"]["claudeDir"] = "/store/claude-default"
    launcher.config["default"]["env"]["A"] = "1"
    with_project(launcher, manifest(command=["echo", "from-manifest"], claudeDir=f"{'/nix/store/' + 'a' * 32}-claude-project"))  # fmt: skip
    result = launcher.run()
    inv = result.pasta
    assert inv.command == ["echo", "from-manifest"]
    assert result.stdout == "from-manifest\n"
    assert inv.bind("/etc/claude-code").endswith("-claude-project")
    assert inv.setenv["A"] == "1"
    # A command given wins.
    assert launcher.run("echo", "given").pasta.command == ["echo", "given"]
    # Without Claude Code in the profile, none comes in through the project.
    launcher.config["default"]["claudeDir"] = None
    assert all(
        len(m) < 3 or m[2] != "/etc/claude-code" for m in launcher.run().pasta.mounts
    )


def test_no_project_config(launcher):
    with_project(launcher, manifest(command=["echo", "from-manifest"]))
    result = launcher.run("--no-project-config")
    assert not result.calls("nix")
    assert result.pasta.command is None


@pytest.mark.parametrize(
    "bad",
    [
        {"claudeDir": "/etc/claude-code"},
        {"claudeDir": "/nix/store/" + "a" * 32 + "-x/../../etc"},
        {"env": {"A": "b"}},
        {"binds": [bind("~/x", mode="rwx")]},
        {"binds": [{"src": "~/x"}]},
        {"binds": [bind("~/x", optional="yes")]},
        {"hostPorts": [5432]},
        {"command": []},
        {"command": "ls"},
        {"extra": True},
    ],
)
def test_refuses_a_bad_manifest(launcher, bad):
    """It comes out of a sandbox; nothing in it is taken on trust."""
    with_project(launcher, manifest(**bad))
    result = launcher.run()
    assert result.returncode == 1
    assert "bad sandbox.nix result" in result.stderr
    assert len(result.calls("pasta")) == 1  # Only the evaluation.


def test_refuses_a_manifest_that_is_not_json(launcher):
    with_project(launcher, manifest())
    launcher.env["FAKE_NIX_OUT"] = store_file(launcher.tmp / "broken", "{", raw=True)
    result = launcher.run()
    assert result.returncode == 1
    assert "can't read the sandbox.nix result" in result.stderr


@pytest.mark.parametrize(
    ("env", "message"),
    [
        ({"FAKE_NIX_OUT": "/etc/passwd"}, "gave no result"),
        (
            {"FAKE_NIX_OUT": "/nix/store/" + "a" * 32 + "-env/../../etc/passwd"},
            "gave no result",
        ),
        ({"FAKE_NIX_EXIT": "1"}, "evaluating .*sandbox.nix failed"),
    ],
)
def test_project_evaluation_failures(launcher, env, message):
    (launcher.project / "sandbox.nix").write_text("{ ... }: { }\n")
    result = launcher.run(env=env)
    assert result.returncode == 1
    assert re.search(message, result.stderr), result.stderr


def test_project_file_must_be_a_regular_file(launcher):
    """The launcher reads it on the host; a link would let the sandbox pick
    which host file."""
    (launcher.project / "sandbox.nix").symlink_to(launcher.config_path)
    refused(launcher.run(), "it must be a regular file")
    (launcher.project / "sandbox.nix").unlink()
    os.mkfifo(launcher.project / "sandbox.nix")
    refused(launcher.run(), "must be a regular file")
    assert not launcher.run().calls("nix")


ACCESS = manifest(hostPorts=["5432"], binds=[bind("~/d", mode="rw"), bind("/srv/x", dst="/x", optional=True)])  # fmt: skip


def test_project_without_host_access_needs_no_approval(launcher):
    with_project(
        launcher, manifest(command=["true"], claudeDir="/nix/store/" + "a" * 32 + "-c")
    )
    assert launcher.run().returncode == 0


def test_host_access_is_asked_once_until_it_changes(launcher):
    with_project(launcher, ACCESS)
    p = launcher.pty("true")
    shown = p.expect("Allow? [y/N] ")
    assert f"{launcher.project}/sandbox.nix asks for host access" in shown
    assert "bind ~/d (read-write)" in shown
    assert "bind /srv/x at /x (read-only, optional)" in shown
    assert "host port 5432" in shown
    p.send("y\r")
    result = p.wait()
    assert result.returncode == 0, result.stdout
    inv = result.pasta
    assert ("--bind", f"{launcher.home}/d", f"{launcher.home}/d") in inv.mounts
    assert ("--ro-bind-try", "/srv/x", "/x") in inv.mounts
    assert inv.pasta_opt("-T") == "5432"

    # Not again, even without a terminal.
    assert launcher.run("true").returncode == 0

    with_project(
        launcher,
        {**ACCESS, "hostPorts": ["5432", "22"]},
        "{ ... }: { x = 1; }\n",
        "m2.json",
    )
    p = launcher.pty("true")
    assert "host port 22" in p.expect("Allow? [y/N] ")
    p.send("n\r")
    result = p.wait()
    assert result.returncode == 1
    assert "host access not approved, not starting" in result.stdout
    assert len(result.calls("pasta")) == 1  # Only the evaluation.


def test_host_access_without_a_terminal_is_refused(launcher):
    with_project(launcher, ACCESS)
    result = launcher.run()
    assert result.returncode == 1
    assert "start the sandbox from a terminal to approve it" in result.stderr


# -- ~/.config/sandbox/config.nix ---------------------------------------------------


class UserConfig:
    """A home with a config.nix, a sandbox that takes one, and a stand-in
    nix-build giving a built config with its own state dir."""

    def __init__(self, launcher, result=None):
        self.launcher = launcher
        self.dir = launcher.home / ".config/sandbox"
        self.dir.mkdir(parents=True)
        (self.dir / "config.nix").write_text("{ ... }: { }\n")
        self.user_state = launcher.tmp / "user-state"
        built = {
            **launcher.config,
            "stateDir": str(self.user_state),
            "userConfig": None,
        }
        self.out = store_file(launcher.tmp / "built.json", result or built)
        launcher.config["userConfig"] = {"eval": "/store/user.nix", "nixpkgs": "/store/np", "system": "s"}  # fmt: skip
        launcher.env["FAKE_NIX_BUILD_OUT"] = self.out

    def builds(self, *args, env=None, **kw):
        result = self.launcher.run(*args, env=env, **kw)
        assert result.returncode == 0, result.stderr
        return result.calls("nix-build")


def test_user_config_is_built_and_cached(launcher):
    u = UserConfig(launcher)
    home = launcher.home
    [argv] = u.builds()
    assert argv == [
        "/store/user.nix", "--argstr", "nixpkgs", "/store/np", "--argstr", "system", "s",
        "--argstr", "file", str(u.dir / "config.nix"),
        "--out-link", str(home / ".local/state/sandbox/config"),
    ]  # fmt: skip
    # Its stateDir, among the rest, is the one used.
    assert (u.user_state / volume_name(str(launcher.project))).is_dir()
    assert not u.builds()
    # A changed or new file in the dir, or --reload, builds it again.
    (u.dir / "config.nix").write_text("{ ... }: { env.A = 1; }\n")
    assert len(u.builds()) == 1
    (u.dir / "sub").mkdir()
    (u.dir / "sub/more.nix").write_text("{ }\n")
    assert len(u.builds()) == 1
    assert not u.builds()
    assert len(u.builds("--reload")) == 1
    # As does another sandbox: an upgrade changes nixpkgs.
    other = launcher.tmp / "other.json"
    other.write_text(launcher.config_path.read_text())
    assert len(u.builds(config=other)) == 1


def test_no_user_config(launcher):
    u = UserConfig(launcher)
    (u.dir / "config.nix").unlink()
    assert not u.builds()
    assert (launcher.state / volume_name(str(launcher.project))).is_dir()
    # A sandbox with a config of its own (mkSandbox, home-manager).
    (u.dir / "config.nix").write_text("{ }\n")
    launcher.config["userConfig"] = None
    assert not u.builds()


def test_user_config_follows_xdg_dirs(launcher):
    u = UserConfig(launcher)
    xdg = launcher.tmp / "xdg"
    (xdg / "sandbox").mkdir(parents=True)
    (xdg / "sandbox/config.nix").write_text("{ }\n")
    [argv] = u.builds(
        env={"XDG_CONFIG_HOME": str(xdg), "XDG_STATE_HOME": str(launcher.tmp / "st")}
    )
    assert argv[argv.index("file") + 1] == str(xdg / "sandbox/config.nix")
    assert argv[-1] == str(launcher.tmp / "st/sandbox/config")


def test_user_config_in_the_project_is_refused(launcher):
    """A dotfiles repo opened as a project: the sandbox could write what the
    host then builds and runs."""
    u = UserConfig(launcher)
    dotfiles = launcher.home / "dotfiles"
    (dotfiles / ".git").mkdir(parents=True)
    (dotfiles / "sandbox").mkdir()
    (dotfiles / "sandbox/config.nix").write_text("{ }\n")
    (u.dir / "config.nix").unlink()
    (u.dir / "config.nix").symlink_to(dotfiles / "sandbox/config.nix")
    refused(
        launcher.run(cwd=dotfiles),
        "refusing to use .*config.nix: .* is in this project",
    )
    # The whole dir linked in too.
    (u.dir / "config.nix").unlink()
    u.dir.rmdir()
    u.dir.symlink_to(dotfiles / "sandbox")
    result = launcher.run(cwd=dotfiles)
    refused(result, "is in this project")
    assert not result.calls("nix-build")
    # From another project it's fine.
    assert len(u.builds()) == 1


def test_user_config_result_must_not_take_one_itself(launcher):
    UserConfig(launcher, result={"userConfig": {"eval": "x"}})
    refused(launcher.run(), "bad .*config.nix result")


def test_user_config_result_must_be_json(launcher):
    UserConfig(launcher)
    launcher.env["FAKE_NIX_BUILD_OUT"] = store_file(
        launcher.tmp / "garbage", "not json", raw=True
    )
    refused(launcher.run(), "can't read the .*config.nix result")


@pytest.mark.parametrize(
    ("env", "message"),
    [
        ({"FAKE_NIX_BUILD_EXIT": "1"}, "building .*config.nix failed"),
        ({"FAKE_NIX_BUILD_OUT": "/etc/passwd"}, "building .*config.nix failed"),
        ({"PATH": "/nonexistent"}, "building .*config.nix needs nix-build on PATH"),
    ],
)
def test_user_config_build_failures(launcher, env, message):
    (launcher.home / ".config/sandbox").mkdir(parents=True)
    (launcher.home / ".config/sandbox/config.nix").write_text("{ }\n")
    launcher.config["userConfig"] = {"eval": "e", "nixpkgs": "n", "system": "s"}
    refused(launcher.run(env=env), message)


# -- Claude API key --------------------------------------------------------------------

KEY = "sk-ant-api03-" + "k" * 40


def type_secret(p, prompt, text):
    """Typed only once the prompt is out and echo is off: read_secret
    flushes pending input when it turns echo off, as a terminal user never
    types ahead."""
    p.expect(prompt)
    time.sleep(0.3)
    p.send(text + "\r")


def api_profile(launcher, where=None):
    launcher.config["profiles"] = [
        Launcher.profile(
            "api", paths=[str(where or launcher.project)], claudeApiKey=True
        )
    ]


def test_claude_api_key_option_follows_the_profile(launcher):
    api_profile(launcher, launcher.home / "api")
    refused(launcher.run("--claude-api-key"), "needs guards.claudeApiKey.enable for this project's profile \\(default\\)")  # fmt: skip


def test_claude_api_key_is_asked_once_and_kept_out_of_the_home(launcher):
    api_profile(launcher)
    p = launcher.pty()
    shown = p.expect("API key (Enter to skip): ")
    assert "https://platform.claude.com/settings/keys" in shown
    time.sleep(0.3)
    p.send(KEY + "\r")
    result = p.wait()
    assert result.returncode == 0, result.stdout
    assert KEY not in result.stdout  # Not echoed.
    key_file = launcher.volume() / "claude-api-key"
    assert key_file.read_text() == KEY + "\n"
    assert stat.S_IMODE(key_file.stat().st_mode) == 0o600
    run = str(launcher.runtime)
    inv = result.pasta
    assert inv.setenv["ANTHROPIC_UNIX_SOCKET"] == f"{run}/claude-api.sock"
    assert inv.setenv["ANTHROPIC_BASE_URL"] == "http://api.anthropic.com"
    assert inv.bind(f"{run}/claude-api.sock").endswith("/claude-api.sock")
    # Not asked again.
    assert launcher.run().returncode == 0


def test_claude_api_key_can_be_replaced_or_kept(launcher):
    api_profile(launcher)

    def set_key(answer):
        p = launcher.pty("--claude-api-key")
        type_secret(p, "API key (Enter to skip): ", answer)
        result = p.wait()
        assert result.returncode == 0, result.stdout
        assert not result.calls("pasta")
        return result

    set_key(KEY)
    key_file = launcher.volume() / "claude-api-key"
    set_key("")
    assert key_file.read_text() == KEY + "\n"
    other = "sk-ant-api03-" + "o" * 40
    set_key(other)
    assert key_file.read_text() == other + "\n"
    assert "doesn't look like an API key" in set_key("x y").stdout
    assert key_file.read_text() == other + "\n"


@pytest.mark.parametrize("answer", ["", "not a key"])
def test_claude_api_key_skipped_or_malformed_is_not_saved(launcher, answer):
    api_profile(launcher)
    p = launcher.pty("true")
    type_secret(p, "API key (Enter to skip): ", answer)
    result = p.wait()
    assert result.returncode == 0, result.stdout
    assert "until `sandbox --claude-api-key` sets one" in result.stdout
    assert not (launcher.volume() / "claude-api-key").exists()


def test_claude_api_key_without_a_terminal_starts_anyway(launcher):
    api_profile(launcher)
    result = launcher.run()
    assert result.returncode == 0
    assert "run `sandbox --claude-api-key` from a terminal" in result.stderr
    assert not (launcher.volume() / "claude-api-key").exists()
    assert "ANTHROPIC_UNIX_SOCKET" in result.pasta.setenv


# -- tokens ---------------------------------------------------------------------------

TOKEN = "github_pat_" + "t" * 40


def test_github_token_is_kept_out_of_the_home(launcher):
    launcher.config["guards"]["github"] = True

    def set_token(answer):
        p = launcher.pty("--gh-token")
        shown = p.expect("GitHub token (Enter to keep the current one): ")
        assert "personal-access-tokens/new" in shown
        time.sleep(0.3)
        p.send(answer + "\r")
        result = p.wait()
        assert result.returncode == 0, result.stdout
        assert not result.calls("pasta")
        return result.stdout

    assert TOKEN not in set_token(TOKEN)
    token_file = launcher.volume() / "github-token"
    assert token_file.read_text() == TOKEN + "\n"
    assert stat.S_IMODE(token_file.stat().st_mode) == 0o600
    assert "nothing changed" in set_token("")
    assert "doesn't look like a token" in set_token("has space")
    assert token_file.read_text() == TOKEN + "\n"


def test_forgejo_tokens_are_kept_per_host(launcher):
    launcher.config["guards"]["forgejo"] = True
    for host, token in (("https://A.example/x/", "aaaaaaaa"), ("b.example", "bbbbbbbb"),
                        ("a.example:443", "cccccccc")):  # fmt: skip
        p = launcher.pty("--fj-token", host)
        shown = p.expect("(Enter to keep the current one): ")
        assert (
            "https://"
            + host.lower().removeprefix("https://").split("/")[0].removesuffix(":443")
            in shown
        )
        time.sleep(0.3)
        p.send(token + "\r")
        assert p.wait().returncode == 0
    tokens_file = launcher.volume() / "forgejo-tokens.json"
    assert json.loads(tokens_file.read_text()) == {
        "a.example": "cccccccc",
        "b.example": "bbbbbbbb",
    }
    assert stat.S_IMODE(tokens_file.stat().st_mode) == 0o600


def test_forgejo_tokens_file_that_is_not_a_map_is_replaced(launcher):
    launcher.config["guards"]["forgejo"] = True
    launcher.run()
    (launcher.volume() / "forgejo-tokens.json").write_text("[1]")
    p = launcher.pty("--fj-token", "a.example")
    type_secret(p, "(Enter to keep the current one): ", "aaaaaaaa")
    assert p.wait().returncode == 0
    assert json.loads((launcher.volume() / "forgejo-tokens.json").read_text()) == {
        "a.example": "aaaaaaaa"
    }


@pytest.mark.parametrize(
    ("args", "guard"),
    [(["--gh-token"], "github"), (["--fj-token", "a.example"], "forgejo")],
)
def test_tokens_need_their_guard_and_a_terminal(launcher, args, guard):
    refused(launcher.run(*args), f"needs guards.{guard}.enable")
    launcher.config["guards"][guard] = True
    refused(launcher.run(*args), "setting a token needs a terminal")
    # Inside a sandbox it would land in that sandbox's volume.
    refused(launcher.run(*args, env={"SANDBOX_EXCHANGE": "/x/exchange"}), "inside a sandbox - set the token on the host")  # fmt: skip
    assert not (launcher.volume() / "github-token").exists()


# -- guards ---------------------------------------------------------------------------


def guard_procs(path):
    """Processes with path in their command line."""
    found = []
    for pid in os.listdir("/proc"):
        try:
            cmdline = Path(f"/proc/{pid}/cmdline").read_bytes()
        except OSError:
            continue
        if pid.isdigit() and str(path).encode() in cmdline:
            found.append(pid)
    return found


class FakeAgent:
    """An upstream ssh agent answering every request with no identities."""

    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.bind(str(path))
        self.sock.listen(4)
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                if conn.recv(4096):
                    conn.sendall(struct.pack(">IBI", 5, 12, 0))


LIST_IDENTITIES = """
import os, socket, struct
s = socket.socket(socket.AF_UNIX)
s.connect(os.environ["SSH_AUTH_SOCK"])
s.sendall(struct.pack(">IB", 1, 11))
print(s.recv(64).hex())
"""


def test_ssh_agent_guard(launcher):
    launcher.config["guards"]["sshAgent"]["enable"] = True
    FakeAgent(launcher.tmp / "agent.sock")
    result = launcher.run(
        *py(LIST_IDENTITIES), env={"SSH_AUTH_SOCK": str(launcher.tmp / "agent.sock")}
    )
    assert result.returncode == 0, result.stderr
    inside = f"{launcher.runtime}/ssh-agent.sock"
    inv = result.pasta
    assert inv.setenv["SSH_AUTH_SOCK"] == inside
    assert (
        "--ro-bind-try",
        f"{launcher.home}/.ssh/known_hosts",
        "/etc/ssh/ssh_known_hosts",
    ) in inv.mounts
    # Through the guard: identities answer, no keys.
    assert result.stdout.strip() == "000000050c00000000"
    assert not os.path.exists(inv.bind(inside))


def test_ssh_agent_socket_from_the_config(launcher):
    agent = launcher.config["guards"]["sshAgent"]
    agent.update(
        enable=True, socket="~/agent.sock", path="$XDG_RUNTIME_DIR/my-agent.sock"
    )
    FakeAgent(launcher.home / "agent.sock")
    launcher.env.pop("SSH_AUTH_SOCK", None)
    result = launcher.run(*py(LIST_IDENTITIES))
    assert result.returncode == 0, result.stderr
    assert result.pasta.setenv["SSH_AUTH_SOCK"] == f"{launcher.runtime}/my-agent.sock"
    assert result.stdout.strip() == "000000050c00000000"


def test_no_ssh_agent(launcher):
    launcher.config["guards"]["sshAgent"]["enable"] = True
    launcher.env.pop("SSH_AUTH_SOCK", None)
    result = launcher.run()
    assert "no ssh agent ($SSH_AUTH_SOCK unset), none inside" in result.stderr
    assert "SSH_AUTH_SOCK" not in result.pasta.setenv


def test_secret_service_guard(launcher):
    if not os.path.exists(launcher.config["dbusDaemon"]):
        pytest.skip("no dbus-daemon")
    launcher.config["guards"]["secretService"] = True
    result = launcher.run()
    assert result.returncode == 0, result.stderr
    run = str(launcher.runtime)
    inv = result.pasta
    assert inv.setenv["DBUS_SESSION_BUS_ADDRESS"] == f"unix:path={run}/bus"
    assert inv.bind(f"{run}/bus").endswith("/bus.sock")
    volume = launcher.volume()
    assert stat.S_IMODE(volume.stat().st_mode) == 0o700
    # The database is never bound in, only the socket.
    assert all(len(m) < 3 or "secrets.sqlite3" not in m[1] for m in inv.mounts)


def test_a_guard_that_exits_stops_the_start(launcher):
    launcher.config["guards"]["secretService"] = True
    launcher.config["dbusDaemon"] = shutil.which("false")
    refused(launcher.run(), "dbus-daemon exited with status 1")
    # Its temp dir is removed all the same.
    assert not list(launcher.tmpdir.iterdir())


PROXY_CHECK = """
import base64, json, os, re, socket
ca = open(os.environ["SANDBOX_CA_FILE"]).read()
assert ca.startswith("SYSTEM CA BUNDLE\\n-----BEGIN CERTIFICATE-----"), ca[:80]
url = os.environ[os.environ["VAR"]]
secret, port = re.fullmatch(r"http://sandbox:([^@:]+)@127\\.0\\.0\\.1:([0-9]+)", url).groups()

def connect(secret):
    s = socket.create_connection(("127.0.0.1", int(port)), timeout=10)
    auth = base64.b64encode(f"sandbox:{secret}".encode()).decode()
    s.sendall(f"CONNECT 127.0.0.1:9 HTTP/1.1\\r\\nProxy-Authorization: Basic {auth}\\r\\n\\r\\n".encode())
    return s.recv(64).split(b"\\r\\n")[0].decode()

print(json.dumps([port, connect(secret), connect("wrong")]))
"""


@pytest.mark.parametrize(
    ("guard", "var"), [("github", "SANDBOX_GH_PROXY"), ("forgejo", "SANDBOX_FJ_PROXY")]
)
def test_https_proxy_guards(launcher, guard, var):
    """The proxy URL carries the secret the guard checks, its port is mapped
    in, and its CA is in the bundle gh/fj inside trust."""
    launcher.config["guards"][guard] = True
    result = launcher.run(*py(PROXY_CHECK), env={"VAR": var})
    assert result.returncode == 0, result.stderr
    port, ok, wrong = json.loads(result.stdout)
    inv = result.pasta
    assert inv.pasta_opt("-T") == port
    assert " 407 " not in ok, ok
    assert " 407 " in wrong, wrong
    run = str(launcher.runtime)
    assert inv.setenv["SANDBOX_CA_FILE"] == f"{run}/sandbox-ca.pem"
    assert (
        "--ro-bind",
        inv.bind(f"{run}/sandbox-ca.pem"),
        f"{run}/sandbox-ca.pem",
    ) in inv.mounts
    if guard == "github":
        # Only so gh considers itself logged in; never the host's token.
        assert inv.setenv["GH_TOKEN"] == "sandbox-placeholder"


def test_host_ports_and_proxy_ports_together(launcher):
    launcher.config["guards"]["forgejo"] = True
    launcher.config["hostPorts"] = ["5037"]
    inv = launcher.run().pasta
    ports = inv.pasta_opt("-T").split(",")
    assert ports[0] == "5037" and len(ports) == 2


def test_no_ca_bundle_without_intercepting_guards(launcher):
    inv = launcher.run().pasta
    assert "SANDBOX_CA_FILE" not in inv.setenv


XDG_OPEN_LOG = """
import json, os, sys
with open(os.environ["XDG_OPEN_LOG"], "a") as f:
    f.write(json.dumps({"argv": sys.argv[1:], "PATH": os.environ["PATH"],
                        "PYTHONPATH": os.environ.get("PYTHONPATH")}) + "\\n")
"""


def open_url(launcher, url):
    xdg = launcher.host_bin / "xdg-open"
    xdg.write_text(f"#!{sys.executable}\n{XDG_OPEN_LOG}")
    xdg.chmod(0o755)
    launcher.config["guards"]["openUrl"] = True
    return launcher.pty(
        sys.executable, str(BIN_DIR / "sandbox-xdg-open"), url,
        env={"XDG_OPEN_LOG": str(launcher.tmp / "xdg.log"), "PYTHONPATH": "/project"},
    )  # fmt: skip


def test_open_url_asks_in_a_popup_and_opens_on_the_host(launcher):
    """The guard runs the host's xdg-open, from the store's tools first on
    PATH and without the launcher's PYTHONPATH, after a yes in the popup the
    launcher draws on its terminal."""
    p = open_url(launcher, "https://example.org/x")
    shown = p.expect("y = once, A = always in this sandbox, N = no:")
    assert "https://example.org/x" in shown
    time.sleep(0.6)  # Keys typed right after a popup appears are dropped.
    p.send("y\r")
    result = p.wait()
    assert result.returncode == 0, result.stdout
    # Started in the background, so the sandbox doesn't wait for the browser.
    log = launcher.tmp / "xdg.log"
    deadline = time.monotonic() + 10
    while not log.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    [opened] = [json.loads(line) for line in log.read_text().splitlines()]
    assert opened["argv"] == ["https://example.org/x"]
    assert opened["PATH"].startswith(f"{launcher.host_bin}:")
    assert opened["PYTHONPATH"] is None
    inv = result.pasta
    assert inv.setenv["BROWSER"] == "/usr/bin/xdg-open"
    # The guard is stopped and its dir removed with the sandbox.
    sock_dir = Path(inv.bind(f"{launcher.runtime}/open-url.sock")).parent
    assert not list(launcher.tmpdir.iterdir())
    assert guard_procs(sock_dir) == []


def test_open_url_denied_in_the_popup(launcher):
    p = open_url(launcher, "https://example.org/x")
    p.expect("N = no:")
    time.sleep(0.6)
    p.send("n\r")
    result = p.wait()
    assert result.returncode == 4, result.stdout
    assert "denied" in result.stdout
    assert not (launcher.tmp / "xdg.log").exists()


def test_open_url_without_a_terminal_is_denied(launcher):
    """No one to ask: the guards answer no."""
    launcher.config["guards"]["openUrl"] = True
    (launcher.host_bin / "xdg-open").write_text("#!/bin/sh\nexit 0\n")
    result = launcher.run(
        sys.executable, str(BIN_DIR / "sandbox-xdg-open"), "https://example.org/"
    )
    assert result.returncode == 4
    assert "denied" in result.stderr


# -- the terminal ---------------------------------------------------------------------


ECHO = """
import os, sys
print("size", *os.get_terminal_size(), flush=True)
print("got", input("say: "), flush=True)
"""


def test_terminal_is_relayed(launcher):
    """The sandbox runs on a pty of the launcher's, sized like its own."""
    p = launcher.pty(*py(ECHO))
    assert "size 80 24" in p.expect("say: ")
    p.send("hello\r")
    p.expect("got hello")
    result = p.wait()
    assert result.returncode == 0
    [entry] = [e for e in result.log if e["tool"] == "pasta"]
    assert entry["tty"]


def test_sigterm_stops_the_sandbox_and_its_guards(launcher):
    launcher.config["guards"]["openUrl"] = True
    ready = launcher.tmp / "ready"
    proc = subprocess.Popen(
        launcher.argv([*py(f"import pathlib, time; pathlib.Path({str(ready)!r}).touch(); time.sleep(60)")], None),
        cwd=launcher.project,
        env=launcher.env,
        stdin=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )  # fmt: skip
    deadline = time.monotonic() + 20
    while not ready.exists():
        assert time.monotonic() < deadline and proc.poll() is None
        time.sleep(0.05)
    log = [json.loads(line) for line in launcher.log_path.read_text().splitlines()]
    sock = [a for a in log[-1]["argv"] if a.endswith("/open-url.sock") and not a.startswith(str(launcher.runtime))]  # fmt: skip
    sock_dir = Path(sock[0]).parent
    assert guard_procs(sock_dir)
    proc.terminate()
    assert proc.wait(timeout=10) != 0
    assert not list(launcher.tmpdir.iterdir())
    deadline = time.monotonic() + 5
    while guard_procs(sock_dir) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert guard_procs(sock_dir) == []
