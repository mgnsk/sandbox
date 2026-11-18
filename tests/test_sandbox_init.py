"""Black-box tests for src/sandbox-init, run as a program against a fake
$HOME and fake home-manager generations - it only touches $HOME, so most of
this needs no real sandbox.

What it reads from the mount namespace - the mounts over the volume, the
managed Claude Code config at /etc/claude-code - is tested in one made with
bwrap, so those tests need a host with unprivileged user namespaces and skip
themselves elsewhere (e.g. inside a sandbox). $SANDBOX_GUARD_CMD (see
guards.py) runs another implementation."""

import os
import shutil
import subprocess

import pytest
from guards import guard_argv

MANAGED = "/etc/claude-code/known_marketplaces.json"


@pytest.fixture
def env(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    store = tmp_path / "store"
    store.mkdir()
    current = [None]

    def generation(name, files):
        """A home-files tree of links to store files, made current."""
        gen = store / f"{name}-home-manager-files"
        gen.mkdir()
        for rel, content in files.items():
            src = store / f"{name}-{rel.replace('/', '-')}"
            src.write_text(content)
            (gen / rel).parent.mkdir(parents=True, exist_ok=True)
            (gen / rel).symlink_to(src)
        current[0] = store / f"{name}-home-manager-generation"
        current[0].mkdir()
        (current[0] / "home-files").symlink_to(gen)
        return gen

    def run(*cmd, profile="/nix/profile", wrap=()):
        result = subprocess.run(
            [
                *wrap,
                *guard_argv(
                    "sandbox-init", profile, current[0] or "", *(cmd or ["true"])
                ),
            ],
            env={"HOME": str(home), "PATH": os.environ["PATH"]},
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        return result

    return home, generation, run


def test_links_every_file_into_the_generation(env):
    home, generation, run = env
    gen = generation("a", {".bashrc": "a\n", ".config/foo/conf": "foo\n"})
    run()
    assert (home / ".bashrc").readlink() == gen / ".bashrc"
    assert (home / ".config/foo/conf").read_text() == "foo\n"
    # For tools that diff a build against the current generation.
    profile = home / ".local/state/nix/profiles/home-manager"
    assert (profile / "home-files").resolve() == gen


def test_a_switch_changes_content_and_unlinks_removed_files(env):
    home, generation, run = env
    generation("a", {".bashrc": "a\n", ".config/old": "old\n"})
    run()
    generation("b", {".bashrc": "b\n", ".config/new": "new\n"})
    run()
    assert (home / ".bashrc").read_text() == "b\n"
    assert not (home / ".config/old").is_symlink()
    assert (home / ".config/new").read_text() == "new\n"


def test_unlinks_files_of_a_garbage_collected_generation(env):
    home, generation, run = env
    old = generation("a", {".config/old": "old\n"})
    run()
    shutil.rmtree(old)
    generation("b", {".bashrc": "b\n"})
    run()
    assert not (home / ".config/old").is_symlink()


def test_leaves_the_volumes_own_files_alone(env):
    home, generation, run = env
    generation("a", {".config/managed": "a\n"})
    run()
    (home / ".config/managed").unlink()
    (home / ".config/managed").write_text("the sandbox's own\n")
    (home / "notes").write_text("mine\n")
    (home / "broken").symlink_to("/nonexistent")
    (home / "other").symlink_to("/nix/store/abc-foo/bar")
    # Into the same store, but not to a generation's files.
    (home / "tool").symlink_to(home.parent / "store/abc-tool/bin/tool")
    generation("b", {})
    run()
    assert (home / "tool").is_symlink()
    assert (home / ".config/managed").read_text() == "the sandbox's own\n"
    assert (home / "notes").read_text() == "mine\n"
    assert (home / "broken").is_symlink()
    assert (home / "other").is_symlink()


def test_replaces_files_and_empty_dirs_but_not_full_dirs(env):
    home, generation, run = env
    (home / ".stub").mkdir()
    (home / ".copy").write_text("stale\n")
    (home / ".full").mkdir()
    (home / ".full/keep").write_text("keep\n")
    generation("a", {".stub": "s\n", ".copy": "c\n", ".full": "f\n"})
    result = run()
    assert (home / ".stub").read_text() == "s\n"
    assert (home / ".copy").read_text() == "c\n"
    assert (home / ".full/keep").read_text() == "keep\n"
    assert (
        "sandbox-init: not linking ~/.full, a non-empty directory is in the way"
        in result.stderr
    )


def test_a_file_where_a_directory_is_needed_is_reported(env):
    home, generation, run = env
    (home / ".config").write_text("a file, not a dir\n")
    generation("a", {".config/foo": "a\n", ".bashrc": "b\n"})
    result = run()
    assert "sandbox-init: not linking ~/.config/foo: " in result.stderr
    # The rest is linked all the same, and the sandbox still starts.
    assert (home / ".bashrc").read_text() == "b\n"
    assert "sandbox-init: not writing" in result.stderr


def test_a_switch_splitting_a_file_into_a_directory_relinks_it(env):
    home, generation, run = env
    generation("a", {".config/foo": "a\n"})
    run()
    generation("b", {".config/foo/bar": "b\n"})
    run()
    assert not (home / ".config/foo").is_symlink()
    assert (home / ".config/foo/bar").read_text() == "b\n"


def test_keeps_a_link_to_a_directory_symlink(env):
    home, generation, run = env
    gen = generation("a", {".bashrc": "a\n"})
    src = home.parent / "store" / "dir"
    src.mkdir()
    (gen / ".dirlink").symlink_to(src)
    run()
    run()
    assert (home / ".dirlink").readlink() == gen / ".dirlink"


def test_a_leftover_temp_link_is_replaced(env):
    home, generation, run = env
    generation("a", {".bashrc": "a\n"})
    (home / "..bashrc.sandbox-init").symlink_to("/nonexistent")
    run()
    assert (home / ".bashrc").read_text() == "a\n"
    assert not (home / "..bashrc.sandbox-init").is_symlink()


def test_links_nix_profile_and_execs_the_command(env):
    home, generation, run = env
    generation("a", {})
    result = run("echo", "ran")
    assert result.stdout == "ran\n"
    assert str((home / ".nix-profile").readlink()) == "/nix/profile"
    assert (home / ".config/gh/config.yml").read_text() == "git_protocol: ssh\n"


def test_an_existing_gh_config_is_the_sandboxs_own(env):
    home, _, run = env
    (home / ".config/gh").mkdir(parents=True)
    (home / ".config/gh/config.yml").write_text("git_protocol: https\n")
    run()
    assert (home / ".config/gh/config.yml").read_text() == "git_protocol: https\n"
    (home / ".config/gh/config.yml").unlink()
    (home / ".config/gh/config.yml").symlink_to("/nonexistent")
    run()
    assert (home / ".config/gh/config.yml").is_symlink()


def test_without_profile_or_generation_only_execs(env):
    home, _, run = env
    result = run("echo", "ran", profile="")
    assert result.stdout == "ran\n"
    assert not (home / ".nix-profile").is_symlink()
    assert not (home / ".local/state/nix/profiles").exists()


def test_a_missing_generation_is_skipped(env, tmp_path):
    home, generation, run = env
    generation("a", {".bashrc": "a\n"})
    shutil.rmtree(tmp_path / "store/a-home-manager-generation")
    assert run("echo", "ran").stdout == "ran\n"
    assert not (home / ".bashrc").exists()


def test_marketplace_list_follows_this_hosts_managed_one(env):
    """Whatever this host has at /etc/claude-code; the bwrap tests below
    cover both cases on any host."""
    home, _, run = env
    link = home / ".claude/plugins/known_marketplaces.json"
    run()
    if os.path.exists(MANAGED):
        assert str(link.readlink()) == MANAGED
    else:
        assert not link.parent.exists()


# -- in a mount namespace ---------------------------------------------------------


def _bwrap():
    bwrap = shutil.which("bwrap")
    if bwrap is None:
        return None
    probe = subprocess.run(
        [bwrap, "--unshare-user", "--dev-bind", "/", "/", "true"],
        capture_output=True,
        check=False,
    )
    return bwrap if probe.returncode == 0 else None


@pytest.fixture
def bwrap():
    found = _bwrap()
    if found is None:
        pytest.skip(
            "needs bwrap and unprivileged user namespaces (unavailable inside a sandbox)"
        )
    return found


def test_skips_mounts_over_the_volume(env, bwrap, tmp_path):
    """A bind under $HOME (a repo, say) may hold links that look like
    generation links; they're not the volume's to remove."""
    home, generation, run = env
    old = generation("a", {".bashrc": "a\n"})
    repo = tmp_path / "repo with space"
    repo.mkdir()
    (repo / "link").symlink_to(old / ".bashrc")
    (home / "mounted dir").mkdir()
    generation("b", {".bashrc": "b\n"})
    run(
        wrap=[
            bwrap,
            "--unshare-user",
            "--dev-bind",
            "/",
            "/",
            "--bind",
            repo,
            home / "mounted dir",
            "--",
        ]
    )
    assert (repo / "link").is_symlink()
    assert (home / ".bashrc").read_text() == "b\n"


def test_links_known_marketplaces_to_the_managed_list(env, bwrap, tmp_path):
    home, _, run = env
    managed = tmp_path / "managed"
    managed.mkdir()
    link = home / ".claude/plugins/known_marketplaces.json"
    target = "/etc/claude-code/known_marketplaces.json"

    def run_with_managed():
        run(
            wrap=[
                bwrap,
                "--unshare-user",
                "--dev-bind",
                "/",
                "/",
                # bwrap can't make the mount point in the host's /etc, which
                # may have no claude-code; sandbox-init needs nothing else there.
                "--tmpfs",
                "/etc",
                "--ro-bind",
                managed,
                "/etc/claude-code",
                "--",
            ]
        )

    # A fresh volume has no list yet; with no managed one, nothing is made.
    run_with_managed()
    assert not link.parent.exists()

    # One Claude Code wrote itself is replaced.
    link.parent.mkdir(parents=True)
    link.write_text("{}")
    (managed / "known_marketplaces.json").write_text('{"sandbox": {}}')
    run_with_managed()
    assert str(link.readlink()) == target
    run_with_managed()
    assert str(link.readlink()) == target

    # Gone from the configuration, the link goes too.
    (managed / "known_marketplaces.json").unlink()
    run_with_managed()
    assert not link.is_symlink()

    # The volume's own list, without a managed one, stays.
    link.write_text("{}")
    run_with_managed()
    assert link.read_text() == "{}"
