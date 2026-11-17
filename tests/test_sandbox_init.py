"""Tests for src/sandbox-init, against a fake $HOME and fake home-manager
generations - it only touches $HOME, so unlike test_sandbox.py this needs no
real sandbox."""

import os
import shutil
import subprocess
import sys

import pytest
from conftest import BIN_DIR, load_module

SANDBOX_INIT = BIN_DIR / "sandbox-init"


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

    def run(*cmd):
        return subprocess.run(
            [sys.executable, str(SANDBOX_INIT), "/nix/profile", str(current[0]), *(cmd or ["true"])],
            env={"HOME": str(home), "PATH": os.environ["PATH"]},
            capture_output=True,
            text=True,
            check=True,
        )

    return home, generation, run


def test_links_every_file_into_the_generation(env):
    home, generation, run = env
    gen = generation("a", {".bashrc": "a\n", ".config/foo/conf": "foo\n"})
    run()
    assert (home / ".bashrc").readlink() == gen / ".bashrc"
    assert (home / ".config/foo/conf").read_text() == "foo\n"


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
    generation("b", {})
    run()
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
    assert "~/.full" in result.stderr


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


def test_links_nix_profile_and_execs_the_command(env):
    home, generation, run = env
    generation("a", {})
    result = run("echo", "ran")
    assert result.stdout == "ran\n"
    assert str((home / ".nix-profile").readlink()) == "/nix/profile"
    profile = home / ".local/state/nix/profiles/home-manager"
    assert (profile / "home-files").is_symlink()
    assert (home / ".config/gh/config.yml").read_text() == "git_protocol: ssh\n"


def test_without_profile_or_generation_only_execs(env):
    home, _, _ = env
    result = subprocess.run(
        [sys.executable, str(SANDBOX_INIT), "", "", "echo", "ran"],
        env={"HOME": str(home), "PATH": os.environ["PATH"]},
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout == "ran\n"
    assert not (home / ".nix-profile").is_symlink()
    assert not (home / ".local/state/nix/profiles").exists()


def test_skips_mounts_over_the_volume(env, monkeypatch):
    """A bind under $HOME (a repo, say) may hold links that look like
    generation links; they're not the volume's to remove."""
    home, generation, _ = env
    old = generation("a", {".bashrc": "a\n"})
    mounted = home / "mounted"
    mounted.mkdir()
    (mounted / "link").symlink_to(old / ".bashrc")
    init = load_module("sandbox-init")
    generation("b", {".bashrc": "b\n"})
    monkeypatch.setattr(init, "mount_points", lambda _home: {str(mounted)})
    monkeypatch.setenv("HOME", str(home))
    init.link_generation(home, home.parent / "store" / "b-home-manager-generation")
    assert (mounted / "link").is_symlink()
    assert (home / ".bashrc").read_text() == "b\n"


def test_links_known_marketplaces_to_the_managed_list(tmp_path):
    init = load_module("sandbox-init")
    home, managed = tmp_path / "home", tmp_path / "managed"
    home.mkdir()
    managed.mkdir()
    link = home / ".claude/plugins/known_marketplaces.json"
    target = managed / "known_marketplaces.json"

    # A fresh volume has no list yet; with no managed one, nothing is made.
    init.link_known_marketplaces(home, managed)
    assert not link.parent.exists()

    # One Claude Code wrote itself is replaced.
    link.parent.mkdir(parents=True)
    link.write_text("{}")
    target.write_text('{"sandbox": {}}')
    init.link_known_marketplaces(home, managed)
    assert link.readlink() == target
    assert link.read_text() == '{"sandbox": {}}'

    # Gone from the configuration, the link goes too.
    target.unlink()
    init.link_known_marketplaces(home, managed)
    assert not link.is_symlink()


def test_leaves_the_volumes_own_marketplace_list_without_a_managed_one(tmp_path):
    init = load_module("sandbox-init")
    link = tmp_path / ".claude/plugins/known_marketplaces.json"
    link.parent.mkdir(parents=True)
    link.write_text("{}")
    init.link_known_marketplaces(tmp_path, tmp_path / "managed")
    assert link.read_text() == "{}"
