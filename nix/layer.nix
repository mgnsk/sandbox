# What the top level and each profile can set, and the options both take
# with a note on whose word they are. For module.nix.
#
# Not packages or env: those are the top level's alone (module.nix). A
# project's tools and variables come from its dev shell (a flake, devenv),
# yours from your config, ~/.nix-profile or home-manager.
{ lib, pkgs }:
let
  inherit (lib) mkOption types;
  json = pkgs.formats.json { };

  bindType = types.submodule {
    options = {
      src = mkOption {
        type = types.str;
        description = "Host path. `~` and `$HOME`, `$USER`, `$XDG_RUNTIME_DIR` are expanded at start.";
      };
      dst = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Path inside; the same as src when null.";
      };
      mode = mkOption {
        type = types.enum [
          "ro"
          "rw"
        ];
        default = "ro";
        description = "Read-only, or read-write.";
      };
      optional = mkOption {
        type = types.bool;
        default = false;
        description = "Skip silently when src doesn't exist.";
      };
      hideGit = mkOption {
        type = types.bool;
        default = false;
        description = "Put an empty tmpfs over src/.git, so a repo bound for reference doesn't show its history. A bind of the project itself is skipped in favour of the project bind, read-write with .git.";
      };
    };
  };
in
{
  inherit json;

  # guards.*.tokenCommand(s): the same options at the top level and in a
  # profile. Only whose word it is differs,
  # which note says.
  tokenCommandOptions = note: {
    github.tokenCommand = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "op read op://Employee/GitHub/token";
      description = ''
        A shell command that prints the GitHub token, e.g. from a secret
        manager, run on the host at each start. With one, GitHub API
        requests from inside - any gh's, or any other client's - go through
        a host proxy that adds the token and holds writes for a popup. The
        token is handed to the proxy in memory: never on disk, never inside
        the sandbox. Without one that proxy doesn't run, and requests go
        out without a token. ${note}
      '';
    };
    forgejo.tokenCommands = mkOption {
      type = types.attrsOf types.str;
      default = { };
      example = {
        "codeberg.org" = "op read op://Employee/Codeberg/token";
      };
      description = ''
        The same per Forgejo instance, by host[:port]: each command prints
        that instance's token. ${note}
      '';
    };
    claudeApiKey.tokenCommand = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "op read op://Employee/Claude/credential";
      description = ''
        A shell command that prints a Claude API key, run like
        guards.github.tokenCommand. With one, Claude Code inside sends its
        requests to a host proxy that adds the key - in place of logging in
        inside, so not for Claude subscriptions. claude.enable's Claude
        Code takes the placeholder key it needs then; another needs
        `apiKeyHelper` set to `echo sandbox-placeholder`. ${note}
      '';
    };
  };

  hostPortsOption =
    note:
    mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [
        "5037"
        "8080/udp"
        "9000-9010"
      ];
      description = "Host loopback ports reachable inside at 127.0.0.1, in addition to $SANDBOX_HOST_PORTS at start. ${note}";
    };

  allowNetOption =
    note:
    mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [
        "192.168.1.50"
        "10.0.0.0/8"
        "192.168.1.*"
        "nas.lan"
        "tailscale"
      ];
      description = "Where the sandbox may connect besides the public internet, in addition to $SANDBOX_ALLOW_NET at start: by default it reaches no private, CGNAT, link-local or multicast address, so no other machine on the LAN or tailnet. An entry is an address, a CIDR, an IPv4 address with `*` for its last octets, a host name (resolved on the host at start), `lan` (the private and link-local ranges), `tailscale` (100.64.0.0/10 and fd7a:115c:a1e0::/48) or `all`. The host's own services stay behind hostPorts. ${note}";
    };

  options = {
    binds = mkOption {
      type = types.listOf bindType;
      default = [ ];
      description = "Host paths bound in, after the per-project home volume (so they shadow it).";
    };
  };
}
