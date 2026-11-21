# The options of a project's sandbox module (sandbox.lib.mkShell's
# `sandbox`): for manifest.nix, which evaluates one, and the options
# reference (options-doc.nix).
{ lib, layer }:
let
  inherit (lib) mkOption types;

  # What a project asks of the host is the user's to allow.
  approved = "Takes the user's yes on the terminal, asked once and again for anything new; their own config's wins.";
in
layer.options
// {
  hostPorts = layer.hostPortsOption approved;
  command = mkOption {
    type = types.nullOr (types.listOf types.str);
    default = null;
    example = [
      "nix"
      "develop"
    ];
    description = "What `sandbox` with no command runs, in place of a login shell.";
  };
  git.fromHost = mkOption {
    type = types.bool;
    default = false;
    description = ''
      Take git's name, email and ssh signing key inside from each
      user's global git config on the host (`git config --global`,
      run from /), where nothing more specific sets them. A user's
      .sandbox.yml can turn it off (git.fromHost: false).
    '';
  };
  git.signingKey = mkOption {
    type = types.nullOr types.str;
    default = null;
    example = "ssh-ed25519 AAAA...";
    description = "An ssh public key in the user's agent: git inside signs commits and tags with it. A user's .sandbox.yml wins.";
  };
  git.signingKeyCommand = mkOption {
    type = types.nullOr types.str;
    default = null;
    example = "op read \"op://Employee/GitHub SSH key/public key\"";
    description = ''
      A shell command printing that public key, run on the host at
      each start once the user approves it, like the token
      commands. A user's .sandbox.yml wins.
    '';
  };
  guards = layer.tokenCommandOptions approved // {
    wayland.enable = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Windows on the host's Wayland display, for GUI programs
        inside, through a proxy that passes on only an allowlist of
        the compositor's globals. Takes the user's yes on the
        terminal (asked once, and again for anything new); their
        own config can turn it on or off for every project.
      '';
    };
    wayland.globals = mkOption {
      type = types.attrsOf types.bool;
      default = { };
      example = {
        wl_data_device_manager = true;
      };
      description = ''
        Changes to the allowlist of Wayland globals, by interface
        name: true adds one to the default list, which takes the
        user's yes like enable; false removes one. The user's own
        changes go over these.
      '';
    };
  };
}
