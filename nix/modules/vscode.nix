# vscode.*: VS Code in the sandbox, as `code`, its windows on the host's
# Wayland display through the Wayland guard, which this turns on.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib) mkOption types;
  cfg = config.vscode;

  vscode =
    if cfg.extensions == [ ] then
      cfg.package
    else
      pkgs.vscode-with-extensions.override {
        vscode = cfg.package;
        vscodeExtensions = cfg.extensions;
      };

  fontsConf = pkgs.makeFontsConf {
    # The stock rules: generic family aliases, and 50-user.conf, which reads
    # the user's own ~/.config/fontconfig.
    includes = [ "${pkgs.fontconfig.out}/etc/fonts/conf.d" ];
    fontDirectories = cfg.fonts;
  };

  code = pkgs.writeShellScriptBin "code" ''
    # Set by the Wayland guard.
    if [ -z "''${WAYLAND_DISPLAY-}" ]; then
      echo "code: no Wayland display in the sandbox: start it from a Wayland session" >&2
      exit 1
    fi
    # No /etc/fonts inside.
    export FONTCONFIG_FILE=''${FONTCONFIG_FILE:-${fontsConf}}
    # Chromium's own sandbox needs user namespaces, which the sandbox
    # blocks.
    exec ${lib.getExe vscode} --no-sandbox --ozone-platform=wayland \
      ${lib.escapeShellArgs cfg.args} "$@"
  '';
in
{
  options.vscode = {
    enable = lib.mkEnableOption "VS Code in the sandbox, as `code`, with the Wayland guard on";
    package = mkOption {
      type = types.package;
      default = pkgs.vscode;
      defaultText = lib.literalExpression "pkgs.vscode";
      description = "VS Code (unfree: the pkgs given must allow it).";
    };
    extensions = mkOption {
      type = types.listOf types.package;
      default = [ ];
      example = lib.literalExpression "[ pkgs.vscode-extensions.anthropic.claude-code ]";
      description = "Extensions, built in (vscode-with-extensions): pinned like the rest, none installed into the volume by hand.";
    };
    fonts = mkOption {
      type = types.listOf types.package;
      default = [
        pkgs.dejavu_fonts
        pkgs.noto-fonts-color-emoji
      ];
      defaultText = lib.literalExpression "[ pkgs.dejavu_fonts pkgs.noto-fonts-color-emoji ]";
      description = "Fonts for its fontconfig: the sandbox has no host fonts.";
    };
    args = mkOption {
      type = types.listOf types.str;
      default = [ "--disable-workspace-trust" ];
      description = ''
        Arguments it's always started with. The default skips the workspace
        trust prompt, which keeps extensions off until it is answered: the
        sandbox is the boundary.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    packages = [ code ];
    guards.wayland.enable = lib.mkDefault true;
  };
}
