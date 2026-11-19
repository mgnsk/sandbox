# Options for one `sandbox` command, evaluated by lib.mkSandbox (flake.nix).
# config.package is the result.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib) mkOption types;
  cfg = config;
  json = pkgs.formats.json { };

  sandboxPkgs = pkgs.callPackage ./packages.nix { };

  # An option that's gone, as an error naming what to do instead.
  removed = path: {
    options = lib.setAttrByPath path (mkOption {
      type = types.unspecified;
      visible = false;
      apply =
        _:
        throw "${lib.concatStringsSep "." path} is gone: the sandbox adds no tools - they come from the project's dev shell (or your ~/.nix-profile, home-manager)";
    });
  };

  layer' = import ./layer.nix { inherit lib pkgs; };
  layerOptions = layer'.options;

  profileType = types.submodule {
    imports = map (path: removed path) [
      [ "packages" ]
      [ "basePackages" ]
      [
        "claude"
        "package"
      ]
    ];

    options = layerOptions // {
      guards.claudeApiKey.tokenCommand = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "guards.claudeApiKey.tokenCommand for projects of this profile; null keeps the top level's.";
      };
      guards.github.tokenCommand = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "guards.github.tokenCommand for projects of this profile; null keeps the top level's.";
      };
      guards.forgejo.tokenCommands = mkOption {
        type = types.attrsOf types.str;
        default = { };
        description = "guards.forgejo.tokenCommands for projects of this profile, over the top level's.";
      };
      paths = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "The profile applies when the sandbox starts in or under one of these (`~` expanded).";
      };
      projectFiles = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "The profile applies when the project root has one of these, e.g. flake.nix.";
      };
      priority = mkOption {
        type = types.int;
        default = 0;
        description = "Among matching profiles, the highest priority wins.";
      };
    };
  };

  githubHook = pkgs.writeShellApplication {
    name = "deny-github-http";
    runtimeInputs = [
      pkgs.jq
      pkgs.gnugrep
      pkgs.gnused
    ];
    text = builtins.readFile ./claude/deny-github-http.sh;
  };

  # The userland inside, fixed: what the sandbox itself needs (a shell, nix
  # to enter the project's dev shell, terminfo; git and ssh, which its
  # ssh-agent guard and commit signing are for - pushes run ssh, ssh signing
  # runs ssh-keygen) plus the tools `nix develop` puts on PATH anyway
  # (stdenv's initialPath). Every other tool - Claude Code, ... - comes from
  # the project's dev shell, or the user's ~/.nix-profile or home-manager;
  # no configuration adds any.
  basePackages = [
    pkgs.bashInteractive
    pkgs.nix
    pkgs.ncurses
    pkgs.git
    pkgs.openssh
  ]
  ++ pkgs.stdenv.initialPath
  ++ lib.optional cfg.guards.openUrl.enable sandboxPkgs.xdg-open;

  # The same for every profile.
  env = pkgs.buildEnv {
    name = "sandbox-env";
    paths = basePackages;
    pathsToLink = [
      "/bin"
      "/share"
    ];
    ignoreCollisions = true;
  };

  # One resolved layer (the top level, or it plus a profile) as the launcher
  # reads it.
  resolve =
    name: l:
    let
      path = [
        "${env}/bin"
      ]
      ++ lib.optional cfg.nixProfile.enable "$HOME/.nix-profile/bin";
      claudeApiKeyCommand =
        let
          own = l.guards.claudeApiKey.tokenCommand or null;
        in
        if !cfg.claude.enable then
          null
        else if own != null then
          own
        else
          cfg.guards.claudeApiKey.tokenCommand;
      claudeApiKey = claudeApiKeyCommand != null;
      claudeDir = layer'.claudeDir name (layer'.claudeValues {
        lspMarketplace = "sandbox";
        claude = {
          settings = lib.recursiveUpdate (lib.recursiveUpdate cfg.claude.settings l.claude.settings) (
            lib.optionalAttrs claudeApiKey {
              # A placeholder, so Claude Code neither asks to log in nor to
              # approve an environment key; claude-api-proxy swaps in the
              # real one.
              apiKeyHelper = "echo sandbox-placeholder";
            }
          );
          memory = lib.concatStringsSep "\n" (
            lib.filter (s: s != "") [
              cfg.claude.memory
              l.claude.memory
            ]
          );
          mcpServers = cfg.claude.mcpServers // l.claude.mcpServers;
          lspServers = cfg.claude.lspServers // l.claude.lspServers;
          marketplaces = cfg.claude.marketplaces // l.claude.marketplaces;
        };
      }) { };
    in
    {
      env = {
        PATH = lib.concatStringsSep ":" path;
        SHELL = "${env}/bin/bash";
        TERMINFO_DIRS = "${env}/share/terminfo";
        LOCALE_ARCHIVE = "${cfg.locales}/lib/locale/locale-archive";
        SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
        NIX_SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
        NIX_LD = pkgs.stdenv.cc.bintools.dynamicLinker;
        NIX_LD_LIBRARY_PATH = lib.makeLibraryPath cfg.nixLd.libraries;
        # The store is read-only in here; builds go through the host's daemon.
        NIX_REMOTE = "daemon";
        NIX_CONFIG = cfg.nixConfig;
      }
      // cfg.env;
      binds = cfg.binds ++ l.binds;
      claudeDir = if cfg.claude.enable then "${claudeDir}" else null;
      inherit claudeApiKeyCommand;
      githubTokenCommand =
        let
          own = l.guards.github.tokenCommand or null;
        in
        if own != null then own else cfg.guards.github.tokenCommand;
      forgejoTokenCommands = cfg.guards.forgejo.tokenCommands // (l.guards.forgejo.tokenCommands or { });
    };

  runtimeConfig = {
    seccomp = "${sandboxPkgs.seccomp}";
    dbusDaemon = lib.getExe' pkgs.dbus "dbus-daemon";
    tools = {
      pasta = lib.getExe' pkgs.passt "pasta";
      bwrap = lib.getExe pkgs.bubblewrap;
      ip = lib.getExe' pkgs.iproute2 "ip";
      bash = lib.getExe pkgs.bash;
      shell = lib.getExe pkgs.bashInteractive;
    };
    # Host-side tools the guards run: xdg-open to hand URLs to the browser.
    # No gh or fj: the guards only use the projects' own tokens.
    hostPath = lib.makeBinPath [
      pkgs.xdg-utils
      pkgs.coreutils
    ];
    fhs = {
      bin = "${sandboxPkgs.fhs}/bin";
      usrBin = "${sandboxPkgs.fhs}/usr/bin";
      nixLd = "${pkgs.nix-ld}/libexec/nix-ld";
      ldPath =
        if pkgs.stdenv.hostPlatform.isx86_64 then
          "/lib64/ld-linux-x86-64.so.2"
        else
          "/lib/${baseNameOf pkgs.stdenv.cc.bintools.dynamicLinker}";
      ssl = "${pkgs.cacert}/etc/ssl";
    };
    # Per-host files read where they are; not dependencies, just the
    # system's identity and name resolution.
    hostEtc = [
      "/etc/resolv.conf"
      "/etc/hosts"
      "/etc/passwd"
      "/etc/group"
      "/etc/localtime"
      "/etc/nsswitch.conf"
    ];
    stateDir = cfg.stateDir;
    hostPorts = cfg.hostPorts;
    passEnv = [
      "TERM"
      "COLORTERM"
      "LANG"
      "LC_ALL"
    ]
    ++ cfg.passEnv;
    guards = {
      sshAgent = {
        inherit (cfg.guards.sshAgent) enable socket path;
      };
      secretService = cfg.guards.secretService.enable;
      github = cfg.guards.github.enable;
      forgejo = cfg.guards.forgejo.enable;
      openUrl = cfg.guards.openUrl.enable;
    };
    # A project's sandbox.nix, evaluated inside a sandbox by project.nix
    # against this nixpkgs.
    project = {
      eval = "${./.}/project.nix";
      nixpkgs = "${pkgs.path}";
      system = pkgs.stdenv.hostPlatform.system;
    };
    init = {
      nixProfile = cfg.nixProfile.enable;
      homeManager = cfg.homeManager.enable;
    };
    default = resolve "default" {
      binds = [ ];
      claude = {
        settings = { };
        memory = "";
        mcpServers = { };
        lspServers = { };
        marketplaces = { };
      };
    };
    profiles = lib.mapAttrsToList (
      name: p:
      resolve name p
      // {
        inherit name;
        inherit (p) paths projectFiles priority;
      }
    ) cfg.profiles;
  };

  configFile = json.generate "sandbox-config.json" runtimeConfig;
in
{
  options = layerOptions // {
    env = mkOption {
      type = types.attrsOf types.str;
      default = { };
      description = "Environment variables inside, with `~`/`$HOME`/`$USER`/`$XDG_RUNTIME_DIR` expanded at start.";
    };

    profiles = mkOption {
      type = types.attrsOf profileType;
      default = { };
      description = "Per-project additions, picked at start by path or project file.";
    };

    stateDir = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = ''
        Host directory with every project's volume, secrets and exchange dir;
        $XDG_DATA_HOME/sandbox (~/.local/share/sandbox) when null. `~` and
        environment variables are expanded at start; $SANDBOX_STATE_DIR
        overrides it.
      '';
    };

    hostPorts = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [
        "5037"
        "8080/udp"
        "9000-9010"
      ];
      description = "Host loopback ports reachable inside at 127.0.0.1, in addition to $SANDBOX_HOST_PORTS at start.";
    };

    passEnv = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = ''
        Host environment variables passed in, besides TERM, COLORTERM, LANG
        and LC_ALL. Everything else is cleared.
      '';
    };

    locales = mkOption {
      type = types.package;
      default = pkgs.glibcLocales.override {
        allLocales = false;
        locales = [
          "C.UTF-8/UTF-8"
          "en_US.UTF-8/UTF-8"
        ];
      };
      defaultText = lib.literalMD "C.UTF-8 and en_US.UTF-8";
      description = "glibcLocales build for LOCALE_ARCHIVE.";
    };

    nixConfig = mkOption {
      type = types.lines;
      default = "experimental-features = nix-command flakes";
      description = ''
        Nix settings inside, as NIX_CONFIG. The host's /etc/nix isn't bound
        in (it can name access tokens), so without this nix inside runs on
        defaults - no flakes, no `nix develop`.
      '';
    };

    nixLd.libraries = mkOption {
      type = types.listOf types.package;
      default = with pkgs; [
        stdenv.cc.cc.lib
        zlib
        openssl
        curl
        libgcc
      ];
      description = "Libraries prebuilt (non-nix) binaries find through nix-ld at /lib64/ld-linux-x86-64.so.2.";
    };

    nixProfile.enable = mkOption {
      type = types.bool;
      default = true;
      description = "Link the host's ~/.nix-profile into the volume and put its bin/ on PATH (after the sandbox's own).";
    };

    homeManager.enable = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Link the host's current home-manager generation into the volume at
        each start, removing links into older ones. The home-manager module
        turns this on.
      '';
    };

    guards = {
      sshAgent = {
        enable = mkOption {
          type = types.bool;
          default = true;
          description = "Proxy the host's ssh agent, with non-commit-signing requests behind a popup.";
        };
        socket = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "Host agent socket; $SSH_AUTH_SOCK at start when null.";
        };
        path = mkOption {
          type = types.str;
          default = "$XDG_RUNTIME_DIR/ssh-agent.sock";
          description = "Where the proxied socket appears inside; SSH_AUTH_SOCK points there.";
        };
      };
      secretService.enable = mkOption {
        type = types.bool;
        default = true;
        description = "A private D-Bus bus with a per-project Secret Service, for libsecret users (gh, ...).";
      };
      github.enable = mkOption {
        type = types.bool;
        default = true;
        description = "GitHub API requests from inside - any gh's, or any other client's - routed (by the router, the HTTPS_PROXY inside) to a host proxy that holds the token from tokenCommand and gates writes. gh itself isn't provided: bring it in the project's dev shell, ~/.nix-profile or home-manager.";
      };
      github.tokenCommand = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "op read op://Employee/GitHub/token";
        description = ''
          A shell command, run on the host at each start, that prints the
          GitHub token, e.g. from a secret manager. The token is handed to
          the guard in memory: never written to disk, never inside the
          sandbox. Trusted, as your config: run without asking. It wins over
          a project's sandbox.nix, whose command is run only once you
          approve it. Without either, GitHub API requests from inside are
          refused.
        '';
      };
      forgejo.enable = mkOption {
        type = types.bool;
        default = false;
        description = "Forgejo API requests from inside, to instances in tokenCommands, routed to a host proxy (as for GitHub) holding their tokens. fj itself isn't provided.";
      };
      forgejo.tokenCommands = mkOption {
        type = types.attrsOf types.str;
        default = { };
        example = {
          "codeberg.org" = "op read op://Employee/Codeberg/token";
        };
        description = ''
          Shell commands, by Forgejo host (host[:port]), run on the host at
          each start, each printing that instance's token; as for
          github.tokenCommand, they win over sandbox.nix's for the same
          host.
        '';
      };
      claudeApiKey.tokenCommand = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "op read op://Employee/Claude/credential";
        description = ''
          A shell command printing a Claude API key, run on the host at each
          start, like github.tokenCommand. With one, Claude Code inside runs
          on that key, which a host proxy adds and which never enters the
          sandbox or the disk - in place of logging in inside, so not for
          Claude subscriptions. Trusted, and wins over a project's
          sandbox.nix, whose command runs only once approved. A profile can
          set its own.
        '';
      };
      openUrl.enable = mkOption {
        type = types.bool;
        default = true;
        description = "xdg-open inside opens http(s) URLs in the host's browser, after a popup.";
      };
    };

    claude = layerOptions.claude // {
      enable = mkOption {
        type = types.bool;
        default = true;
        description = "Managed settings/memory for Claude Code at /etc/claude-code - for the `claude` the project's dev shell (or your ~/.nix-profile, home-manager) brings; the sandbox ships none.";
      };
    };

    package = mkOption {
      type = types.package;
      readOnly = true;
      description = "The `sandbox` command.";
    };

    configFile = mkOption {
      type = types.package;
      readOnly = true;
      internal = true;
    };
  };

  config = {
    inherit configFile;

    package = pkgs.writeShellScriptBin "sandbox" ''
      exec ${lib.getExe sandboxPkgs.sandbox} launch --config ${configFile} "$@"
    '';

    claude.settings = lib.mkMerge [
      {
        # A store path can't update itself.
        env.DISABLE_AUTOUPDATER = 1;
      }
      (lib.mkIf cfg.guards.github.enable {
        hooks.PreToolUse = [
          {
            matcher = "Bash";
            hooks = [
              {
                type = "command";
                command = lib.getExe githubHook;
              }
            ];
          }
        ];
      })
    ];

    claude.memory = lib.mkMerge [
      (builtins.readFile ./claude/sandbox.md)
      (lib.mkIf cfg.guards.github.enable (builtins.readFile ./claude/github.md))
      (lib.mkIf cfg.guards.forgejo.enable (builtins.readFile ./claude/forgejo.md))
    ];
  };
}
