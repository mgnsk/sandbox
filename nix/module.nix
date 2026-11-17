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

  layer' = import ./layer.nix { inherit lib pkgs; };
  layerOptions = layer'.options;

  profileType = types.submodule {
    options = layerOptions // {
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

  basePackages =
    cfg.basePackages
    ++ lib.optional cfg.claude.enable cfg.claude.package
    ++ lib.optional cfg.guards.github.enable sandboxPkgs.gh
    ++ lib.optional cfg.guards.forgejo.enable sandboxPkgs.forgejo-cli
    ++ lib.optional cfg.guards.openUrl.enable sandboxPkgs.xdg-open;

  # One resolved layer (the top level, or it plus a profile) as the launcher
  # reads it.
  resolve =
    name: l:
    let
      env = pkgs.buildEnv {
        name = "sandbox-env-${name}";
        paths = basePackages ++ cfg.packages ++ l.packages;
        pathsToLink = [
          "/bin"
          "/share"
        ];
        ignoreCollisions = true;
      };
      path = [
        "${env}/bin"
      ]
      ++ lib.optional cfg.nixProfile.enable "$HOME/.nix-profile/bin";
      claudeDir = layer'.claudeDir name (layer'.claudeValues {
        lspMarketplace = "sandbox";
        claude = {
          settings = lib.recursiveUpdate cfg.claude.settings l.claude.settings;
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
      // cfg.env
      // l.env;
      binds = cfg.binds ++ l.binds;
      claudeDir = if cfg.claude.enable then "${claudeDir}" else null;
    };

  runtimeConfig = {
    src = "${sandboxPkgs.src}";
    python = sandboxPkgs.python.interpreter;
    seccomp = "${sandboxPkgs.seccomp}";
    dbusDaemon = lib.getExe' pkgs.dbus "dbus-daemon";
    tools = {
      pasta = lib.getExe' pkgs.passt "pasta";
      bwrap = lib.getExe pkgs.bubblewrap;
      ip = lib.getExe' pkgs.iproute2 "ip";
      bash = lib.getExe pkgs.bash;
      shell = lib.getExe pkgs.bashInteractive;
    };
    # Host-side tools the guards run: tmux for popups, gh for the host's
    # token, xdg-open to hand URLs to the browser.
    hostPath = lib.makeBinPath [
      pkgs.tmux
      pkgs.gh
      pkgs.xdg-utils
      pkgs.coreutils
      pkgs.less
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
      claudeApiKey = cfg.guards.claudeApiKey.enable;
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
      script = "${sandboxPkgs.src}/sandbox-init";
      nixProfile = cfg.nixProfile.enable;
      homeManager = cfg.homeManager.enable;
    };
    default = resolve "default" {
      packages = [ ];
      env = { };
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
    basePackages = mkOption {
      type = types.listOf types.package;
      default = with pkgs; [
        bashInteractive
        bash-completion
        coreutils
        findutils
        diffutils
        gnugrep
        gnused
        gawk
        gnutar
        gzip
        bzip2
        xz
        zstd
        unzip
        gnumake
        which
        file
        less
        procps
        getent
        iproute2
        ncurses
        git
        openssh
        curl
        jq
        ripgrep
        python3
        nix
      ];
      defaultText = lib.literalMD "a small POSIX userland plus git, openssh, curl, jq, ripgrep, python3 and nix";
      description = "The userland inside. Nothing of the host's /usr is visible, so whatever isn't here (or in `packages`) doesn't exist.";
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
          description = "Proxy the host's ssh agent, with non-commit-signing requests behind a tmux popup.";
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
        description = "gh inside, talking to the API through a host proxy that holds the host gh's token and gates writes.";
      };
      forgejo.enable = mkOption {
        type = types.bool;
        default = false;
        description = "fj (forgejo-cli) inside, through a host proxy holding the host fj's tokens.";
      };
      claudeApiKey.enable = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Claude Code inside on a per-project API key that stays outside, added
          by a host proxy. The key is asked for on the terminal at a project's
          first start (or with `sandbox --claude-api-key`). Replaces logging in
          inside, so not for Claude subscriptions.
        '';
      };
      openUrl.enable = mkOption {
        type = types.bool;
        default = true;
        description = "xdg-open inside opens http(s) URLs in the host's browser, after a tmux popup.";
      };
    };

    claude = layerOptions.claude // {
      enable = mkOption {
        type = types.bool;
        default = true;
        description = "Claude Code inside, with managed settings/memory at /etc/claude-code.";
      };
      package = mkOption {
        type = types.package;
        default = pkgs.claude-code;
        defaultText = lib.literalExpression "pkgs.claude-code";
      };
    };

    package = mkOption {
      type = types.package;
      readOnly = true;
      description = "The `sandbox` command.";
    };

    clientPackages = mkOption {
      type = types.listOf types.package;
      readOnly = true;
      description = ''
        The patched clients the guards rely on (gh, fj), for putting first in
        a profile whose PATH entry can come before the sandbox's own inside.
        Patched, they behave as usual without the sandbox's socket variables.
      '';
    };

    configFile = mkOption {
      type = types.package;
      readOnly = true;
      internal = true;
    };
  };

  config = {
    inherit configFile;

    clientPackages =
      lib.optional cfg.guards.github.enable sandboxPkgs.gh
      ++ lib.optional cfg.guards.forgejo.enable sandboxPkgs.forgejo-cli;

    package = pkgs.writeShellScriptBin "sandbox" ''
      exec ${sandboxPkgs.python.interpreter} -E -s ${sandboxPkgs.src}/sandbox ${configFile} "$@"
    '';

    claude.settings = lib.mkMerge [
      {
        # A store path can't update itself.
        env.DISABLE_AUTOUPDATER = 1;
      }
      (lib.mkIf cfg.guards.claudeApiKey.enable {
        # A placeholder, so Claude Code neither asks to log in nor to approve
        # an environment key; claude-api-proxy swaps in the real one.
        apiKeyHelper = "echo sandbox-placeholder";
      })
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
