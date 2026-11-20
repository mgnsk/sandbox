# Options for one `sandbox` command, evaluated by mkSandbox (flake.nix).
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
      guards = layer'.tokenCommandOptions "For projects of this profile, over the top level's.";
      paths = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "The profile applies when the sandbox starts in or under one of these (`~` expanded).";
      };
      projectFiles = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = ''
          The profile applies when the project root has one of these, e.g.
          flake.nix. Such a profile can only set claude.*: sandboxed code can
          create the file, so binds and token commands need paths alone.
        '';
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

  loginHook = pkgs.writeShellApplication {
    name = "deny-cli-login";
    runtimeInputs = [
      pkgs.jq
      pkgs.gnugrep
      pkgs.gnused
    ];
    text = builtins.readFile ./claude/deny-cli-login.sh;
  };

  # The userland inside, fixed: what the sandbox itself needs (a shell, nix
  # to enter the project's dev shell, terminfo; git and ssh, which its
  # ssh-agent guard and commit signing are for - pushes run ssh, ssh signing
  # runs ssh-keygen; less and nano, the pager and editor git runs), the tools
  # `nix develop` puts on PATH anyway (stdenv's initialPath), and the few
  # every session reaches for whatever the project is. Every other tool -
  # Claude Code, ... - comes from the project's dev shell, or the user's
  # ~/.nix-profile or home-manager; no configuration adds any.
  basePackages = [
    pkgs.bashInteractive
    pkgs.bash-completion
    pkgs.nix
    pkgs.ncurses
    pkgs.git
    # The pager git runs for log, diff, ...: without it they fail.
    pkgs.less
    pkgs.openssh
    # git's editor for a commit message or a rebase, through EDITOR in
    # /etc/profile: git itself would run vi, which is not here.
    pkgs.nano
    # What Claude Code and shell scripts reach for in any project: JSON,
    # HTTP, code search, processes and zip archives (tar is in stdenv's set).
    pkgs.jq
    pkgs.curl
    pkgs.ripgrep
    pkgs.which
    pkgs.procps
    pkgs.unzip
    pkgs.zip
  ]
  ++ pkgs.stdenv.initialPath
  ++ lib.optional cfg.guards.openUrl.enable sandboxPkgs.xdg-open;

  # bash's system-wide startup files, managed: every interactive shell -
  # nix develop's too, which reads /etc/bashrc despite its --rcfile - loads
  # bash-completion, which finds the completions of the dev shell's packages
  # through the XDG_DATA_DIRS nix develop sets, and those of the base set
  # through PATH. The user's own files run after these.
  bashrc = pkgs.replaceVars ./etc/bashrc { bashCompletion = "${pkgs.bash-completion}"; };
  profile = ./etc/profile;

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
      };
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
      wlVeil = lib.getExe sandboxPkgs.wl-veil;
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
      # At /usr/share/bash-completion: a fixed path a user's own ~/.bashrc
      # can source across upgrades.
      bashCompletion = "${pkgs.bash-completion}/share/bash-completion";
      # The managed, read-only /etc/bashrc and /etc/profile bash reads
      # before the user's files.
      bashrc = "${bashrc}";
      profile = "${profile}";
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
      openUrl = cfg.guards.openUrl.enable;
      notifications = cfg.guards.notifications.enable;
      wayland = {
        inherit (cfg.guards.wayland) enable globals;
        defaultGlobals = import ./wayland.nix;
      };
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
      # The sandbox writes the project: a file there can't be what gives a
      # project more of the host.
      lib.throwIf
        (
          p.projectFiles != [ ]
          && (
            p.binds != [ ]
            || p.guards.github.tokenCommand != null
            || p.guards.forgejo.tokenCommands != { }
            || p.guards.claudeApiKey.tokenCommand != null
          )
        )
        "profiles.${name}: a profile picked by projectFiles can only set claude.*, as sandboxed code can create the file: binds and token commands go in a profile picked by paths alone"
        (
          resolve name p
          // {
            inherit name;
            inherit (p) paths projectFiles priority;
          }
        )
    ) cfg.profiles;
  };

  configFile = json.generate "sandbox-config.json" runtimeConfig;
in
{
  options = layerOptions // {
    profiles = mkOption {
      type = types.attrsOf profileType;
      default = { };
      description = "Per-project additions, picked at start by path or project file.";
    };

    stateDir = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = ''
        Host directory with a folder per project: its home volume, its
        exchange dir and what the host keeps for it (sandbox.nix approvals);
        $XDG_DATA_HOME/sandbox (~/.local/share/sandbox) when null. `~` and
        environment variables are expanded at start; $SANDBOX_STATE_DIR
        overrides it.
      '';
    };

    hostPorts = layer'.hostPortsOption "For every project.";

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
      description = "Libraries prebuilt (non-nix) binaries find through nix-ld, which is at the dynamic loader's path (/lib64/ld-linux-x86-64.so.2 on x86_64).";
    };

    nixProfile.enable = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Link the host's ~/.nix-profile into the volume and put its bin/ on
        PATH (after the sandbox's own). Off, a link from an earlier start is
        removed. The home-manager module turns this on.
      '';
    };

    homeManager.enable = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Link the host's current home-manager generation into the volume at
        each start, removing links into older ones. Off, the links of an
        earlier start are removed. The home-manager module
        turns this on.
      '';
    };

    guards =
      layer'.tokenCommandOptions "Trusted, as your config: run without asking, and it wins over a project's, which runs only once you approve it. A profile can set its own."
      // {
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
          description = ''
            A private D-Bus bus with a Secret Service for libsecret users (gh, ...),
            keeping each project's items apart in the host's own Secret Service
            (gnome-keyring, KeePassXC, ...). With it on, a sandbox doesn't start
            without one on the host's session bus.
          '';
        };
        openUrl.enable = mkOption {
          type = types.bool;
          default = true;
          description = "xdg-open inside opens http(s) URLs in the host's browser, after a popup.";
        };
        notifications.enable = mkOption {
          type = types.bool;
          default = true;
          description = ''
            In a sandbox with a Wayland display (guards.wayland), show a
            guard's popup as a desktop notification as well, with the same
            answers, when the request doesn't come from the terminal the
            sandbox runs on - from a window inside, say. The popup on the
            terminal stays, and the first answer counts. Needs a notification
            daemon that shows actions on your session bus.
          '';
        };
        wayland = {
          enable = mkOption {
            type = types.nullOr types.bool;
            default = null;
            description = ''
              Windows on the host's Wayland display, for GUI programs inside:
              through a proxy (wl-veil) that passes on only an allowlist of
              the compositor's globals, as $XDG_RUNTIME_DIR/wayland-0 inside.
              The real socket is never bound in. null leaves it to each
              project's sandbox.nix, whose guards.wayland.enable takes your
              yes on the terminal; true or false decides it for every
              project.
            '';
          };
          globals = mkOption {
            type = types.attrsOf types.bool;
            default = { };
            example = {
              wl_data_device_manager = true;
              zwp_pointer_constraints_v1 = false;
            };
            description = ''
              Changes to the allowlist of Wayland globals, by interface name:
              true adds one to the default list (nix/wayland.nix), false
              removes one. Applied after a project's sandbox.nix's changes,
              so yours win.
            '';
          };
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
      {
        hooks.PreToolUse = [
          {
            matcher = "Bash";
            hooks = [
              {
                type = "command";
                command = lib.getExe githubHook;
              }
              {
                type = "command";
                command = lib.getExe loginHook;
              }
            ];
          }
        ];
      }
    ];

    claude.memory = lib.mkMerge [
      (builtins.readFile ./claude/sandbox.md)
      (builtins.readFile ./claude/github.md)
      (builtins.readFile ./claude/forgejo.md)
    ];
  };
}
