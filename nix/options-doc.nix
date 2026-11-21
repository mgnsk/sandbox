# OPTIONS.md, from the option declarations: a sandbox config's (module.nix),
# a project's sandbox module's (project-options.nix) and mkClaude's
# (claude.nix). The check fails when
# the file in the repository isn't what these give; `make options` writes
# it (passthru.doc).
{
  lib,
  pkgs,
  runCommand,
  writeText,
}:
let
  layer = import ./layer.nix { inherit lib pkgs; };

  # The documented options of modules, in the order of their names.
  optionsOf =
    modules:
    lib.filter (o: o.visible && !o.internal && !lib.hasPrefix "_module." o.name) (
      lib.optionAttrSetToDocList
        (lib.evalModules { modules = modules ++ [ { _module.args.pkgs = pkgs; } ]; }).options
    );
  names = map (o: o.name);

  # What a sandbox config, a profile and a project all take is said once.
  shared = optionsOf [ { options = layer.options; } ];
  config = optionsOf [ ./module.nix ];
  project = optionsOf [ { options = import ./project-options.nix { inherit lib layer; }; } ];
  claude = optionsOf [ (import ./claude.nix { inherit lib; }).module ];
  # A profile's option that the top level has too, under its name there.
  ofProfile =
    o:
    lib.hasPrefix "profiles.<name>." o.name
    && lib.elem (lib.removePrefix "profiles.<name>." o.name) (names config);
  own = lib.filter (o: !lib.elem o.name (names shared));

  # A default or an example: in the list when it's a line, under it when
  # it's more.
  short = v: !lib.hasInfix "\n" v.text;
  item =
    label: v:
    if v._type == "literalMD" then
      "- ${label}: ${v.text}\n"
    else
      lib.optionalString (short v) "- ${label}: `${v.text}`\n";
  block =
    label: v:
    lib.optionalString (v._type != "literalMD" && !short v) "\n${label}:\n\n```nix\n${v.text}\n```\n";
  both =
    f: o:
    lib.optionalString (o ? default) (f "Default" o.default)
    + lib.optionalString (o ? example) (f "Example" o.example);

  render =
    o:
    assert lib.assertMsg ((o.description or null) != null) "the option ${o.name} has no description";
    ''
      ### `${o.name}`

      ${lib.trim o.description}

      - Type: `${o.type}`${lib.optionalString o.readOnly " (read only)"}
    ''
    + both item o
    + both block o;

  section = lib.concatMapStringsSep "\n" render;

  doc = writeText "OPTIONS.md" ''
    # Options

    Every option, with its type and default. Generated from the option
    declarations in `nix/` by `make options`: change those, not this file.
    The [README](README.md#configuring-the-sandbox) says what they're for
    and where a setting belongs.

    - [In your config, a profile or a project](#in-your-config-a-profile-or-a-project)
    - [Your sandbox config](#your-sandbox-config)
    - [A project's sandbox](#a-projects-sandbox)
    - [A project's Claude Code](#a-projects-claude-code)

    ## In your config, a profile or a project

    These are the same in all three. A profile's go over your config's for
    its projects, and a project's over both - where its binds take your yes
    on the terminal first.

    ${section shared}
    ## Your sandbox config

    `programs.sandbox.settings` in home-manager. Trusted like the rest of
    your config: nothing here is asked about. A profile
    (`profiles.<name>`) also takes the options above and the guards' token
    commands, for its projects.

    ${section (lib.filter (o: !ofProfile o) (own config))}
    ## A project's sandbox

    `sandbox` of `sandbox.lib.mkShell` in the project's flake.nix, which
    sandboxed code can write: what reaches the host takes your yes on the
    terminal first.

    ${section (own project)}
    ## A project's Claude Code

    `claude` of `sandbox.lib.mkShell`, or `sandbox.lib.mkClaude`'s
    arguments besides `pkgs`.

    ${section claude}'';
in
runCommand "sandbox-options-check" { passthru = { inherit doc; }; } ''
  if ! diff -u ${../OPTIONS.md} ${doc}; then
    echo "OPTIONS.md is not what the option declarations give: run 'make options'" >&2
    exit 1
  fi
  touch $out
''
