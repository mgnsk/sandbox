# OPTIONS.md, from the option declarations: a sandbox config's (module.nix
# and the modules it imports). The check fails when
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

  # What the top level and a profile both take is said once.
  shared = optionsOf [ { options = layer.options; } ];
  config = optionsOf [ ./module.nix ];
  under = prefix: lib.filter (o: lib.hasPrefix prefix o.name) config;
  # A profile's option that the top level has too, under its name there.
  ofProfile =
    o:
    lib.hasPrefix "profiles.<name>." o.name
    && lib.elem (lib.removePrefix "profiles.<name>." o.name) (names config);
  own = lib.filter (
    o:
    !lib.elem o.name (names shared)
    && !lib.hasPrefix "antigravity." o.name
    && !lib.hasPrefix "claude." o.name
    && !lib.hasPrefix "vscode." o.name
  );

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
    The [README](README.md#configuring-the-sandbox) says what they're for.

    They're the modules given to `sandbox.lib.mkSandbox`: a distribution's
    own, trusted like the rest of it. Nothing here is asked about.

    - [At the top level or in a profile](#at-the-top-level-or-in-a-profile)
    - [The sandbox](#the-sandbox)
    - [Claude Code](#claude-code)
    - [Antigravity CLI](#antigravity-cli)
    - [VS Code](#vs-code)

    ## At the top level or in a profile

    A profile's (`profiles.<name>`) go over the top level's for its
    projects; a profile also takes the guards' token commands.

    ${section shared}
    ## The sandbox

    ${section (lib.filter (o: !ofProfile o) (own config))}
    ## Claude Code

    ${section (under "claude.")}
    ## Antigravity CLI

    ${section (under "antigravity.")}
    ## VS Code

    ${section (under "vscode.")}'';
in
runCommand "sandbox-options-check" { passthru = { inherit doc; }; } ''
  if ! diff -u ${../OPTIONS.md} ${doc}; then
    echo "OPTIONS.md is not what the option declarations give: run 'make options'" >&2
    exit 1
  fi
  touch $out
''
