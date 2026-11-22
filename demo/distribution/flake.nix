# A distribution of the sandbox, as an organisation's tools flake has it:
# one `sandbox` command for everyone, with the tools every project gets
# inside. The entrypoint installs it with `nix profile add`.
{
  description = "sandbox demo: a distribution";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    sandbox = {
      url = "github:mgnsk/sandbox";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    { nixpkgs, sandbox, ... }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems =
        f:
        nixpkgs.lib.genAttrs systems (
          system:
          f (
            import nixpkgs {
              inherit system;
              # Claude Code is unfree.
              config.allowUnfreePredicate = p: nixpkgs.lib.getName p == "claude-code";
            }
          )
        );
    in
    {
      packages = forAllSystems (pkgs: {
        sandbox = sandbox.lib.mkSandbox {
          inherit pkgs;
          modules = [ ./sandbox.nix ];
        };
      });

      formatter = forAllSystems (pkgs: pkgs.nixfmt);
    };
}
