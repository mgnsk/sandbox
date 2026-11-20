# A standalone home-manager config with the sandbox's module, as
# `home-manager init` makes it plus the sandbox input. The entrypoint
# copies it to ~/.config/home-manager and switches to it.
{
  description = "Home Manager configuration of tester";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    home-manager = {
      url = "github:nix-community/home-manager";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    # The `sandbox` command and its programs.sandbox module, from the remote
    # like `nix run github:mgnsk/sandbox`. Updating the sandbox is
    # `nix flake update sandbox` and a switch.
    sandbox = {
      url = "github:mgnsk/sandbox";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      nixpkgs,
      home-manager,
      sandbox,
      ...
    }:
    let
      # home-manager init writes the host's; the entrypoint replaces it on
      # other systems.
      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system;
        # Claude Code is unfree.
        config.allowUnfreePredicate = p: nixpkgs.lib.getName p == "claude-code";
      };
    in
    {
      homeConfigurations.tester = home-manager.lib.homeManagerConfiguration {
        inherit pkgs;
        modules = [
          sandbox.homeManagerModules.default
          ./home.nix
        ];
      };
    };
}
