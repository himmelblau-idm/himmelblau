{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-25.11";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      ...
    }:
    let
      eachSystem = nixpkgs.lib.genAttrs [
        "x86_64-linux"
        # Not tested
        "aarch64-linux"
      ];
      # Instantiate only once for each system.
      #
      # Still allow flakes users to override dependencies in the normal flake
      # way.
      himmelblau = eachSystem (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        import ./. {
          inherit system pkgs;
        }
      );
    in
    {

      packages = eachSystem (
        system: builtins.removeAttrs himmelblau.${system}.packages [ "recurseForDerivations" ]
      );

      # devShells.default = pkgs.mkShell {
      #   name = "himmelblau-devshell";
      #   inputsFrom = [ packages.himmelblau-desktop ];
      #   nativeBuildInputs = with pkgs; [
      #     rust-analyzer
      #     rustfmt
      #     clippy
      #   ];
      # };

      # nixosConfigurations.testing = nixpkgs.lib.nixosSystem {
      #   inherit system;
      #   modules = [
      #     (
      #       { pkgs, lib, ... }:
      #       {
      #         imports = [ self.nixosModules.himmelblau ];
      #         boot.isContainer = true; # stop nix flake check complaining about missing root fs
      #         documentation.nixos.enable = false; # skip generating nixos docs
      #         virtualisation.vmVariant = {
      #           boot.isContainer = lib.mkForce false; # let vm variant create a virtual disk
      #           virtualisation.graphics = false; # connect serial console to terminal
      #         };
      #         nix.nixPath = [ "nixpkgs=${nixpkgs}" ];
      #         users.users.root.initialPassword = "test";
      #         services.sshd.enable = true;
      #         services.himmelblau = {
      #           enable = true;
      #           settings = {
      #             domain = "example.com";
      #             pam_allow_groups = [ "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" ];
      #           };
      #           domains."extra.com" = {
      #             pam_allow_groups = [ "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" ];
      #             shell = "/run/current-system/sw/bin/fish";
      #           };
      #         };
      #         environment.systemPackages = with pkgs; [ pamtester ];
      #       }
      #     )
      #   ];
      # };
    };
}
