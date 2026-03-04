{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    {
      self,
      nixpkgs,
      ...
    }:
    let
      eachSystem = nixpkgs.lib.genAttrs [
        "x86_64-linux"
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
      nixosModules.himmelblau = (
        { pkgs, ... }:
        {
          imports = [
            ./nix/modules/himmelblau.nix
          ];

          services.himmelblau =
            let
              system = pkgs.stdenv.hostPlatform.system;
            in
            {
              daemonPackage = pkgs.lib.mkDefault self.packages.${system}.daemon;
              ssoPackage = pkgs.lib.mkDefault self.packages.${system}.sso;
              brokerPackage = pkgs.lib.mkDefault self.packages.${system}.broker;
              pamPackage = pkgs.lib.mkDefault self.packages.${system}.pam;
              nssPackage = pkgs.lib.mkDefault self.packages.${system}.nss;
            };
        }
      );

      devShells = eachSystem (
        system:
        let
          default = import ./default.nix { inherit system; };
          inherit (default.passthru) pkgs;
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              rust-analyzer
              rustfmt
              clippy
            ];

            env = {
              # For rust-analyzer support
              RUST_SRC_PATH = "${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}";
            };
          };
        }
      );

      packages = eachSystem (
        system: builtins.removeAttrs himmelblau.${system}.packages [ "recurseForDerivations" ]
      );
    };
}
