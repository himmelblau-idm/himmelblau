{
  system ? builtins.currentSystem,
  sources ? import ./sources.nix,
  pkgs ? import sources.nixpkgs {
    inherit system;
  },
}:
rec {

  nixosModules.himmelblau = {
    imports = [ ./nix/modules/himmelblau.nix ];
    services.himmelblau.package = packages.himmelblau;
  };

  packages.himmelblau = pkgs.callPackage ./nix/packages/himmelblau.nix { };
}
