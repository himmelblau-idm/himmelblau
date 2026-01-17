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
    services.himmelblau.package = pkgs.lib.mkDefault packages.himmelblau;
  };

  packages = {
    himmelblau = pkgs.callPackage ./nix/packages/himmelblau.nix { };
    himmelblau-desktop = pkgs.callPackage ./nix/packages/himmelblau.nix { withO365 = true; };
  };

  passthru = { inherit pkgs; };
}
