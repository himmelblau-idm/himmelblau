# Evaluation fixture consumed by scripts/test_nixos_services.py; no packages are built.
{
  nixpkgs ? <nixpkgs>,
  tpmEnabled ? true,
  tcti ? "device:/dev/tpmrm0",
  tssGroup ? "tss",
}:
let
  pkgs = import nixpkgs { };
  evaluated = import (pkgs.path + "/nixos/lib/eval-config.nix") {
    system = builtins.currentSystem;
    modules = [
      ../modules/himmelblau.nix
      {
        services.himmelblau = {
          enable = true;
          daemonPackage = pkgs.emptyDirectory;
          ssoPackage = pkgs.emptyDirectory;
          brokerPackage = pkgs.emptyDirectory;
          pamPackage = pkgs.emptyDirectory // { lib = pkgs.emptyDirectory; };
          nssPackage = pkgs.emptyDirectory;
          settings.tpm_tcti_name = tcti;
        };
        security.tpm2 = {
          enable = tpmEnabled;
          inherit tssGroup;
        };
      }
    ];
  };
  cfg = evaluated.config;
in
{
  version = cfg.systemd.package.version;
  nscdEnabled = cfg.services.nscd.enable;
  tmpfilesRules = cfg.systemd.tmpfiles.rules;
  assertions = map (assertion: assertion.message) (
    builtins.filter (assertion: !assertion.assertion) cfg.assertions
  );
  units = pkgs.lib.mapAttrs (name: unit: unit.text) (
    pkgs.lib.filterAttrs (name: unit: pkgs.lib.hasPrefix "himmelblau" name) cfg.systemd.units
  );
}
