# Evaluation fixture consumed by scripts/test_nixos_services.py; no packages are built.
{
  nixpkgs ? <nixpkgs>,
  tpmEnabled ? true,
  tcti ? "device:/dev/tpmrm0",
  tssGroup ? "tss",
  socketPath ? "/var/run/himmelblaud/socket",
  taskSocketPath ? "/var/run/himmelblaud/task_sock",
  brokerSocketPath ? "/var/run/himmelblaud/broker_sock",
  pinPath ? "/var/lib/himmelblaud/hsm-pin",
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
          settings.hsm_pin_path = pinPath;
          settings.socket_path = socketPath;
          settings.task_socket_path = taskSocketPath;
          settings.broker_socket_path = brokerSocketPath;
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
  hsmPinPath = cfg.services.himmelblau.settings.hsm_pin_path;
  tmpfilesRules = cfg.systemd.tmpfiles.rules;
  warnings = cfg.warnings;
  assertions = map (assertion: assertion.message) (
    builtins.filter (assertion: !assertion.assertion) cfg.assertions
  );
  # Independent paths for projecting packaged commands and NixOS's environment.
  paths = {
    daemon = toString cfg.services.himmelblau.daemonPackage;
    broker = toString cfg.services.himmelblau.brokerPackage;
    config = toString cfg.environment.etc."himmelblau/himmelblau.conf".source;
    localeArchive = "${cfg.i18n.glibcLocales}/lib/locale/locale-archive";
    timezone = "${pkgs.tzdata}/share/zoneinfo";
    defaultTools = map toString [
      pkgs.coreutils
      pkgs.findutils
      pkgs.gnugrep
      pkgs.gnused
      pkgs.systemd
    ];
    initializerTools = map toString [
      pkgs.coreutils
      pkgs.gnugrep
      pkgs.openssl
      pkgs.systemd
      pkgs.tpm2-tools
    ];
    tasksTools = map toString [
      pkgs.shadow
      pkgs.bash
      pkgs.util-linux
    ];
  };
  units = pkgs.lib.mapAttrs (name: unit: unit.text) (
    pkgs.lib.filterAttrs (name: unit: pkgs.lib.hasPrefix "himmelblau" name) cfg.systemd.units
  );
  userUnits = pkgs.lib.mapAttrs (name: unit: unit.text) (
    pkgs.lib.filterAttrs (name: unit: pkgs.lib.hasPrefix "himmelblau" name) cfg.systemd.user.units
  );
}
