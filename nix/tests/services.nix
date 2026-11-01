# Evaluation fixture consumed by scripts/test_nixos_services.py; no packages are built.
{
  nixpkgs ? <nixpkgs>,
  tpmEnabled ? true,
  tcti ? "device:/dev/tpmrm0",
  tssGroup ? "tss",
  pinPath ? "/var/lib/himmelblaud/hsm-pin",
  brokerPinentry ? "gnome3",
}:
let
  pkgs = import nixpkgs { };
  brokerPinentryPackage =
    if brokerPinentry == null then
      null
    else if brokerPinentry == "gnome3" then
      pkgs.pinentry-gnome3
    else if brokerPinentry == "curses" then
      pkgs.pinentry-curses
    else
      throw "unsupported brokerPinentry fixture value: ${brokerPinentry}";
  evaluated = import (pkgs.path + "/nixos/lib/eval-config.nix") {
    system = builtins.currentSystem;
    modules = [
      ../modules/himmelblau.nix
      {
        services.himmelblau = {
          enable = true;
          daemonPackage = pkgs.emptyDirectory;
          aadToolPackage = pkgs.writeShellScriptBin "aad-tool" "";
          ssoPackage = pkgs.emptyDirectory;
          brokerPackage = pkgs.emptyDirectory;
          inherit brokerPinentryPackage;
          pamPackage = pkgs.emptyDirectory // { lib = pkgs.emptyDirectory; };
          nssPackage = pkgs.emptyDirectory;
          settings.tpm_tcti_name = tcti;
          settings.hsm_pin_path = pinPath;
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
  dbusPackages = map toString cfg.services.dbus.packages;
  warnings = cfg.warnings;
  assertions = map (assertion: assertion.message) (
    builtins.filter (assertion: !assertion.assertion) cfg.assertions
  );
  # Independent paths for projecting packaged commands and NixOS's environment.
  paths = {
    daemon = toString cfg.services.himmelblau.daemonPackage;
    aadTool = toString cfg.services.himmelblau.aadToolPackage;
    broker = toString cfg.services.himmelblau.brokerPackage;
    gcr = toString pkgs.gcr;
    xdgUtils = toString pkgs.xdg-utils;
    pinentryGnome3 = toString pkgs.pinentry-gnome3;
    pinentryCurses = toString pkgs.pinentry-curses;
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
    brokerTools = map toString [
      pkgs.xdg-utils
    ] ++ pkgs.lib.optional (brokerPinentryPackage != null) brokerPinentryPackage;
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
