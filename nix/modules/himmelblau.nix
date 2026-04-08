{
  lib,
  config,
  pkgs,
  ...
}:
let
  cfg = config.services.himmelblau;

  # Convert a value to INI format string
  toIniValue =
    v:
    if v == null then
      null
    else if lib.isBool v then
      (if v then "true" else "false")
    else if lib.isList v then
      lib.concatStringsSep "," v
    else
      toString v;

  # Filter out null values from an attrset
  filterNulls = attrs: lib.filterAttrs (n: v: v != null) attrs;

  # Convert typed settings to INI-compatible attrset
  # The settings structure has global options at the top level and
  # subsections (like offline_breakglass) as nested attrsets
  toIniSettings =
    settings:
    let
      # Separate top-level (global) options from subsections
      isSubsection = n: v: lib.isAttrs v && !(lib.isList v);

      globalOpts = lib.filterAttrs (n: v: !(isSubsection n v)) settings;
      subsections = lib.filterAttrs isSubsection settings;

      # Convert global options (they go in [global] section)
      globalSection = lib.mapAttrs (n: v: toIniValue v) (filterNulls globalOpts);

      # Convert each subsection
      convertedSubsections = lib.mapAttrs (
        sectionName: sectionOpts: lib.mapAttrs (n: v: toIniValue v) (filterNulls sectionOpts)
      ) subsections;
    in
    # Only include global section if it has values
    (if globalSection != { } then { global = globalSection; } else { }) // convertedSubsections;

  ini = pkgs.formats.ini { };
  configFile = ini.generate "himmelblau.conf" (toIniSettings cfg.settings);
in
{
  # Import the auto-generated typed options
  imports = [ ./himmelblau-options.nix ];

  options = {
    services.himmelblau = {
      enable = lib.mkEnableOption "Himmelblau";

      daemonPackage = lib.mkOption {
        type = lib.types.path;
        description = "Package of the himmelblau daemon";
      };

      ssoPackage = lib.mkOption {
        type = lib.types.path;
        description = "Package of the linux-entra-sso native messaging host";
      };

      brokerPackage = lib.mkOption {
        type = lib.types.path;
        description = "Package himmelblau_broker - used for sso";
      };

      pamPackage = lib.mkOption {
        type = lib.types.path;
        description = "Library for the pam module";
      };

      nssPackage = lib.mkOption {
        type = lib.types.path;
        description = "Library for the nss lookup";
      };

      mfaSshWorkaroundFlag = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          Whether to add the mfa_poll_prompt option to the libpam_himmelblau.so PAM module
          to workaround OpenSSH Bug 2876.
        '';
      };

      debugFlag = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Whether to pass the debug (-d) flag to the himmelblaud binary.";
      };

      tryUnsealFlag = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          Whether to add a try_unseal auth module to automatically unseal
          Entra ID secrets (TOTP, refresh tokens) using the login password as PIN,
          similar to how pam_gnome_keyring unlocks the keyring at login.
        '';
      };

      pamServices = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [
          "passwd"
          "login"
          "systemd-user"
        ];
        description = "Which PAM services to add the himmelblau module to.";
      };

      # Note: settings options are now defined in himmelblau-options.nix
      # which is auto-generated from docs-xml/ by src/common/scripts/gen_param_code.py
    };
  };

  config = lib.mkIf cfg.enable {
    environment.etc."himmelblau/himmelblau.conf".source = configFile;

    systemd.tmpfiles.rules = [
      "d /var/cache/nss-himmelblau 0755 root root -"
    ];

    programs.firefox = {
      policies = {
        Extensions.Install = [
          "https://github.com/siemens/linux-entra-sso/releases/download/v1.7.1/linux_entra_sso-1.7.1.xpi"
        ];
      };
      nativeMessagingHosts.packages = [ cfg.ssoPackage ];
    };

    programs.chromium.extensions = [
      "jlnfnnolkbjieggibinobhkjdfbpcohn"
    ];
    environment.etc."chromium/native-messaging-hosts/linux_entra_sso.json".source =
      "${cfg.ssoPackage}/lib/chromium/native-messaging-hosts/linux_entra_sso.json";
    environment.etc."opt/chrome/native-messaging-hosts/linux_entra_sso.json".source =
      "${cfg.ssoPackage}/lib/chromium/native-messaging-hosts/linux_entra_sso.json";
    services.dbus.packages = [ cfg.brokerPackage ];

    # Add himmelblau to the list of name services to lookup users/groups
    system.nssModules = [ cfg.nssPackage ];
    system.nssDatabases.passwd = lib.mkOrder 1501 [ "himmelblau" ]; # will be merged with entries from other modules
    system.nssDatabases.group = lib.mkOrder 1501 [ "himmelblau" ]; # will be merged with entries from other modules
    system.nssDatabases.shadow = lib.mkOrder 1501 [ "himmelblau" ]; # will be merged with entries from other modules

    # Add entries for authenticating users via pam
    security.pam.services =
      let
        genServiceCfg = service: {
          rules =
            let
              super = config.security.pam.services.${service}.rules;
            in
            {
              account.himmelblau = {
                order = super.account.unix.order - 10;
                control = "sufficient";
                modulePath = "${cfg.pamPackage.lib}/lib/libpam_himmelblau.so";
                settings.ignore_unknown_user = true;
                settings.debug = cfg.debugFlag;
              };
              auth.himmelblau = {
                order = super.auth.unix.order - 10;
                control = "sufficient";
                modulePath = "${cfg.pamPackage.lib}/lib/libpam_himmelblau.so";
                settings.mfa_poll_prompt = cfg.mfaSshWorkaroundFlag && service == "sshd";
                settings.debug = cfg.debugFlag;
              };
              session.himmelblau = {
                order = super.session.unix.order - 10;
                control = "optional";
                modulePath = "${cfg.pamPackage.lib}/lib/libpam_himmelblau.so";
                settings.debug = cfg.debugFlag;
              };
              auth.himmelblau-unseal = lib.mkIf cfg.tryUnsealFlag {
                order = super.auth.unix.order + 1000;
                control = "optional";
                modulePath = "${cfg.package}/lib/libpam_himmelblau.so";
                settings.try_unseal = true;
                settings.debug = cfg.debugFlag;
              };
            };
        };
        services =
          cfg.pamServices
          ++ lib.optional config.security.sudo.enable "sudo"
          ++ lib.optional config.security.doas.enable "doas"
          ++ lib.optional config.services.sshd.enable "sshd";
      in
      lib.genAttrs services genServiceCfg;

    systemd.user.services.himmelblau-broker = {
      description = "Himmelblau Authentication Broker";
      serviceConfig = {
        Type = "dbus";
        BusName = "com.microsoft.identity.broker1";
        ExecStart = "${cfg.brokerPackage}/bin/himmelblau_broker";
        Slice = "background.slice";
        TimeoutStopSec = 5;
        Restart = "on-failure";
        WatchdogSec = "120s";
      };
    };

    systemd.sockets.himmelblaud = {
      description = "Himmelblau Authentication Daemon Socket";
      wantedBy = [ "sockets.target" ];
      socketConfig = {
        ListenStream = "/run/himmelblaud/socket";
        FileDescriptorName = "himmelblaud";
        SocketMode = "0666";
        Accept = false;
      };
    };

    systemd.sockets.himmelblaud-tasks = {
      description = "Himmelblau Daemon Task Socket";
      wantedBy = [ "sockets.target" ];
      socketConfig = {
        ListenStream = "/run/himmelblaud/task_sock";
        FileDescriptorName = "himmelblaud-task";
        Service = "himmelblaud.service";
        SocketMode = "0600";
        SocketUser = "root";
        SocketGroup = "root";
        Accept = false;
      };
    };

    systemd.sockets.himmelblaud-broker = {
      description = "Himmelblau Daemon Broker Socket";
      wantedBy = [ "sockets.target" ];
      socketConfig = {
        ListenStream = "/run/himmelblaud/broker_sock";
        FileDescriptorName = "himmelblaud-broker";
        Service = "himmelblaud.service";
        SocketMode = "0666";
        Accept = false;
      };
    };

    systemd.services =
      let
        commonServiceConfig = {
          Type = "notify";
          UMask = "0027";
          # SystemCallFilter = "@aio @basic-io @chown @file-system @io-event @network-io @sync";
          NoNewPrivileges = true;
          PrivateDevices = true;
          ProtectHostname = true;
          ProtectClock = true;
          ProtectKernelTunables = true;
          ProtectKernelModules = true;
          ProtectKernelLogs = true;
          ProtectControlGroups = true;
          MemoryDenyWriteExecute = true;
        };
      in
      {

        himmelblaud = {
          description = "Himmelblau Authentication Daemon";
          wants = [
            "chronyd.service"
            "ntpd.service"
            "network-online.target"
          ];
          before = [ "accounts-daemon.service" ];
          wantedBy = [
            "multi-user.target"
            "accounts-daemon.service"
          ];

          upholds = [ "himmelblaud-tasks.service" ];
          serviceConfig = commonServiceConfig // {
            ExecStart =
              "${cfg.daemonPackage}/bin/himmelblaud --config ${configFile}"
              + lib.optionalString cfg.debugFlag " -d";
            Restart = "on-failure";
            WatchdogSec = "120s";
            DynamicUser = "yes";
            CacheDirectory = "himmelblaud"; # /var/cache/himmelblaud
            StateDirectory = "himmelblaud"; # /var/lib/himmelblaud
            PrivateTmp = true;
            # We have to disable this to allow tpmrm0 access for tpm binding.
            PrivateDevices = false;
          };
        };

        himmelblaud-tasks = {
          description = "Himmelblau Local Tasks";
          bindsTo = [ "himmelblaud.service" ];
          wantedBy = [ "multi-user.target" ];
          path = [
            pkgs.shadow
            pkgs.bash
          ];
          serviceConfig = commonServiceConfig // {
            ExecStart = "${cfg.daemonPackage}/bin/himmelblaud_tasks";
            Restart = "on-failure";
            WatchdogSec = "120s";
            User = "root";
            ProtectSystem = "strict";
            ReadWritePaths = "/home /var/run/himmelblaud /tmp /etc/krb5.conf.d /etc /var/lib /var/cache/nss-himmelblau";
            RestrictAddressFamilies = "AF_UNIX";
          };
        };
      };
  };

}
