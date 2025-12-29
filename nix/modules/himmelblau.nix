{
  lib,
  config,
  pkgs,
  ...
}:
let
  cfg = config.services.himmelblau;
  ini = pkgs.formats.ini { };
  configFile = ini.generate "himmelblau.conf" cfg.settings;
in
{

  options = {
    services.himmelblau = {
      enable = lib.mkEnableOption "Himmelblau";

      package = lib.mkOption {
        type = lib.types.path;
        description = "Package to use for Himmelblau service.";
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

      pamServices = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [
          "passwd"
          "login"
          "systemd-user"
        ];
        description = "Which PAM services to add the himmelblau module to.";
      };

      settings = lib.mkOption {
        default = { }; # TODO: maybe include default configuration here
        type = ini.type;
        description = ''
          Configuration for himmelblaud. See
          <https://himmelblau-idm.org/docs/reference/himmelblau-conf/>
          and
          <https://github.com/himmelblau-idm/himmelblau/blob/main/man/man5/himmelblau.conf.5>
        '';
      };

    };
  };

  config = lib.mkIf cfg.enable {
    environment.etc."krb5.conf.d/krb5_himmelblau.conf".source = ../../src/config/krb5_himmelblau.conf;
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
      nativeMessagingHosts.packages = [ cfg.package ];
    };

    programs.chromium.extensions = [
      "jlnfnnolkbjieggibinobhkjdfbpcohn"
    ];
    environment.etc."chromium/native-messaging-hosts/linux_entra_sso.json".source =
      "${cfg.package}/lib/chromium/native-messaging-hosts/linux_entra_sso.json";
    environment.etc."opt/chrome/native-messaging-hosts/linux_entra_sso.json".source =
      "${cfg.package}/lib/chromium/native-messaging-hosts/linux_entra_sso.json";
    services.dbus.packages = [ cfg.package ];

    # Add himmelblau to the list of name services to lookup users/groups
    system.nssModules = [ cfg.package ];
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
                modulePath = "${cfg.package}/lib/libpam_himmelblau.so";
                settings.ignore_unknown_user = true;
                settings.debug = cfg.debugFlag;
              };
              auth.himmelblau = {
                order = super.auth.unix.order - 10;
                control = "sufficient";
                modulePath = "${cfg.package}/lib/libpam_himmelblau.so";
                settings.mfa_poll_prompt = cfg.mfaSshWorkaroundFlag && service == "sshd";
                settings.debug = cfg.debugFlag;
              };
              session.himmelblau = {
                order = super.session.unix.order - 10;
                control = "optional";
                modulePath = "${cfg.package}/lib/libpam_himmelblau.so";
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
          # This is just so that the service restarts on config change
          # Normall we would do `--config ${configFile}`
          # Himmelblau has however a bug where if we supply a config file with `--config`,
          # the default values for fields do not get set.
          environment.HIMMELBLAU_DUMMY_CONFIG = configFile;
          upholds = [ "himmelblaud-tasks.service" ];
          serviceConfig = commonServiceConfig // {
            ExecStart = "${cfg.package}/bin/himmelblaud" + lib.optionalString cfg.debugFlag " -d";
            Restart = "on-failure";
            DynamicUser = "yes";
            CacheDirectory = "himmelblaud"; # /var/cache/himmelblaud
            RuntimeDirectory = "himmelblaud"; # /var/run/himmelblaud
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
          unitConfig = {
            ConditionPathExists = "/var/run/himmelblaud/task_sock";
          };
          serviceConfig = commonServiceConfig // {
            ExecStart = "${cfg.package}/bin/himmelblaud_tasks";
            Restart = "on-failure";
            User = "root";
            ProtectSystem = "strict";
            ReadWritePaths = "/home /var/run/himmelblaud /tmp /etc/krb5.conf.d /etc /var/lib /var/cache/nss-himmelblau";
            RestrictAddressFamilies = "AF_UNIX";
          };
        };
      };
  };

}
