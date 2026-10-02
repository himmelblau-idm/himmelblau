{
  lib,
  config,
  pkgs,
  ...
}:
let
  cfg = config.services.himmelblau;
  mayUseLocalTpmDevice = (
      cfg.settings.tpm_tcti_name == null
      || cfg.settings.tpm_tcti_name == "device"
      || lib.hasPrefix "device:" cfg.settings.tpm_tcti_name
    );
  targetsRawTpmDevice =
    mayUseLocalTpmDevice
    && (
      cfg.settings.tpm_tcti_name == "device"
      || cfg.settings.tpm_tcti_name == "device:"
      || (
        cfg.settings.tpm_tcti_name != null
        && builtins.match "device:/dev/tpm[0-9]+" cfg.settings.tpm_tcti_name != null
      )
    );

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
          cached Entra ID SSO material using the login password as PIN, similar
          to how pam_gnome_keyring unlocks the keyring at login.

          This cannot be used with enable_hello_totp. When Hello TOTP is enabled,
          the daemon refuses the non-interactive unseal before loading cached SSO
          material because the hook cannot collect the required second factor.
        '';
      };

      pamServices = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [
          "passwd"
          "login"
          "su"
          "systemd-user"
        ];
        description = "Which PAM services to add the himmelblau module to.";
      };

      # Note: settings options are now defined in himmelblau-options.nix
      # which is auto-generated from docs-xml/ by src/common/scripts/gen_param_code.py
    };
  };

  config = lib.mkIf cfg.enable {
    security.tpm2.enable = lib.mkDefault mayUseLocalTpmDevice;

    assertions = [
      {
        assertion = !(
          cfg.settings.hsm_type == "tpm"
          && mayUseLocalTpmDevice
          && !config.security.tpm2.enable
        );
        message = "services.himmelblau: hsm_type = \"tpm\" with a device TCTI requires security.tpm2.enable = true.";
      }
      {
        assertion = !targetsRawTpmDevice;
        message = "services.himmelblau: raw TPM device TCTIs (\"device\", \"device:\", and \"device:/dev/tpmN\") are unsupported because the DynamicUser service cannot access /dev/tpmN through security.tpm2.tssGroup; use \"device:/dev/tpmrm0\".";
      }
      {
        assertion = !(
          config.security.tpm2.enable
          && mayUseLocalTpmDevice
          && config.security.tpm2.tssGroup == null
        );
        message = "services.himmelblau: TPM device access requires security.tpm2.tssGroup to be set.";
      }
    ];

    environment.etc."himmelblau/himmelblau.conf".source = configFile;

    systemd.tmpfiles.rules = [
      "d /var/cache/nss-himmelblau 0755 root root -"
      "d /var/cache/himmelblau-policies 0600 root root -"
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
              # nixpkgs adds a second, earlier pam_unix rule named
              # "unix-early" whenever something downstream needs the
              # password already cached (GNOME keyring, fscrypt,
              # kwallet, ...). It prompts, and it displaces the main
              # unix rule to a much later order, so anchoring only to
              # the main rule puts himmelblau behind a password prompt
              # and defeats the device code flow. Anchor to whichever
              # pam_unix rule comes first.
              authUnixOrder =
                if super.auth ? unix-early then
                  lib.min super.auth.unix-early.order super.auth.unix.order
                else
                  super.auth.unix.order;
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
                order = authUnixOrder - 10;
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
          ++ lib.optional config.security.polkit.enable "polkit-1"
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

    systemd.services =
      let
        tpmAccessRequired = config.security.tpm2.enable && mayUseLocalTpmDevice;
        commonAfter = [
          "chronyd.service"
          "ntpd.service"
          "network-online.target"
          "suspend.target"
        ];
        daemonAfter = commonAfter ++ [ "nscd.service" ]
          ++ lib.optional config.security.tpm2.enable "himmelblau-hsm-pin-init.service"
          ++ lib.optional tpmAccessRequired "tpm2-udev-trigger.service";
        daemonSockets = [
          "himmelblaud.socket"
          "himmelblaud-tasks.socket"
          "himmelblaud-broker.socket"
        ];
        commonServiceConfig = {
          Type = "notify";
          # SystemCallFilter = "@aio @basic-io @chown @file-system @io-event @network-io @sync";
          NoNewPrivileges = true;
          PrivateTmp = true;
          PrivateDevices = true;
          ProtectSystem = "strict";
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
            "nss-user-lookup.target"
          ] ++ lib.optional config.security.tpm2.enable "himmelblau-hsm-pin-init.service"
            ++ lib.optional tpmAccessRequired "tpm2-udev-trigger.service";
          after = daemonAfter ++ daemonSockets;
          requires = daemonSockets;
          before = [
            "accounts-daemon.service"
            "systemd-user-sessions.service"
            "sshd.service"
            "nss-user-lookup.target"
          ];
          wantedBy = [
            "multi-user.target"
            "accounts-daemon.service"
          ];

          upholds = [ "himmelblaud-tasks.service" ];
          startLimitIntervalSec = 30;
          startLimitBurst = 8;
          serviceConfig = commonServiceConfig // {
            UMask = "0027";
            ExecStart =
              "${cfg.daemonPackage}/bin/himmelblaud --config ${configFile}"
              + lib.optionalString cfg.debugFlag " -d";
            Restart = "on-failure";
            RestartSec = "500ms";
            WatchdogSec = "120s";
            FileDescriptorStoreMax = 1;
            FileDescriptorStorePreserve = "yes";
            Sockets = daemonSockets;
            DynamicUser = "yes";
            User = "himmelblaud";
            CacheDirectory = "himmelblaud"; # /var/cache/himmelblaud
            StateDirectory = "himmelblaud"; # /var/lib/himmelblaud
            # Expose host devices only when a TPM-backed HSM mode may need them.
            PrivateDevices = !tpmAccessRequired;
            DeviceAllow = lib.optional tpmAccessRequired "char-tpm rw";
            SupplementaryGroups = lib.optional (
              tpmAccessRequired && config.security.tpm2.tssGroup != null
            ) config.security.tpm2.tssGroup;
          } // lib.optionalAttrs config.security.tpm2.enable {
            LoadCredentialEncrypted = "hsm-pin:/var/lib/himmelblaud/hsm-pin-nopcr.enc";
            Environment = "HIMMELBLAU_HSM_PIN_PATH=%d/hsm-pin";
          };
        };

        himmelblau-hsm-pin-init = lib.mkIf config.security.tpm2.enable {
          description = "Himmelblau HSM PIN Initialization";
          before = [ "himmelblaud.service" ];
          after = [
            "local-fs.target"
            "systemd-tpm2-setup.service"
            "tpm2-udev-trigger.service"
          ];
          wants = [
            "systemd-tpm2-setup.service"
            "tpm2-udev-trigger.service"
          ];
          wantedBy = [ "himmelblaud.service" ];
          path = [
            pkgs.coreutils
            pkgs.gnugrep
            pkgs.openssl
            pkgs.systemd
            pkgs.tpm2-tools
          ];
          unitConfig = {
            DefaultDependencies = false;
            ConditionPathExists = "!/var/lib/private/himmelblaud/hsm-pin-nopcr.enc";
          };
          serviceConfig = {
            Type = "oneshot";
            ExecStart = "${cfg.daemonPackage}/libexec/himmelblau-init-hsm-pin";
          };
        };

        himmelblaud-tasks = {
          description = "Himmelblau Local Tasks";
          after = commonAfter ++ [ "himmelblaud.service" ];
          bindsTo = [ "himmelblaud.service" ];
          wantedBy = [ "multi-user.target" ];
          startLimitIntervalSec = 30;
          startLimitBurst = 8;
          path = [
            pkgs.shadow
            pkgs.bash
            pkgs.util-linux
          ];
          unitConfig = {
            ConditionPathExists = "/run/himmelblaud/task_sock";
          };
          serviceConfig = commonServiceConfig // {
            ExecStart = "${cfg.daemonPackage}/bin/himmelblaud_tasks";
            Restart = "on-failure";
            RestartSec = "1s";
            WatchdogSec = "120s";
            User = "root";
            CacheDirectory = "nss-himmelblau";
            CapabilityBoundingSet = [
              "CAP_CHOWN"
              "CAP_FOWNER"
              "CAP_DAC_OVERRIDE"
              "CAP_DAC_READ_SEARCH"
              "CAP_SETUID"
              "CAP_SETGID"
            ];
            AmbientCapabilities = [ "CAP_SETUID" "CAP_SETGID" ];
            InaccessiblePaths = [ "-/sys/firmware/efi/mok-variables" ];
            ReadWritePaths =
              "/home /run/himmelblaud /tmp /etc/krb5.conf.d /etc /var/lib /var/cache/nss-himmelblau /var/cache/himmelblau-policies";
          };
        };
      };

    systemd.sockets =
      let
        daemonAfter = config.systemd.services.himmelblaud.after;
        commonSocket = {
          after = lib.filter (unit: !(lib.hasSuffix ".socket" unit)) daemonAfter
            ++ [ "sockets.target" ];
          before = [ "himmelblaud.service" ];
          partOf = [ "himmelblaud.service" ];
          unitConfig.DefaultDependencies = false;
        };
        commonSocketConfig = {
          DirectoryMode = "0755";
          Accept = false;
          Service = "himmelblaud.service";
        };
      in
      {
        # Pulled in by the daemon, not sockets.target, to avoid early NSS boot hangs.
        himmelblaud = commonSocket // {
          description = "Himmelblau Authentication Daemon Socket";
          socketConfig = commonSocketConfig // {
            ListenStream = "/run/himmelblaud/socket";
            FileDescriptorName = "himmelblaud";
            SocketMode = "0666";
          };
        };
        himmelblaud-tasks = commonSocket // {
          description = "Himmelblau Daemon Task Socket";
          socketConfig = commonSocketConfig // {
            ListenStream = "/run/himmelblaud/task_sock";
            FileDescriptorName = "himmelblaud-task";
            SocketMode = "0600";
            SocketUser = "root";
            SocketGroup = "root";
          };
        };
        himmelblaud-broker = commonSocket // {
          description = "Himmelblau Daemon Broker Socket";
          socketConfig = commonSocketConfig // {
            ListenStream = "/run/himmelblaud/broker_sock";
            FileDescriptorName = "himmelblaud-broker";
            SocketMode = "0666";
          };
        };
      };
  };
}
