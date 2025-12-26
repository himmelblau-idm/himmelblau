{
  lib,
  config,
  pkgs,
  ...
}:
let
  cfg = config.services.himmelblau;
in
{

  options = {
    services.himmelblau =
      let
        globalOptions = {
          domain = lib.mkOption {
            type = lib.types.str;
            example = "my.domain.com";
            description = ''
              The primary Azure Entra ID domain name used for authentication. This value SHOULD
              match the domain name that users enter when signing in (for example, the domain portion of their UPN).
              In most cases, this will be the primary domain of your Azure Entra ID tenant.
              If your organization uses multiple verified domains or aliases, choose the one that your users actually use to sign in.

              This parameter is REQUIRED for successful authentication.
              If it is not specified, no users will be permitted to authenticate.'';
          };
          debug = lib.mkOption {
            type = lib.types.bool;
            default = false;
            description = ''
              Configure whether the daemon will output debug messages to the journal.
            '';
          };
          id_attr_map = lib.mkOption {
            type = lib.types.enum [
              "name"
              "uuid"
            ];
            default = "name";
            description = ''
              Specify whether to map uid/gid based on the object name or the object uuid.
              By object uuid mapping is the old default, but can cause authentication
              issues over SSH. Mapping by name is recommeneded.
            '';
          };
          join_type = lib.mkOption {
            type = lib.types.enum [
              "join"
              "register"
            ];
            default = "join";
            description = ''
              The device join type for Azure. Standard device join, or register only.
            '';
          };
          enable_hello = lib.mkOption {
            type = lib.types.bool;
            default = true;
            description = ''
              Whether to enroll users in Hello authentication. If disabled, MFA may be
              required during each login. Disabling Hello authentication is recommeneded
              when the host is public facing (such as via SSH).
              WARNING: Hello authentication depends on openssl3. If your system does not
              provide openssl3, Hello MUST be disabled or authentication will fail.
              EL8 distros (such as Rocky Linux 8) DO NOT provide openssl3.
            '';
          };
          hello_pin_min_length = lib.mkOption {
            type = lib.types.int;
            default = 6;
            description = ''
              The minimum length of the Hello authentication PIN. This PIN length cannot
              be less than 6, and cannot exceed 32 characters. These are hard requirements
              for the encryption algorithm.
            '';
          };
          enable_sfa_fallback = lib.mkOption {
            type = lib.types.bool;
            default = false;
            description = ''
              Whether to permit attempting a SFA (password only) authentication when MFA
              methods are unavailable. Sometimes this is possible when MFA has yet to be
              configured. This is disabled by default.
            '';
          };
          enable_experimental_mfa = lib.mkOption {
            type = lib.types.bool;
            default = true;
            description = ''
              This option enables the experimental MFA (multi-factor authentication) flow,
              which permits Hello authentication. Note that this flow may fail in certain
              edge cases. When disabled, the system will enforce the DAG (Device Authorization
              Grant) flow for MFA, and Hello authentication will be disabled.
            '';
          };
          cn_name_mapping = lib.mkOption {
            type = lib.types.bool;
            default = true;
            description = ''
              CN to UPN mapping allows users to simply enter the short form of their
              username (`dave` instead of `dave@example.com`). Himmelblau will only map CNs
              to the primary domain (the first domain listed in the `domains` option
              above). WARNING: CN mapping could mask local users, depending on your PAM
              configuration.
            '';
          };
          db_path = lib.mkOption {
            type = lib.types.str;
            default = "/var/cache/himmelblaud/himmelblau.cache.db";
            description = "The location of the cache database";
          };
          hsm_pin_path = lib.mkOption {
            type = lib.types.str;
            default = "/var/lib/himmelblaud/hsm-pin";
            description = "The location where the hsm pin will be stored";
          };
          socket_path = lib.mkOption {
            type = lib.types.str;
            default = "/var/run/himmelblaud/socket";
          };
          task_socket_path = lib.mkOption {
            type = lib.types.str;
            default = "/var/run/himmelblaud/task_sock";
          };
          broker_socket_path = lib.mkOption {
            type = lib.types.str;
            default = "/var/run/himmelblaud/broker_sock";
          };

          connection_timeout = lib.mkOption {
            type = lib.types.ints.unsigned;
            default = 2;
          };
          cache_timeout = lib.mkOption {
            type = lib.types.ints.unsigned;
            default = 300;
          };
          use_etc_skel = lib.mkOption {
            type = lib.types.bool;
            default = false;
          };
          selinux = lib.mkOption {
            type = lib.types.bool;
            default = false;
          };
          local_sudo_group = lib.mkOption {
            type = lib.types.nullOr (lib.types.str);
            default = null;
            example = [ "sudo" ];
            description = ''
              The local group that should be given to users in any of the groups specified in sudo_groups.
              Only has an affect if sudo_groups is set.
            '';
          };
          apply_policy = lib.mkOption {
            type = lib.types.bool;
            default = false;
            description = ''
              A boolean option that enables the application and enforcement of Intune policies to the authenticated user.
              By default, this option is disabled.
            '';
          };
        };
        domainOptions = {
          pam_allow_groups = lib.mkOption {
            default = null;
            type = lib.types.nullOr (lib.types.listOf lib.types.str);
            example = [ "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" ];
            description = ''
              pam_allow_groups SHOULD be defined or else all users will be authorized by
              pam account. The option should be set to a comma seperated list of Users and
              Groups which are allowed access to the system. Groups MUST be specified by
              Object ID, not by UPN. This is because Azure does not permit regular users
              the right to read group names, only the Object IDs which they belong to.
            '';
          };
          odc_provider = lib.mkOption {
            type = lib.types.nullOr lib.types.str;
            default = null;
            example = "odc.officeapps.live.com";
            description = ''
              If you have an ODC provider (the default being odc.officeapps.live.com), specify
              the hostname for sending a federationProvider request. If the federationProvider
              request is successful, the tenant_id and authority_host options do not need to
              be specified.
            '';
          };

          tenant_id = lib.mkOption {
            type = lib.types.nullOr lib.types.str;
            default = null;
            example = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX";
          };
          app_id = lib.mkOption {
            type = lib.types.nullOr lib.types.str;
            default = null;
            example = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX";
          };
          authority_host = lib.mkOption {
            type = lib.types.str;
            default = "login.microsoftonline.com";
          };

          local_groups = lib.mkOption {
            type = lib.types.nullOr (lib.types.listOf lib.types.str);
            default = null;
            example = [ "docker" ];
            description = ''
              A comma seperated list of local groups that every Entra Id user should be a
              member of. For example, you may wish for all Entra Id users to be a member
              of the sudo group. WARNING: This setting will not REMOVE group member entries
              when groups are removed from this list. You must remove them manually.
            '';
          };
          logon_script = lib.mkOption {
            type = lib.types.nullOr lib.types.str;
            default = null;
            example = "./logon.sh";
            description = ''
              Logon user script. This script will execute every time a user logs on. Two
              environment variables are set: USERNAME, and ACCESS_TOKEN. The ACCESS_TOKEN
              environment variable is an access token for the MS graph.
            '';
          };
          logon_token_scopes = lib.mkOption {
            type = lib.types.nullOr (lib.types.listOf lib.types.str);
            default = null;
            description = ''
              The token scope config option sets the comma separated scopes that should be
              requested for the ACCESS_TOKEN. ACCESS_TOKEN will be empty during offline logon.
              The return code of the script determines how the authentication proceeds. 0 is
              success, 1 is a soft failure and authentication will proceed, while 2 is a hard
              failure causing authentication to fail.
            '';
          };
          home_prefix = lib.mkOption {
            type = lib.types.str;
            default = "/home/";
          };
          home_attr = lib.mkOption {
            type = lib.types.enum [
              "UUID"
              "SPN"
              "CN"
            ];
            default = "UUID";
          };
          home_alias = lib.mkOption {
            type = lib.types.enum [
              "UUID"
              "SPN"
              "CN"
            ];
            default = "SPN";
          };
          shell = lib.mkOption {
            type = lib.types.path;
            default = "/run/current-system/sw/bin/bash";
          };
          idmap_range = lib.mkOption {
            type = lib.types.str;
            default = "5000000-5999999";
          };
          sudo_groups = lib.mkOption {
            default = null;
            type = lib.types.nullOr (lib.types.listOf lib.types.str);
            example = [ "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" ];
            description = ''
              A comma separated list of entra groups that should have access to sudo.
              If local_sudo_group is not set, the local group 'sudo' will be used.
              Removes group from user if they are no longer a member of the specified entra group.
            '';
          };
        };
      in
      {
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
          ];
          description = "Which PAM services to add the himmelblau module to.";
        };

        settings = globalOptions // domainOptions; # settings submodule https://github.com/NixOS/rfcs/pull/42
        domains = lib.mkOption {
          default = { };
          type = lib.types.attrsOf (
            lib.types.submodule (
              { name, config, ... }:
              {
                options = domainOptions;
              }
            )
          );
          description = ''
            Setting to override the behaviour of himmelblau on a per-domain basis.
          '';
        };
      };
  };

  config = lib.mkIf cfg.enable {
    environment.etc."krb5.conf.d/krb5_himmelblau.conf".source = ../../src/config/krb5_himmelblau.conf;
    environment.etc."himmelblau/himmelblau.conf".text =
      let
        mkValueString =
          v:
          let
            err = t: v: abort "mkValueString: ${t} not supported: ${lib.generators.toPretty { } v}";
          in
          if builtins.isInt v then
            toString v
          else if builtins.isFloat v then
            lib.strings.floatToString v
          # convert derivations to store paths
          else if lib.attrsets.isDerivation v then
            toString v
          # we default to not quoting strings
          else if builtins.isString v then
            v
          else if true == v then
            "true"
          else if false == v then
            "false"
          # we space separate list elements, and recursively format them
          else if builtins.isList v then
            lib.concatMapStringsSep " " mkValueString v
          # we don't support nulls, attrsets, or functions
          else if null == v then
            err "null" v
          else if builtins.isAttrs v then
            err "attrsets" v
          else if builtins.isFunction v then
            err "functions" v
          else
            err "this value is" (toString v);
        # don't add null fields to config files
        trimAttrs = lib.filterAttrs (n: v: v != null);
        # merge global section with named sections from domains
        configFile = {
          global = trimAttrs cfg.settings;
        }
        // lib.mapAttrs (k: v: trimAttrs v) cfg.domains;
        # toINI generator generates configuration file from an attribute set
      in
      lib.generators.toINI { mkKeyValue = k: v: "${k} = ${mkValueString v}"; } configFile;

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
