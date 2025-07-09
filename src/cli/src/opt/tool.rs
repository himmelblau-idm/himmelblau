/*
   Unix Azure Entra ID implementation
   Copyright (C) David Mulder <dmulder@samba.org> 2024

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
use clap::Subcommand;
use libc::uid_t;
use libc::gid_t;

#[derive(Debug, Subcommand)]
pub enum IdmapOpt {
    /// Add a static user mapping to the idmap cache. This maps an Entra ID user (by UPN or
    /// SAM-compatible name) to a fixed UID and primary group GID.
    UserAdd {
        #[clap(short, long)]
        debug: bool,
        #[clap(short = 'D', long = "name")]
        account_id: String,
        #[clap(short = 'u', long = "uid")]
        uid: uid_t,
        #[clap(short = 'g', long = "gid")]
        gid: gid_t,
    },
    /// Add a static group mapping to the idmap cache. This maps an Entra ID group (by name)
    /// to a fixed GID. This can be used to maintain group identity and membership compatibility
    /// after moving to Entra ID.
    GroupAdd {
        #[clap(short, long)]
        debug: bool,
        #[clap(short = 'D', long = "name")]
        account_id: String,
        #[clap(short = 'g', long = "gid")]
        gid: gid_t,
    },
}

#[derive(Debug, Subcommand)]
pub enum ApplicationOpt {
    /// Lists Entra ID application registrations in the current tenant.
    ///
    /// This command performs a delegated Microsoft Graph API request using an access
    /// token acquired via the specified client application (`--client-id`), which must
    /// have `Application.Read.All` permissions in the tenant.
    ///
    /// If the `--name` parameter is omitted, the command authenticates as the currently
    /// logged-in user via the Himmelblau SSO broker. If the `--name` parameter is
    /// provided, the command attempts to authenticate as the specified Entra ID user.
    /// In this case, the command must be run as `root` to impersonate another user.
    ///
    /// This command must be run from a device that has already been joined to Entra ID.
    List {
        #[clap(short, long)]
        debug: bool,
        #[clap(short = 'D', long = "name")]
        account_id: Option<String>,
        #[clap(long = "client-id")]
        client_id: String,
    },
    /// Creates a new Entra ID application registration in the current tenant.
    ///
    /// This command performs a delegated Microsoft Graph API request using an access
    /// token acquired via the specified client application (`--client-id`), which must
    /// have `Application.ReadWrite.All` permissions in the tenant.
    ///
    /// The new application will be created with the provided `--display-name`.
    ///
    /// You may specify one or more `--redirect-uri` options to configure redirect URIs
    /// for the application (used for public client authentication). If no redirect
    /// URIs are provided, the application will not include any by default.
    ///
    /// Use the `--user-read-write` and/or `--group-read-write` flags to grant the
    /// application additional Microsoft Graph API permissions at registration time,
    /// including `User.ReadWrite.All` and `Group.ReadWrite.All`.
    ///
    /// NOTE: If you grant these permissions, it is strongly recommended that you restrict
    /// access to the application to specific administrators or groups:
    ///
    /// 1. In the Microsoft Entra admin portal, go to Entra ID -> Enterprise applications and find your app's entry.
    /// 2. Under Properties, set "Assignment required?" to Yes.
    /// 3. Go to Users and groups, click Add, and assign only the specific users or groups you want to have access.
    ///
    /// If the `--name` parameter is omitted, the command authenticates as the currently
    /// logged-in user via the Himmelblau SSO broker. If the `--name` parameter is
    /// provided, the command attempts to authenticate as the specified Entra ID user.
    /// In this case, the command must be run as `root` to impersonate another user.
    ///
    /// This command must be run from a device that has already been joined to Entra ID.
    Create {
        #[clap(short, long)]
        debug: bool,
        #[clap(short = 'D', long = "name")]
        account_id: Option<String>,
        #[clap(long = "client-id")]
        client_id: String,
        #[clap(long = "display-name")]
        display_name: String,
        #[clap(long = "redirect-uri", value_name = "URI")]
        redirect_uris: Vec<String>,
        #[clap(long = "user-read-write")]
        user_read_write: bool,
        #[clap(long = "group-read-write")]
        group_read_write: bool,
    },
    /// Lists the schema extension attributes registered on an Entra ID application.
    ///
    /// This command retrieves the directory extension attributes (e.g., `uidNumber`, `gidNumber`,
    /// etc.) that have been added to the application identified by `--schema-app-object-id`.
    ///
    /// The `--schema-app-object-id` parameter must be the Object ID of the application
    /// (not the Client ID), as shown in the Entra Admin Center. This value corresponds to the
    /// `id` field in Microsoft Graph and is required to query extension properties.
    ///
    /// You must also supply a separate `--client-id` that grants `Application.Read.All`
    /// or `Application.ReadWrite.All` permissions in the tenant to perform this query.
    ///
    /// If the `--name` parameter is omitted, the command authenticates as the currently
    /// logged-in user via the Himmelblau SSO broker. If the `--name` parameter is provided,
    /// the command attempts to authenticate as the specified Entra ID user.
    /// In this case, the command must be run as `root` to impersonate another user.
    ///
    /// This command must be run from a device that has already been joined to Entra ID.
    ListSchemaExtensions {
        #[clap(short, long)]
        debug: bool,
        #[clap(short = 'D', long = "name")]
        account_id: Option<String>,
        #[clap(long = "client-id")]
        client_id: String,
        #[clap(long = "schema-app-object-id")]
        schema_app_object_id: String,
    },
    /// Adds a standard set of POSIX-related schema extensions to an existing Entra ID application.
    ///
    /// This command registers directory extension attributes (e.g., `uidNumber`, `gidNumber`,
    /// `unixHomeDirectory`, `loginShell`, `gecos`) on the application specified by `--schema-app-object-id`.
    /// These extensions will be usable on user and/or group objects, as appropriate.
    ///
    /// The application specified by `--schema-app-object-id` must already exist in the tenant,
    /// and must be identified by its Object ID (not the Client ID). This value is labeled
    /// as "Object ID" in the Entra Admin Center and corresponds to the `id` field in Graph API responses.
    ///
    /// You must also supply a separate `--client-id` that grants `Application.ReadWrite.All`
    /// permissions to perform the extension registration.
    ///
    /// If the `--name` parameter is omitted, the command authenticates as the currently
    /// logged-in user via the Himmelblau SSO broker. If the `--name` parameter is provided,
    /// the command attempts to authenticate as the specified Entra ID user.
    /// In this case, the command must be run as `root` to impersonate another user.
    ///
    /// This command must be run from a device that has already been joined to Entra ID.
    AddSchemaExtensions {
        #[clap(short, long)]
        debug: bool,
        #[clap(short = 'D', long = "name")]
        account_id: Option<String>,
        #[clap(long = "client-id")]
        client_id: String,
        #[clap(long = "schema-app-object-id")]
        schema_app_object_id: String,
    }
}

#[derive(Debug, Subcommand)]
pub enum UserOpt {
    /// Sets POSIX-related attributes on a specified Entra ID user object.
    ///
    /// This command updates POSIX attributes (`uidNumber`, `gidNumber`, `unixHomeDirectory`,
    /// `loginShell`, and `gecos`) on the Entra ID user identified by `--user-id`, which must be
    /// a valid Object ID or UPN.
    ///
    /// You must also provide the `--schema-client-id`, which identifies the application
    /// where the extension properties were registered. This value must be the Client ID of the
    /// application used for schema registration. The application associated with
    /// `--schema-client-id` must supply `User.ReadWrite.All` permissions in the tenant.
    ///
    /// If the `--name` parameter is omitted, the command authenticates as the currently
    /// logged-in user via the Himmelblau SSO broker. If the `--name` parameter is provided,
    /// the command must be run as `root` to impersonate another user.
    ///
    /// This command must be run from a device that has already been joined to Entra ID.
    SetPosixAttrs {
        #[clap(short, long)]
        debug: bool,
        #[clap(short = 'D', long = "name")]
        account_id: Option<String>,
        #[clap(long = "schema-client-id")]
        schema_client_id: String,
        #[clap(long = "user-id")]
        user_id: String,
        #[clap(long = "uid")]
        uid: Option<u32>,
        #[clap(long = "gid")]
        gid: Option<u32>,
        #[clap(long = "home")]
        home: Option<String>,
        #[clap(long = "shell")]
        shell: Option<String>,
        #[clap(long = "gecos")]
        gecos: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum GroupOpt {
    /// Sets POSIX-related attributes on a specified Entra ID group object.
    ///
    /// This command updates the `gidNumber` attribute on the Entra ID group identified by
    /// `--group-id`, which must be a valid Object ID.
    ///
    /// You must also provide the `--schema-client-id`, which identifies the application
    /// where the extension properties were registered. This value must be the Client ID of the
    /// application used for schema registration. The application associated with
    /// `--schema-client-id` must supply `Group.ReadWrite.All` permissions in the tenant.
    ///
    /// If the `--name` parameter is omitted, the command authenticates as the currently
    /// logged-in user via the Himmelblau SSO broker. If the `--name` parameter is provided,
    /// the command must be run as `root` to impersonate another user.
    ///
    /// This command must be run from a device that has already been joined to Entra ID.
    SetPosixAttrs {
        #[clap(short, long)]
        debug: bool,
        #[clap(short = 'D', long = "name")]
        account_id: Option<String>,
        #[clap(long = "schema-client-id")]
        schema_client_id: String,
        #[clap(long = "group-id")]
        group_id: String,
        #[clap(long = "gid")]
        gid: u32,
    },
}

#[derive(Debug, Subcommand)]
pub enum AddCredOpt {
    /// Store a client secret for confidential client authentication.
    ///
    /// To set this up:
    ///
    /// 1. In the Entra ID portal, navigate to Azure Active Directory
    ///    -> App registrations, then open (or create) your application.
    /// 
    /// 2. Under Manage > Certificates & secrets, go to the Client secrets tab.
    /// 
    /// 3. Click New client secret, choose an expiry, and click Add.
    /// 
    /// 4. Copy the Value (not Secret ID) immediately. You won't be able to see it again.
    /// 
    /// 5. Use that value with this command to store it in Himmelblau’s encrypted cache.
    ///
    /// When this cred needs renewed in the future, simple run this command
    /// again to replace the expired secret.
    /// 
    /// Example:
    ///     aad-tool add-cred secret --client-id <CLIENT_ID> --secret <SECRET_VALUE>
    Secret {
        #[clap(short, long)]
        debug: bool,
        /// The Azure AD application (client) ID this secret is associated with.
        #[arg(long)]
        client_id: String,
        /// The tenant domain this secret is associated with.
        #[arg(long)]
        domain: String,
        /// The client secret value copied from the Entra ID portal.
        #[arg(long)]
        secret: String,
    },

    /// Generate an RS256 HSM-backed key pair with a self-signed certificate
    /// for confidential client authentication.
    ///
    /// To set this up:
    ///
    /// 1. In the Entra ID portal, navigate to Azure Active Directory
    ///    -> App registrations, then open (or create) your application.
    /// 
    /// 2. Under Manage > Certificates & secrets, go to the Certificates tab.
    /// 
    /// 3. Click Upload certificate and select the PEM file generated by this command.
    /// 
    /// 4. Azure will store this cert for authenticating via public key.
    ///
    /// The private key never leaves your TPM (or SoftHSM).
    /// 
    /// When this cred needs renewed in the future, simple run this command
    /// again to replace the expired certificate.
    ///
    /// Example:
    ///     aad-tool add-cred cert --client-id <CLIENT_ID> --valid-days 365 --cert-out /tmp/my-cert.crt
    Cert {
        #[clap(short, long)]
        debug: bool,
        /// The Azure AD application (client) ID this certificate is associated with.
        #[arg(long)]
        client_id: String,
        /// The tenant domain this certificate is associated with.
        #[arg(long)]
        domain: String,
        /// Number of days the self-signed certificate will be valid.
        #[arg(long)]
        valid_days: u64,
        /// Path to write the generated PEM certificate file.
        /// This is the file you will upload to Entra ID.
        #[arg(long)]
        cert_out: String,
    },
}

#[derive(Debug, Subcommand)]
#[clap(about = "Himmelblau Management Utility")]
pub enum HimmelblauUnixOpt {
    /// Add a confidential client credential for authenticating to Entra ID.
    ///
    /// This command has two modes: `secret` and `cert`, each of which stores
    /// credentials securely in Himmelblau’s encrypted cache.
    ///
    /// These credentials are used for querying Entra ID for user and group
    /// attributes (such as rfc2307 uid/gid or group names).
    #[clap(subcommand)]
    AddCred(AddCredOpt),
    /// Manage Entra ID application registrations, including creation, listing, and extension
    /// schema configuration.
    #[clap(subcommand)]
    Application(ApplicationOpt),
    /// Test authentication of a user via the himmelblaud resolver "pam" channel. This does not
    /// test that your pam configuration is correct - only that himmelblaud is correctly processing
    /// and validating authentications.
    AuthTest {
        #[clap(short, long)]
        debug: bool,
        #[clap(short = 'D', long = "name")]
        account_id: String,
    },
    /// Erase the content of the himmelblaud resolver cache. You should probably use `invalidate`
    /// instead.
    CacheClear {
        #[clap(short, long)]
        debug: bool,
        #[clap(long)]
        really: bool,
    },
    /// Invalidate, but don't erase the content of the himmelblaud resolver cache. This will force
    /// the himmelblaud daemon to refresh all user and group content immediately. If the connection
    /// is offline, entries will still be available and will be refreshed as soon as the daemon
    /// is online again.
    CacheInvalidate {
        #[clap(short, long)]
        debug: bool,
    },
    /// Configure PAM to use pam_himmelblau
    ConfigurePam {
        #[clap(short, long)]
        debug: bool,
        #[clap(long)]
        really: bool,
        #[clap(long = "auth-file")]
        auth_file: Option<String>,
        #[clap(long = "account-file")]
        account_file: Option<String>,
        #[clap(long = "session-file")]
        session_file: Option<String>,
        #[clap(long = "password-file")]
        password_file: Option<String>,
    },
    /// Enumerate all users and groups in Entra ID that have `rfc2307` attributes,
    /// and cache their values locally. This addresses the issue where UID/GID
    /// mappings are needed before authentication can succeed, but are normally
    /// only retrievable after login.
    ///
    /// The `--client-id` parameter is optional and must refer to a registered
    /// Entra ID application with `User.Read.All` and `Group.Read.All` permissions.
    ///
    /// The `--name` parameter specifies the Entra ID user on whose behalf the token
    /// is requested, enabling delegated access through the specified client application.
    ///
    /// This command can only be executed from an Entra Id enrolled host.
    Enumerate {
        #[clap(short, long)]
        debug: bool,
        #[clap(short = 'D', long = "name")]
        account_id: Option<String>,
        #[clap(long = "client-id")]
        client_id: Option<String>,
    },
    /// Manage Entra ID user accounts, including POSIX attribute assignment and UID mapping.
    #[clap(subcommand)]
    User(UserOpt),
    /// Manage Entra ID groups, including POSIX attribute assignment and GID mapping.
    #[clap(subcommand)]
    Group(GroupOpt),
    /// Manage the static idmapping cache used to map Entra ID accounts to static UID/GID values.
    /// This is useful for migrations from on-prem AD to Entra ID, where existing UID/GID mappings
    /// need to be preserved.
    #[clap(subcommand)]
    Idmap(IdmapOpt),
    /// Check that the himmelblaud daemon is online and able to connect correctly to the himmelblaud server.
    Status {
        #[clap(short, long)]
        debug: bool,
    },
    /// Show the version of this tool.
    Version {
        #[clap(short, long)]
        debug: bool,
    }
}

#[derive(Debug, clap::Parser)]
#[clap(about = "Himmelblau Management Utility")]
pub struct HimmelblauUnixParser {
    #[clap(subcommand)]
    pub commands: HimmelblauUnixOpt,
}
