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
#[clap(about = "Idmapping Utility")]
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
#[clap(about = "Himmelblau Management Utility")]
pub enum HimmelblauUnixOpt {
    /// Test authentication of a user via the unixd resolver "pam" channel. This does not
    /// test that your pam configuration is correct - only that unixd is correctly processing
    /// and validating authentications.
    AuthTest {
        #[clap(short, long)]
        debug: bool,
        #[clap(short = 'D', long = "name")]
        account_id: String,
    },
    /// Erase the content of the unixd resolver cache. You should probably use `invalidate`
    /// instead.
    CacheClear {
        #[clap(short, long)]
        debug: bool,
        #[clap(long)]
        really: bool,
    },
    /// Invalidate, but don't erase the content of the unixd resolver cache. This will force
    /// the unixd daemon to refresh all user and group content immediately. If the connection
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
    /// The `--client-id` parameter is required and must refer to a registered
    /// Entra ID application with `User.Read.All` permissions.
    ///
    /// The `--name` specifies the Entra ID user on whose behalf the token
    /// is requested, enabling delegated access through the specified client application.
    ///
    /// This command can only be executed from an Entra Id enrolled host.
    Enumerate {
        #[clap(short, long)]
        debug: bool,
        #[clap(short = 'D', long = "name")]
        account_id: String,
        #[clap(long = "client-id")]
        client_id: String,
    },
    /// Manage the static idmapping cache used to map Entra ID accounts to static UID/GID values.
    /// This is useful for migrations from on-prem AD to Entra ID, where existing UID/GID mappings
    /// need to be preserved.
    #[clap(subcommand)]
    Idmap(IdmapOpt),
    /// Check that the unixd daemon is online and able to connect correctly to the himmelblaud server.
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
