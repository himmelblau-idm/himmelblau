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
