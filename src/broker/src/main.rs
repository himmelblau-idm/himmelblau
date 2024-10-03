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
use himmelblau_unix_common::config::HimmelblauConfig;
use identity_dbus_broker::himmelblau_session_broker_serve;
use std::process::ExitCode;
use tracing::error;

#[tokio::main]
async fn main() -> ExitCode {
    // Read the configuration
    let cfg = match HimmelblauConfig::new(None) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to parse: {}", e);
            return ExitCode::FAILURE;
        }
    };

    let sock_path = cfg.get_broker_socket_path();
    let timeout = cfg.get_connection_timeout();

    match himmelblau_session_broker_serve(&sock_path, timeout).await {
        Ok(_) => return ExitCode::SUCCESS,
        Err(e) => {
            error!("Broker service failed: {}", e);
            return ExitCode::FAILURE;
        }
    }
}
