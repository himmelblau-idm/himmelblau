/*
   Unix Azure Entra ID implementation
   Copyright (C) David Mulder <dmulder@samba.org> 2024

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program. If not, see <https://www.gnu.org/licenses/>.
*/
use std::future::pending;
use zbus::{connection, interface, Result};

pub struct Broker;

#[interface(name = "com.microsoft.identity.broker1")]
impl Broker {
    #[zbus(name = "getAccounts")]
    fn get_accounts(&mut self, num: &str, session_id: &str, context: &str) -> String {
        "[]".to_string()
    }

    #[zbus(name = "acquirePrtSsoCookie")]
    fn acquire_prt_sso_cookie(&mut self, num: &str, session_id: &str, request: &str) -> String {
        "{}".to_string()
    }

    #[zbus(name = "acquireTokenSilently")]
    fn acquire_token_silently(&mut self, num: &str, session_id: &str, request: &str) -> String {
        "{}".to_string()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let _conn = connection::Builder::session()?
        .name("com.microsoft.identity.broker1")?
        .serve_at("/com/microsoft/identity/broker1", Broker)?
        .build()
        .await?;
    pending::<()>().await;
    Ok(())
}
