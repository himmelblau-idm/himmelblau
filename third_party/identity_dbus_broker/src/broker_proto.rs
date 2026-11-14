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

use serde::{Deserialize, Serialize};
use std::fmt;

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize)]
pub enum ClientRequest {
    acquireTokenInteractively(String, String, String),
    acquireTokenSilently(String, String, String),
    getAccounts(String, String, String),
    removeAccount(String, String, String),
    acquirePrtSsoCookie(String, String, String),
    generateSignedHttpRequest(String, String, String),
    cancelInteractiveFlow(String, String, String),
    getLinuxBrokerVersion(String, String, String),
}

impl ClientRequest {
    pub fn method_name(&self) -> &'static str {
        match self {
            ClientRequest::acquireTokenInteractively(..) => "acquireTokenInteractively",
            ClientRequest::acquireTokenSilently(..) => "acquireTokenSilently",
            ClientRequest::getAccounts(..) => "getAccounts",
            ClientRequest::removeAccount(..) => "removeAccount",
            ClientRequest::acquirePrtSsoCookie(..) => "acquirePrtSsoCookie",
            ClientRequest::generateSignedHttpRequest(..) => "generateSignedHttpRequest",
            ClientRequest::cancelInteractiveFlow(..) => "cancelInteractiveFlow",
            ClientRequest::getLinuxBrokerVersion(..) => "getLinuxBrokerVersion",
        }
    }

    pub fn correlation_id(&self) -> &str {
        match self {
            ClientRequest::acquireTokenInteractively(_, cid, _)
            | ClientRequest::acquireTokenSilently(_, cid, _)
            | ClientRequest::getAccounts(_, cid, _)
            | ClientRequest::removeAccount(_, cid, _)
            | ClientRequest::acquirePrtSsoCookie(_, cid, _)
            | ClientRequest::generateSignedHttpRequest(_, cid, _)
            | ClientRequest::cancelInteractiveFlow(_, cid, _)
            | ClientRequest::getLinuxBrokerVersion(_, cid, _) => cid,
        }
    }
}

impl fmt::Display for ClientRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}(correlation_id={})", self.method_name(), self.correlation_id())
    }
}
