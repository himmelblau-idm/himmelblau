/*
   Unix Azure Entra ID implementation
   Copyright (C) David Mulder <dmulder@samba.org> 2025

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

#[macro_export]
macro_rules! auth_handle_mfa_resp {
    ($resp:ident, $on_fido:expr, $on_prompt:expr, $on_poll:expr) => {
        match $resp.mfa_method.as_str() {
            "FidoKey" => $on_fido,
            "AccessPass" | "PhoneAppOTP" | "OneWaySMS" | "ConsolidatedTelephony" => $on_prompt,
            _ => $on_poll,
        }
    };
}
