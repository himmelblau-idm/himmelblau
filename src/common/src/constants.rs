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
use crate::config::IdAttr;
use crate::unix_config::HomeAttr;

pub const DEFAULT_CONFIG_PATH: &str = "/etc/himmelblau/himmelblau.conf";
pub const DEFAULT_SOCK_PATH: &str = "/var/run/himmelblaud/socket";
pub const DEFAULT_TASK_SOCK_PATH: &str = "/var/run/himmelblaud/task_sock";
pub const DEFAULT_BROKER_SOCK_PATH: &str = "/var/run/himmelblaud/broker_sock";
pub const DEFAULT_DB_PATH: &str = "/var/cache/himmelblaud/himmelblau.cache.db";
pub const MAPPED_NAME_CACHE: &str = "/var/cache/nss-himmelblau/mapping.cache.db";
pub const NSS_CACHE: &str = "/var/cache/nss-himmelblau/cache.db";
pub const SERVER_CONFIG_PATH: &str = "/var/cache/himmelblaud/himmelblau.conf";
pub const DEFAULT_HOME_PREFIX: &str = "/home/";
pub const DEFAULT_HOME_ATTR: HomeAttr = HomeAttr::Uuid;
pub const DEFAULT_HOME_ALIAS: Option<HomeAttr> = Some(HomeAttr::Spn);
pub const DEFAULT_USE_ETC_SKEL: bool = false;
pub const DEFAULT_SHELL: &str = "/bin/bash";
pub const DEFAULT_ODC_PROVIDER: &str = "odc.officeapps.live.com";
pub const DEFAULT_AUTHORITY_HOST: &str = "login.microsoftonline.com";
pub const DEFAULT_GRAPH: &str = "https://graph.microsoft.com";
pub const DEFAULT_APP_ID: &str = "b743a22d-6705-4147-8670-d92fa515ee2b";
pub const DRS_APP_ID: &str = "01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9";
pub const DEFAULT_CONN_TIMEOUT: u64 = 30;
pub const DEFAULT_CACHE_TIMEOUT: u64 = 300;
pub const DEFAULT_SELINUX: bool = true;
pub const DEFAULT_HSM_PIN_PATH: &str = "/var/lib/himmelblaud/hsm-pin";
pub const DEFAULT_HELLO_ENABLED: bool = true;
pub const DEFAULT_SFA_FALLBACK_ENABLED: bool = false;
pub const DEFAULT_ID_ATTR_MAP: IdAttr = IdAttr::Name;
pub const BROKER_APP_ID: &str = "29d9ed98-a469-4536-ade2-f981bc1d605e";
pub const BROKER_CLIENT_IDENT: &str = "38aa3b87-a06d-4817-b275-7a316988d93b";
pub const CN_NAME_MAPPING: bool = true;
pub const DEFAULT_HELLO_PIN_MIN_LEN: usize = 6;
pub const DEFAULT_CCACHE_DIR: &str = "/tmp/krb5cc_";
pub const EDGE_BROWSER_CLIENT_ID: &str = "d7b530a4-7680-4c23-a8bf-c52c121d2e87";
