/*
 * Unix Azure Entra ID implementation
 * Copyright (C) William Brown <william@blackhats.net.au> and the Kanidm team 2018-2024
 * Copyright (C) David Mulder <dmulder@samba.org> 2024
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
use himmelblau_unix_common::client_sync::DaemonClientBlocking;
use himmelblau_unix_common::config::HimmelblauConfig;
use himmelblau_unix_common::constants::DEFAULT_CONFIG_PATH;
use himmelblau_unix_common::unix_proto::{ClientRequest, ClientResponse, NssGroup, NssUser};
use kanidm_unix_common::unix_config::KanidmUnixdConfig;
use libnss::group::{Group, GroupHooks};
use libnss::interop::Response;
use libnss::passwd::{Passwd, PasswdHooks};

struct HimmelblauPasswd;
libnss_passwd_hooks!(himmelblau, HimmelblauPasswd);

impl PasswdHooks for HimmelblauPasswd {
    fn get_all_entries() -> Response<Vec<Passwd>> {
        let cfg = match HimmelblauConfig::new(Some(DEFAULT_CONFIG_PATH)) {
            Ok(c) => c,
            Err(_) => {
                return Response::Unavail;
            }
        };
        let req = ClientRequest::NssAccounts;

        let mut daemon_client = match DaemonClientBlocking::new(cfg.get_socket_path().as_str()) {
            Ok(dc) => dc,
            Err(_) => {
                return Response::Unavail;
            }
        };

        daemon_client
            .call_and_wait(&req, cfg.get_unix_sock_timeout())
            .map(|r| match r {
                ClientResponse::NssAccounts(l) => l.into_iter().map(passwd_from_nssuser).collect(),
                _ => Vec::new(),
            })
            .map(Response::Success)
            .unwrap_or_else(|_| Response::Success(vec![]))
    }

    fn get_entry_by_uid(uid: libc::uid_t) -> Response<Passwd> {
        let cfg = match HimmelblauConfig::new(Some(DEFAULT_CONFIG_PATH)) {
            Ok(c) => c,
            Err(_) => {
                return Response::Unavail;
            }
        };
        let req = ClientRequest::NssAccountByUid(uid);

        let mut daemon_client = match DaemonClientBlocking::new(cfg.get_socket_path().as_str()) {
            Ok(dc) => dc,
            Err(_) => {
                return Response::Unavail;
            }
        };

        daemon_client
            .call_and_wait(&req, cfg.get_unix_sock_timeout())
            .map(|r| match r {
                ClientResponse::NssAccount(opt) => opt
                    .map(passwd_from_nssuser)
                    .map(Response::Success)
                    .unwrap_or_else(|| Response::NotFound),
                _ => Response::NotFound,
            })
            .unwrap_or_else(|_| Response::NotFound)
    }

    fn get_entry_by_name(name: String) -> Response<Passwd> {
        let cfg = match HimmelblauConfig::new(Some(DEFAULT_CONFIG_PATH)) {
            Ok(c) => c,
            Err(_) => {
                return Response::Unavail;
            }
        };
        let name = cfg.map_cn_name(&name);
        let req = ClientRequest::NssAccountByName(name.clone());
        let mut daemon_client = match DaemonClientBlocking::new(cfg.get_socket_path().as_str()) {
            Ok(dc) => dc,
            Err(_) => {
                return Response::Unavail;
            }
        };

        daemon_client
            .call_and_wait(&req, cfg.get_unix_sock_timeout())
            .map(|r| match r {
                ClientResponse::NssAccount(opt) => opt
                    .map(|nu| {
                        let mut passwd = passwd_from_nssuser(nu);
                        passwd.name = name;
                        Response::Success(passwd)
                    })
                    .unwrap_or_else(|| Response::NotFound),
                _ => Response::NotFound,
            })
            .unwrap_or_else(|_| Response::NotFound)
    }
}

struct HimmelblauGroup;
libnss_group_hooks!(himmelblau, HimmelblauGroup);

impl GroupHooks for HimmelblauGroup {
    fn get_all_entries() -> Response<Vec<Group>> {
        let cfg = match HimmelblauConfig::new(Some(DEFAULT_CONFIG_PATH)) {
            Ok(c) => c,
            Err(_) => {
                return Response::Unavail;
            }
        };
        let req = ClientRequest::NssGroups;
        let mut daemon_client = match DaemonClientBlocking::new(cfg.get_socket_path().as_str()) {
            Ok(dc) => dc,
            Err(_) => {
                return Response::Unavail;
            }
        };

        daemon_client
            .call_and_wait(&req, cfg.get_unix_sock_timeout())
            .map(|r| match r {
                ClientResponse::NssGroups(l) => l.into_iter().map(group_from_nssgroup).collect(),
                _ => Vec::new(),
            })
            .map(Response::Success)
            .unwrap_or_else(|_| Response::Success(vec![]))
    }

    fn get_entry_by_gid(gid: libc::gid_t) -> Response<Group> {
        let cfg = match HimmelblauConfig::new(Some(DEFAULT_CONFIG_PATH)) {
            Ok(c) => c,
            Err(_) => {
                return Response::Unavail;
            }
        };
        let req = ClientRequest::NssGroupByGid(gid);
        let mut daemon_client = match DaemonClientBlocking::new(cfg.get_socket_path().as_str()) {
            Ok(dc) => dc,
            Err(_) => {
                return Response::Unavail;
            }
        };

        daemon_client
            .call_and_wait(&req, cfg.get_unix_sock_timeout())
            .map(|r| match r {
                ClientResponse::NssGroup(opt) => opt
                    .map(group_from_nssgroup)
                    .map(Response::Success)
                    .unwrap_or_else(|| Response::NotFound),
                _ => Response::NotFound,
            })
            .unwrap_or_else(|_| Response::NotFound)
    }

    fn get_entry_by_name(name: String) -> Response<Group> {
        let cfg = match HimmelblauConfig::new(Some(DEFAULT_CONFIG_PATH)) {
            Ok(c) => c,
            Err(_) => {
                return Response::Unavail;
            }
        };
        let req = ClientRequest::NssGroupByName(name);
        let mut daemon_client = match DaemonClientBlocking::new(cfg.get_socket_path().as_str()) {
            Ok(dc) => dc,
            Err(_) => {
                return Response::Unavail;
            }
        };

        daemon_client
            .call_and_wait(&req, cfg.get_unix_sock_timeout())
            .map(|r| match r {
                ClientResponse::NssGroup(opt) => opt
                    .map(group_from_nssgroup)
                    .map(Response::Success)
                    .unwrap_or_else(|| Response::NotFound),
                _ => Response::NotFound,
            })
            .unwrap_or_else(|_| Response::NotFound)
    }
}

fn passwd_from_nssuser(nu: NssUser) -> Passwd {
    Passwd {
        name: nu.name,
        gecos: nu.gecos,
        passwd: "x".to_string(),
        uid: nu.gid,
        gid: nu.gid,
        dir: nu.homedir,
        shell: nu.shell,
    }
}

fn group_from_nssgroup(ng: NssGroup) -> Group {
    Group {
        name: ng.name,
        passwd: "x".to_string(),
        gid: ng.gid,
        members: ng.members,
    }
}
