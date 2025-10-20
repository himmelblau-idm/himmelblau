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
use himmelblau_unix_common::constants::{DEFAULT_CONFIG_PATH, NSS_CACHE};
use himmelblau_unix_common::idprovider::interface::Id;
use himmelblau_unix_common::nss_cache::{Mode, NssCache};
use himmelblau_unix_common::unix_proto::{ClientRequest, ClientResponse, NssGroup, NssUser};
use himmelblau_unix_common::user_map::UserMap;
use libnss::group::{Group, GroupHooks};
use libnss::interop::Response;
use libnss::passwd::{Passwd, PasswdHooks};
use uuid::Uuid;

struct HimmelblauPasswd;
libnss_passwd_hooks!(himmelblau, HimmelblauPasswd);

macro_rules! try_nss_cache {
    () => {
        match NssCache::new(NSS_CACHE, &Mode::ReadWrite) {
            Ok(cache) => Some(cache),
            Err(_) => None,
        }
    };
}

macro_rules! fetch_cached_user {
    ($cache:expr, $cfg:ident, $id:expr, $ret:expr) => {{
        match $cache {
            Some(ref c) => match c.get_user(&$id) {
                Some(nu) => {
                    let mut passwd = passwd_from_nssuser(nu);
                    passwd.name = $cfg.map_upn_to_name(&passwd.name);
                    return Response::Success(passwd);
                }
                None => return $ret,
            },
            None => return $ret,
        }
    }};
}

macro_rules! insert_cached_user {
    ($cache:expr, $nu:ident) => {{
        if let Some(ref cache) = $cache {
            let _ = cache.insert_user(&$nu);
        }
    }};
}

macro_rules! fetch_all_cached_users {
    ($cache:expr, $cfg:ident) => {{
        match $cache {
            Some(ref c) => c
                .get_users()
                .into_iter()
                .map(|nu| {
                    let mut passwd = passwd_from_nssuser(nu);
                    passwd.name = $cfg.map_upn_to_name(&passwd.name);
                    passwd
                })
                .collect(),
            None => Vec::new(),
        }
    }};
}

impl PasswdHooks for HimmelblauPasswd {
    fn get_all_entries() -> Response<Vec<Passwd>> {
        let cfg = match HimmelblauConfig::new(Some(DEFAULT_CONFIG_PATH)) {
            Ok(c) => c,
            Err(_) => {
                return Response::Unavail;
            }
        };
        let req = ClientRequest::NssAccounts;

        let nss_cache = try_nss_cache!();

        let mut daemon_client = match DaemonClientBlocking::new(cfg.get_socket_path().as_str()) {
            Ok(dc) => dc,
            Err(_) => {
                return Response::Success(fetch_all_cached_users!(nss_cache, cfg));
            }
        };

        daemon_client
            .call_and_wait(&req, cfg.get_unix_sock_timeout())
            .map(|r| match r {
                ClientResponse::NssAccounts(l) => l
                    .into_iter()
                    .map(|nu| {
                        insert_cached_user!(nss_cache, nu);
                        let mut passwd = passwd_from_nssuser(nu);
                        passwd.name = cfg.map_upn_to_name(&passwd.name);
                        passwd
                    })
                    .collect(),
                _ => fetch_all_cached_users!(nss_cache, cfg),
            })
            .map(Response::Success)
            .unwrap_or_else(|_| Response::Success(fetch_all_cached_users!(nss_cache, cfg)))
    }

    fn get_entry_by_uid(uid: libc::uid_t) -> Response<Passwd> {
        let cfg = match HimmelblauConfig::new(Some(DEFAULT_CONFIG_PATH)) {
            Ok(c) => c,
            Err(_) => {
                return Response::Unavail;
            }
        };
        let req = ClientRequest::NssAccountByUid(uid);

        let nss_cache = try_nss_cache!();

        let mut daemon_client = match DaemonClientBlocking::new(cfg.get_socket_path().as_str()) {
            Ok(dc) => dc,
            Err(_) => {
                fetch_cached_user!(nss_cache, cfg, Id::Gid(uid), Response::Unavail);
            }
        };

        daemon_client
            .call_and_wait(&req, cfg.get_unix_sock_timeout())
            .map(|r| match r {
                ClientResponse::NssAccount(opt) => opt
                    .map(|nu| {
                        insert_cached_user!(nss_cache, nu);
                        let mut passwd = passwd_from_nssuser(nu);
                        passwd.name = cfg.map_upn_to_name(&passwd.name);
                        Response::Success(passwd)
                    })
                    .unwrap_or_else(|| {
                        fetch_cached_user!(nss_cache, cfg, Id::Gid(uid), Response::NotFound)
                    }),
                _ => fetch_cached_user!(nss_cache, cfg, Id::Gid(uid), Response::NotFound),
            })
            .unwrap_or_else(|_| {
                fetch_cached_user!(nss_cache, cfg, Id::Gid(uid), Response::NotFound)
            })
    }

    fn get_entry_by_name(name: String) -> Response<Passwd> {
        let cfg = match HimmelblauConfig::new(Some(DEFAULT_CONFIG_PATH)) {
            Ok(c) => c,
            Err(_) => {
                return Response::Unavail;
            }
        };

        // Ignore request for mapped users (some other nss module handles this name)
        let user_map = UserMap::new(&cfg.get_user_map_file());
        if user_map.get_upn_from_local(&name).is_some() {
            return Response::NotFound;
        }

        let upn = cfg.map_name_to_upn(&name);
        let req = ClientRequest::NssAccountByName(upn.clone());

        let nss_cache = try_nss_cache!();

        let mut daemon_client = match DaemonClientBlocking::new(cfg.get_socket_path().as_str()) {
            Ok(dc) => dc,
            Err(_) => {
                fetch_cached_user!(nss_cache, cfg, Id::Name(upn), Response::Unavail);
            }
        };

        daemon_client
            .call_and_wait(&req, cfg.get_unix_sock_timeout())
            .map(|r| match r {
                ClientResponse::NssAccount(opt) => opt
                    .map(|nu| {
                        insert_cached_user!(nss_cache, nu);
                        let mut passwd = passwd_from_nssuser(nu);
                        passwd.name = cfg.map_upn_to_name(&passwd.name);
                        Response::Success(passwd)
                    })
                    .unwrap_or_else(|| {
                        fetch_cached_user!(
                            nss_cache,
                            cfg,
                            Id::Name(upn.clone()),
                            Response::NotFound
                        )
                    }),
                _ => fetch_cached_user!(nss_cache, cfg, Id::Name(upn.clone()), Response::NotFound),
            })
            .unwrap_or_else(|_| {
                fetch_cached_user!(nss_cache, cfg, Id::Name(upn), Response::NotFound)
            })
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
                ClientResponse::NssGroups(l) => l
                    .into_iter()
                    .map(|ng| {
                        let mut group = group_from_nssgroup(ng);
                        group.name = cfg.map_upn_to_name(&group.name);
                        group.members = group
                            .members
                            .into_iter()
                            .map(|member| cfg.map_upn_to_name(&member))
                            .collect();
                        group
                    })
                    .collect(),
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
                    .map(|ng| {
                        let mut group = group_from_nssgroup(ng);
                        group.name = cfg.map_upn_to_name(&group.name);
                        group.members = group
                            .members
                            .into_iter()
                            .map(|member| cfg.map_upn_to_name(&member))
                            .collect();
                        Response::Success(group)
                    })
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
        let upn = cfg.map_name_to_upn(&name);
        let mut daemon_client = match DaemonClientBlocking::new(cfg.get_socket_path().as_str()) {
            Ok(dc) => dc,
            Err(_) => {
                return Response::Unavail;
            }
        };

        // Attempt to respond to a request for the fake primary group name.
        match if upn.contains("@") {
            let req = ClientRequest::NssGroupByName(upn);
            daemon_client
                .call_and_wait(&req, cfg.get_unix_sock_timeout())
                .map(|r| match r {
                    ClientResponse::NssGroup(opt) => opt
                        .map(|ng| {
                            let mut group = group_from_nssgroup(ng);
                            group.name = cfg.map_upn_to_name(&group.name);
                            group.members = group
                                .members
                                .into_iter()
                                .map(|member| cfg.map_upn_to_name(&member))
                                .collect();
                            Response::Success(group)
                        })
                        .unwrap_or_else(|| Response::NotFound),
                    _ => Response::NotFound,
                })
                .unwrap_or_else(|_| Response::NotFound)
        } else {
            Response::NotFound
        } {
            Response::NotFound => {
                // If the mapped UPN name isn't found, then this is probably a
                // real Entra Id group, instead of a fake primary group.
                //
                // If this appears to be a GUID, we can respond to that request (but
                // we have to validate that GUID wasn't the Group name!).
                if Uuid::parse_str(&name).is_ok() {
                    let req = ClientRequest::NssGroupByName(name.clone());
                    daemon_client
                        .call_and_wait(&req, cfg.get_unix_sock_timeout())
                        .map(|r| match r {
                            ClientResponse::NssGroup(opt) => opt
                                .map(|ng| {
                                    let group = group_from_nssgroup(ng);
                                    // We can only respond if the request was not by name
                                    if name.to_lowercase() != group.name.to_lowercase() {
                                        Response::Success(group)
                                    } else {
                                        Response::NotFound
                                    }
                                })
                                .unwrap_or_else(|| Response::NotFound),
                            _ => Response::NotFound,
                        })
                        .unwrap_or_else(|_| Response::NotFound)
                } else {
                    // Never ever EVER respond to a group request by Entra Id group
                    // name. This is a SECURITY RISK! See CVE-2025-49012. Group
                    // names ARE NOT unique in Entra Id. Responding to this name
                    // request could expose SUDO and other privileged commands to
                    // an attacker. Admins should only ever specify group names in
                    // configuration via the Object Id GUID or the GID. Ignoring
                    // this request will still permit commands such as `ls`, etc
                    // to display the group name, while prohibiting dangerous
                    // behavior.
                    Response::NotFound
                }
            }
            other => other,
        }
    }
}

fn passwd_from_nssuser(nu: NssUser) -> Passwd {
    Passwd {
        name: nu.name,
        gecos: nu.gecos,
        passwd: "x".to_string(),
        uid: nu.uid,
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
