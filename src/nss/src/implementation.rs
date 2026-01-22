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
        fetch_cached_user!($cache, $cfg, $id, $ret, None::<String>)
    }};
    ($cache:expr, $cfg:ident, $id:expr, $ret:expr, $local_name:expr) => {{
        match $cache {
            Some(ref c) => match c.get_user(&$id) {
                Some(nu) => {
                    let mut passwd = passwd_from_nssuser(nu);
                    // Use local_name override if provided, otherwise use cn_name_mapping
                    passwd.name = $local_name.unwrap_or_else(|| $cfg.map_upn_to_name(&passwd.name));
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
    ($cache:expr, $cfg:ident, $user_map:expr) => {{
        match $cache {
            Some(ref c) => c
                .get_users()
                .into_iter()
                .filter_map(|nu| {
                    // Skip users whose UPN is mapped to a local user
                    if $user_map.get_local_from_upn(&nu.name.to_lowercase()).is_some() {
                        return None;
                    }
                    let mut passwd = passwd_from_nssuser(nu);
                    passwd.name = $cfg.map_upn_to_name(&passwd.name);
                    Some(passwd)
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

        // Load user map to filter out mapped users (they are handled by local NSS)
        let user_map = UserMap::new(&cfg.get_user_map_file());

        let mut daemon_client = match DaemonClientBlocking::new(cfg.get_socket_path().as_str()) {
            Ok(dc) => dc,
            Err(_) => {
                return Response::Success(fetch_all_cached_users!(nss_cache, cfg, user_map));
            }
        };

        daemon_client
            .call_and_wait(&req, cfg.get_unix_sock_timeout())
            .map(|r| match r {
                ClientResponse::NssAccounts(l) => l
                    .into_iter()
                    .filter_map(|nu| {
                        // Skip users whose UPN is mapped to a local user
                        // (the local NSS module handles these)
                        if user_map.get_local_from_upn(&nu.name.to_lowercase()).is_some() {
                            return None;
                        }
                        insert_cached_user!(nss_cache, nu);
                        let mut passwd = passwd_from_nssuser(nu);
                        passwd.name = cfg.map_upn_to_name(&passwd.name);
                        Some(passwd)
                    })
                    .collect(),
                _ => fetch_all_cached_users!(nss_cache, cfg, user_map),
            })
            .map(Response::Success)
            .unwrap_or_else(|_| Response::Success(fetch_all_cached_users!(nss_cache, cfg, user_map)))
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

        // Check if this is a mapped local user or a UPN mapped to a local user.
        // We still need to handle these lookups (not return NotFound), but we
        // need to look up the UPN and return the result with the local name.
        let user_map = UserMap::new(&cfg.get_user_map_file());
        let (upn, local_name) = if let Some(mapped_upn) = user_map.get_upn_from_local(&name) {
            // Local name is mapped to a UPN - look up the UPN
            (mapped_upn, Some(name.clone()))
        } else if let Some(local) = user_map.get_local_from_upn(&name.to_lowercase()) {
            // UPN is mapped to a local name - look up the UPN, return as local name
            (name.to_lowercase(), Some(local))
        } else {
            // No mapping - use standard cn_name_mapping
            (cfg.map_name_to_upn(&name), None)
        };

        let req = ClientRequest::NssAccountByName(upn.clone());

        let nss_cache = try_nss_cache!();

        let mut daemon_client = match DaemonClientBlocking::new(cfg.get_socket_path().as_str()) {
            Ok(dc) => dc,
            Err(_) => {
                fetch_cached_user!(nss_cache, cfg, Id::Name(upn), Response::Unavail, local_name);
            }
        };

        daemon_client
            .call_and_wait(&req, cfg.get_unix_sock_timeout())
            .map(|r| match r {
                ClientResponse::NssAccount(opt) => opt
                    .map(|nu| {
                        insert_cached_user!(nss_cache, nu);
                        let mut passwd = passwd_from_nssuser(nu);
                        // Use the local name from user_map if present, otherwise use cn_name_mapping
                        passwd.name = local_name
                            .clone()
                            .unwrap_or_else(|| cfg.map_upn_to_name(&passwd.name));
                        Response::Success(passwd)
                    })
                    .unwrap_or_else(|| {
                        fetch_cached_user!(
                            nss_cache,
                            cfg,
                            Id::Name(upn.clone()),
                            Response::NotFound,
                            local_name.clone()
                        )
                    }),
                _ => fetch_cached_user!(
                    nss_cache,
                    cfg,
                    Id::Name(upn.clone()),
                    Response::NotFound,
                    local_name.clone()
                ),
            })
            .unwrap_or_else(|_| {
                fetch_cached_user!(
                    nss_cache,
                    cfg,
                    Id::Name(upn),
                    Response::NotFound,
                    local_name
                )
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
