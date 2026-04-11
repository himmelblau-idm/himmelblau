/*
 * Unix Azure Entra ID implementation
 * Copyright (C) William Brown <william@blackhats.net.au> and the Kanidm team 2018-2024
 * Copyright (C) David Mulder <dmulder@samba.org> 2024
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
use himmelblau_unix_common::client_sync::{should_skip_daemon_call, DaemonClientBlocking};
use himmelblau_unix_common::config::HimmelblauConfig;
use himmelblau_unix_common::constants::{DEFAULT_CONFIG_PATH, NSS_CACHE};
use himmelblau_unix_common::idprovider::interface::Id;
use himmelblau_unix_common::nss_cache::{Mode, NssCache};
use himmelblau_unix_common::unix_passwd::parse_etc_group;
use himmelblau_unix_common::unix_proto::{ClientRequest, ClientResponse, NssGroup, NssUser};
use himmelblau_unix_common::user_map::UserMap;
use libnss::group::{Group, GroupHooks};
use libnss::interop::Response;
use libnss::passwd::{Passwd, PasswdHooks};
use std::fs::File;
use std::io::Read;
use uuid::Uuid;

struct HimmelblauPasswd;
libnss_passwd_hooks!(himmelblau, HimmelblauPasswd);

fn is_local_group(name: &str) -> bool {
    let contents = read_etc_group();
    is_group_name_in_groups(name, &contents)
}

fn is_group_name_in_groups(name: &str, group_contents: &[u8]) -> bool {
    parse_etc_group(group_contents)
        .unwrap_or_default()
        .iter()
        .any(|g| g.name == name)
}

fn read_etc_group() -> Vec<u8> {
    let mut contents = vec![];
    if let Ok(mut file) = File::open("/etc/group") {
        let _ = file.read_to_end(&mut contents);
    }
    contents
}

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
                    if $user_map
                        .get_local_from_upn(&nu.name.to_lowercase())
                        .is_some()
                    {
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
        if should_skip_daemon_call() {
            return Response::Unavail;
        }
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
                        if user_map
                            .get_local_from_upn(&nu.name.to_lowercase())
                            .is_some()
                        {
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
            .unwrap_or_else(|_| {
                Response::Success(fetch_all_cached_users!(nss_cache, cfg, user_map))
            })
    }

    fn get_entry_by_uid(uid: libc::uid_t) -> Response<Passwd> {
        if should_skip_daemon_call() {
            return Response::Unavail;
        }
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
        if should_skip_daemon_call() {
            return Response::Unavail;
        }
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
        if should_skip_daemon_call() {
            return Response::Unavail;
        }
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
        if should_skip_daemon_call() {
            return Response::Unavail;
        }
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
        if should_skip_daemon_call() {
            return Response::Unavail;
        }
        let cfg = match HimmelblauConfig::new(Some(DEFAULT_CONFIG_PATH)) {
            Ok(c) => c,
            Err(_) => {
                return Response::Unavail;
            }
        };
        // Don't let fake primary groups shadow local groups
        if is_local_group(&cfg.map_upn_to_name(&name)) {
            return Response::NotFound;
        }
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

/// Implement the glibc "initgroups_dyn" NSS interface.
///
/// When glibc needs the supplementary groups for a user (e.g. via
/// initgroups()), it prefers calling _nss_MODULE_initgroups_dyn() if
/// the module exports it. Otherwise it falls back to enumerating all
/// groups via getgrent_r(), which can be very slow for Entra ID users
/// who may belong to hundreds of groups.
///
/// This function sends a single targeted "NssInitgroups" request to the
/// daemon and populates the GID array directly.
///
/// # Safety
///
/// Called by glibc's NSS machinery. All pointer arguments must be valid
/// and writable. The "groupsp" array may be realloc'd.
#[no_mangle]
pub unsafe extern "C" fn _nss_himmelblau_initgroups_dyn(
    user: *const libc::c_char,
    primary_gid: libc::gid_t,
    start: *mut libc::c_long,
    size: *mut libc::c_long,
    groupsp: *mut *mut libc::gid_t,
    limit: libc::c_long,
    errnop: *mut libc::c_int,
) -> libc::c_int {
    // NSS status codes (from <nss.h>)
    const NSS_STATUS_SUCCESS: libc::c_int = 1;
    const NSS_STATUS_NOTFOUND: libc::c_int = 0;
    const NSS_STATUS_UNAVAIL: libc::c_int = -1;
    const NSS_STATUS_TRYAGAIN: libc::c_int = -2;

    // Validate all pointer arguments before any dereference.
    if user.is_null()
        || start.is_null()
        || size.is_null()
        || groupsp.is_null()
        || errnop.is_null()
    {
        return NSS_STATUS_UNAVAIL;
    }

    if should_skip_daemon_call() {
        return NSS_STATUS_UNAVAIL;
    }

    let c_user = match std::ffi::CStr::from_ptr(user).to_str() {
        Ok(s) => s,
        Err(_) => {
            *errnop = libc::EINVAL;
            return NSS_STATUS_UNAVAIL;
        }
    };

    let cfg = match HimmelblauConfig::new(Some(DEFAULT_CONFIG_PATH)) {
        Ok(c) => c,
        Err(_) => return NSS_STATUS_UNAVAIL,
    };

    let user_map = UserMap::new(&cfg.get_user_map_file());
    let account_id = match user_map.get_upn_from_local(c_user) {
        Some(upn) => upn,
        None => cfg.map_name_to_upn(c_user),
    };
    let req = ClientRequest::NssInitgroups(account_id);

    let mut daemon_client = match DaemonClientBlocking::new(cfg.get_socket_path().as_str()) {
        Ok(dc) => dc,
        Err(_) => return NSS_STATUS_UNAVAIL,
    };

    let gids = match daemon_client.call_and_wait(&req, cfg.get_unix_sock_timeout()) {
        Ok(ClientResponse::NssInitgroups(Some(g))) => g,
        // User not found in himmelblau: let glibc try the next
        // nsswitch source so that local groups are preserved.
        Ok(ClientResponse::NssInitgroups(None)) => return NSS_STATUS_NOTFOUND,
        Ok(_) | Err(_) => return NSS_STATUS_UNAVAIL,
    };

    let mut cur_start = *start;
    let mut cur_size = *size;
    let mut groups = *groupsp;
    if cur_start < 0 || cur_size < 0 || cur_start > cur_size || (cur_size > 0 && groups.is_null())
    {
        *errnop = libc::EINVAL;
        return NSS_STATUS_UNAVAIL;
    }

    for gid in gids {
        // Skip primary GID, glibc already includes it
        if gid == primary_gid {
            continue;
        }
        // Skip duplicates already in the array
        let already_present = (0..cur_start).any(|i| *groups.offset(i as isize) == gid);
        if already_present {
            continue;
        }
        // Hard cap reached, stop adding, don't signal an error, like
        // glibc's add_group() does.
        if limit > 0 && cur_start >= limit {
            break;
        }
        // Grow the array if needed
        if cur_start >= cur_size {
            let new_size = if limit > 0 {
                std::cmp::min(limit, std::cmp::max(16, cur_size.saturating_mul(2)))
            } else {
                std::cmp::max(16, cur_size.saturating_mul(2))
            };
            let alloc_bytes = match usize::try_from(new_size)
                .ok()
                .and_then(|n| n.checked_mul(std::mem::size_of::<libc::gid_t>()))
            {
                Some(b) if b > 0 => b,
                _ => {
                    *errnop = libc::ENOMEM;
                    *start = cur_start;
                    return NSS_STATUS_TRYAGAIN;
                }
            };
            let new_groups = libc::realloc(
                groups as *mut libc::c_void,
                alloc_bytes,
            ) as *mut libc::gid_t;
            if new_groups.is_null() {
                *errnop = libc::ENOMEM;
                *start = cur_start;
                return NSS_STATUS_TRYAGAIN;
            }
            groups = new_groups;
            *groupsp = groups;
            cur_size = new_size;
            *size = cur_size;
        }
        *groups.offset(cur_start as isize) = gid;
        cur_start += 1;
    }

    *start = cur_start;
    NSS_STATUS_SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn create_temp_config(contents: &str) -> String {
        let file_path = format!(
            "/tmp/himmelblau_nss_test_config_{}.ini",
            uuid::Uuid::new_v4()
        );
        fs::write(&file_path, contents).expect("Failed to write temporary config file");
        file_path
    }

    fn test_config() -> HimmelblauConfig {
        let config_data = r#"
            [global]
            domains = contoso.com,fabrikam.com
            cn_name_mapping = true
        "#;

        let temp_file = create_temp_config(config_data);
        HimmelblauConfig::new(Some(&temp_file)).expect("Failed to create test config")
    }

    #[test]
    fn blocks_short_group_name_collision() {
        let cfg = test_config();
        let groups = b"root:x:0:\nsudo:x:27:\nwheel:x:10:\n";

        assert!(is_group_name_in_groups(
            &cfg.map_upn_to_name("sudo"),
            groups
        ));
    }

    #[test]
    fn blocks_primary_domain_upn_group_collision() {
        let cfg = test_config();
        let groups = b"root:x:0:\nsudo:x:27:\nwheel:x:10:\n";

        assert!(is_group_name_in_groups(
            &cfg.map_upn_to_name("sudo@contoso.com"),
            groups
        ));
    }

    #[test]
    fn allows_non_primary_domain_upn_lookup() {
        let cfg = test_config();
        let groups = b"root:x:0:\nsudo:x:27:\nwheel:x:10:\n";

        assert!(!is_group_name_in_groups(
            &cfg.map_upn_to_name("sudo@fabrikam.com"),
            groups
        ));
    }

    #[test]
    fn allows_non_colliding_group_name() {
        let cfg = test_config();
        let groups = b"root:x:0:\nsudo:x:27:\nwheel:x:10:\n";

        assert!(!is_group_name_in_groups(
            &cfg.map_upn_to_name("engineering"),
            groups
        ));
    }
}
