/*
   Unix Azure Entra ID implementation
   Copyright (C) David Mulder <dmulder@samba.org> 2026

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

/// Lowest UID/GID systemd allocates to a `DynamicUser=yes` service.
pub const SYSTEMD_DYNAMIC_ID_MIN: u32 = 61184;
/// Highest UID/GID systemd allocates to a `DynamicUser=yes` service.
pub const SYSTEMD_DYNAMIC_ID_MAX: u32 = 65519;

/// True when `id` falls in systemd's dynamic user/group range.
///
/// nss-systemd synthesizes these identities at runtime, so they never appear
/// in /etc/passwd or /etc/group and are therefore invisible to the nxset
/// collision check the daemon builds from those two files. himmelblaud itself
/// runs as a dynamic user on any distribution whose systemd supports it, and
/// owns /run/himmelblaud (including the task socket) under that UID.
///
/// A directory identity handed an ID from this range shares a kernel identity
/// with the daemon: it can signal it, replace its task socket, and answer the
/// root task helper, which does not authenticate the server it connects to.
/// Reject such an ID before accepting or caching the identity.
/// See GHSA-6gp8-pp9v-gx45.
pub fn is_systemd_dynamic_id(id: u32) -> bool {
    (SYSTEMD_DYNAMIC_ID_MIN..=SYSTEMD_DYNAMIC_ID_MAX).contains(&id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_the_systemd_dynamic_range() {
        for id in [
            SYSTEMD_DYNAMIC_ID_MIN,
            SYSTEMD_DYNAMIC_ID_MIN + 1,
            63000,
            SYSTEMD_DYNAMIC_ID_MAX - 1,
            SYSTEMD_DYNAMIC_ID_MAX,
        ] {
            assert!(is_systemd_dynamic_id(id), "expected {} to be rejected", id);
        }
    }

    #[test]
    fn accepts_ids_outside_the_range() {
        for id in [
            0,
            1000,
            SYSTEMD_DYNAMIC_ID_MIN - 1,
            SYSTEMD_DYNAMIC_ID_MAX + 1,
            // nobody
            65534,
            // DEFAULT_IDMAP_RANGE start
            200000,
            u32::MAX,
        ] {
            assert!(!is_systemd_dynamic_id(id), "expected {} to be accepted", id);
        }
    }
}
