/*
   Himmelblaud

   ID-mapping library

   Copyright (C) David Mulder 2024

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
#![deny(warnings)]
#![warn(unused_extern_crates)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]
use std::collections::HashMap;
use std::fmt;
use std::io::Cursor;
use std::num::NonZeroU32;
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;

const MURMUR3_SEED: u32 = 0xdeadbeef;

#[derive(PartialEq, Eq)]
pub struct IdmapError(u32);

pub const IDMAP_SUCCESS: IdmapError = IdmapError(0);
pub const IDMAP_NOT_IMPLEMENTED: IdmapError = IdmapError(1);
pub const IDMAP_ERROR: IdmapError = IdmapError(2);
pub const IDMAP_OUT_OF_MEMORY: IdmapError = IdmapError(3);
pub const IDMAP_NO_DOMAIN: IdmapError = IdmapError(4);
pub const IDMAP_CONTEXT_INVALID: IdmapError = IdmapError(5);
pub const IDMAP_SID_INVALID: IdmapError = IdmapError(6);
pub const IDMAP_SID_UNKNOWN: IdmapError = IdmapError(7);
pub const IDMAP_NO_RANGE: IdmapError = IdmapError(8);
pub const IDMAP_BUILTIN_SID: IdmapError = IdmapError(9);
pub const IDMAP_OUT_OF_SLICES: IdmapError = IdmapError(10);
pub const IDMAP_COLLISION: IdmapError = IdmapError(11);
pub const IDMAP_EXTERNAL: IdmapError = IdmapError(12);
pub const IDMAP_NAME_UNKNOWN: IdmapError = IdmapError(13);
pub const IDMAP_NO_REVERSE: IdmapError = IdmapError(14);
pub const IDMAP_UTF8_ERROR: IdmapError = IdmapError(15);
pub const IDMAP_ERR_LAST: IdmapError = IdmapError(16);

impl fmt::Display for IdmapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let error_name = match *self {
            IDMAP_SUCCESS => "IDMAP_SUCCESS",
            IDMAP_NOT_IMPLEMENTED => "IDMAP_NOT_IMPLEMENTED",
            IDMAP_ERROR => "IDMAP_ERROR",
            IDMAP_OUT_OF_MEMORY => "IDMAP_OUT_OF_MEMORY",
            IDMAP_NO_DOMAIN => "IDMAP_NO_DOMAIN",
            IDMAP_CONTEXT_INVALID => "IDMAP_CONTEXT_INVALID",
            IDMAP_SID_INVALID => "IDMAP_SID_INVALID",
            IDMAP_SID_UNKNOWN => "IDMAP_SID_UNKNOWN",
            IDMAP_NO_RANGE => "IDMAP_NO_RANGE",
            IDMAP_BUILTIN_SID => "IDMAP_BUILTIN_SID",
            IDMAP_OUT_OF_SLICES => "IDMAP_OUT_OF_SLICES",
            IDMAP_COLLISION => "IDMAP_COLLISION",
            IDMAP_EXTERNAL => "IDMAP_EXTERNAL",
            IDMAP_NAME_UNKNOWN => "IDMAP_NAME_UNKNOWN",
            IDMAP_NO_REVERSE => "IDMAP_NO_REVERSE",
            IDMAP_UTF8_ERROR => "IDMAP_UTF8_ERROR",
            IDMAP_ERR_LAST => "IDMAP_ERR_LAST",
            _ => "UNKNOWN_ERROR",
        };
        write!(f, "IdmapError({})", error_name)
    }
}

impl fmt::Debug for IdmapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl std::error::Error for IdmapError {}

#[derive(Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub struct AadSid {
    sid_rev_num: u8,
    num_auths: i8,
    id_auth: u64, // Technically only 48 bits
    sub_auths: [u32; 15],
}

impl AadSid {
    pub fn from_sid_str(sid_str: &str) -> Result<Self, IdmapError> {
        let parts: Vec<&str> = sid_str.trim().split('-').collect();

        if parts.len() < 4 || !sid_str.starts_with("S-") {
            return Err(IDMAP_SID_INVALID);
        }

        let sid_rev_num = parts[1].parse::<u8>().map_err(|_| IDMAP_SID_INVALID)?;
        let id_auth = parts[2].parse::<u64>().map_err(|_| IDMAP_SID_INVALID)?;

        let sub_auths_iter = parts[3..]
            .iter()
            .map(|s| s.parse::<u32>().map_err(|_| IDMAP_SID_INVALID));

        let mut sub_auths = [0u32; 15];
        let mut count = 0;

        for (i, sub_auth) in sub_auths_iter.enumerate() {
            if i >= sub_auths.len() {
                return Err(IDMAP_SID_INVALID);
            }
            sub_auths[i] = sub_auth?;
            count += 1;
        }

        Ok(AadSid {
            sid_rev_num,
            num_auths: count as i8,
            id_auth,
            sub_auths,
        })
    }

    pub fn from_object_id(object_id: &Uuid) -> Result<Self, IdmapError> {
        let bytes_array = object_id.as_bytes();
        let s_bytes_array = [
            bytes_array[6],
            bytes_array[7],
            bytes_array[4],
            bytes_array[5],
        ];

        let mut sid = AadSid {
            sid_rev_num: 1,
            num_auths: 5,
            id_auth: 12,
            sub_auths: [0; 15],
        };

        sid.sub_auths[0] = 1;
        sid.sub_auths[1] = u32::from_be_bytes(
            bytes_array[0..4]
                .try_into()
                .map_err(|_| IDMAP_SID_INVALID)?,
        );
        sid.sub_auths[2] = u32::from_be_bytes(s_bytes_array);
        sid.sub_auths[3] = u32::from_le_bytes(
            bytes_array[8..12]
                .try_into()
                .map_err(|_| IDMAP_SID_INVALID)?,
        );
        sid.sub_auths[4] = u32::from_le_bytes(
            bytes_array[12..]
                .try_into()
                .map_err(|_| IDMAP_SID_INVALID)?,
        );

        Ok(sid)
    }

    pub fn rid(&self) -> Result<u32, IdmapError> {
        Ok(self.sub_auths[usize::try_from(self.num_auths).map_err(|_| IDMAP_SID_INVALID)? - 1])
    }
}

pub const DEFAULT_IDMAP_RANGE: (u32, u32) = (200000, 2000200000);

/// Default range for subordinate UIDs/GIDs used by container runtimes (podman, etc.)
/// Each user gets a 65536-ID slice from this range.
/// This range must not overlap with DEFAULT_IDMAP_RANGE (200000-2000200000).
pub const DEFAULT_SUBID_RANGE: (u32, u32) = (2100000000, 4200000000);

/// Number of subordinate IDs allocated per user (standard for container runtimes)
pub const SUBID_COUNT: u32 = 65536;

#[derive(Debug, Clone, Copy)]
struct DomainRange {
    min: u32,
    max: u32,
}

pub struct Idmap {
    ranges: HashMap<String, DomainRange>,
}

impl Idmap {
    pub fn new() -> Result<Idmap, IdmapError> {
        Ok(Idmap {
            ranges: HashMap::new(),
        })
    }

    pub fn add_gen_domain(
        &mut self,
        _domain_name: &str,
        tenant_id: &str,
        range: (u32, u32),
    ) -> Result<(), IdmapError> {
        if self.ranges.contains_key(tenant_id) {
            return Err(IDMAP_COLLISION);
        }

        for existing in self.ranges.values() {
            if ranges_collide(*existing, range) {
                return Err(IDMAP_COLLISION);
            }
        }

        self.ranges.insert(
            tenant_id.to_string(),
            DomainRange {
                min: range.0,
                max: range.1,
            },
        );
        Ok(())
    }

    pub fn gen_to_unix(&self, tenant_id: &str, input: &str) -> Result<u32, IdmapError> {
        let range = self.ranges.get(tenant_id).ok_or(IDMAP_NO_DOMAIN)?;
        let range_size = range.max.checked_sub(range.min).ok_or(IDMAP_NO_RANGE)?;
        let range_size = range_size.checked_add(1).ok_or(IDMAP_NO_RANGE)?;
        if range_size == 0 {
            return Err(IDMAP_NO_RANGE);
        }

        let input = normalize_for_hash(input);
        let hash = murmur3_32(&input)?;
        Ok(range.min + (hash % range_size))
    }

    pub fn object_id_to_unix_id(&self, tenant_id: &str, sid: &AadSid) -> Result<u32, IdmapError> {
        let rid = sid.rid()?;
        let range = self.ranges.get(tenant_id).ok_or(IDMAP_NO_RANGE)?;
        let (lo, hi) = (range.min, range.max);
        let uid_count = NonZeroU32::new(hi.saturating_sub(lo)).ok_or(IDMAP_NO_RANGE)?;
        Ok((rid % uid_count) + lo)
    }
}

/// Calculate the subordinate ID range start for a user based on their username.
/// Uses MurmurHash3 (same as gen_to_unix) to deterministically assign a 65536-ID slot.
///
/// # Arguments
/// * `username` - The user's name (will be lowercased for consistency)
/// * `subid_range` - The (min, max) range of subordinate IDs available
///
/// # Returns
/// The starting subordinate ID for this user's range
pub fn gen_subid_start(username: &str, subid_range: (u32, u32)) -> u32 {
    let (min_id, max_id) = subid_range;
    let range_size = max_id.saturating_sub(min_id);

    // Calculate number of available slots (each slot is SUBID_COUNT IDs)
    let num_slots = range_size / SUBID_COUNT;

    if num_slots == 0 {
        // Range is too small, just return min_id
        return min_id;
    }

    let input = username.to_lowercase();
    let hash = murmur3_32(&input).unwrap_or(0);

    // Map hash to a slot number and calculate the start ID
    let slot = hash % num_slots;
    min_id + (slot * SUBID_COUNT)
}

fn ranges_collide(existing: DomainRange, new: (u32, u32)) -> bool {
    // Check if ranges overlap in any way:
    // 1. new.min falls within existing range
    // 2. new.max falls within existing range
    // 3. new range completely contains existing range
    (new.0 >= existing.min && new.0 <= existing.max)
        || (new.1 >= existing.min && new.1 <= existing.max)
        || (new.0 <= existing.min && new.1 >= existing.max)
}

fn normalize_for_hash(input: &str) -> String {
    input.to_lowercase().nfkc().collect()
}

fn murmur3_32(input: &str) -> Result<u32, IdmapError> {
    murmur3::murmur3_32(&mut Cursor::new(input.as_bytes()), MURMUR3_SEED).map_err(|_| IDMAP_ERROR)
}

#[cfg(test)]
mod tests {
    use crate::{
        gen_subid_start, AadSid, Idmap, DEFAULT_IDMAP_RANGE, DEFAULT_SUBID_RANGE,
        IDMAP_BUILTIN_SID, IDMAP_COLLISION, IDMAP_CONTEXT_INVALID, IDMAP_ERROR, IDMAP_ERR_LAST,
        IDMAP_EXTERNAL, IDMAP_NAME_UNKNOWN, IDMAP_NOT_IMPLEMENTED, IDMAP_NO_DOMAIN, IDMAP_NO_RANGE,
        IDMAP_NO_REVERSE, IDMAP_OUT_OF_MEMORY, IDMAP_OUT_OF_SLICES, IDMAP_SID_INVALID,
        IDMAP_SID_UNKNOWN, IDMAP_SUCCESS, SUBID_COUNT,
    };
    use std::collections::HashMap;
    use uuid::Uuid;

    #[test]
    fn sssd_idmapping() -> Result<(), Box<dyn std::error::Error>> {
        let domain = "contoso.onmicrosoft.com";
        let tenant_id = "d7af6c1b-0497-40fe-9d17-07e6b0f8332e";
        let mut idmap = Idmap::new()?;

        idmap.add_gen_domain(domain, tenant_id, DEFAULT_IDMAP_RANGE)?;

        // Verify we always get the same mapping for various users
        let mut usermap: HashMap<String, u32> = HashMap::new();
        usermap.insert("tux@contoso.onmicrosoft.com".to_string(), 1912749799);
        usermap.insert("admin@contoso.onmicrosoft.com".to_string(), 297515919);
        usermap.insert("dave@contoso.onmicrosoft.com".to_string(), 132631922);
        usermap.insert("joe@contoso.onmicrosoft.com".to_string(), 361591965);
        usermap.insert("georg@contoso.onmicrosoft.com".to_string(), 866887005);

        for (username, expected_uid) in &usermap {
            let uid = idmap.gen_to_unix(tenant_id, username)?;
            assert_eq!(uid, *expected_uid, "Uid for {} did not match", username);
        }

        Ok(())
    }

    #[test]
    fn legacy_idmapping() -> Result<(), Box<dyn std::error::Error>> {
        let domain = "contoso.onmicrosoft.com";
        let tenant_id = "d7af6c1b-0497-40fe-9d17-07e6b0f8332e";
        let mut idmap = Idmap::new()?;

        // Test using the legacy default idmap range
        idmap.add_gen_domain(domain, tenant_id, (1000000, 6999999))?;

        // Verify we always get the same mapping for various users
        let mut usermap: HashMap<String, (u32, String)> = HashMap::new();
        usermap.insert(
            "tux@contoso.onmicrosoft.com".to_string(),
            (5627207, "cd4ebec9-434c-4bad-af7c-9c39a4127551".to_string()),
        );
        usermap.insert(
            "admin@contoso.onmicrosoft.com".to_string(),
            (5290834, "4210d86f-ce97-4aff-97f7-bd3789727903".to_string()),
        );
        usermap.insert(
            "dave@contoso.onmicrosoft.com".to_string(),
            (4845027, "97bfcfc4-fb12-445e-aaca-28c6b5375855".to_string()),
        );
        usermap.insert(
            "joe@contoso.onmicrosoft.com".to_string(),
            (3215932, "1e26150d-efe0-4551-b9d3-49ea287c80a7".to_string()),
        );
        usermap.insert(
            "georg@contoso.onmicrosoft.com".to_string(),
            (4966353, "8193af72-71e1-4689-a4ea-b9a05f2639c9".to_string()),
        );

        for (username, (expected_uid, object_id)) in &usermap {
            let object_uuid = Uuid::parse_str(object_id)?;
            let sid = AadSid::from_object_id(&object_uuid)?;
            let uid = idmap.object_id_to_unix_id(tenant_id, &sid)?;
            assert_eq!(uid, *expected_uid, "Uid for {} did not match", username);
        }

        Ok(())
    }

    #[test]
    fn sid_match_object_id() -> Result<(), Box<dyn std::error::Error>> {
        let object_id =
            AadSid::from_object_id(&Uuid::parse_str("e8b5ca15-cb55-4b86-9113-a616d7f84214")?)?;
        let sid = AadSid::from_sid_str("S-1-12-1-3904227861-1267125077-379982737-339933399")?;

        assert_eq!(object_id, sid, "Parsed object id did not match parsed sid!");
        assert_eq!(
            object_id.rid(),
            sid.rid(),
            "Parsed object id RID did not match parsed sid RID!"
        );

        Ok(())
    }

    #[test]
    fn subid_allocation() {
        // Test that subid allocation is deterministic
        let user1 = "tux@contoso.onmicrosoft.com";
        let user2 = "admin@contoso.onmicrosoft.com";

        let subid1_a = gen_subid_start(user1, DEFAULT_SUBID_RANGE);
        let subid1_b = gen_subid_start(user1, DEFAULT_SUBID_RANGE);
        let subid2 = gen_subid_start(user2, DEFAULT_SUBID_RANGE);

        // Same user should always get the same subid start
        assert_eq!(
            subid1_a, subid1_b,
            "Subid for same user should be deterministic"
        );

        // Different users should (very likely) get different subid starts
        // Note: There's a tiny chance of collision, but with the large range it's unlikely
        assert_ne!(
            subid1_a, subid2,
            "Different users should get different subid ranges"
        );

        // Subid should be within the configured range
        assert!(
            subid1_a >= DEFAULT_SUBID_RANGE.0,
            "Subid should be >= min range"
        );
        assert!(
            subid1_a + SUBID_COUNT <= DEFAULT_SUBID_RANGE.1,
            "Subid + count should be <= max range"
        );

        // Subid should be aligned to SUBID_COUNT boundary
        assert_eq!(
            (subid1_a - DEFAULT_SUBID_RANGE.0) % SUBID_COUNT,
            0,
            "Subid should be slot-aligned"
        );
    }

    #[test]
    fn subid_case_insensitive() {
        // Test that subid allocation is case-insensitive
        let user_lower = "tux@contoso.onmicrosoft.com";
        let user_upper = "TUX@CONTOSO.ONMICROSOFT.COM";
        let user_mixed = "Tux@Contoso.OnMicrosoft.Com";

        let subid_lower = gen_subid_start(user_lower, DEFAULT_SUBID_RANGE);
        let subid_upper = gen_subid_start(user_upper, DEFAULT_SUBID_RANGE);
        let subid_mixed = gen_subid_start(user_mixed, DEFAULT_SUBID_RANGE);

        assert_eq!(subid_lower, subid_upper, "Subid should be case-insensitive");
        assert_eq!(subid_lower, subid_mixed, "Subid should be case-insensitive");
    }

    #[test]
    fn subid_small_range() {
        // Test behavior with a range smaller than SUBID_COUNT
        let small_range = (100000, 100100);
        let subid = gen_subid_start("user@example.com", small_range);

        // Should return min_id when range is too small
        assert_eq!(subid, small_range.0, "Small range should return min_id");
    }

    #[test]
    fn gen_to_unix_parity_cases() -> Result<(), Box<dyn std::error::Error>> {
        let domain = "contoso.onmicrosoft.com";
        let tenant_id = "d7af6c1b-0497-40fe-9d17-07e6b0f8332e";
        let mut idmap = Idmap::new()?;

        idmap.add_gen_domain(domain, tenant_id, DEFAULT_IDMAP_RANGE)?;

        let cases = [
            ("", 233362409),
            ("TUX@CONTOSO.ONMICROSOFT.COM", 1912749799),
            ("Tux@Contoso.OnMicrosoft.Com", 1912749799),
            ("tux@contoso.onmicrosoft.com", 1912749799),
            ("user@example.com", 1608008066),
            ("Ａlice@contoso.onmicrosoft.com", 245350431),
            ("Alice@contoso.onmicrosoft.com", 245350431),
            ("é@example.com", 1844060247),
            ("e\u{301}@example.com", 1844060247),
        ];

        for (input, expected_uid) in cases {
            assert_eq!(
                idmap.gen_to_unix(tenant_id, input)?,
                expected_uid,
                "Uid for {input:?} did not match"
            );
        }

        Ok(())
    }

    #[test]
    fn gen_to_unix_range_and_domain_errors() -> Result<(), Box<dyn std::error::Error>> {
        let mut idmap = Idmap::new()?;

        idmap.add_gen_domain("domain-a", "tenant-a", (100, 100))?;
        assert_eq!(idmap.gen_to_unix("tenant-a", "anything")?, 100);
        assert_eq!(
            idmap.gen_to_unix("missing", "anything"),
            Err(IDMAP_NO_DOMAIN)
        );
        assert_eq!(
            idmap.add_gen_domain("domain-a", "tenant-a", (30, 40)),
            Err(IDMAP_COLLISION)
        );
        assert_eq!(
            idmap.add_gen_domain("domain-b", "tenant-b", (100, 110)),
            Err(IDMAP_COLLISION)
        );
        assert_eq!(
            idmap.gen_to_unix("tenant-b", "anything"),
            Err(IDMAP_NO_DOMAIN)
        );

        Ok(())
    }

    #[test]
    fn gen_to_unix_degenerate_ranges() -> Result<(), Box<dyn std::error::Error>> {
        for (range, expected) in [
            ((1000, 1000), Ok(1000)),
            ((1000, 1001), Ok(1001)),
            ((1000, 1002), Ok(1002)),
            ((2000, 1000), Err(IDMAP_NO_RANGE)),
        ] {
            let mut idmap = Idmap::new()?;
            idmap.add_gen_domain("domain", "tenant", range)?;
            assert_eq!(
                idmap.gen_to_unix("tenant", "x"),
                expected,
                "Mapping result for range {range:?} did not match"
            );
        }

        Ok(())
    }

    #[test]
    fn subid_parity_cases() {
        for (input, expected_start) in [
            ("", 3249566976),
            ("user@example.com", 3312284928),
            ("USER@EXAMPLE.COM", 3312284928),
            ("tux@contoso.onmicrosoft.com", 4151342336),
            ("admin@contoso.onmicrosoft.com", 3473962240),
        ] {
            assert_eq!(
                gen_subid_start(input, DEFAULT_SUBID_RANGE),
                expected_start,
                "Subid start for {input:?} did not match"
            );
        }

        for (range, expected_start) in [
            ((100000, 165536), 100000),
            ((100000, 165535), 100000),
            ((100000, 231072), 100000),
            ((2000, 1000), 2000),
        ] {
            assert_eq!(
                gen_subid_start("user@example.com", range),
                expected_start,
                "Subid start for range {range:?} did not match"
            );
        }
    }

    #[test]
    fn object_id_to_sid_parity_cases() -> Result<(), Box<dyn std::error::Error>> {
        let cases = [
            (
                "00000000-0000-0000-0000-000000000000",
                "S-1-12-1-0-0-0-0",
                0,
            ),
            (
                "ffffffff-ffff-ffff-ffff-ffffffffffff",
                "S-1-12-1-4294967295-4294967295-4294967295-4294967295",
                u32::MAX,
            ),
            (
                "4210d86f-ce97-4aff-97f7-bd3789727903",
                "S-1-12-1-1108400239-1258278551-935196567-58290825",
                58290825,
            ),
        ];

        for (object_id, sid_str, expected_rid) in cases {
            let object_sid = AadSid::from_object_id(&Uuid::parse_str(object_id)?)?;
            let parsed_sid = AadSid::from_sid_str(sid_str)?;

            assert_eq!(object_sid, parsed_sid);
            assert_eq!(object_sid.rid()?, expected_rid);
        }

        Ok(())
    }

    #[test]
    fn sid_parser_rejects_invalid_inputs() {
        for sid in [
            "",
            "s-1-12-1",
            " S-1-12-1",
            "S-1",
            "S-1-12",
            "S-1-12-",
            "S-1-12-1-",
            "S-1-12--1",
            "S-1-12--",
            "S-1-12-4294967296",
            "S-1-12-1-1-1-1-1-1-1-1-1-1-1-1-1-1-1-1",
        ] {
            assert_eq!(
                AadSid::from_sid_str(sid),
                Err(IDMAP_SID_INVALID),
                "{sid:?} should be rejected"
            );
        }
    }

    #[test]
    fn error_constants_are_stable() {
        assert_eq!(IDMAP_SUCCESS.0, 0);
        assert_eq!(IDMAP_NOT_IMPLEMENTED.0, 1);
        assert_eq!(IDMAP_ERROR.0, 2);
        assert_eq!(IDMAP_OUT_OF_MEMORY.0, 3);
        assert_eq!(IDMAP_NO_DOMAIN.0, 4);
        assert_eq!(IDMAP_CONTEXT_INVALID.0, 5);
        assert_eq!(IDMAP_SID_INVALID.0, 6);
        assert_eq!(IDMAP_SID_UNKNOWN.0, 7);
        assert_eq!(IDMAP_NO_RANGE.0, 8);
        assert_eq!(IDMAP_BUILTIN_SID.0, 9);
        assert_eq!(IDMAP_OUT_OF_SLICES.0, 10);
        assert_eq!(IDMAP_COLLISION.0, 11);
        assert_eq!(IDMAP_EXTERNAL.0, 12);
        assert_eq!(IDMAP_NAME_UNKNOWN.0, 13);
        assert_eq!(IDMAP_NO_REVERSE.0, 14);
        assert_eq!(IDMAP_ERR_LAST.0, 16);
        assert_eq!(format!("{IDMAP_NO_RANGE:?}"), "IdmapError(IDMAP_NO_RANGE)");
    }

    #[test]
    fn idmap_range_overlap_detection() -> Result<(), Box<dyn std::error::Error>> {
        // === 1. Non-overlapping ranges (should succeed) ===

        // 1.1: Adjacent ranges (touching boundaries) should be allowed
        let mut idmap = Idmap::new()?;
        idmap.add_gen_domain("domain-a", "tenant-a", (1000, 1999))?;
        idmap.add_gen_domain("domain-b", "tenant-b", (2000, 2999))?;
        idmap.add_gen_domain("domain-c", "tenant-c", (3000, 3999))?;

        // 1.2: Non-adjacent ranges with gaps should be allowed
        let mut idmap = Idmap::new()?;
        idmap.add_gen_domain("domain-a", "tenant-a", (1000, 1999))?;
        idmap.add_gen_domain("domain-b", "tenant-b", (5000, 5999))?;
        idmap.add_gen_domain("domain-c", "tenant-c", (10000, 19999))?;

        // 1.3: Single-ID ranges that don't overlap
        let mut idmap = Idmap::new()?;
        idmap.add_gen_domain("domain-a", "tenant-a", (100, 100))?;
        idmap.add_gen_domain("domain-b", "tenant-b", (101, 101))?;
        idmap.add_gen_domain("domain-c", "tenant-c", (200, 200))?;

        // 1.4: Real-world ranges (DEFAULT_IDMAP_RANGE vs DEFAULT_SUBID_RANGE)
        // These are the production ranges that must never overlap
        let mut idmap = Idmap::new()?;
        idmap.add_gen_domain("idmap", "tenant-idmap", DEFAULT_IDMAP_RANGE)?;
        idmap.add_gen_domain("subid", "tenant-subid", DEFAULT_SUBID_RANGE)?;

        // 1.5: Minimum and maximum u32 boundary ranges
        let mut idmap = Idmap::new()?;
        idmap.add_gen_domain("domain-min", "tenant-min", (0, 1000))?;
        idmap.add_gen_domain("domain-mid", "tenant-mid", (2000000000, 3000000000))?;
        idmap.add_gen_domain("domain-max", "tenant-max", (4000000000, u32::MAX))?;

        // === 2. Overlapping ranges (should fail with IDMAP_COLLISION) ===

        // 2.1: Complete overlap (new range entirely contains existing range)
        let mut idmap = Idmap::new()?;
        idmap.add_gen_domain("domain-a", "tenant-a", (1000, 2000))?;
        assert_eq!(
            idmap.add_gen_domain("domain-b", "tenant-b", (500, 2500)),
            Err(IDMAP_COLLISION),
            "New range completely containing existing range should be rejected"
        );

        // 2.2: Complete containment (new range entirely within existing range)
        let mut idmap = Idmap::new()?;
        idmap.add_gen_domain("domain-a", "tenant-a", (1000, 5000))?;
        assert_eq!(
            idmap.add_gen_domain("domain-b", "tenant-b", (2000, 3000)),
            Err(IDMAP_COLLISION),
            "New range completely within existing range should be rejected"
        );

        // 2.3: Exact duplicate range
        let mut idmap = Idmap::new()?;
        idmap.add_gen_domain("domain-a", "tenant-a", (1000, 2000))?;
        assert_eq!(
            idmap.add_gen_domain("domain-b", "tenant-b", (1000, 2000)),
            Err(IDMAP_COLLISION),
            "Exact duplicate range should be rejected"
        );

        // 2.4: Partial overlap at lower boundary (new.min overlaps)
        let mut idmap = Idmap::new()?;
        idmap.add_gen_domain("domain-a", "tenant-a", (1000, 2000))?;
        assert_eq!(
            idmap.add_gen_domain("domain-b", "tenant-b", (500, 1500)),
            Err(IDMAP_COLLISION),
            "New range overlapping at lower boundary should be rejected"
        );

        // 2.5: Partial overlap at upper boundary (new.max overlaps)
        let mut idmap = Idmap::new()?;
        idmap.add_gen_domain("domain-a", "tenant-a", (1000, 2000))?;
        assert_eq!(
            idmap.add_gen_domain("domain-b", "tenant-b", (1500, 2500)),
            Err(IDMAP_COLLISION),
            "New range overlapping at upper boundary should be rejected"
        );

        // 2.6: Single ID overlap at exact boundary (new.min == existing.max)
        let mut idmap = Idmap::new()?;
        idmap.add_gen_domain("domain-a", "tenant-a", (1000, 2000))?;
        assert_eq!(
            idmap.add_gen_domain("domain-b", "tenant-b", (2000, 3000)),
            Err(IDMAP_COLLISION),
            "New range starting at existing.max should be rejected (inclusive boundary)"
        );

        // 2.7: Single ID overlap at exact boundary (new.max == existing.min)
        let mut idmap = Idmap::new()?;
        idmap.add_gen_domain("domain-a", "tenant-a", (2000, 3000))?;
        assert_eq!(
            idmap.add_gen_domain("domain-b", "tenant-b", (1000, 2000)),
            Err(IDMAP_COLLISION),
            "New range ending at existing.min should be rejected (inclusive boundary)"
        );

        // 2.8: Multiple existing ranges, overlap with first
        let mut idmap = Idmap::new()?;
        idmap.add_gen_domain("domain-a", "tenant-a", (1000, 2000))?;
        idmap.add_gen_domain("domain-b", "tenant-b", (5000, 6000))?;
        idmap.add_gen_domain("domain-c", "tenant-c", (10000, 11000))?;
        assert_eq!(
            idmap.add_gen_domain("domain-d", "tenant-d", (1500, 1700)),
            Err(IDMAP_COLLISION),
            "Overlap with first of multiple ranges should be rejected"
        );

        // 2.9: Multiple existing ranges, overlap with middle
        let mut idmap = Idmap::new()?;
        idmap.add_gen_domain("domain-a", "tenant-a", (1000, 2000))?;
        idmap.add_gen_domain("domain-b", "tenant-b", (5000, 6000))?;
        idmap.add_gen_domain("domain-c", "tenant-c", (10000, 11000))?;
        assert_eq!(
            idmap.add_gen_domain("domain-d", "tenant-d", (5500, 5700)),
            Err(IDMAP_COLLISION),
            "Overlap with middle of multiple ranges should be rejected"
        );

        // 2.10: Multiple existing ranges, overlap with last
        let mut idmap = Idmap::new()?;
        idmap.add_gen_domain("domain-a", "tenant-a", (1000, 2000))?;
        idmap.add_gen_domain("domain-b", "tenant-b", (5000, 6000))?;
        idmap.add_gen_domain("domain-c", "tenant-c", (10000, 11000))?;
        assert_eq!(
            idmap.add_gen_domain("domain-d", "tenant-d", (10500, 10700)),
            Err(IDMAP_COLLISION),
            "Overlap with last of multiple ranges should be rejected"
        );

        // 2.11: New range spans multiple existing ranges
        let mut idmap = Idmap::new()?;
        idmap.add_gen_domain("domain-a", "tenant-a", (1000, 2000))?;
        idmap.add_gen_domain("domain-b", "tenant-b", (5000, 6000))?;
        idmap.add_gen_domain("domain-c", "tenant-c", (10000, 11000))?;
        assert_eq!(
            idmap.add_gen_domain("domain-d", "tenant-d", (500, 20000)),
            Err(IDMAP_COLLISION),
            "New range spanning multiple existing ranges should be rejected"
        );

        // 2.12: Single-ID ranges that overlap
        let mut idmap = Idmap::new()?;
        idmap.add_gen_domain("domain-a", "tenant-a", (100, 100))?;
        assert_eq!(
            idmap.add_gen_domain("domain-b", "tenant-b", (100, 100)),
            Err(IDMAP_COLLISION),
            "Duplicate single-ID ranges should be rejected"
        );

        // 2.13: Single-ID range overlapping with multi-ID range
        let mut idmap = Idmap::new()?;
        idmap.add_gen_domain("domain-a", "tenant-a", (1000, 2000))?;
        assert_eq!(
            idmap.add_gen_domain("domain-b", "tenant-b", (1500, 1500)),
            Err(IDMAP_COLLISION),
            "Single-ID range within existing range should be rejected"
        );

        // 2.14: Verify DEFAULT_IDMAP_RANGE and DEFAULT_SUBID_RANGE don't overlap
        // This is a critical production constraint
        assert!(
            DEFAULT_IDMAP_RANGE.1 < DEFAULT_SUBID_RANGE.0,
            "Production ranges must not overlap: DEFAULT_IDMAP_RANGE ({:?}) vs DEFAULT_SUBID_RANGE ({:?})",
            DEFAULT_IDMAP_RANGE,
            DEFAULT_SUBID_RANGE
        );

        // === 3. Duplicate tenant_id (should fail with IDMAP_COLLISION) ===

        // 3.1: Same tenant_id with identical range
        let mut idmap = Idmap::new()?;
        idmap.add_gen_domain("domain-a", "tenant-same", (1000, 2000))?;
        assert_eq!(
            idmap.add_gen_domain("domain-b", "tenant-same", (1000, 2000)),
            Err(IDMAP_COLLISION),
            "Same tenant_id should be rejected even with identical range"
        );

        // 3.2: Same tenant_id with different non-overlapping range
        let mut idmap = Idmap::new()?;
        idmap.add_gen_domain("domain-a", "tenant-same", (1000, 2000))?;
        assert_eq!(
            idmap.add_gen_domain("domain-b", "tenant-same", (5000, 6000)),
            Err(IDMAP_COLLISION),
            "Same tenant_id should be rejected even with different range"
        );

        // === 4. Boundary value testing ===

        // 4.1: Zero-width range (min == max) should be allowed but shouldn't overlap
        let mut idmap = Idmap::new()?;
        idmap.add_gen_domain("domain-a", "tenant-a", (1000, 1000))?;
        idmap.add_gen_domain("domain-b", "tenant-b", (1001, 1001))?;
        assert_eq!(
            idmap.add_gen_domain("domain-c", "tenant-c", (1000, 1001)),
            Err(IDMAP_COLLISION),
            "Range overlapping zero-width range should be rejected"
        );

        // 4.2: Maximum u32 boundary overlap detection
        let mut idmap = Idmap::new()?;
        idmap.add_gen_domain("domain-a", "tenant-a", (u32::MAX - 1000, u32::MAX))?;
        assert_eq!(
            idmap.add_gen_domain("domain-b", "tenant-b", (u32::MAX - 500, u32::MAX)),
            Err(IDMAP_COLLISION),
            "Overlap at u32::MAX boundary should be rejected"
        );

        // 4.3: Minimum u32 boundary overlap detection
        let mut idmap = Idmap::new()?;
        idmap.add_gen_domain("domain-a", "tenant-a", (0, 1000))?;
        assert_eq!(
            idmap.add_gen_domain("domain-b", "tenant-b", (0, 500)),
            Err(IDMAP_COLLISION),
            "Overlap at u32::MIN (0) boundary should be rejected"
        );

        // 4.4: Full u32 range
        let mut idmap = Idmap::new()?;
        idmap.add_gen_domain("domain-a", "tenant-a", (0, u32::MAX))?;
        assert_eq!(
            idmap.add_gen_domain("domain-b", "tenant-b", (1000, 2000)),
            Err(IDMAP_COLLISION),
            "Any range should overlap with full u32 range"
        );

        // === 5. Off-by-one boundary testing ===

        // 5.1: Range ending just before another starts (should succeed)
        let mut idmap = Idmap::new()?;
        idmap.add_gen_domain("domain-a", "tenant-a", (1000, 1999))?;
        idmap.add_gen_domain("domain-b", "tenant-b", (2000, 2999))?;

        // 5.2: Range starting just after another ends (already tested above, but explicitly)
        let mut idmap = Idmap::new()?;
        idmap.add_gen_domain("domain-a", "tenant-a", (2000, 2999))?;
        idmap.add_gen_domain("domain-b", "tenant-b", (1000, 1999))?;

        // 5.3: One-ID gap between ranges (should succeed)
        let mut idmap = Idmap::new()?;
        idmap.add_gen_domain("domain-a", "tenant-a", (1000, 1999))?;
        idmap.add_gen_domain("domain-b", "tenant-b", (2001, 2999))?;

        // 5.4: Overlap by exactly one ID at upper boundary
        let mut idmap = Idmap::new()?;
        idmap.add_gen_domain("domain-a", "tenant-a", (1000, 2000))?;
        assert_eq!(
            idmap.add_gen_domain("domain-b", "tenant-b", (2000, 2001)),
            Err(IDMAP_COLLISION),
            "Single-ID overlap at boundary should be rejected"
        );

        // === 6. Stress testing with many ranges ===

        // 6.1: Many non-overlapping ranges in sequence
        let mut idmap = Idmap::new()?;
        for i in 0..100 {
            let base = i * 1000;
            idmap.add_gen_domain(
                &format!("domain-{i}"),
                &format!("tenant-{i}"),
                (base, base + 999),
            )?;
        }

        // 6.2: Attempt to add overlapping range to crowded idmap
        assert_eq!(
            idmap.add_gen_domain("overlap", "tenant-overlap", (50500, 50600)),
            Err(IDMAP_COLLISION),
            "Overlap detection should work with many existing ranges"
        );

        // 6.3: Add valid non-overlapping range to crowded idmap (in a gap)
        idmap.add_gen_domain("domain-gap", "tenant-gap", (500000, 600000))?;

        // === 7. Real-world scenario validation ===

        // 7.1: Simulate multiple Azure tenants (realistic scenario)
        let mut idmap = Idmap::new()?;
        let tenant_ranges = [
            (
                "contoso.onmicrosoft.com",
                "tenant-contoso",
                (200000, 1000000),
            ),
            (
                "fabrikam.onmicrosoft.com",
                "tenant-fabrikam",
                (1000001, 1800000),
            ),
            (
                "adventure-works.onmicrosoft.com",
                "tenant-adventure",
                (1800001, 2600000),
            ),
        ];

        for (domain, tenant, range) in tenant_ranges {
            idmap.add_gen_domain(domain, tenant, range)?;
        }

        // 7.2: Verify overlap detection still works
        assert_eq!(
            idmap.add_gen_domain("overlap-low", "tenant-low", (500000, 700000)),
            Err(IDMAP_COLLISION),
            "Overlap with first tenant should be rejected"
        );
        assert_eq!(
            idmap.add_gen_domain("overlap-mid", "tenant-mid", (1400000, 1900000)),
            Err(IDMAP_COLLISION),
            "Overlap spanning two tenants should be rejected"
        );

        Ok(())
    }
}
