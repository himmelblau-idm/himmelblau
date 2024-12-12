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
use std::ffi::CString;
use std::fmt;
use std::ptr;
use std::sync::RwLock;
use uuid::Uuid;

#[macro_use]
extern crate tracing;

mod ffi {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(dead_code)]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

#[derive(PartialEq, Eq)]
pub struct IdmapError(u32);

pub const IDMAP_SUCCESS: IdmapError = IdmapError(ffi::idmap_error_code_IDMAP_SUCCESS);
pub const IDMAP_NOT_IMPLEMENTED: IdmapError =
    IdmapError(ffi::idmap_error_code_IDMAP_NOT_IMPLEMENTED);
pub const IDMAP_ERROR: IdmapError = IdmapError(ffi::idmap_error_code_IDMAP_ERROR);
pub const IDMAP_OUT_OF_MEMORY: IdmapError = IdmapError(ffi::idmap_error_code_IDMAP_OUT_OF_MEMORY);
pub const IDMAP_NO_DOMAIN: IdmapError = IdmapError(ffi::idmap_error_code_IDMAP_NO_DOMAIN);
pub const IDMAP_CONTEXT_INVALID: IdmapError =
    IdmapError(ffi::idmap_error_code_IDMAP_CONTEXT_INVALID);
pub const IDMAP_SID_INVALID: IdmapError = IdmapError(ffi::idmap_error_code_IDMAP_SID_INVALID);
pub const IDMAP_SID_UNKNOWN: IdmapError = IdmapError(ffi::idmap_error_code_IDMAP_SID_UNKNOWN);
pub const IDMAP_NO_RANGE: IdmapError = IdmapError(ffi::idmap_error_code_IDMAP_NO_RANGE);
pub const IDMAP_BUILTIN_SID: IdmapError = IdmapError(ffi::idmap_error_code_IDMAP_BUILTIN_SID);
pub const IDMAP_OUT_OF_SLICES: IdmapError = IdmapError(ffi::idmap_error_code_IDMAP_OUT_OF_SLICES);
pub const IDMAP_COLLISION: IdmapError = IdmapError(ffi::idmap_error_code_IDMAP_COLLISION);
pub const IDMAP_EXTERNAL: IdmapError = IdmapError(ffi::idmap_error_code_IDMAP_EXTERNAL);
pub const IDMAP_NAME_UNKNOWN: IdmapError = IdmapError(ffi::idmap_error_code_IDMAP_NAME_UNKNOWN);
pub const IDMAP_NO_REVERSE: IdmapError = IdmapError(ffi::idmap_error_code_IDMAP_NO_REVERSE);
pub const IDMAP_ERR_LAST: IdmapError = IdmapError(ffi::idmap_error_code_IDMAP_ERR_LAST);

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

#[allow(dead_code)]
struct AadSid {
    sid_rev_num: u8,
    num_auths: i8,
    id_auth: u64, // Technically only 48 bits
    sub_auths: [u32; 15],
}

fn object_id_to_sid(object_id: &Uuid) -> Result<AadSid, IdmapError> {
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

fn rid_from_sid(sid: &AadSid) -> Result<u32, IdmapError> {
    Ok(sid.sub_auths[usize::try_from(sid.num_auths).map_err(|_| IDMAP_SID_INVALID)? - 1])
}

pub const DEFAULT_IDMAP_RANGE: (u32, u32) = (200000, 2000200000);

// The ctx is behind a read/write lock to make it 'safer' to Send/Sync.
// Granted, dereferencing a raw pointer is still inherently unsafe.
pub struct Idmap {
    ctx: RwLock<*mut ffi::sss_idmap_ctx>,
    ranges: HashMap<String, (u32, u32)>,
}

impl Idmap {
    pub fn new() -> Result<Idmap, IdmapError> {
        let mut ctx = ptr::null_mut();
        unsafe {
            match IdmapError(ffi::sss_idmap_init(None, ptr::null_mut(), None, &mut ctx)) {
                IDMAP_SUCCESS => Ok(Idmap {
                    ctx: RwLock::new(ctx),
                    ranges: HashMap::new(),
                }),
                e => Err(e),
            }
        }
    }

    pub fn add_gen_domain(
        &mut self,
        domain_name: &str,
        tenant_id: &str,
        range: (u32, u32),
    ) -> Result<(), IdmapError> {
        let ctx = self.ctx.write().map_err(|e| {
            error!("Failed obtaining write lock on sss_idmap_ctx: {}", e);
            IDMAP_ERROR
        })?;
        let domain_name_cstr = CString::new(domain_name).map_err(|_| IDMAP_OUT_OF_MEMORY)?;
        let tenant_id_cstr = CString::new(tenant_id).map_err(|_| IDMAP_OUT_OF_MEMORY)?;
        let mut idmap_range = ffi::sss_idmap_range {
            min: range.0,
            max: range.1,
        };
        self.ranges.insert(tenant_id.to_string(), range);
        unsafe {
            match IdmapError(ffi::sss_idmap_add_gen_domain_ex(
                *ctx,
                domain_name_cstr.as_ptr(),
                tenant_id_cstr.as_ptr(),
                &mut idmap_range,
                ptr::null_mut(),
                None,
                None,
                ptr::null_mut(),
                0,
                false,
            )) {
                IDMAP_SUCCESS => Ok(()),
                e => Err(e),
            }
        }
    }

    pub fn gen_to_unix(&self, tenant_id: &str, input: &str) -> Result<u32, IdmapError> {
        let ctx = self.ctx.write().map_err(|e| {
            error!("Failed obtaining write lock on sss_idmap_ctx: {}", e);
            IDMAP_ERROR
        })?;
        let tenant_id_cstr = CString::new(tenant_id).map_err(|_| IDMAP_OUT_OF_MEMORY)?;
        let input_cstr = CString::new(input.to_lowercase()).map_err(|_| IDMAP_OUT_OF_MEMORY)?;
        unsafe {
            let mut id: u32 = 0;
            match IdmapError(ffi::sss_idmap_gen_to_unix(
                *ctx,
                tenant_id_cstr.as_ptr(),
                input_cstr.as_ptr(),
                &mut id,
            )) {
                IDMAP_SUCCESS => Ok(id),
                e => Err(e),
            }
        }
    }

    pub fn object_id_to_unix_id(
        &self,
        tenant_id: &str,
        object_id: &Uuid,
    ) -> Result<u32, IdmapError> {
        let sid = object_id_to_sid(object_id)?;
        let rid = rid_from_sid(&sid)?;
        let idmap_range = match self.ranges.get(tenant_id) {
            Some(idmap_range) => idmap_range,
            None => return Err(IDMAP_NO_RANGE),
        };
        let uid_count = idmap_range.1 - idmap_range.0;
        Ok((rid % uid_count) + idmap_range.0)
    }
}

impl Drop for Idmap {
    fn drop(&mut self) {
        match self.ctx.write() {
            Ok(ctx) => unsafe {
                let _ = ffi::sss_idmap_free(*ctx);
            },
            Err(e) => {
                error!(
                    "Failed obtaining write lock on sss_idmap_ctx during drop: {}",
                    e
                );
            }
        }
    }
}

unsafe impl Send for Idmap {}
unsafe impl Sync for Idmap {}

#[cfg(test)]
mod tests {
    use crate::{Idmap, DEFAULT_IDMAP_RANGE};
    use std::collections::HashMap;
    use uuid::Uuid;

    #[test]
    fn sssd_idmapping() {
        let domain = "contoso.onmicrosoft.com";
        let tenant_id = "d7af6c1b-0497-40fe-9d17-07e6b0f8332e";
        let mut idmap = Idmap::new().expect("Idmap initialization failed");

        idmap
            .add_gen_domain(domain, tenant_id, DEFAULT_IDMAP_RANGE)
            .expect("Failed initializing test domain idmapping");

        // Verify we always get the same mapping for various users
        let mut usermap: HashMap<String, u32> = HashMap::new();
        usermap.insert("tux@contoso.onmicrosoft.com".to_string(), 1912749799);
        usermap.insert("admin@contoso.onmicrosoft.com".to_string(), 297515919);
        usermap.insert("dave@contoso.onmicrosoft.com".to_string(), 132631922);
        usermap.insert("joe@contoso.onmicrosoft.com".to_string(), 361591965);
        usermap.insert("georg@contoso.onmicrosoft.com".to_string(), 866887005);

        for (username, expected_uid) in &usermap {
            let uid = idmap
                .gen_to_unix(tenant_id, username)
                .expect(&format!("Failed converting username {} to uid", username));
            assert_eq!(uid, *expected_uid, "Uid for {} did not match", username);
        }
    }

    #[test]
    fn legacy_idmapping() {
        let domain = "contoso.onmicrosoft.com";
        let tenant_id = "d7af6c1b-0497-40fe-9d17-07e6b0f8332e";
        let mut idmap = Idmap::new().expect("Idmap initialization failed");

        // Test using the legacy default idmap range
        idmap
            .add_gen_domain(domain, tenant_id, (1000000, 6999999))
            .expect("Failed initializing test domain idmapping");

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
            let object_uuid = Uuid::parse_str(&object_id).expect("Failed parsing object_id");
            let uid = idmap
                .object_id_to_unix_id(tenant_id, &object_uuid)
                .expect(&format!("Failed converting uuid {} to uid", object_id));
            assert_eq!(uid, *expected_uid, "Uid for {} did not match", username);
        }
    }
}
