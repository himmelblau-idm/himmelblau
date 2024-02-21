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

#[derive(Debug)]
#[allow(non_camel_case_types)]
pub enum IdmapError {
    IDMAP_SUCCESS,
    IDMAP_NOT_IMPLEMENTED,
    IDMAP_ERROR,
    IDMAP_OUT_OF_MEMORY,
    IDMAP_NO_DOMAIN,
    IDMAP_CONTEXT_INVALID,
    IDMAP_SID_INVALID,
    IDMAP_SID_UNKNOWN,
    IDMAP_NO_RANGE,
    IDMAP_BUILTIN_SID,
    IDMAP_OUT_OF_SLICES,
    IDMAP_COLLISION,
    IDMAP_EXTERNAL,
    IDMAP_NAME_UNKNOWN,
    IDMAP_NO_REVERSE,
    IDMAP_ERR_LAST,
}

fn map_err(e: ffi::idmap_error_code) -> IdmapError {
    match e {
        ffi::idmap_error_code_IDMAP_SUCCESS => IdmapError::IDMAP_SUCCESS,
        ffi::idmap_error_code_IDMAP_NOT_IMPLEMENTED => IdmapError::IDMAP_NOT_IMPLEMENTED,
        ffi::idmap_error_code_IDMAP_ERROR => IdmapError::IDMAP_ERROR,
        ffi::idmap_error_code_IDMAP_OUT_OF_MEMORY => IdmapError::IDMAP_OUT_OF_MEMORY,
        ffi::idmap_error_code_IDMAP_NO_DOMAIN => IdmapError::IDMAP_NO_DOMAIN,
        ffi::idmap_error_code_IDMAP_CONTEXT_INVALID => IdmapError::IDMAP_CONTEXT_INVALID,
        ffi::idmap_error_code_IDMAP_SID_INVALID => IdmapError::IDMAP_SID_INVALID,
        ffi::idmap_error_code_IDMAP_SID_UNKNOWN => IdmapError::IDMAP_SID_UNKNOWN,
        ffi::idmap_error_code_IDMAP_NO_RANGE => IdmapError::IDMAP_NO_RANGE,
        ffi::idmap_error_code_IDMAP_BUILTIN_SID => IdmapError::IDMAP_BUILTIN_SID,
        ffi::idmap_error_code_IDMAP_OUT_OF_SLICES => IdmapError::IDMAP_OUT_OF_SLICES,
        ffi::idmap_error_code_IDMAP_COLLISION => IdmapError::IDMAP_COLLISION,
        ffi::idmap_error_code_IDMAP_EXTERNAL => IdmapError::IDMAP_EXTERNAL,
        ffi::idmap_error_code_IDMAP_NAME_UNKNOWN => IdmapError::IDMAP_NAME_UNKNOWN,
        ffi::idmap_error_code_IDMAP_NO_REVERSE => IdmapError::IDMAP_NO_REVERSE,
        ffi::idmap_error_code_IDMAP_ERR_LAST => IdmapError::IDMAP_ERR_LAST,
        _ => {
            error!("Unknown error code '{}'", e);
            IdmapError::IDMAP_ERROR
        }
    }
}

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
            .map_err(|_| IdmapError::IDMAP_SID_INVALID)?,
    );
    sid.sub_auths[2] = u32::from_be_bytes(s_bytes_array);
    sid.sub_auths[3] = u32::from_le_bytes(
        bytes_array[8..12]
            .try_into()
            .map_err(|_| IdmapError::IDMAP_SID_INVALID)?,
    );
    sid.sub_auths[4] = u32::from_le_bytes(
        bytes_array[12..]
            .try_into()
            .map_err(|_| IdmapError::IDMAP_SID_INVALID)?,
    );

    Ok(sid)
}

fn rid_from_sid(sid: &AadSid) -> Result<u32, IdmapError> {
    Ok(sid.sub_auths
        [usize::try_from(sid.num_auths).map_err(|_| IdmapError::IDMAP_SID_INVALID)? - 1])
}

pub const DEFAULT_IDMAP_RANGE: (u32, u32) = (200000, 2000200000);

// The ctx is behind a read/write lock to make it 'safer' to Send/Sync.
// Granted, dereferencing a raw pointer is still inherently unsafe.
pub struct SssIdmap {
    ctx: RwLock<*mut ffi::sss_idmap_ctx>,
    ranges: HashMap<String, (u32, u32)>,
}

unsafe impl Send for SssIdmap {}
unsafe impl Sync for SssIdmap {}

impl SssIdmap {
    pub fn new() -> Result<SssIdmap, IdmapError> {
        let mut ctx = ptr::null_mut();
        unsafe {
            match map_err(ffi::sss_idmap_init(None, ptr::null_mut(), None, &mut ctx)) {
                IdmapError::IDMAP_SUCCESS => Ok(SssIdmap {
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
            IdmapError::IDMAP_ERROR
        })?;
        let domain_name_cstr =
            CString::new(domain_name).map_err(|_| IdmapError::IDMAP_OUT_OF_MEMORY)?;
        let tenant_id_cstr =
            CString::new(tenant_id).map_err(|_| IdmapError::IDMAP_OUT_OF_MEMORY)?;
        let mut idmap_range = ffi::sss_idmap_range {
            min: range.0,
            max: range.1,
        };
        self.ranges.insert(tenant_id.to_string(), range);
        unsafe {
            match map_err(ffi::sss_idmap_add_gen_domain_ex(
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
                IdmapError::IDMAP_SUCCESS => Ok(()),
                e => Err(e),
            }
        }
    }

    pub fn gen_to_unix(&self, tenant_id: &str, input: &str) -> Result<u32, IdmapError> {
        let ctx = self.ctx.write().map_err(|e| {
            error!("Failed obtaining write lock on sss_idmap_ctx: {}", e);
            IdmapError::IDMAP_ERROR
        })?;
        let tenant_id_cstr =
            CString::new(tenant_id).map_err(|_| IdmapError::IDMAP_OUT_OF_MEMORY)?;
        let input_cstr = CString::new(input).map_err(|_| IdmapError::IDMAP_OUT_OF_MEMORY)?;
        unsafe {
            let mut id: u32 = 0;
            match map_err(ffi::sss_idmap_gen_to_unix(
                *ctx,
                tenant_id_cstr.as_ptr(),
                input_cstr.as_ptr(),
                &mut id,
            )) {
                IdmapError::IDMAP_SUCCESS => Ok(id),
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
            None => return Err(IdmapError::IDMAP_NO_RANGE),
        };
        let uid_count = idmap_range.1 - idmap_range.0;
        Ok((rid % uid_count) + idmap_range.0)
    }
}

impl Drop for SssIdmap {
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
