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
        ffi::idmap_error_code_IDMAP_ERR_LAST => IdmapError::IDMAP_ERR_LAST,
        _ => {
            error!("Unknown error code '{}'", e);
            IdmapError::IDMAP_ERROR
        }
    }
}

fn object_id_to_sid(object_id: &Uuid) -> Result<String, IdmapError> {
    let bytes_array = object_id.as_bytes();
    let s_bytes_array = [
        bytes_array[6],
        bytes_array[7],
        bytes_array[4],
        bytes_array[5],
    ];

    Ok(format!(
        "S-1-12-1-{}-{}-{}-{}",
        u32::from_be_bytes(
            bytes_array[0..4]
                .try_into()
                .map_err(|_| IdmapError::IDMAP_SID_INVALID)?
        ),
        u32::from_be_bytes(
            s_bytes_array
                .try_into()
                .map_err(|_| IdmapError::IDMAP_SID_INVALID)?
        ),
        u32::from_le_bytes(
            bytes_array[8..12]
                .try_into()
                .map_err(|_| IdmapError::IDMAP_SID_INVALID)?
        ),
        u32::from_le_bytes(
            bytes_array[12..]
                .try_into()
                .map_err(|_| IdmapError::IDMAP_SID_INVALID)?
        )
    ))
}

pub const DEFAULT_IDMAP_RANGE: (u32, u32) = (200000, 2000200000);

// The ctx is behind a read/write lock to make it 'safer' to Send/Sync.
// Granted, dereferencing a raw pointer is still inherently unsafe.
pub struct SssIdmap {
    ctx: RwLock<*mut ffi::sss_idmap_ctx>,
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
                }),
                e => Err(e),
            }
        }
    }

    pub fn set_autorid(&self, use_autorid: bool) -> Result<(), IdmapError> {
        let ctx = self.ctx.write().map_err(|e| {
            error!("Failed obtaining write lock on sss_idmap_ctx: {}", e);
            IdmapError::IDMAP_ERROR
        })?;
        unsafe {
            match map_err(ffi::sss_idmap_ctx_set_autorid(*ctx, use_autorid)) {
                IdmapError::IDMAP_SUCCESS => Ok(()),
                e => Err(e),
            }
        }
    }

    pub fn set_lower(&self, lower: ffi::id_t) -> Result<(), IdmapError> {
        let ctx = self.ctx.write().map_err(|e| {
            error!("Failed obtaining write lock on sss_idmap_ctx: {}", e);
            IdmapError::IDMAP_ERROR
        })?;
        unsafe {
            match map_err(ffi::sss_idmap_ctx_set_lower(*ctx, lower)) {
                IdmapError::IDMAP_SUCCESS => Ok(()),
                e => Err(e),
            }
        }
    }

    pub fn set_upper(&self, upper: ffi::id_t) -> Result<(), IdmapError> {
        let ctx = self.ctx.write().map_err(|e| {
            error!("Failed obtaining write lock on sss_idmap_ctx: {}", e);
            IdmapError::IDMAP_ERROR
        })?;
        unsafe {
            match map_err(ffi::sss_idmap_ctx_set_upper(*ctx, upper)) {
                IdmapError::IDMAP_SUCCESS => Ok(()),
                e => Err(e),
            }
        }
    }

    pub fn set_rangesize(&self, rangesize: ffi::id_t) -> Result<(), IdmapError> {
        let ctx = self.ctx.write().map_err(|e| {
            error!("Failed obtaining write lock on sss_idmap_ctx: {}", e);
            IdmapError::IDMAP_ERROR
        })?;
        unsafe {
            match map_err(ffi::sss_idmap_ctx_set_rangesize(*ctx, rangesize)) {
                IdmapError::IDMAP_SUCCESS => Ok(()),
                e => Err(e),
            }
        }
    }

    pub fn object_id_to_unix(&self, object_id: &Uuid) -> Result<u32, IdmapError> {
        let ctx = self.ctx.write().map_err(|e| {
            error!("Failed obtaining write lock on sss_idmap_ctx: {}", e);
            IdmapError::IDMAP_ERROR
        })?;
        let sid: String = object_id_to_sid(object_id)?;
        let cstr_sid = CString::new(sid.as_bytes()).map_err(|_| IdmapError::IDMAP_SID_INVALID)?;
        unsafe {
            let mut unix: u32 = 0;
            match map_err(ffi::sss_idmap_sid_to_unix(
                *ctx,
                cstr_sid.as_ptr(),
                &mut unix,
            )) {
                IdmapError::IDMAP_SUCCESS => Ok(unix),
                e => Err(e),
            }
        }
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
