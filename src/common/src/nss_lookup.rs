use std::ffi::{CStr, CString};
use std::io;
use std::mem::MaybeUninit;

type BlockFn = unsafe extern "C" fn(bool) -> libc::c_int;

struct Module(*mut libc::c_void);

impl Drop for Module {
    fn drop(&mut self) {
        if unsafe { libc::dlclose(self.0) } != 0 {
            error!("Failed to close Himmelblau NSS module: {}", loader_error());
        }
    }
}

fn loader_error() -> String {
    let error = unsafe { libc::dlerror() };
    if error.is_null() {
        "No dynamic-loader diagnostic available".to_string()
    } else {
        unsafe { CStr::from_ptr(error) }
            .to_string_lossy()
            .into_owned()
    }
}

// The raw module handle makes the guard !Send, so it cannot unblock a different thread.
struct NssBlock {
    _module: Module,
    block: BlockFn,
}

impl NssBlock {
    fn acquire() -> io::Result<Option<Self>> {
        let handle = unsafe {
            libc::dlopen(
                c"libnss_himmelblau.so.2".as_ptr(),
                libc::RTLD_NOW | libc::RTLD_NODELETE,
            )
        };
        if handle.is_null() {
            // Like systemd's NSS blocker, an unavailable module needs no suppression.
            debug!(
                "Himmelblau NSS module unavailable during user lookup: {}",
                loader_error()
            );
            return Ok(None);
        }
        let module = Module(handle);
        let symbol = unsafe { libc::dlsym(module.0, c"_nss_himmelblau_block".as_ptr()) };
        if symbol.is_null() {
            return Err(io::Error::other(format!(
                "Himmelblau NSS module lacks recursion protection; upgrade the NSS module: {}",
                loader_error()
            )));
        }
        // This exported C ABI belongs to the loaded NSS module, not this executable's copy of common.
        let block = unsafe { std::mem::transmute::<*mut libc::c_void, BlockFn>(symbol) };
        let result = unsafe { block(true) };
        if result < 0 {
            return Err(io::Error::from_raw_os_error(-result));
        }
        Ok(Some(Self {
            _module: module,
            block,
        }))
    }
}

impl Drop for NssBlock {
    fn drop(&mut self) {
        let result = unsafe { (self.block)(false) };
        if result < 0 {
            error!(
                "Failed to unblock Himmelblau NSS lookups: {}",
                io::Error::from_raw_os_error(-result)
            );
        }
    }
}

/// Resolve an account through NSS without re-entering the Himmelblau daemon.
/// This is blocking; async callers must run it on a blocking worker.
/// On top of this, the NSS proxy sockets are inaccessible to the services as
/// well.
pub fn user_ids(name: &str) -> io::Result<Option<(u32, u32)>> {
    let name =
        CString::new(name).map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let _block = NssBlock::acquire()?;
    let mut buffer = vec![0_u8; 16 * 1024];

    loop {
        let mut passwd = MaybeUninit::<libc::passwd>::uninit();
        let mut result = std::ptr::null_mut();
        let error = unsafe {
            libc::getpwnam_r(
                name.as_ptr(),
                passwd.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if error == libc::ERANGE && buffer.len() < 1024 * 1024 {
            buffer.resize(buffer.len() * 2, 0);
            continue;
        }
        // Match systemd's handling of the documented missing-account error codes.
        if matches!(
            error,
            libc::ENOENT | libc::ESRCH | libc::EBADF | libc::EPERM
        ) {
            return Ok(None);
        }
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error));
        }
        if result.is_null() {
            return Ok(None);
        }
        let passwd = unsafe { passwd.assume_init() };
        return Ok(Some((passwd.pw_uid, passwd.pw_gid)));
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn invalid_user_name_is_rejected_before_nss() {
        assert_eq!(
            super::user_ids("invalid\0name")
                .err()
                .map(|error| error.kind()),
            Some(std::io::ErrorKind::InvalidInput)
        );
    }
}
