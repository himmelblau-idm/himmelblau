use std::mem::MaybeUninit;
use std::sync::OnceLock;

static BLOCKED_KEY: OnceLock<Result<libc::pthread_key_t, libc::c_int>> = OnceLock::new();

fn blocked_key() -> Result<libc::pthread_key_t, libc::c_int> {
    *BLOCKED_KEY.get_or_init(|| {
        let mut key = MaybeUninit::uninit();
        let result = unsafe { libc::pthread_key_create(key.as_mut_ptr(), None) };
        if result == 0 {
            Ok(unsafe { key.assume_init() })
        } else {
            Err(result)
        }
    })
}

// Use pthread-specific storage, like nss-systemd, rather than fallible dynamic ELF TLS allocation.
#[no_mangle]
pub extern "C" fn _nss_himmelblau_block(block: bool) -> libc::c_int {
    let key = match blocked_key() {
        Ok(key) => key,
        Err(error) => return -error,
    };
    let count = unsafe { libc::pthread_getspecific(key) }.addr();
    let next = if block {
        count.checked_add(1)
    } else {
        count.checked_sub(1)
    };
    let Some(next) = next else {
        return -libc::EOVERFLOW;
    };
    let result = unsafe { libc::pthread_setspecific(key, std::ptr::without_provenance(next)) };
    if result != 0 {
        return -result;
    }
    if block {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn _nss_himmelblau_is_blocked() -> bool {
    match blocked_key() {
        Ok(key) => !unsafe { libc::pthread_getspecific(key) }.is_null(),
        Err(error) => {
            tracing::error!(
                "Failed to initialize the NSS recursion guard: {}",
                std::io::Error::from_raw_os_error(error)
            );
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_are_nested_and_balanced() {
        assert!(!_nss_himmelblau_is_blocked());
        assert_eq!(_nss_himmelblau_block(true), 1);
        assert_eq!(_nss_himmelblau_block(true), 1);
        assert!(_nss_himmelblau_is_blocked());
        assert_eq!(_nss_himmelblau_block(false), 0);
        assert!(_nss_himmelblau_is_blocked());
        assert_eq!(_nss_himmelblau_block(false), 0);
        assert!(!_nss_himmelblau_is_blocked());
        assert_eq!(_nss_himmelblau_block(false), -libc::EOVERFLOW);
        assert!(!_nss_himmelblau_is_blocked());
    }

    #[test]
    fn blocks_are_thread_local() -> Result<(), String> {
        assert_eq!(_nss_himmelblau_block(true), 1);
        let other = std::thread::spawn(|| {
            assert!(!_nss_himmelblau_is_blocked());
            assert_eq!(_nss_himmelblau_block(true), 1);
            assert_eq!(_nss_himmelblau_block(false), 0);
            assert!(!_nss_himmelblau_is_blocked());
        });
        let result = other.join();
        assert!(_nss_himmelblau_is_blocked());
        assert_eq!(_nss_himmelblau_block(false), 0);
        result.map_err(|_| "NSS guard test thread panicked".to_string())
    }

    #[test]
    fn nesting_overflow_is_rejected() -> Result<(), libc::c_int> {
        let key = blocked_key()?;
        assert_eq!(
            unsafe { libc::pthread_setspecific(key, std::ptr::without_provenance(usize::MAX)) },
            0
        );
        let result = _nss_himmelblau_block(true);
        assert_eq!(
            unsafe { libc::pthread_setspecific(key, std::ptr::null()) },
            0
        );
        assert_eq!(result, -libc::EOVERFLOW);
        assert!(!_nss_himmelblau_is_blocked());
        Ok(())
    }
}
