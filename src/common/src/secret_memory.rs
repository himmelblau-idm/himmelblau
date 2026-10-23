//! Dedicated, locked allocations for short-lived credentials.
//!
//! This reduces accidental disclosure and swapping, not access by a compromised host.
//! Linux mappings are not inherited across fork; do not use them in a fork child.
use std::{fmt, io, ptr::NonNull};
use zeroize::Zeroize;

pub struct SecretBuffer {
    ptr: NonNull<u8>,
    len: usize,
    allocation_len: usize,
}

// The allocation has unique ownership; access follows Rust slice borrowing rules.
unsafe impl Send for SecretBuffer {}
unsafe impl Sync for SecretBuffer {}

impl SecretBuffer {
    pub fn new(len: usize) -> io::Result<Self> {
        Self::allocate(len, false)
    }

    fn allocate(len: usize, fail_lock: bool) -> io::Result<Self> {
        let allocation_len = len.max(1);
        // A private anonymous mapping owns independent pages, so locking/dump policy
        // cannot accidentally affect unrelated allocator objects.
        let raw = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                allocation_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if raw == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let locked = !fail_lock && unsafe { libc::mlock(raw, allocation_len) } == 0;
        if !locked {
            let error = if fail_lock {
                io::Error::from(io::ErrorKind::PermissionDenied)
            } else {
                io::Error::last_os_error()
            };
            unsafe {
                libc::munmap(raw, allocation_len);
            }
            return Err(error);
        }
        #[cfg(target_os = "linux")]
        if unsafe { libc::madvise(raw, allocation_len, libc::MADV_DONTDUMP) } != 0
            || unsafe { libc::madvise(raw, allocation_len, libc::MADV_DONTFORK) } != 0
        {
            let error = io::Error::last_os_error();
            unsafe {
                libc::munlock(raw, allocation_len);
                libc::munmap(raw, allocation_len);
            }
            return Err(error);
        }
        let Some(ptr) = NonNull::new(raw.cast()) else {
            unsafe {
                libc::munlock(raw, allocation_len);
                libc::munmap(raw, allocation_len);
            }
            return Err(io::Error::other("null secret mapping"));
        };
        Ok(Self {
            ptr,
            len,
            allocation_len,
        })
    }

    pub fn from_slice(value: &[u8]) -> io::Result<Self> {
        let mut secret = Self::new(value.len())?;
        secret.as_mut_slice().copy_from_slice(value);
        Ok(secret)
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn clear(&mut self) {
        // Wipe the entire requested mapping, including the empty-buffer sentinel.
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.allocation_len) }.zeroize();
    }
}
impl fmt::Debug for SecretBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBuffer([REDACTED])")
    }
}
#[cfg(test)]
thread_local! {
    static ZEROIZED_DROPS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

impl Drop for SecretBuffer {
    fn drop(&mut self) {
        self.clear();
        #[cfg(test)]
        {
            // Inspect while still mapped: checking freed memory would be UB.
            assert!(self.as_slice().iter().all(|byte| *byte == 0));
            ZEROIZED_DROPS.with(|count| count.set(count.get() + 1));
        }
        unsafe {
            libc::munlock(self.ptr.as_ptr().cast(), self.allocation_len);
            libc::munmap(self.ptr.as_ptr().cast(), self.allocation_len);
        }
    }
}

/// Grow a transient wire buffer without abandoning its previous allocation
/// with live bytes. The caller must also wipe the final allocation on drop.
#[doc(hidden)]
pub fn extend_secret(buffer: &mut zeroize::Zeroizing<Vec<u8>>, bytes: &[u8]) {
    if buffer.capacity() - buffer.len() < bytes.len() {
        let capacity = (buffer.len() + bytes.len()).max(buffer.capacity().saturating_mul(2));
        let mut replacement = zeroize::Zeroizing::new(Vec::with_capacity(capacity));
        replacement.extend_from_slice(buffer);
        std::mem::swap(buffer, &mut replacement);
    }
    buffer.extend_from_slice(bytes);
}

#[doc(hidden)]
pub fn encode_json<T: serde::Serialize>(
    value: &T,
) -> Result<zeroize::Zeroizing<Vec<u8>>, serde_json::Error> {
    struct Writer(zeroize::Zeroizing<Vec<u8>>);
    impl std::io::Write for Writer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            extend_secret(&mut self.0, bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = Writer(zeroize::Zeroizing::new(Vec::with_capacity(1024)));
    serde_json::to_writer(&mut writer, value)?;
    Ok(writer.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn secret_lifecycle() -> io::Result<()> {
        let mut secret = SecretBuffer::from_slice(b"sensitive")?;
        assert_eq!(secret.as_slice(), b"sensitive");
        assert_eq!(format!("{secret:?}"), "SecretBuffer([REDACTED])");
        secret.clear();
        assert!(secret.as_slice().iter().all(|byte| *byte == 0));
        assert!(SecretBuffer::new(0)?.is_empty());
        Ok(())
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn mapping_is_locked_dump_excluded_and_not_inherited() -> io::Result<()> {
        let secret = SecretBuffer::from_slice(b"test mapping flags")?;
        let Ok(smaps) = std::fs::read_to_string("/proc/self/smaps") else {
            return Ok(());
        };
        let address = secret.ptr.as_ptr() as usize;
        let mut in_mapping = false;
        for line in smaps.lines() {
            if let Some(range) = line.split_whitespace().next() {
                if let Some((start, end)) = range.split_once('-') {
                    if let (Ok(start), Ok(end)) = (
                        usize::from_str_radix(start, 16),
                        usize::from_str_radix(end, 16),
                    ) {
                        in_mapping = start <= address && address < end;
                    }
                }
            }
            if in_mapping && line.starts_with("VmFlags:") {
                let flags: Vec<_> = line.split_whitespace().collect();
                assert!(flags.contains(&"lo"));
                assert!(flags.contains(&"dd"));
                assert!(flags.contains(&"dc"));
                return Ok(());
            }
        }
        Err(io::Error::other("secret mapping absent from smaps"))
    }

    #[test]
    fn drop_wipes_before_releasing_mapping() -> io::Result<()> {
        let before = ZEROIZED_DROPS.with(std::cell::Cell::get);
        {
            let _secret = SecretBuffer::from_slice(b"drop must wipe this")?;
        }
        assert_eq!(ZEROIZED_DROPS.with(std::cell::Cell::get), before + 1);
        Ok(())
    }

    #[test]
    fn lock_failure_is_fatal() {
        assert!(SecretBuffer::allocate(32, true).is_err());
    }
}
