// SPDX-License-Identifier: GPL-3.0-or-later

use std::fs::File;
use std::io::{self, Write};
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixDatagram;
use std::time::Duration;

const JOURNAL_SOCKET: &str = "/run/systemd/journal/socket";

/// Submit byte-valued fields using journald's native, length-delimited format.
pub fn send(fields: &[(&str, &[u8])]) -> io::Result<()> {
    let entry = encode(fields)?;
    let socket = UnixDatagram::unbound()?;
    socket.set_write_timeout(Some(Duration::from_secs(1)))?;
    socket.connect(JOURNAL_SOCKET)?;
    send_entry(&socket, &entry)
}

fn encode(fields: &[(&str, &[u8])]) -> io::Result<Vec<u8>> {
    if fields.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Empty journal entry",
        ));
    }
    let mut entry = Vec::new();
    for (name, value) in fields {
        if name.len() > 64
            || !name.as_bytes().first().is_some_and(u8::is_ascii_uppercase)
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Invalid journal field name: {name:?}"),
            ));
        }
        entry.extend_from_slice(name.as_bytes());
        entry.push(b'\n');
        entry.extend_from_slice(&(value.len() as u64).to_le_bytes());
        entry.extend_from_slice(value);
        entry.push(b'\n');
    }
    Ok(entry)
}

fn send_entry(socket: &UnixDatagram, entry: &[u8]) -> io::Result<()> {
    loop {
        match socket.send(entry) {
            Ok(sent) if sent == entry.len() => return Ok(()),
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "Short journal send",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(libc::EMSGSIZE | libc::ENOBUFS | libc::EAGAIN)
                ) =>
            {
                return send_memfd(socket, entry);
            }
            Err(error) => return Err(error),
        }
    }
}

fn send_memfd(socket: &UnixDatagram, entry: &[u8]) -> io::Result<()> {
    let flags = libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING;
    // SAFETY: the name is NUL-terminated and the flags are valid for memfd_create.
    let mut fd = unsafe {
        libc::memfd_create(
            c"himmelblau-journal".as_ptr(),
            flags | libc::MFD_NOEXEC_SEAL,
        )
    };
    if fd < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
        // SAFETY: the same arguments without MFD_NOEXEC_SEAL support kernels older than 6.3.
        fd = unsafe { libc::memfd_create(c"himmelblau-journal".as_ptr(), flags) };
    }
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: memfd_create returned a new descriptor, owned only here.
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(entry)?;
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    // SAFETY: file owns fd and F_ADD_SEALS takes an integer mask.
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) } < 0 {
        return Err(io::Error::last_os_error());
    }

    // A native journal FD message must have no payload and exactly one sealed FD.
    // SAFETY: CMSG_SPACE/CMSG_LEN are evaluated for one RawFd.
    let (space, length) = unsafe {
        (
            libc::CMSG_SPACE(size_of::<RawFd>() as u32) as usize,
            libc::CMSG_LEN(size_of::<RawFd>() as u32) as usize,
        )
    };
    let mut control = vec![0usize; space.div_ceil(size_of::<usize>())];
    // SAFETY: an empty msghdr is all zeros; the control buffer is aligned and large enough.
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = space;
    // SAFETY: control holds a complete cmsghdr and one RawFd, and file stays open through sendmsg.
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = length;
        libc::CMSG_DATA(header)
            .cast::<RawFd>()
            .write(file.as_raw_fd());
    }
    loop {
        // SAFETY: all message pointers are valid and socket owns its descriptor.
        if unsafe { libc::sendmsg(socket.as_raw_fd(), &message, libc::MSG_NOSIGNAL) } >= 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::{BufRead, Cursor, Read};
    use std::mem::size_of_val;
    use std::os::unix::fs::FileExt;

    fn decode(entry: &[u8]) -> HashMap<String, Vec<u8>> {
        let mut reader = Cursor::new(entry);
        let mut fields = HashMap::new();
        while reader.position() < entry.len() as u64 {
            let mut name = Vec::new();
            reader.read_until(b'\n', &mut name).expect("field name");
            assert_eq!(name.pop(), Some(b'\n'));
            let mut length = [0; 8];
            reader.read_exact(&mut length).expect("binary length");
            let mut value = vec![0; u64::from_le_bytes(length) as usize];
            reader.read_exact(&mut value).expect("binary value");
            let mut newline = [0];
            reader.read_exact(&mut newline).expect("field terminator");
            assert_eq!(newline, [b'\n']);
            assert!(fields
                .insert(String::from_utf8(name).expect("name"), value)
                .is_none());
        }
        fields
    }

    #[test]
    fn native_datagram_preserves_binary_fields_and_metadata() {
        let script = b"#!/bin/sh\nMESSAGE=not another field\n\0\xff\n\n ";
        let entry = encode(&[
            ("MESSAGE", b"Executing script"),
            ("HIMMELBLAU_SCRIPT", script),
            ("HIMMELBLAU_POLICY_ID", b"policy\nwith newline"),
        ])
        .expect("encode");
        let (sender, receiver) = UnixDatagram::pair().expect("socket pair");
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("read timeout");
        send_entry(&sender, &entry).expect("send");
        let mut data = vec![0; 1024];
        let count = receiver.recv(&mut data).expect("receive");
        let fields = decode(&data[..count]);
        assert_eq!(fields.len(), 3);
        assert_eq!(fields["MESSAGE"], b"Executing script");
        assert_eq!(fields["HIMMELBLAU_SCRIPT"], script);
        assert_eq!(fields["HIMMELBLAU_POLICY_ID"], b"policy\nwith newline");
    }

    #[test]
    fn large_entries_are_sent_as_a_sealed_fd_without_payload() {
        let script = vec![0xff; 2 * 1024 * 1024];
        let entry = encode(&[("HIMMELBLAU_SCRIPT", &script)]).expect("encode");
        let (sender, receiver) = UnixDatagram::pair().expect("socket pair");
        let buffer_size: libc::c_int = 4096;
        // SAFETY: the option buffer contains a c_int and sender is a live socket.
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    sender.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    std::ptr::from_ref(&buffer_size).cast(),
                    size_of_val(&buffer_size) as libc::socklen_t,
                )
            },
            0
        );
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("read timeout");
        send_entry(&sender, &entry).expect("send large entry");

        let mut control = [0usize; 16];
        let mut payload = [0u8; 1];
        let mut iov = libc::iovec {
            iov_base: payload.as_mut_ptr().cast(),
            iov_len: payload.len(),
        };
        // SAFETY: the data and aligned control buffers outlive recvmsg.
        let mut message: libc::msghdr = unsafe { zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = size_of_val(&control);
        // SAFETY: receiver is valid and all message buffers are writable.
        let received =
            unsafe { libc::recvmsg(receiver.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
        assert_eq!(received, 0, "{}", io::Error::last_os_error());
        assert_eq!(message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC), 0);
        // SAFETY: recvmsg filled the control buffer; validate the header before reading the FD.
        let file = unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            assert!(!header.is_null());
            assert_eq!((*header).cmsg_level, libc::SOL_SOCKET);
            assert_eq!((*header).cmsg_type, libc::SCM_RIGHTS);
            assert_eq!(
                (*header).cmsg_len,
                libc::CMSG_LEN(size_of::<RawFd>() as u32) as usize
            );
            File::from_raw_fd(libc::CMSG_DATA(header).cast::<RawFd>().read())
        };
        // SAFETY: file owns the received memfd.
        let seals = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
        assert!(seals >= 0);
        let required =
            libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
        assert_eq!(seals & required, required);
        let mut data = vec![0; file.metadata().expect("metadata").len() as usize];
        file.read_exact_at(&mut data, 0).expect("read memfd");
        assert_eq!(decode(&data)["HIMMELBLAU_SCRIPT"], script);
    }

    #[test]
    fn invalid_fields_and_transport_errors_are_reported() {
        for name in ["", "_PID", "1INVALID", "lowercase", "BAD=KEY", "BAD\nKEY"] {
            assert!(encode(&[(name, b"value")]).is_err());
        }
        let (sender, receiver) = UnixDatagram::pair().expect("socket pair");
        drop(receiver);
        let entry = encode(&[("MESSAGE", b"test")]).expect("encode");
        assert!(send_entry(&sender, &entry).is_err());
    }
}
