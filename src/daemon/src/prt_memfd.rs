/*
   Unix Azure Entra ID implementation

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

use libc;
use memfd::{FileSeal, MemfdOptions};
use sd_notify::NotifyState;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::BorrowedFd;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use tracing::{debug, warn};

/// The FDNAME we use when storing/retrieving the PRT memfd.
const PRT_FDNAME: &str = "broker-prt";

/// Well-known FileDescriptorName values for socket-activated sockets.
pub const FDNAME_MAIN_SOCKET: &str = "himmelblaud";
pub const FDNAME_TASK_SOCKET: &str = "himmelblaud-task";
pub const FDNAME_BROKER_SOCKET: &str = "himmelblaud-broker";

/// File descriptors passed by systemd at startup.
///
/// Collected once via `listen_fds_with_names()` so that both socket
/// activation and FD-store restoration share one call.
pub struct SystemdFds {
    /// The main daemon socket (PAM/NSS/CLI), if passed via socket activation.
    pub main_socket: Option<RawFd>,
    /// The task socket (root-only IPC), if passed via socket activation.
    pub task_socket: Option<RawFd>,
    /// The broker socket, if passed via socket activation.
    pub broker_socket: Option<RawFd>,
    /// PRT data restored from the FileDescriptorStore, if any.
    pub prt_data: Option<Vec<u8>>,
}

/// Collect all file descriptors passed by systemd and classify them.
///
/// Must be called exactly once, early in daemon startup.  Returns
/// socket-activation FDs (by well-known name) and PRT memfd data.
pub fn collect_systemd_fds() -> SystemdFds {
    let fds = match sd_notify::listen_fds_with_names() {
        Ok(fds) => fds,
        Err(e) => {
            debug!(
                "listen_fds_with_names returned error (not under systemd?): {}",
                e
            );
            return SystemdFds {
                main_socket: None,
                task_socket: None,
                broker_socket: None,
                prt_data: None,
            };
        }
    };

    let mut result = SystemdFds {
        main_socket: None,
        task_socket: None,
        broker_socket: None,
        prt_data: None,
    };

    for (fd, name) in fds {
        match name.as_str() {
            FDNAME_MAIN_SOCKET => {
                if result.main_socket.is_some() {
                    warn!("Duplicate main socket fd={}, closing", fd);
                    unsafe { libc::close(fd) };
                } else {
                    debug!("Received main socket fd={} from systemd", fd);
                    result.main_socket = Some(fd);
                }
            }
            FDNAME_TASK_SOCKET => {
                if result.task_socket.is_some() {
                    warn!("Duplicate task socket fd={}, closing", fd);
                    unsafe { libc::close(fd) };
                } else {
                    debug!("Received task socket fd={} from systemd", fd);
                    result.task_socket = Some(fd);
                }
            }
            FDNAME_BROKER_SOCKET => {
                if result.broker_socket.is_some() {
                    warn!("Duplicate broker socket fd={}, closing", fd);
                    unsafe { libc::close(fd) };
                } else {
                    debug!("Received broker socket fd={} from systemd", fd);
                    result.broker_socket = Some(fd);
                }
            }
            PRT_FDNAME => {
                debug!("Found PRT memfd (fd={}) in FileDescriptorStore", fd);
                match read_fd_contents(fd) {
                    Ok(data) => result.prt_data = Some(data),
                    Err(e) => warn!("Failed to read PRT memfd: {}", e),
                }
            }
            _ => {
                warn!("Closing unknown systemd fd={} name={}", fd, name);
                unsafe { libc::close(fd) };
            }
        }
    }

    result
}

/// Create a sealed memfd containing `data` and store it in systemd's
/// FileDescriptorStore.
///
/// The memfd is created with `MFD_ALLOW_SEALING`, written, then sealed
/// with `F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_SEAL` so
/// that no process (including ourselves) can tamper with the contents
/// afterwards.
///
/// After `notify_with_fds` succeeds, systemd holds its own duplicate
/// of the FD (received via `SCM_RIGHTS`).
pub fn store_prts_to_fdstore(data: &[u8]) -> io::Result<()> {
    let opts = MemfdOptions::default().allow_sealing(true);
    let mfd = opts
        .create("himmelblau-prt")
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    // Write PRT data into the memfd
    mfd.as_file().write_all(data)?;

    // Seal the memfd: no further writes, shrinks, grows, or seal changes
    mfd.add_seals(&[
        FileSeal::SealShrink,
        FileSeal::SealGrow,
        FileSeal::SealWrite,
        FileSeal::SealSeal,
    ])
    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    debug!("Created sealed memfd with {} bytes of PRT data", data.len());

    // Hand to systemd's FD store.
    // SAFETY: as_raw_fd() borrows from the still-live `mfd`.
    let borrowed = unsafe { BorrowedFd::borrow_raw(mfd.as_raw_fd()) };
    sd_notify::notify_with_fds(
        &[NotifyState::FdStore, NotifyState::FdName(PRT_FDNAME)],
        &[borrowed],
    )?;

    debug!("Stored PRT memfd in systemd FileDescriptorStore");

    // `mfd` is dropped here, closing the local FD. systemd already
    // received its own duplicate via SCM_RIGHTS.

    Ok(())
}

/// Retrieve PRT data from a pre-collected `SystemdFds`.
///
/// This is a convenience wrapper; the actual collection happens in
/// `collect_systemd_fds()`.
pub fn restore_prts(fds: &mut SystemdFds) -> Option<Vec<u8>> {
    fds.prt_data.take()
}

/// Read the full contents of a file descriptor into a `Vec<u8>`.
///
/// Takes ownership of `fd` (wraps it in a `File`) and closes it when
/// done.  The FDs returned by `listen_fds_with_names` are owned by
/// this process.
fn read_fd_contents(fd: RawFd) -> io::Result<Vec<u8>> {
    // SAFETY: the fd was passed to us by systemd and is valid; we take
    // ownership so `File` will close it on drop.
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    file.seek(SeekFrom::Start(0))?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    Ok(buf)
}

/// Remove any previously stored PRT fd from systemd's FD store.
/// Called before storing a new one to avoid accumulating stale entries.
pub fn remove_prts_from_fdstore() {
    if let Err(e) = sd_notify::notify(
        false,
        &[
            NotifyState::FdStoreRemove,
            NotifyState::FdName(PRT_FDNAME),
        ],
    ) {
        warn!("Failed to remove old PRT from FD store: {}", e);
    }
}
