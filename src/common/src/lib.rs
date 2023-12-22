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

#[cfg(target_family = "unix")]
#[macro_use]
extern crate tracing;
#[cfg(target_family = "unix")]
#[macro_use]
extern crate rusqlite;

#[cfg(target_family = "unix")]
pub mod config;
#[cfg(target_family = "unix")]
pub mod constants;
#[cfg(target_family = "unix")]
pub mod unix_config;

// Kanidm modules
#[cfg(target_family = "unix")]
#[path = "../../kanidm/unix_integration/src/client.rs"]
pub mod client;
#[cfg(target_family = "unix")]
#[path = "../../kanidm/unix_integration/src/client_sync.rs"]
pub mod client_sync;
#[cfg(target_family = "unix")]
#[path = "../../kanidm/unix_integration/src/db.rs"]
pub mod db;
#[cfg(target_family = "unix")]
#[path = "../../kanidm/libs/file_permissions/src/lib.rs"]
pub mod file_permissions;
#[cfg(target_family = "unix")]
pub mod idprovider;
#[cfg(target_family = "unix")]
#[path = "../../kanidm/unix_integration/src/resolver.rs"]
pub mod resolver;
#[cfg(target_family = "unix")]
#[path = "../../kanidm/unix_integration/src/unix_passwd.rs"]
pub mod unix_passwd;
#[cfg(target_family = "unix")]
#[path = "../../kanidm/unix_integration/src/unix_proto.rs"]
pub mod unix_proto;
