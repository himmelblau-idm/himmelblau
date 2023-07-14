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
pub use himmelblau_unix_common::unix_proto;

#[cfg(target_family = "unix")]
pub use himmelblau_unix_common::client_sync;

#[cfg(target_family = "unix")]
pub use himmelblau_unix_common::constants;

#[cfg(target_family = "unix")]
pub mod unix_config;
