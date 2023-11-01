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
pub mod authentication;

#[cfg(target_family = "unix")]
pub mod misc;

#[cfg(target_family = "unix")]
pub mod discovery;

#[cfg(target_family = "unix")]
pub mod nonce;

#[cfg(target_family = "unix")]
pub mod enroll;

#[cfg(target_family = "unix")]
pub mod constants;

#[cfg(target_family = "unix")]
pub mod user;

#[cfg(target_family = "unix")]
pub mod application;
