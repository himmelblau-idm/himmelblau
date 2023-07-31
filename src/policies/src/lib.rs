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
pub mod policies;

#[cfg(target_family = "unix")]
pub mod cse;

/* The following are Client Side Extensions for applying policy to the host.
 * Make sure these are added to policies::apply_group_policy().
 */

#[cfg(target_family = "unix")]
pub mod chromium_ext;
