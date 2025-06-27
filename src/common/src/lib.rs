/*
 * Unix Azure Entra ID implementation
 * Copyright (C) William Brown <william@blackhats.net.au> and the Kanidm team 2018-2024
 * Copyright (C) David Mulder <dmulder@samba.org> 2024
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
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
pub mod auth;
#[cfg(target_family = "unix")]
pub mod client;
#[cfg(target_family = "unix")]
pub mod client_sync;
#[cfg(target_family = "unix")]
pub mod db;
#[cfg(target_family = "unix")]
pub mod hello_pin_complexity;
#[cfg(target_family = "unix")]
pub mod idmap_cache;
#[cfg(target_family = "unix")]
pub mod idprovider;
#[cfg(target_family = "unix")]
pub mod mapping;
#[cfg(target_family = "unix")]
pub mod nss_cache;
#[cfg(target_family = "unix")]
pub mod pam;
#[cfg(target_family = "unix")]
pub mod resolver;
#[cfg(target_family = "unix")]
pub mod tpm;
#[cfg(target_family = "unix")]
pub mod unix_passwd;
#[cfg(target_family = "unix")]
pub mod unix_proto;
