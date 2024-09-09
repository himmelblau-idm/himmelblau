/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#[cfg(target_family = "windows")]
mod windows;
#[cfg(target_family = "windows")]
pub use windows::{diagnose_path, readonly};

#[cfg(target_family = "unix")]
mod unix;
#[cfg(target_family = "unix")]
pub use unix::{diagnose_path, readonly};
