/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use core::fmt;
use std::{fs::Metadata, path::Path};
/// Check a given file's metadata is read-only for the current user (true = read-only) Stub function if you're building for windows!
pub fn readonly(meta: &Metadata) -> bool {
    eprintln!(
        "Windows target asked to check metadata on {:?} returning false",
        meta
    );
    false
}

#[derive(Debug)]
pub struct Diagnosis;

impl fmt::Display for Diagnosis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Unable to diagnose path issues on windows 😢")
    }
}

pub fn diagnose_path(path: &Path) -> Diagnosis {
    Diagnosis {}
}
