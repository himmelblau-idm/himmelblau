/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use crate::Sha256Digest;

pub use ::x509_cert::der;
pub use ::x509_cert::der::pem;
pub use ::x509_cert::Certificate;

use ::sha2::{Digest, Sha256};

pub fn x509_public_key_s256(certificate: &Certificate) -> Option<Sha256Digest> {
    let public_key_bytes = certificate
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()?;

    let mut hasher = Sha256::new();
    hasher.update(public_key_bytes);
    Some(hasher.finalize())
}
