/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! Shared URIs
//!
//! ⚠️  ⚠️   WARNING  ⚠️  ⚠️
//!
//! IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS EVERYWHERE
//!
//! SERIOUSLY... DO NOT CHANGE THEM!
//!
/// ⚠️  ⚠️   WARNING DO NOT CHANGE THIS ⚠️  ⚠️
pub const OAUTH2_AUTHORISE: &str = "/oauth2/authorise";
/// ⚠️  ⚠️   WARNING DO NOT CHANGE THIS ⚠️  ⚠️
pub const OAUTH2_AUTHORISE_PERMIT: &str = "/oauth2/authorise/permit";
/// ⚠️  ⚠️   WARNING DO NOT CHANGE THIS  ⚠️  ⚠️
pub const OAUTH2_AUTHORISE_REJECT: &str = "/oauth2/authorise/reject";

pub const V1_AUTH_VALID: &str = "/v1/auth/valid";
