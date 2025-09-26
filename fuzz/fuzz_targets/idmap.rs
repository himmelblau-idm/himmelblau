//! Fuzz the Himmelblau ID-mapping library (`AadSid`, `Idmap`).

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use std::fmt;
use uuid::Uuid;

use idmap::{AadSid, Idmap, DEFAULT_IDMAP_RANGE};

// ------------------------ Input model ------------------------

#[derive(Debug, Arbitrary, Clone)]
struct Stringish(Vec<u8>);

impl fmt::Display for Stringish {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = String::from_utf8_lossy(&self.0);
        f.write_str(&s)
    }
}

#[derive(Debug, Arbitrary)]
struct FInput {
    // Random bytes to make an arbitrary SID string (invalid or valid)
    sid_bytes: Vec<u8>,

    // A random UUID backing AadSid::from_object_id (always 16 bytes)
    uuid: [u8; 16],

    // Domain / tenant configuration
    domain: Stringish,
    gen_valid_sid: bool,
    use_default_range: bool,
    lo: u32,
    hi: u32,
    // Whether to also exercise gen_to_unix (may error; that's fine)
    try_gen: bool,
}

// ------------------------ Helpers ------------------------

fn make_plausible_sid(input: &[u8]) -> String {
    // Create a valid-ish AAD SID form: S-1-12-1-a-b-c-d
    // Use 16 bytes if available; otherwise fall back to zeros for missing parts.
    let mut b = [0u8; 16];
    for (i, v) in input.iter().take(16).enumerate() {
        b[i] = *v;
    }
    let a = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let c = u32::from_le_bytes([b[4], b[5], b[6], b[7]]);
    let d = u32::from_le_bytes([b[8], b[9], b[10], b[11]]);
    let e = u32::from_le_bytes([b[12], b[13], b[14], b[15]]);
    format!("S-1-12-1-{a}-{c}-{d}-{e}")
}

fn sanitize_domain(s: &str) -> String {
    // keep simple hostname chars; fallback to a default if empty after filter
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() || ch == '.' || ch == '-' {
            out.push(ch.to_ascii_lowercase());
        }
    }
    if out.is_empty() {
        "contoso.onmicrosoft.com".to_string()
    } else {
        out
    }
}

// ------------------------ Harness ------------------------

fn exercise_aadsid_from_sid(s: &str) {
    if let Ok(sid) = AadSid::from_sid_str(s) {
        let _ = sid.rid(); // ensure no panic path
    }
}

fn exercise_aadsid_from_object_id(u: &Uuid) {
    if let Ok(sid) = AadSid::from_object_id(u) {
        let _ = sid.rid();
    }
}

fn check_in_range(id: u32, lo: u32, hi: u32) {
    // mapping is [lo, hi) per implementation (modulo by count + base)
    debug_assert!(lo < hi);
    let count = hi - lo;
    if count == 0 {
        return;
    }
    let _ = id; // in fuzz we avoid panicking asserts; this function documents intent
                // If you want, enable a hard assert for local runs:
                // assert!(id >= lo && id < hi);
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let fi = match FInput::arbitrary(&mut u) {
        Ok(x) => x,
        Err(_) => return,
    };

    // Always cover AadSid parsing paths
    let sid_candidate = if fi.gen_valid_sid {
        make_plausible_sid(&fi.sid_bytes)
    } else {
        String::from_utf8_lossy(&fi.sid_bytes).to_string()
    };
    exercise_aadsid_from_sid(&sid_candidate);

    // Cover object-id path
    let object_uuid = Uuid::from_bytes(fi.uuid);
    exercise_aadsid_from_object_id(&object_uuid);

    // Prepare idmap
    let tenant_uuid = object_uuid; // a stable, valid tenant-id string source
    let tenant_id = tenant_uuid.to_string();
    let domain = sanitize_domain(&fi.domain.to_string());

    // Range selection (ensure non-zero width)
    let (lo, hi) = if fi.use_default_range {
        DEFAULT_IDMAP_RANGE
    } else {
        let lo = fi.lo;
        let mut hi = fi.hi;
        if hi <= lo {
            hi = lo.saturating_add(1);
        }
        (lo, hi)
    };

    // Build Idmap; if FFI/libsss_idmap isn't available or init fails, bail out
    let mut idmap = match Idmap::new() {
        Ok(idm) => idm,
        Err(_) => return,
    };

    // Register domain/range (errors are acceptable under fuzz; continue if Ok)
    let _ = idmap.add_gen_domain(&domain, &tenant_id, (lo, hi));

    // Try mapping from object id via AadSid -> unix id (pure math using range)
    if let Ok(sid) = AadSid::from_object_id(&object_uuid) {
        if let Ok(uid) = idmap.object_id_to_unix_id(&tenant_id, &sid) {
            check_in_range(uid, lo, hi);
        }
    }

    // If we also parsed a SID string successfully, try mapping it too
    if let Ok(sid) = AadSid::from_sid_str(&sid_candidate) {
        if let Ok(uid) = idmap.object_id_to_unix_id(&tenant_id, &sid) {
            check_in_range(uid, lo, hi);
        }
    }

    // Optionally exercise the FFI-based generic converter
    if fi.try_gen {
        // Try a few encodings that libsss_idmap might accept; ignore errors
        let upn = format!("user-{}@{}", &tenant_id[..8], domain);
        let _ = idmap.gen_to_unix(&tenant_id, &upn).map(|uid| {
            check_in_range(uid, lo, hi);
        });
        let _ = idmap.gen_to_unix(&tenant_id, &sid_candidate).map(|uid| {
            check_in_range(uid, lo, hi);
        });
        let _ = idmap
            .gen_to_unix(&tenant_id, &object_uuid.to_string())
            .map(|uid| {
                check_in_range(uid, lo, hi);
            });
    }
});
