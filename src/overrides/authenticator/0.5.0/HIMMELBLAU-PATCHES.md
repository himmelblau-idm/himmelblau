# Himmelblau local patch to authenticator 0.5.0

Upstream: https://crates.io/crates/authenticator/0.5.0 (Mozilla MPL-2.0).
Downloaded upstream .crate SHA-256:
`bbd6f57365675990f2db272a6560b28945df74cf3749c70aafd9b1c7829edebc`.

The original license is retained. This directory is pinned with the root
`[patch.crates-io]` entry and Cargo.lock; it is not a new upstream release.

Local changes:

* Add an opt-in `internal_uv_only` register/sign policy. It requires a biometric
  management-capable hmac-secret authenticator with configured built-in UV,
  rejects supplied PINs, rejects PIN fallback and internal UV lockout, and bounds
  reported verification failures. A nonserialized remaining-attempt limit caps
  synchronous CTAP 2.0 and 2.1 retry loops; zero is rejected before operation I/O.
  Existing WebAuthn callers leave the policy false and use existing defaults.
* Add a local-only transport path selector that is never serialized to CTAP;
  add an explicit management-only PIN assertion mode without HMAC output to prove
  selected-token credential ownership; expose constrained Linux selected-device
  management traits and non-interactive
  getInfo capability discovery. Make biometric enrollment and set/change-PIN
  helpers available to the daemon adapter.
* Opt-in bounded Linux HID reads for biometric discovery and operations use poll;
  legacy transport reads retain their previous behavior.
* Make decrypted hmac-secret outputs non-clonable, redact Debug, and wipe on
  drop. Wipe the transient decrypted output vector, PIN string, padded PIN,
  PIN hash, ECDH shared point, KDF PRK and component keys, shared-secret keys,
  PIN/UV tokens and authentication parameters, and PRF outputs. Native-backend
  ECDH/decryption buffers wipe on error and digest temporaries wipe after use. Existing
  protocol-required token/shared-key clones wipe their own allocations on drop.
* Remove the raw PIN-hash trace so secret-derived material is not retained in logs.
* Keep the existing malformed-length HMAC protocol fixtures and add fake-device
  tests proving biometric-only policy rejects PIN substitution before CTAP I/O.

This is a targeted hardening patch, not an independent security audit or a claim
that privileged hostile software cannot observe live secrets. OpenSSL owns and
frees native key/cipher contexts; Rust zeroization cannot attest compiler stacks,
CPU registers, or host integrity. Hardware-dependent behavior and supported
firmware must be validated on separate test machines before release.
