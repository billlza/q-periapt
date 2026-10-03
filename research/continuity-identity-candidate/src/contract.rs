// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Shared candidate format and resource constants for service adapters.
//!
//! These describe the implemented profile, not authenticated peer assertions,
//! runtime grants, a negotiated algorithm list or a frozen product specification.
//! Parsing, signature verification, current authority and durable admission remain
//! separate. In particular, the application-send allowance comes from the signed
//! session policy; no unsigned default is supplied here.

/// External ML-DSA context and prefix for the dual-signature envelope.
pub const SIGNATURE_CONTEXT: &[u8] = b"Q-PERIAPT-CONTINUITY-IDENTITY-CANDIDATE/v1";
/// Exact fixed rekey profile description hashed into every signed control.
pub const REKEY_PROFILE: &[u8] = b"ML-KEM-768+X25519/ContextBound;ML-DSA-65+P-256/SHA-256;accountable-epoch-ratchet/v6;messages/v3;retained-epochs=4;settled-prefix-attestation/v1;application-send-budget/v1;control-request/v1";
/// Rekey transcript/KDF domain, including its separator before each purpose label.
pub const REKEY_DOMAIN: &[u8] = b"Q-PERIAPT-CONTINUITY-REKEY-CANDIDATE/v1/";
/// Epoch-scoped message, identifier and acknowledgement domain.
pub const MESSAGE_DOMAIN: &[u8] = b"Q-PERIAPT-CONTINUITY-MESSAGES-CANDIDATE/v2/";
/// Fixed public profile commitment found in every signed rekey control.
pub fn rekey_profile_digest() -> [u8; 32] {
    crate::crypto::digest(&[REKEY_DOMAIN, b"offer-profile"].concat(), REKEY_PROFILE)
}
/// Largest body admitted by the shared signed-envelope codec, in bytes.
pub const MAX_SIGNED_BODY_BYTES: usize = 16 * 1024;
/// Largest complete untrusted public bootstrap container, in bytes.
pub const MAX_BOOTSTRAP_BUNDLE_BYTES: usize = 65_536;
/// Largest individual field of that container, excluding its u16 length.
pub const MAX_BOOTSTRAP_FIELD_BYTES: usize = 8192;
/// Largest application plaintext, in bytes; zero-length plaintext is permitted.
pub const MAX_PLAINTEXT_BYTES: usize = 16 * 1024;
/// Largest application associated-data input, in bytes.
pub const MAX_ASSOCIATED_DATA_BYTES: usize = 1024;
/// Largest retained skipped-key set for one direction in one retained epoch.
pub const MAX_SKIPPED_MESSAGE_KEYS: usize = 128;
/// Largest outstanding record count for one direction in one retained epoch.
pub const MAX_OUTSTANDING_MESSAGES: usize = 64;
/// Largest retained traffic history. Retirement still requires signed settlement.
pub const MAX_TRAFFIC_EPOCHS: usize = 4;
/// Largest signed control carried inside QPCCTL01, excluding the carrier header.
pub const MAX_CONTROL_BYTES: usize = 8192;
/// Largest complete QPCNET01 carrier frame, including its nine-byte header.
pub const MAX_CONNECTION_FRAME_BYTES: usize = 32_768;
/// Largest session/operation record count, excluding prekeys and account rosters.
pub const MAX_SESSION_OPERATION_RECORDS: usize = 128;
/// Largest prekey record count, including retained retired/consumed identities.
pub const MAX_PREKEY_RECORDS: usize = 1024;
/// Largest number of separately counted installed account rosters.
pub const MAX_ACCOUNT_ROSTER_RECORDS: usize = 64;
/// Largest retained device-generation history for each installed account.
pub const MAX_DEVICE_HISTORY_PER_ACCOUNT: usize = 256;
/// Largest authenticated aggregate journal image, in bytes.
pub const MAX_JOURNAL_IMAGE_BYTES: usize = 2 * 1024 * 1024;
/// Largest request-attempt allowance for one native carrier invocation.
pub const MAX_NETWORK_EXCHANGES: u16 = 128;
/// Largest total native carrier deadline interval; retries do not refresh it.
pub const MAX_RUN_TIMEOUT_SECONDS: u64 = 120;
/// Largest duration of one TCP connection attempt, in seconds.
pub const MAX_CONNECT_TIMEOUT_SECONDS: u64 = 5;
