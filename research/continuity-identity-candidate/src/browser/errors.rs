// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::AnchorClientError;
use std::io::ErrorKind;
fn io_code(kind: ErrorKind, otherwise: &'static str) -> &'static str {
    match kind {
        ErrorKind::WouldBlock => "Busy",
        ErrorKind::Interrupted => "Cancelled",
        ErrorKind::TimedOut => "Deadline",
        ErrorKind::InvalidData => "InvalidData",
        ErrorKind::InvalidInput => "InvalidInput",
        ErrorKind::Unsupported => "Unavailable",
        _ => otherwise,
    }
}
fn runtime_code(error: &q_periapt_sdk::Error) -> &'static str {
    use q_periapt_sdk::Error as E;
    match error {
        E::Closed => "Closed",
        E::InvalidLength => "InvalidLength",
        E::PolicyDenied => "PolicyDenied",
        E::UpdateOwnerRequired => "UpdateOwnerRequired",
        E::InvalidKeyShare => "InvalidKeyShare",
        E::Entropy => "Entropy",
        E::ResourceLimit => "Capacity",
        E::InvalidLimits => "InvalidLimits",
        E::InvalidPurpose => "InvalidPurpose",
        E::InvalidPrivateKey => "InvalidPrivateKey",
        E::Backend => "Backend",
    }
}
fn protocol_code(error: &Error) -> &'static str {
    match error {
        Error::Encoding => "Encoding",
        Error::Authentication => "Authentication",
        Error::Scope => "Scope",
        Error::Validity => "Validity",
        Error::Checkpoint => "Checkpoint",
        Error::PolicyDenied => "PolicyDenied",
        Error::Conflict => "Conflict",
        Error::State => "State",
        Error::Runtime(error) => runtime_code(error),
        Error::Capacity => "Capacity",
        Error::RekeyRequired => "RekeyRequired",
        Error::Retired => "Retired",
        Error::Closed => "Closed",
        Error::Entropy => "Entropy",
        Error::Provider => "Provider",
    }
}
fn code(error: &DurableError) -> &'static str {
    use DurableError as E;
    match error {
        E::Absent => "Absent",
        E::Closed => "Closed",
        E::PrivateFile => "PrivateFile",
        E::Database(_) => "Database",
        E::Io(error) => io_code(error.kind(), "Io"),
        E::Storage(_) => "Storage",
        E::CommitUncertain(_) => "CommitUnknown",
        E::Authentication => "Authentication",
        E::Corrupt => "Corrupt",
        E::InvalidCheckpoint(_) => "InvalidCheckpoint",
        E::Conflict => "Conflict",
        E::PrekeyClaimed => "PrekeyClaimed",
        E::KeyRetired => "KeyRetired",
        E::Capacity => "Capacity",
        E::Suspended => "Suspended",
        E::AnchorRequired => "AnchorRequired",
        E::ArchiveRequired => "ArchiveRequired",
        E::Rejected => "Rejected",
        E::Protocol(error) => protocol_code(error),
        E::Anchor(error) => match error.as_ref() {
            AnchorClientError::Transport(error) => io_code(error.kind(), "WitnessTransport"),
            AnchorClientError::Verification(_) => "WitnessVerification",
            AnchorClientError::Conflict => "WitnessConflict",
            AnchorClientError::AuthorityDenied => "WitnessAuthorityDenied",
        },
    }
}
/// Classify a shared engine failure without discarding its original cause/receipts.
pub fn failure(error: &DurableError) -> JsValue {
    Storage::continuity_failure(code(error), &Storage::failure_value(error), None)
}
/// Classify a binding input failure before dispatch, preserving the original error.
pub fn input_failure(error: JsValue) -> JsValue {
    Storage::continuity_failure("InvalidInput", &error, None)
}
pub(super) fn owned(error: JsValue, closed: bool) -> JsValue {
    Storage::continuity_failure("NativeFailure", &error, Some(closed))
}
