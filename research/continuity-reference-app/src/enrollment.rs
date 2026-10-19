// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Host transaction values. A returned root or roster is not a client trust anchor.
use crate::error::Error;
use q_periapt_continuity_identity_candidate as sdk;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub version: u64,
    pub digest: [u8; 32],
}
impl From<sdk::RosterCheckpoint> for Checkpoint {
    fn from(value: sdk::RosterCheckpoint) -> Self {
        Self {
            version: value.version(),
            digest: value.digest(),
        }
    }
}
impl Checkpoint {
    pub fn as_sdk(self) -> Result<sdk::RosterCheckpoint, sdk::Error> {
        sdk::RosterCheckpoint::from_trusted_state(self.version, self.digest)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Invitation {
    pub operation: [u8; 32],
    /// Caller-retained correlation identity; it grants no authority.
    pub request_id: [u8; 32],
    pub application: [u8; 32],
    pub root_revision: u64,
    #[serde(with = "wire")]
    pub root: Vec<u8>,
    pub family: [u8; 32],
    pub device: [u8; 16],
    pub generation: u64,
    pub valid_from: u64,
    pub valid_until: u64,
    pub deadline: u64,
    pub predecessor: Option<Checkpoint>,
}
impl Invitation {
    /// Use only after independently authenticating the host and its approval.
    pub fn intent(&self) -> Result<sdk::EnrollmentIntent, sdk::Error> {
        Ok(sdk::EnrollmentIntent::new(
            sdk::PublicKey::decode(&self.root)?,
            sdk::DeviceDescription::new(
                self.device,
                self.generation,
                self.family,
                sdk::Validity::new(self.valid_from, self.valid_until)?,
            )?,
        ))
    }
    pub(crate) fn current(&self, now: u64) -> Result<(), Error> {
        if now < self.valid_from || now >= self.deadline || now >= self.valid_until {
            return Err(Error::Conflict("Original enrollment approval expired"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RootInfo {
    pub revision: u64,
    pub account: [u8; 32],
    #[serde(with = "wire")]
    pub public_key: Vec<u8>,
    pub family: [u8; 32],
    pub suspended: bool,
    pub roster: Option<RosterSnapshot>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RosterSnapshot {
    pub checkpoint: Checkpoint,
    #[serde(with = "wire")]
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IssuedEnrollment {
    pub operation: [u8; 32],
    pub root_revision: u64,
    #[serde(with = "wire")]
    pub certificate: Vec<u8>,
    #[serde(with = "wire")]
    pub roster: Vec<u8>,
    pub checkpoint: Checkpoint,
}

/// Explicit host approval for a same-key validity extension. Retain this exact
/// request before submission. It is not a device possession proof or a G grant.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CredentialExtensionRequest {
    pub request_id: [u8; 32],
    pub enrollment: [u8; 32],
    /// None selects the original issued enrollment; otherwise select an exact
    /// extension request ID from this same account and original enrollment.
    #[serde(deserialize_with = "selected_extension")]
    pub previous_extension: Option<[u8; 32]>,
    pub predecessor: Checkpoint,
    pub valid_until: u64,
}

fn selected_extension<'de, D: serde::Deserializer<'de>>(
    value: D,
) -> Result<Option<[u8; 32]>, D::Error> {
    Option::<[u8; 32]>::deserialize(value)
}

/// Exact committed certificate/roster result. Independent current root, roster
/// and policy verification still belongs to the consumer.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IssuedCredentialExtension {
    pub request: CredentialExtensionRequest,
    pub root_revision: u64,
    #[serde(with = "wire")]
    pub certificate: Vec<u8>,
    #[serde(with = "wire")]
    pub roster: Vec<u8>,
    pub checkpoint: Checkpoint,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", deny_unknown_fields)]
pub enum EnrollmentStatus {
    Invited {
        invitation: Invitation,
    },
    Approved {
        invitation: Invitation,
    },
    Issued {
        /// Exact committed JSON response. Historical issuance is not present authority.
        #[serde(with = "wire")]
        response: Vec<u8>,
        current: RootInfo,
    },
    Closed,
    /// Historical transition to a separately approved successor operation.
    /// Query that exact successor; this observation grants no current permission.
    Reapproved {
        successor: Invitation,
    },
}

pub(crate) fn now() -> Result<u64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| Error::internal("trusted host clock", e))
}
pub(crate) fn random<const N: usize>() -> Result<[u8; N], Error> {
    let mut value = [0; N];
    getrandom::fill(&mut value).map_err(|e| Error::internal("enrollment identity entropy", e))?;
    if value == [0; N] {
        return Err(Error::Internal);
    }
    Ok(value)
}

#[cfg(test)]
pub(crate) fn test_boundary(name: &str, bytes: &[u8]) -> Result<(), Error> {
    if std::env::var("QPERIAPT_ISSUER_BARRIER").ok().as_deref() != Some(name) {
        return Ok(());
    }
    let marker = std::env::var_os("QPERIAPT_ISSUER_MARKER").ok_or(Error::Internal)?;
    let marker = std::path::PathBuf::from(marker);
    let pending = marker.with_extension("partial");
    std::fs::write(&pending, bytes).map_err(db_test_error)?;
    std::fs::rename(pending, marker).map_err(db_test_error)?;
    loop {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}
#[cfg(test)]
fn db_test_error(e: std::io::Error) -> Error {
    Error::internal("issuer fault boundary", e)
}
pub(crate) mod wire {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&URL_SAFE_NO_PAD.encode(bytes))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value.len() > 128 * 1024 {
            return Err(serde::de::Error::custom("byte field exceeds bound"));
        }
        URL_SAFE_NO_PAD
            .decode(value)
            .map_err(serde::de::Error::custom)
    }
}
