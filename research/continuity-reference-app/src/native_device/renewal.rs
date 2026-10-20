// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Original SDK-owned public request for retained-state credential authorization.
use super::*;
use crate::enrollment::wire;
use serde::Deserialize;

/// Public issuer inputs only. A received request supplies no account permission,
/// trusted root, reservation or signed G; issuers must check their own records.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedCredentialRequest {
    pub schema: String,
    pub application: [u8; 32],
    pub enrollment: [u8; 32],
    pub root_revision: u64,
    pub operation: [u8; 32],
    pub journal: [u8; 32],
    pub original_owner: [u8; 32],
    pub original_policy: Checkpoint,
    pub current_policy: Checkpoint,
    pub current_policy_authorization: Option<[u8; 32]>,
    pub previous_checkpoint: Checkpoint,
    #[serde(with = "wire")]
    pub original_certificate: Vec<u8>,
    #[serde(with = "wire")]
    pub previous_certificate: Vec<u8>,
    #[serde(with = "wire")]
    pub original_roster: Vec<u8>,
    #[serde(with = "wire")]
    pub previous_roster: Vec<u8>,
}

fn checkpoint(value: sdk::PolicyCheckpoint) -> Checkpoint {
    Checkpoint {
        version: value.version(),
        digest: value.digest(),
    }
}

impl NativeDevice {
    /// Observe the original enrollment and matched journal, including after
    /// expiry. No fresh identity, signature or live runtime owner is returned.
    pub fn credential_renewal_request(
        &mut self,
        operation: [u8; 32],
        original_policy: &sdk::HistoricalSessionPolicy,
        witness: Option<sdk::AnchorPin>,
        endpoint: Option<SocketAddr>,
    ) -> Result<RetainedCredentialRequest> {
        let result = self.credential_request_attempt(operation, original_policy, witness, endpoint);
        if result.is_err() {
            self.close();
        }
        result
    }
    fn credential_request_attempt(
        &mut self,
        operation: [u8; 32],
        original_policy: &sdk::HistoricalSessionPolicy,
        witness: Option<sdk::AnchorPin>,
        endpoint: Option<SocketAddr>,
    ) -> Result<RetainedCredentialRequest> {
        if original_policy.family() != self.invitation.family {
            return Err("Historical policy family differs from original enrollment".into());
        }
        let operation = sdk::CredentialRenewalId::from_trusted_state(operation)?;
        let request = match (witness, endpoint) {
            (None, None) => self
                .owner
                .credential_renewal_request(operation, original_policy)?,
            (Some(pin), Some(address)) => {
                let carrier = self.owner.credential_renewal_request_anchor_client(
                    original_policy,
                    pin,
                    Box::new(sdk::AnchorTcpTransport::new(address)),
                    Duration::from_secs(10),
                )?;
                self.owner.witnessed_credential_renewal_request(
                    operation,
                    original_policy,
                    carrier,
                )?
            }
            _ => return Err("Historical witness pin and endpoint must match".into()),
        };
        Ok(RetainedCredentialRequest {
            schema: "qperiapt-retained-credential-request/1".into(),
            application: self.invitation.application,
            enrollment: self.invitation.operation,
            root_revision: self.invitation.root_revision,
            operation: *request.operation().as_bytes(),
            journal: *request.journal().as_bytes(),
            original_owner: request.original_owner(),
            original_policy: checkpoint(original_policy.checkpoint()),
            current_policy: checkpoint(request.current_policy()),
            current_policy_authorization: request.current_policy_authorization(),
            previous_checkpoint: request.authorization().previous.into(),
            original_certificate: request.original_credential().to_vec(),
            previous_certificate: request.previous_credential().to_vec(),
            original_roster: request.original_roster().to_vec(),
            previous_roster: request.previous_roster().to_vec(),
        })
    }
}
