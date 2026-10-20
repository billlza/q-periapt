// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Public policy-only request; account authentication and issuer decisions remain external.
use crate::enrollment::{wire, Checkpoint, Invitation, RootInfo};
use q_periapt_continuity_identity_candidate as sdk;
use serde::{Deserialize, Serialize};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub fn checkpoint(value: sdk::PolicyCheckpoint) -> Checkpoint {
    Checkpoint {
        version: value.version(),
        digest: value.digest(),
    }
}
fn policy(value: Checkpoint) -> Result<sdk::PolicyCheckpoint> {
    Ok(sdk::PolicyCheckpoint::from_trusted_state(
        value.version,
        value.digest,
    )?)
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub operation: [u8; 32],
    pub journal: [u8; 32],
    pub original_owner: [u8; 32],
    pub original_credential: [u8; 32],
    pub current_credential: [u8; 32],
    pub current_roster: Checkpoint,
    pub original_policy: Checkpoint,
    pub previous_policy: Checkpoint,
    #[serde(deserialize_with = "required_authorization")]
    pub previous_authorization: Option<[u8; 32]>,
}
fn required_authorization<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<[u8; 32]>, D::Error> {
    Option::deserialize(d)
}
impl Scope {
    pub fn as_sdk(&self) -> Result<sdk::PolicyRenewalScope> {
        Ok(sdk::PolicyRenewalScope {
            operation: sdk::PolicyRenewalId::from_trusted_state(self.operation)?,
            journal: sdk::JournalIdentity::from_trusted_state(self.journal)?,
            original_owner: self.original_owner,
            original_credential: self.original_credential,
            current_credential: self.current_credential,
            current_roster: self.current_roster.as_sdk()?,
            original_policy: policy(self.original_policy)?,
            previous_policy: policy(self.previous_policy)?,
            previous_authorization: self.previous_authorization,
        })
    }
}
impl From<&sdk::PolicyRenewalScope> for Scope {
    fn from(value: &sdk::PolicyRenewalScope) -> Self {
        Self {
            operation: *value.operation.as_bytes(),
            journal: *value.journal.as_bytes(),
            original_owner: value.original_owner,
            original_credential: value.original_credential,
            current_credential: value.current_credential,
            current_roster: value.current_roster.into(),
            original_policy: checkpoint(value.original_policy),
            previous_policy: checkpoint(value.previous_policy),
            previous_authorization: value.previous_authorization,
        }
    }
}
/// Reported public context, never proof of account permission or durable reservation.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema: String,
    pub application: [u8; 32],
    pub enrollment: [u8; 32],
    pub root_revision: u64,
    pub scope: Scope,
    pub original_checkpoint: Checkpoint,
    #[serde(with = "wire")]
    pub original_certificate: Vec<u8>,
    #[serde(with = "wire")]
    pub original_roster: Vec<u8>,
    #[serde(with = "wire")]
    pub current_certificate: Vec<u8>,
    #[serde(with = "wire")]
    pub current_roster: Vec<u8>,
}
impl Request {
    pub(crate) fn from_owner(value: &sdk::PolicyRenewalRequest, invitation: &Invitation) -> Self {
        Self {
            schema: "qperiapt-retained-policy-request/1".into(),
            application: invitation.application,
            enrollment: invitation.operation,
            root_revision: invitation.root_revision,
            scope: value.scope().into(),
            original_checkpoint: value.original_device().roster().checkpoint().into(),
            original_certificate: value.original_credential().to_vec(),
            original_roster: value.original_roster().to_vec(),
            current_certificate: value.current_credential().to_vec(),
            current_roster: value.current_roster().to_vec(),
        }
    }
    /// Check signed identities against independently selected current account trust.
    /// Issuers still authenticate the caller and approve this exact scope; the SDK
    /// later compares it with the original enrollment and actual journal history.
    pub fn verify_identities(
        &self,
        current: &RootInfo,
        now: u64,
    ) -> Result<VerifiedPolicyIdentities> {
        self.identities(current, Some(now))
    }
    /// Authenticate retained signed snapshots for result recovery only. This
    /// neither checks current validity nor authorizes a new issuer decision.
    pub fn verify_historical_identities(
        &self,
        current: &RootInfo,
    ) -> Result<VerifiedPolicyIdentities> {
        self.identities(current, None)
    }
    pub(crate) fn check_shape(&self) -> Result<()> {
        if self.schema != "qperiapt-retained-policy-request/1"
            || self.application == [0; 32]
            || self.enrollment == [0; 32]
            || self.root_revision == 0
            || [
                &self.original_certificate,
                &self.original_roster,
                &self.current_certificate,
                &self.current_roster,
            ]
            .iter()
            .any(|bytes| bytes.is_empty() || bytes.len() > 16384)
        {
            return Err("Invalid retained policy request".into());
        }
        self.scope.as_sdk()?;
        Ok(())
    }
    fn identities(
        &self,
        current: &RootInfo,
        live_at: Option<u64>,
    ) -> Result<VerifiedPolicyIdentities> {
        self.check_shape()?;
        if self.root_revision != current.revision {
            return Err("Policy request root revision differs".into());
        }
        let scope = self.scope.as_sdk()?;
        let roster = current
            .roster
            .as_ref()
            .ok_or("Current roster is required")?;
        if roster.checkpoint != self.scope.current_roster || roster.bytes != self.current_roster {
            return Err("Policy request differs from independently current roster".into());
        }
        let key = sdk::PublicKey::decode(&current.public_key)?;
        let original = sdk::AccountPin::new(
            current.account,
            key.clone(),
            self.original_checkpoint.as_sdk()?,
            current.family,
        )?
        .verify_historical_device(&self.original_certificate, &self.original_roster)?;
        let current_pin = sdk::AccountPin::new(
            current.account,
            key,
            roster.checkpoint.as_sdk()?,
            current.family,
        )?;
        let current = match live_at {
            Some(now) => {
                current_pin.verify_device(&self.current_certificate, &self.current_roster, now)?
            }
            None => current_pin
                .verify_historical_device(&self.current_certificate, &self.current_roster)?,
        };
        Ok(VerifiedPolicyIdentities {
            scope,
            original,
            current,
        })
    }
}
/// Signature-verified identity snapshots; no current owner or issuer authorization.
pub struct VerifiedPolicyIdentities {
    scope: sdk::PolicyRenewalScope,
    original: sdk::VerifiedDevice,
    current: sdk::VerifiedDevice,
}
impl VerifiedPolicyIdentities {
    pub fn historical_materials<'a>(
        &'a self,
        original: &'a sdk::HistoricalSessionPolicy,
        previous: &'a sdk::HistoricalSessionPolicy,
        target: &'a sdk::HistoricalSessionPolicy,
    ) -> sdk::HistoricalPolicyRenewalMaterials<'a> {
        sdk::HistoricalPolicyRenewalMaterials {
            original,
            previous,
            target,
            original_device: &self.original,
            current_device: &self.current,
        }
    }
    pub fn materials<'a>(
        &'a self,
        original: &'a sdk::HistoricalSessionPolicy,
        previous: &'a sdk::HistoricalSessionPolicy,
        target: &'a sdk::VerifiedSessionPolicy,
    ) -> sdk::PolicyRenewalMaterials<'a> {
        sdk::PolicyRenewalMaterials {
            original,
            previous,
            target,
            original_device: &self.original,
            current_device: &self.current,
        }
    }
    /// Reported scope; statement verification and the durable owner still bind it.
    pub fn scope(&self) -> &sdk::PolicyRenewalScope {
        &self.scope
    }
}
