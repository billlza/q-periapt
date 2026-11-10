// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Bounded public metadata authenticated by both approval signatures. This never
//! manufactures a VerifiedDevice or a current-policy/runtime permission.
use super::*;
use crate::{DeviceDescription, RosterCheckpoint};

const POLICY_BODY_BYTES: usize = 200;
const DESCRIPTION_BYTES: usize = 72;
pub(crate) const REQUEST_BYTES: usize = 8
    + 2 * crate::PUBLIC_KEY_BYTES
    + 2 * DESCRIPTION_BYTES
    + 40
    + 2 * POLICY_BODY_BYTES
    + MAX_ANCHOR_HANDOFF_ADOPTION_BYTES;

pub(super) struct Claims<'a> {
    pub(super) original: &'a DeviceDescription,
    pub(super) current: &'a DeviceDescription,
    pub(super) roster: RosterCheckpoint,
    pub(super) account: &'a PublicKey,
    pub(super) device: &'a PublicKey,
    pub(super) original_policy: &'a HistoricalSessionPolicy,
    pub(super) current_policy: &'a HistoricalSessionPolicy,
    pub(super) history: &'a AnchorHandoffHistory,
    pub(super) activation: &'a AnchorHandoffActivationReceipt,
}
fn owner(account: [u8; 32], description: &DeviceDescription, device: &PublicKey) -> [u8; 32] {
    crate::bootstrap::credential_storage_owner(
        account,
        description.id,
        description.generation,
        crate::identity::device_credential_digest(account, description, device),
    )
}
pub(super) fn check_claims(s: &AnchorHandoffAdoptionScope, m: &Claims<'_>) -> Result<(), Error> {
    AnchorHandoffAdoptionScope::decode(&s.encode())?;
    continuation::same_profile(m.original_policy, m.current_policy)?;
    let account = crate::identity::account_id(m.account);
    let (_, original_owner, original_policy) = s.subject.journal_parts();
    if original_owner != owner(account, m.original, m.device)
        || original_policy != m.original_policy.checkpoint().digest()
        || s.namespace != m.history.namespace_binding()
        || s.history != m.history.checkpoint()
        || s.successor != m.history.current_pin().binding()
        || s.predecessor == s.successor
        || s.history != m.activation.history_checkpoint()
        || s.activation != activation_digest(m.activation.as_bytes())
        || s.family != m.original_policy.family()
        || s.policy != m.current_policy.checkpoint()
        || s.credential_owner != owner(account, m.current, m.device)
        || s.authority != crate::identity::authority_binding(account, m.roster, s.family)
        || m.original.id != m.current.id
        || m.original.generation != m.current.generation
        || m.original.family != s.family
        || m.current.family != s.family
        || m.original.validity.from() != m.current.validity.from()
        || m.original.validity.until() > m.current.validity.until()
        || m.current_policy.checkpoint().version() < m.original_policy.checkpoint().version()
        || (m.current_policy.checkpoint().version() == m.original_policy.checkpoint().version()
            && m.current_policy.checkpoint() != m.original_policy.checkpoint())
        || m.current_policy.validity().until() < m.original_policy.validity().until()
        || m.original_policy.anchor_requirement().binding() != Some(s.logical)
    {
        return Err(Error::Scope);
    }
    for binding in [s.logical, s.predecessor, s.successor] {
        let pin = m.history.historical_pin(binding)?;
        if pin.public_key().shares_component(m.device)
            || pin.public_key().shares_component(m.account)
        {
            return Err(Error::Scope);
        }
        m.original_policy.check_external_signer(pin.public_key())?;
    }
    m.original_policy.check_external_signer(m.device)?;
    m.original_policy.check_external_signer(m.account)
}

fn encode_description(d: &DeviceDescription, out: &mut Vec<u8>) {
    out.extend_from_slice(&d.id);
    out.extend_from_slice(&d.generation.to_be_bytes());
    out.extend_from_slice(&d.family);
    d.validity.encode(out);
}
fn decode_description(d: &mut Decoder<'_>) -> Result<DeviceDescription, Error> {
    let id = d.array()?;
    let generation = d.u64()?;
    let family = d.array()?;
    DeviceDescription::new(id, generation, family, Validity::decode(d)?)
}
fn policy_body(p: &HistoricalSessionPolicy) -> Result<Vec<u8>, Error> {
    let mut out = POLICY_TAG.to_vec();
    out.extend_from_slice(&p.family);
    out.extend_from_slice(&p.checkpoint.version().to_be_bytes());
    p.validity.encode(&mut out);
    out.extend_from_slice(&bootstrap_suite_digest());
    out.extend_from_slice(&p.sdk);
    out.push(p.modes.0);
    p.anchor.encode(&mut out);
    out.extend_from_slice(&p.budget.messages().to_be_bytes());
    if out.len() != POLICY_BODY_BYTES {
        return Err(Error::Encoding);
    }
    PolicyPin::new(p.family, p.signer.clone(), p.checkpoint)?.decode_bound_body(&out)?;
    Ok(out)
}

/// Authenticated only after verifying both roots AND matching these claims with
/// the original imported entry or independently retained original client owner.
pub(crate) struct RetainedAdoptionRequest {
    pub(crate) approved: HistoricalAnchorHandoffAdoption,
    pub(crate) original: DeviceDescription,
    pub(crate) account: [u8; 32],
    bytes: Vec<u8>,
}
impl RetainedAdoptionRequest {
    pub(crate) fn scope(&self) -> &AnchorHandoffAdoptionScope {
        self.approved.scope()
    }
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    // This is only bounded grammar for choosing an existing original entry. No
    // key or permission may be accepted until restore verifies the whole request.
    pub(crate) fn unverified_scope(bytes: &[u8]) -> Result<AnchorHandoffAdoptionScope, Error> {
        if bytes.len() != REQUEST_BYTES {
            return Err(Error::Encoding);
        }
        let pair_start = REQUEST_BYTES
            .checked_sub(MAX_ANCHOR_HANDOFF_ADOPTION_BYTES)
            .ok_or(Error::Encoding)?;
        let (a, _) = read_pair(bytes.get(pair_start..).ok_or(Error::Encoding)?)?;
        AnchorHandoffAdoptionScope::decode(open_envelope(a.as_bytes())?.0)
    }
    pub(crate) fn restore(
        bytes: &[u8],
        device: &PublicKey,
        history: &AnchorHandoffHistory,
        activation: &AnchorHandoffActivationReceipt,
    ) -> Result<Self, Error> {
        let scope = Self::unverified_scope(bytes)?;
        let mut d = Decoder::new(bytes);
        if d.array::<8>()? != *b"QPAHCQ01" {
            return Err(Error::Encoding);
        }
        let account_key = PublicKey::decode(d.take(crate::PUBLIC_KEY_BYTES)?)?;
        let policy_key = PublicKey::decode(d.take(crate::PUBLIC_KEY_BYTES)?)?;
        let original = decode_description(&mut d)?;
        let current = decode_description(&mut d)?;
        let roster = RosterCheckpoint::from_trusted_state(d.u64()?, d.array()?)?;
        let original_body = d.take(POLICY_BODY_BYTES)?;
        let current_body = d.take(POLICY_BODY_BYTES)?;
        let signed = d.take(MAX_ANCHOR_HANDOFF_ADOPTION_BYTES)?;
        d.finish()?;
        let (a, p) = read_pair(signed)?;
        verify_pair(&a, &p, &scope, &account_key, &policy_key)?;
        // The dual approval commits to both complete policy-body digests. Reuse
        // the normal policy parser only after their authentication above.
        let mut original_header = Decoder::new(original_body);
        original_header.take(40)?;
        let expected_original = PolicyCheckpoint::from_trusted_state(
            original_header.u64()?,
            scope.subject.journal_parts().2,
        )?;
        let original_policy = PolicyPin::new(scope.family, policy_key.clone(), expected_original)?
            .decode_bound_body(original_body)?;
        let current_policy = PolicyPin::new(scope.family, policy_key, scope.policy)?
            .decode_bound_body(current_body)?;
        check_claims(
            &scope,
            &Claims {
                original: &original,
                current: &current,
                roster,
                account: &account_key,
                device,
                original_policy: &original_policy,
                current_policy: &current_policy,
                history,
                activation,
            },
        )?;
        Ok(Self {
            approved: HistoricalAnchorHandoffAdoption {
                scope,
                wire: signed.to_vec(),
            },
            original,
            account: crate::identity::account_id(&account_key),
            bytes: bytes.to_vec(),
        })
    }
}
impl HistoricalAnchorHandoffAdoption {
    /// Prepare bounded public metadata for the target's actual authorization
    /// transaction. The target independently rechecks both signatures and its
    /// original entry. This request is not a commit or a client adoption receipt.
    pub fn prepare_witness_authorization(
        &self,
        m: &AnchorHandoffAdoptionMaterials<'_>,
    ) -> Result<Vec<u8>, Error> {
        Self::from_bytes(self.as_bytes(), self.scope(), m)?;
        let mut bytes = b"QPAHCQ01".to_vec();
        bytes.extend_from_slice(&m.current_device.authority_key.encode());
        bytes.extend_from_slice(&m.original_policy.signer.encode());
        encode_description(&m.original_device.description, &mut bytes);
        encode_description(&m.current_device.description, &mut bytes);
        let roster = m.current_device.roster().checkpoint();
        bytes.extend_from_slice(&roster.version().to_be_bytes());
        bytes.extend_from_slice(&roster.digest());
        bytes.extend_from_slice(&policy_body(m.original_policy)?);
        bytes.extend_from_slice(&policy_body(m.current_policy)?);
        bytes.extend_from_slice(self.as_bytes());
        RetainedAdoptionRequest::restore(&bytes, &m.current_device.key, m.history, m.activation)?;
        Ok(bytes)
    }
}
