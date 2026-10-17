// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Candidate qperiapt-credential-renewal/1 root authorization.
//! Verification is not a durable transition, session permission, or witness grant.
use super::*;

const CONTAINER: &[u8; 8] = b"QPRNB001";
const STATEMENT: &[u8; 8] = b"QPCRNW01";
const RETAINED_ESTABLISHED: u8 = 1;
const BODY_BYTES: usize = 8 + 32 + 32 + 16 + 8 + 6 * 32 + 2 * (8 + 32) + 1;
const MAX_FIELD: usize = 8192;
/// Maximum complete untrusted renewal authorization container.
pub const MAX_CREDENTIAL_RENEWAL_BYTES: usize = 65_536;

/// Caller-retained identity of one independently authorized renewal operation.
/// Possessing this public value grants no authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialRenewalId([u8; 32]);
impl CredentialRenewalId {
    /// Generate once, retain before submission, and reuse after an unknown result.
    pub fn generate() -> Result<Self, Error> {
        let mut bytes = [0; 32];
        getrandom::fill(&mut bytes).map_err(|_| Error::Entropy)?;
        Self::from_trusted_state(bytes)
    }
    /// Reconstruct the application's independently retained original operation.
    pub fn from_trusted_state(bytes: [u8; 32]) -> Result<Self, Error> {
        nonzero(&bytes)?;
        Ok(Self(bytes))
    }
    /// Stable public operation bytes, not a commit receipt.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Public signed materials for one exact predecessor-to-successor transition.
/// Old credentials/rosters are historical inputs, never current authorization.
pub struct CredentialRenewalMaterials<'a> {
    /// Original root-signed credential that defines the immutable storage owner.
    pub original_credential: &'a [u8],
    /// Exact root-signed predecessor, which may have expired.
    pub previous_credential: &'a [u8],
    /// Root-signed target extending validity for the same complete device key.
    pub successor_credential: &'a [u8],
    /// Signed historical roster containing the exact predecessor.
    pub previous_roster: &'a [u8],
    /// Signed current roster selected by the independent target pin.
    pub successor_roster: &'a [u8],
}
impl CredentialRenewalMaterials<'_> {
    fn fields(&self) -> [&[u8]; 5] {
        [
            self.original_credential,
            self.previous_credential,
            self.successor_credential,
            self.previous_roster,
            self.successor_roster,
        ]
    }
}

/// Exact host-approved scope supplied to the account issuer.
/// The issuer must separately authenticate the user, serialize current authority,
/// and durably deduplicate this operation. A signature does none of those things.
pub struct CredentialRenewalAuthorization {
    /// Original independently retained request identity, reused for exact retry.
    pub operation: CredentialRenewalId,
    /// Host-approved expected predecessor head; this value is not a freshness grant.
    pub previous: RosterCheckpoint,
    /// Exact nonzero protocol-policy digest for the authorized retained sessions.
    pub policy_digest: [u8; 32],
}

/// Original public grant bytes. Retain these exact bytes for a retry.
pub struct IssuedCredentialRenewal(Vec<u8>);
impl IssuedCredentialRenewal {
    /// Borrow the complete bounded public container without re-signing it.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Statement {
    operation: CredentialRenewalId,
    account: [u8; 32],
    device: [u8; 16],
    generation: u64,
    family: [u8; 32],
    key: [u8; 32],
    original: [u8; 32],
    previous: [u8; 32],
    successor: [u8; 32],
    policy: [u8; 32],
    previous_roster: RosterCheckpoint,
    successor_roster: RosterCheckpoint,
}
impl Statement {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(BODY_BYTES);
        out.extend_from_slice(STATEMENT);
        out.extend_from_slice(self.operation.as_bytes());
        out.extend_from_slice(&self.account);
        out.extend_from_slice(&self.device);
        out.extend_from_slice(&self.generation.to_be_bytes());
        for value in [
            self.family,
            self.key,
            self.original,
            self.previous,
            self.successor,
            self.policy,
        ] {
            out.extend_from_slice(&value);
        }
        for checkpoint in [self.previous_roster, self.successor_roster] {
            out.extend_from_slice(&checkpoint.version().to_be_bytes());
            out.extend_from_slice(&checkpoint.digest());
        }
        // Permission is identity-and-exact-policy scoped retained established
        // sessions. It never substitutes for current fresh-bootstrap admission.
        out.push(RETAINED_ESTABLISHED);
        out
    }
    fn decode(body: &[u8]) -> Result<Self, Error> {
        if body.len() != BODY_BYTES {
            return Err(Error::Encoding);
        }
        let mut d = Decoder::new(body);
        if d.array::<8>()? != *STATEMENT {
            return Err(Error::Encoding);
        }
        let value = Self {
            operation: CredentialRenewalId::from_trusted_state(d.array()?)?,
            account: d.array()?,
            device: d.array()?,
            generation: d.u64()?,
            family: d.array()?,
            key: d.array()?,
            original: d.array()?,
            previous: d.array()?,
            successor: d.array()?,
            policy: d.array()?,
            previous_roster: RosterCheckpoint::from_trusted_state(d.u64()?, d.array()?)?,
            successor_roster: RosterCheckpoint::from_trusted_state(d.u64()?, d.array()?)?,
        };
        if d.array::<1>()? != [RETAINED_ESTABLISHED] {
            return Err(Error::Encoding);
        }
        d.finish()?;
        nonzero(&value.account)?;
        nonzero(&value.device)?;
        generation(value.generation)?;
        for field in [
            value.family,
            value.key,
            value.original,
            value.previous,
            value.successor,
            value.policy,
        ] {
            nonzero(&field)?;
        }
        Ok(value)
    }
}

fn credential(root: &PublicKey, bytes: &[u8]) -> Result<(Credential, [u8; 32]), Error> {
    let (body, signature) = open_envelope(bytes)?;
    root.verify(Purpose::Credential, body, signature)?;
    let credential = Credential::decode(body)?;
    if credential.account != account_id(root) || credential.key.shares_component(root) {
        return Err(Error::Scope);
    }
    Ok((credential, certificate_digest(body)))
}

fn check_materials(
    materials: &CredentialRenewalMaterials<'_>,
    authorization: &CredentialRenewalAuthorization,
    pin: &AccountPin,
    now: u64,
) -> Result<(Statement, VerifiedDevice, VerifiedDevice), Error> {
    nonzero(&authorization.policy_digest)?;
    if materials
        .fields()
        .iter()
        .any(|field| field.is_empty() || field.len() > MAX_FIELD)
    {
        return Err(Error::Capacity);
    }
    if pin.checkpoint.version() <= authorization.previous.version() {
        return Err(Error::Checkpoint);
    }
    let (origin, original_digest) = credential(&pin.root, materials.original_credential)?;
    let previous_pin = AccountPin::new(
        pin.account,
        pin.root.clone(),
        authorization.previous,
        pin.family,
    )?;
    // This instant only validates historical signatures, membership and overlap.
    // It cannot authorize current traffic or revive a revoked predecessor.
    let historical =
        previous_pin.snapshot_start(materials.previous_credential, materials.previous_roster)?;
    if historical > now {
        return Err(Error::Validity);
    }
    let previous = previous_pin.verify_device(
        materials.previous_credential,
        materials.previous_roster,
        historical,
    )?;
    let successor = pin.verify_device(
        materials.successor_credential,
        materials.successor_roster,
        now,
    )?;
    let od = &origin.description;
    let pd = &previous.description;
    let sd = &successor.description;
    if origin.account != pin.account
        || od.id != pd.id
        || od.id != sd.id
        || od.generation != pd.generation
        || od.generation != sd.generation
        || od.family != pin.family
        || pd.family != pin.family
        || sd.family != pin.family
        || origin.key != previous.key
        || origin.key != successor.key
    {
        return Err(Error::Scope);
    }
    if od.validity.from != pd.validity.from
        || od.validity.from != sd.validity.from
        || od.validity.until > pd.validity.until
        || pd.validity.until >= sd.validity.until
    {
        return Err(Error::Validity);
    }
    let statement = Statement {
        operation: authorization.operation,
        account: pin.account,
        device: od.id,
        generation: od.generation,
        family: pin.family,
        key: digest(b"Q-PERIAPT-CREDENTIAL-RENEWAL-KEY/v1", &origin.key.encode()),
        original: original_digest,
        previous: previous.credential_digest(),
        successor: successor.credential_digest(),
        policy: authorization.policy_digest,
        previous_roster: authorization.previous,
        successor_roster: pin.checkpoint,
    };
    Ok((statement, previous, successor))
}

fn container(
    statement: &[u8],
    materials: &CredentialRenewalMaterials<'_>,
) -> Result<Vec<u8>, Error> {
    let mut out = CONTAINER.to_vec();
    for field in std::iter::once(statement).chain(materials.fields()) {
        if field.is_empty() || field.len() > MAX_FIELD {
            return Err(Error::Capacity);
        }
        let length = u16::try_from(field.len()).map_err(|_| Error::Capacity)?;
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(field);
    }
    if out.len() > MAX_CREDENTIAL_RENEWAL_BYTES {
        return Err(Error::Capacity);
    }
    Ok(out)
}
fn field<'a>(d: &mut Decoder<'a>) -> Result<&'a [u8], Error> {
    let length = usize::from(u16::from_be_bytes(d.array()?));
    if length == 0 || length > MAX_FIELD {
        return Err(Error::Capacity);
    }
    d.take(length)
}

impl RootSigningKey {
    /// Issue a same-key, same-generation credential validity extension from an
    /// authenticated historical predecessor. The account host must independently
    /// authorize the user and serialize its current roster. This is only the
    /// successor certificate; it neither signs G nor updates any durable state.
    /// Keep the exact returned bytes before building the target roster and G.
    pub fn issue_credential_extension(
        &self,
        previous: &VerifiedDevice,
        until: u64,
        now: u64,
    ) -> Result<Vec<u8>, Error> {
        if self.public_key()? != previous.authority_key {
            return Err(Error::Scope);
        }
        if until <= previous.description.validity.until() {
            return Err(Error::Validity);
        }
        let mut description = previous.description.clone();
        description.validity = Validity::new(description.validity.from(), until)?;
        description.validity.check(now)?;
        if now < previous.roster_validity.from() {
            return Err(Error::Validity);
        }
        self.issue_device(description, previous.key.clone())
    }
    /// Sign one host-approved same-key validity extension under a separate purpose.
    /// The host owns user approval, current-head serialization and exact dedup.
    /// This method does not update a roster, journal, peer, installation or witness.
    pub fn issue_credential_renewal(
        &self,
        materials: CredentialRenewalMaterials<'_>,
        authorization: &CredentialRenewalAuthorization,
        current_pin: &AccountPin,
        now: u64,
    ) -> Result<IssuedCredentialRenewal, Error> {
        if self.public_key()? != current_pin.root {
            return Err(Error::Scope);
        }
        let (statement, _, _) = check_materials(&materials, authorization, current_pin, now)?;
        let body = statement.encode();
        let signed = envelope(&body, &self.sign(Purpose::CredentialRenewal, &body)?)?;
        Ok(IssuedCredentialRenewal(container(&signed, &materials)?))
    }
}

/// Root-authenticated scoped relation, not a durable permission or owner override.
/// Every use must still match the original local state, exact predecessor or
/// original committed target, current policy/rosters, and required witness.
pub struct VerifiedCredentialRenewal {
    historical: HistoricalCredentialRenewal,
}
/// Authenticated historical root authorization for exact cleanup only.
/// This snapshot grants no current membership, policy permission or new Commit.
/// It exposes no operational device and cannot be converted to a current grant.
///
/// ```compile_fail
/// use q_periapt_continuity_identity_candidate::{AnchorStore, AnchorCredentialRenewalProposal,
///     HistoricalCredentialRenewal, VerifiedSessionPolicy};
/// fn prepare(store: &mut AnchorStore, proposal: AnchorCredentialRenewalProposal,
///            grant: &HistoricalCredentialRenewal, policy: &VerifiedSessionPolicy) {
///     let _ = store.prepare_credential_renewal(proposal, grant, policy, 100);
/// }
/// ```
pub struct HistoricalCredentialRenewal {
    statement: Statement,
    previous: VerifiedDevice,
    successor: Arc<VerifiedDevice>,
    wire: Vec<u8>,
}
impl AsRef<HistoricalCredentialRenewal> for VerifiedCredentialRenewal {
    fn as_ref(&self) -> &HistoricalCredentialRenewal {
        &self.historical
    }
}
impl AsRef<HistoricalCredentialRenewal> for HistoricalCredentialRenewal {
    fn as_ref(&self) -> &HistoricalCredentialRenewal {
        self
    }
}
// Public identity metadata only. This is not a durable or transferable grant.
pub(crate) struct ResolvedSessionIdentity {
    pub(crate) device: Arc<VerifiedDevice>,
    pub(crate) statement: [u8; 32],
    pub(crate) owner: [u8; 32],
}
impl VerifiedCredentialRenewal {
    pub(crate) fn resolve_established(
        &self,
        original: &VerifiedDevice,
        policy: [u8; 32],
    ) -> Result<ResolvedSessionIdentity, Error> {
        let current = &self.historical.successor;
        // The root explicitly grants broad retained-established permission for
        // this full identity and exact policy, including intermediate credentials.
        // The journal must independently prove the original established record.
        if original.account_id() != current.account_id()
            || original.device_id() != current.device_id()
            || original.generation() != current.generation()
            || original.authority_key != current.authority_key
            || original.key != current.key
            || original.description.family != current.description.family
            || policy != self.historical.statement.policy
        {
            return Err(Error::Scope);
        }
        Ok(ResolvedSessionIdentity {
            device: Arc::clone(current),
            statement: self.statement_digest(),
            owner: self.original_storage_owner(),
        })
    }

    // Authenticate retained public evidence at a common historical instant.
    // The root comes from the containing authenticated journal roster, not the
    // container. Current policy, target membership and time remain separate.
    pub(crate) fn from_journal(wire: &[u8], roster: &VerifiedRoster) -> Result<Self, Error> {
        if wire.len() > MAX_CREDENTIAL_RENEWAL_BYTES {
            return Err(Error::Capacity);
        }
        let mut d = Decoder::new(wire);
        if d.array::<8>()? != *CONTAINER {
            return Err(Error::Encoding);
        }
        let signed = field(&mut d)?;
        let (body, _) = open_envelope(signed)?;
        let statement = Statement::decode(body)?;
        let _original = field(&mut d)?;
        let previous = field(&mut d)?;
        let successor = field(&mut d)?;
        let previous_roster = field(&mut d)?;
        let successor_roster = field(&mut d)?;
        d.finish()?;
        let pin = roster.historical_pin(statement.successor_roster)?;
        let previous_pin = roster.historical_pin(statement.previous_roster)?;
        let at = pin
            .snapshot_start(successor, successor_roster)?
            .max(previous_pin.snapshot_start(previous, previous_roster)?);
        Self::verify(wire, &pin, statement.policy, at)
    }
    /// Verify bounded untrusted bytes against the independently current account
    /// pin, exact intended policy, and trusted time. Do not derive either input
    /// from this container. Historical verification grants no current membership.
    pub fn verify(
        wire: &[u8],
        pin: &AccountPin,
        policy: [u8; 32],
        now: u64,
    ) -> Result<Self, Error> {
        Ok(Self {
            historical: HistoricalCredentialRenewal::verify_at(wire, pin, policy, now)?,
        })
    }
    /// Borrow authenticated metadata for historical cleanup without runtime authority.
    pub fn historical(&self) -> &HistoricalCredentialRenewal {
        &self.historical
    }
    pub(crate) fn successor_credential(&self) -> Result<&[u8], Error> {
        let mut d = Decoder::new(&self.historical.wire);
        if d.array::<8>()? != *CONTAINER {
            return Err(Error::Encoding);
        }
        field(&mut d)?; // signed statement
        field(&mut d)?; // original credential
        field(&mut d)?; // predecessor credential
        field(&mut d)
    }
    /// Original public grant bytes, preserved even with randomized signatures.
    pub fn as_bytes(&self) -> &[u8] {
        self.historical.as_bytes()
    }
    /// Original host-selected operation; compare it with protected local intent.
    pub fn operation(&self) -> CredentialRenewalId {
        self.historical.operation()
    }
    /// Stable statement identity excluding randomized envelope signatures.
    pub fn statement_digest(&self) -> [u8; 32] {
        self.historical.statement_digest()
    }
    /// Expected immutable owner, which still must match authenticated local state.
    pub fn original_storage_owner(&self) -> [u8; 32] {
        self.historical.original_storage_owner()
    }
    /// Immutable original credential body commitment; compare with retained state.
    pub fn original_credential_digest(&self) -> [u8; 32] {
        self.historical.statement.original
    }
    /// Exact signed policy scope, which does not itself grant current policy use.
    pub fn policy_digest(&self) -> [u8; 32] {
        self.historical.policy_digest()
    }
    /// Historical authenticated predecessor. It need not currently be valid.
    pub fn previous_device(&self) -> &VerifiedDevice {
        &self.historical.previous
    }
    /// Target authenticated at verification time, not a continuing permission.
    pub fn successor_device(&self) -> &VerifiedDevice {
        &self.historical.successor
    }
}

impl HistoricalCredentialRenewal {
    /// Authenticate bounded original public bytes against an independently retained
    /// exact target account/root/roster pin and policy digest. Signed membership is
    /// checked at its historical interval; no caller-supplied clock can turn this
    /// result into current authority. Untrusted container fields never select the pin.
    pub fn verify(wire: &[u8], pin: &AccountPin, policy: [u8; 32]) -> Result<Self, Error> {
        let (statement, materials) = authenticated_materials(wire, pin, policy)?;
        let previous_pin = AccountPin::new(
            pin.account,
            pin.root.clone(),
            statement.previous_roster,
            pin.family,
        )?;
        let at = pin
            .snapshot_start(materials.successor_credential, materials.successor_roster)?
            .max(
                previous_pin
                    .snapshot_start(materials.previous_credential, materials.previous_roster)?,
            );
        Self::check(wire, pin, statement, materials, at)
    }
    fn verify_at(wire: &[u8], pin: &AccountPin, policy: [u8; 32], now: u64) -> Result<Self, Error> {
        let (statement, materials) = authenticated_materials(wire, pin, policy)?;
        Self::check(wire, pin, statement, materials, now)
    }
    fn check(
        wire: &[u8],
        pin: &AccountPin,
        statement: Statement,
        materials: CredentialRenewalMaterials<'_>,
        at: u64,
    ) -> Result<Self, Error> {
        let authorization = CredentialRenewalAuthorization {
            operation: statement.operation,
            previous: statement.previous_roster,
            policy_digest: statement.policy,
        };
        let (expected, previous, successor) = check_materials(&materials, &authorization, pin, at)?;
        if statement != expected {
            return Err(Error::Scope);
        }
        Ok(Self {
            statement,
            previous,
            successor: Arc::new(successor),
            wire: wire.to_vec(),
        })
    }
    /// Exact original public bytes, without re-signing or changing their validity.
    pub fn as_bytes(&self) -> &[u8] {
        &self.wire
    }
    /// Independently authorized original operation identity.
    pub fn operation(&self) -> CredentialRenewalId {
        self.statement.operation
    }
    /// Complete root statement commitment, independent of randomized signatures.
    pub fn statement_digest(&self) -> [u8; 32] {
        digest(
            b"Q-PERIAPT-CREDENTIAL-RENEWAL-STATEMENT/v1",
            &self.statement.encode(),
        )
    }
    /// Original immutable journal owner expectation, not current state evidence.
    pub fn original_storage_owner(&self) -> [u8; 32] {
        crate::bootstrap::credential_storage_owner(
            self.statement.account,
            self.statement.device,
            self.statement.generation,
            self.statement.original,
        )
    }
    /// Exact signed policy identity, not current policy permission.
    pub fn policy_digest(&self) -> [u8; 32] {
        self.statement.policy
    }
    /// Signed successor roster expectation; never a currentness claim.
    pub fn successor_checkpoint(&self) -> RosterCheckpoint {
        self.statement.successor_roster
    }
    pub(crate) fn original_credential_digest(&self) -> [u8; 32] {
        self.statement.original
    }
    pub(crate) fn previous_device(&self) -> &VerifiedDevice {
        &self.previous
    }
    pub(crate) fn successor_device(&self) -> &VerifiedDevice {
        &self.successor
    }
}
fn authenticated_materials<'a>(
    wire: &'a [u8],
    pin: &AccountPin,
    policy: [u8; 32],
) -> Result<(Statement, CredentialRenewalMaterials<'a>), Error> {
    if wire.len() > MAX_CREDENTIAL_RENEWAL_BYTES {
        return Err(Error::Capacity);
    }
    nonzero(&policy)?;
    let mut d = Decoder::new(wire);
    if d.array::<8>()? != *CONTAINER {
        return Err(Error::Encoding);
    }
    let signed = field(&mut d)?;
    let materials = CredentialRenewalMaterials {
        original_credential: field(&mut d)?,
        previous_credential: field(&mut d)?,
        successor_credential: field(&mut d)?,
        previous_roster: field(&mut d)?,
        successor_roster: field(&mut d)?,
    };
    d.finish()?;
    let (body, signature) = open_envelope(signed)?;
    pin.root
        .verify(Purpose::CredentialRenewal, body, signature)?;
    let statement = Statement::decode(body)?;
    if statement.policy != policy {
        return Err(Error::Scope);
    }
    Ok((statement, materials))
}

#[cfg(test)]
mod tests;
