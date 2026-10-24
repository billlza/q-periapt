// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

pub(super) const BODY_BYTES: usize = 8 + 14 * 32 + 40 + 16;
pub(super) const APPROVAL_BYTES: usize = 4 + BODY_BYTES + crate::crypto::SIGNATURE_BYTES;
const TAG: &[u8; 8] = b"QPAHAD02";
const CONTAINER: &[u8; 8] = b"QPAHAB02";

pub(crate) fn activation_digest(bytes: &[u8]) -> [u8; 32] {
    digest(b"Q-PERIAPT-WITNESS-ADOPTION-ACTIVATION/v1", bytes)
}

impl AnchorHandoffAdoptionScope {
    pub(super) fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(BODY_BYTES);
        bytes.extend_from_slice(TAG);
        bytes.extend_from_slice(self.operation.as_bytes());
        bytes.extend_from_slice(&self.subject.to_bytes());
        for value in [
            self.namespace,
            self.predecessor,
            self.logical,
            self.successor,
            self.history,
            self.activation,
            self.entry,
            self.credential_owner,
            self.authority,
            self.family,
        ] {
            bytes.extend_from_slice(&value);
        }
        bytes.extend_from_slice(&self.policy.version().to_be_bytes());
        bytes.extend_from_slice(&self.policy.digest());
        self.validity.encode(&mut bytes);
        bytes
    }
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != BODY_BYTES {
            return Err(Error::Encoding);
        }
        let mut d = Decoder::new(bytes);
        if d.array::<8>()? != *TAG {
            return Err(Error::Encoding);
        }
        let operation = AnchorHandoffAdoptionId::from_trusted_state(d.array()?)?;
        let subject = AnchorSubject::from_trusted_state(d.take(96)?)?;
        let mut field = || {
            let v = d.array()?;
            nonzero(&v)?;
            Ok::<_, Error>(v)
        };
        let namespace = field()?;
        let predecessor = field()?;
        let logical = field()?;
        let successor = field()?;
        let history = field()?;
        let activation = field()?;
        let entry = field()?;
        let credential_owner = field()?;
        let authority = field()?;
        let family = field()?;
        let policy = PolicyCheckpoint::from_trusted_state(d.u64()?, d.array()?)?;
        let validity = Validity::decode(&mut d)?;
        d.finish()?;
        if predecessor == successor {
            return Err(Error::Scope);
        }
        Ok(Self {
            operation,
            subject,
            namespace,
            predecessor,
            logical,
            successor,
            history,
            activation,
            entry,
            credential_owner,
            authority,
            family,
            policy,
            validity,
        })
    }
}

pub(super) fn verify_pair(
    account: &AnchorHandoffAdoptionApproval,
    policy: &AnchorHandoffAdoptionApproval,
    expected: &AnchorHandoffAdoptionScope,
    account_key: &PublicKey,
    policy_key: &PublicKey,
) -> Result<(), Error> {
    let (a, a_sig) = open_envelope(account.as_bytes())?;
    let (p, p_sig) = open_envelope(policy.as_bytes())?;
    if a != p || a != expected.encode() || account_key.shares_component(policy_key) {
        return Err(Error::Scope);
    }
    account_key.verify(Purpose::AnchorHandoffAdoption, a, a_sig)?;
    policy_key.verify(Purpose::AnchorHandoffAdoption, p, p_sig)
}

pub(super) fn pair(
    account: &AnchorHandoffAdoptionApproval,
    policy: &AnchorHandoffAdoptionApproval,
) -> Result<Vec<u8>, Error> {
    let mut bytes = CONTAINER.to_vec();
    let length = u16::try_from(APPROVAL_BYTES).map_err(|_| Error::Encoding)?;
    for approval in [account, policy] {
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(approval.as_bytes());
    }
    Ok(bytes)
}
pub(super) fn read_pair(
    bytes: &[u8],
) -> Result<(AnchorHandoffAdoptionApproval, AnchorHandoffAdoptionApproval), Error> {
    if bytes.len() != MAX_ANCHOR_HANDOFF_ADOPTION_BYTES {
        return Err(Error::Encoding);
    }
    let mut d = Decoder::new(bytes);
    if d.array::<8>()? != *CONTAINER {
        return Err(Error::Encoding);
    }
    let mut next = || {
        let len = usize::from(u16::from_be_bytes(d.array()?));
        AnchorHandoffAdoptionApproval::from_bytes(d.take(len)?)
    };
    let a = next()?;
    let p = next()?;
    d.finish()?;
    Ok((a, p))
}
