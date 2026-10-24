// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

/// Independent target-operator admission of one exact source plan.
/// Public bytes and approval identifiers do not confer control-plane permission.
#[derive(Clone)]
pub struct AnchorHandoffTargetApproval {
    pub(super) plan: AnchorHandoffPlan,
    validity: Validity,
    authorization: [u8; 32],
}
impl AnchorHandoffTargetApproval {
    /// Bind the exact plan to independently retained source and target pins and
    /// the target operator's approval record. Do not derive these trusted pins
    /// or this decision from an unauthenticated incoming transfer.
    pub fn from_trusted_state(
        plan: &AnchorHandoffPlan,
        trusted_source: &AnchorPin,
        trusted_target: &AnchorPin,
        validity: Validity,
        authorization: [u8; 32],
    ) -> Result<Self, Error> {
        plan.check()?;
        nonzero(&authorization)?;
        if plan.source.binding != trusted_source.binding
            || plan.target.binding != trusted_target.binding
        {
            return Err(Error::Scope);
        }
        Ok(Self {
            plan: plan.clone(),
            validity,
            authorization,
        })
    }

    /// Retain exact approved configuration outside the imported database.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = b"QPAHTA01".to_vec();
        bytes.extend_from_slice(&self.plan.to_bytes());
        self.validity.encode(&mut bytes);
        bytes.extend_from_slice(&self.authorization);
        bytes
    }

    /// Restore independently retained approval and pins. Parsing checks shape
    /// and scope; it is not approval of network-provided configuration.
    pub fn restore_trusted_state(
        bytes: &[u8],
        source: &AnchorPin,
        target: &AnchorPin,
    ) -> Result<Self, Error> {
        let mut d = Decoder::new(bytes);
        if d.array::<8>()? != *b"QPAHTA01" {
            return Err(Error::Encoding);
        }
        let plan = AnchorHandoffPlan::restore_trusted_state(d.take(PLAN_BYTES)?)?;
        let validity = Validity::decode(&mut d)?;
        let authorization = d.array()?;
        d.finish()?;
        Self::from_trusted_state(&plan, source, target, validity, authorization)
    }

    pub(super) fn admit(&self, now: u64) -> Result<(), Error> {
        self.plan.validity.check(now)?;
        self.validity.check(now)
    }

    fn receipt_body(&self, freeze: &[u8]) -> Result<Vec<u8>, Error> {
        if self.plan.verify_receipt(freeze)?.state() != AnchorHandoffState::Frozen {
            return Err(Error::Scope);
        }
        let mut body = b"QPAHIA01".to_vec();
        body.extend_from_slice(&self.to_bytes());
        body.extend_from_slice(&digest(
            b"Q-PERIAPT-CONTINUITY-ANCHOR-HANDOFF-FREEZE/v1",
            freeze,
        ));
        Ok(body)
    }

    pub(super) fn sign_import(
        &self,
        freeze: &[u8],
        signer: &AnchorSigningKey,
    ) -> Result<AnchorHandoffImportReceipt, Error> {
        if signer.public_key()? != self.plan.target.key {
            return Err(Error::Scope);
        }
        let body = self.receipt_body(freeze)?;
        let wire = envelope(&body, &signer.sign(Purpose::AnchorHandoffImport, &body)?)?;
        self.verify_import_receipt(freeze, &wire)
    }

    /// Verify the target's exact historical import acknowledgement. It binds the
    /// original freeze bytes and both operators' scopes, but cannot retire the
    /// source or activate a target. Fresh retirement must still check both
    /// admission intervals and the source's current durable Frozen decision.
    pub fn verify_import_receipt(
        &self,
        freeze: &[u8],
        wire: &[u8],
    ) -> Result<AnchorHandoffImportReceipt, Error> {
        let expected = self.receipt_body(freeze)?;
        let (body, signature) = open_envelope(wire)?;
        if body != expected {
            return Err(Error::Scope);
        }
        self.plan
            .target
            .key
            .verify(Purpose::AnchorHandoffImport, body, signature)?;
        Ok(AnchorHandoffImportReceipt {
            wire: wire.to_vec(),
        })
    }
}

/// Target-signed acknowledgement of an exact durable inactive import.
/// This is neither a source retirement certificate nor live client permission.
#[derive(Clone)]
pub struct AnchorHandoffImportReceipt {
    wire: Vec<u8>,
}
impl AnchorHandoffImportReceipt {
    /// Exact retained dual-signed bytes; recovery never re-signs them.
    pub fn as_bytes(&self) -> &[u8] {
        &self.wire
    }
}
