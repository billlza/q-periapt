// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Prepare a real inherited client scope without changing its pending operations.
use super::*;
use crate::{AnchorHandoffAdoptionId, AnchorHandoffAdoptionMaterials, AnchorHandoffAdoptionScope};

impl AnchorStore {
    /// Read the exact original imported client state for independent account and
    /// policy approval. This neither reserves nor adopts it, changes G/P/R, nor
    /// grants an ordinary request handler. The future adoption transaction must
    /// compare this complete scope with its original immutable imported entry.
    ///
    /// Supply independent original/current identity and policy proofs and the
    /// verified exact target activation. Pending work need not be quiescent; an
    /// applied G/P/R requires its actually adopted current materials. A mismatch
    /// is not evidence that an old unknown command did not commit.
    pub fn handoff_adoption_scope(
        &mut self,
        operation: AnchorHandoffAdoptionId,
        subject: AnchorSubject,
        materials: &AnchorHandoffAdoptionMaterials<'_>,
        validity: Validity,
    ) -> Result<AnchorHandoffAdoptionScope, DurableError> {
        let image = self.image()?;
        let owner = self.active.as_ref().ok_or(DurableError::Closed)?;
        let transferred = owner.transferred.as_ref().ok_or(DurableError::Suspended)?;
        let id = subject.id(&image.namespace);
        if !image.inherited.contains(&id) {
            return Err(DurableError::Conflict);
        }
        if image.subject_retired(subject) || image.subject_frozen(subject) {
            return Err(Error::Retired.into());
        }
        let entry = transferred
            .original
            .image
            .entries
            .get(&id)
            .ok_or(DurableError::Absent)?;
        if entry.subject != subject
            || entry.device != materials.current_device.key
            || entry.original_identity.as_ref().is_some_and(|original| {
                original != &OriginalIdentity::from_verified(materials.original_device)
            })
        {
            return Err(Error::Scope.into());
        }
        let expected_policy = entry
            .policy_authorization
            .or_else(|| entry.independent_policy.as_ref().and_then(|p| p.current))
            .map_or(materials.original_policy.checkpoint(), |p| p.checkpoint);
        if expected_policy != materials.current_policy.checkpoint() {
            return Err(Error::Scope.into());
        }
        let saved = storage::load_authenticated(&owner.db, &owner.wrapping, &transferred.approval)?;
        transferred.admit(&saved)?;
        if saved.digest != image.digest {
            return Err(DurableError::Conflict);
        }
        let activation = saved.activation.as_ref().ok_or(DurableError::Corrupt)?;
        let mut bytes = Vec::new();
        encode_entry(
            entry,
            &transferred.history,
            EntryFormat::COMPLETE,
            &mut bytes,
        )?;
        let scope = AnchorHandoffAdoptionScope {
            operation,
            subject,
            namespace: image.namespace,
            predecessor: transferred.approval.plan.source.binding(),
            logical: materials
                .original_policy
                .anchor_requirement()
                .binding()
                .ok_or(Error::Scope)?,
            successor: owner.pin.binding(),
            history: transferred.history.checkpoint(),
            activation: crate::session_policy::handoff_activation_digest(&activation.receipt),
            entry: digest(b"Q-PERIAPT-WITNESS-ADOPTION-IMPORTED-ENTRY/v1", &bytes),
            credential_owner: entry.credential_owner,
            authority: entry.authority,
            family: materials.original_policy.family(),
            policy: expected_policy,
            validity,
        };
        crate::session_policy::check_handoff_adoption_materials(&scope, materials)?;
        Ok(scope)
    }
}
