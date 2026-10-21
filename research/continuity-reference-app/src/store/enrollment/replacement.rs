// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

#[path = "replacement/schema.rs"]
mod schema;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Intent {
    pub(super) request: DeviceReplacementRequest,
    account: [u8; 32],
    history: history::CredentialSnapshot,
    #[serde(with = "wire")]
    current_roster: Vec<u8>,
}
impl Intent {
    pub(super) fn roster(&self, invitation: &Invitation) -> Result<sdk::VerifiedRoster, Error> {
        sdk::AccountPin::new(
            self.account,
            sdk::PublicKey::decode(&invitation.root).map_err(db_error)?,
            self.request.predecessor.as_sdk().map_err(db_error)?,
            invitation.family,
        )
        .map_err(db_error)?
        .verify_historical_roster(&self.current_roster)
        .map_err(db_error)
    }
    pub(super) fn previous(&self, invitation: &Invitation) -> Result<sdk::VerifiedDevice, Error> {
        if self.request.request_id == [0; 32]
            || self.request.enrollment == [0; 32]
            || invitation.request_id != self.request.request_id
            || invitation.operation == self.request.enrollment
            || invitation.predecessor != Some(self.request.predecessor)
        {
            return Err(Error::Internal);
        }
        let pin = sdk::AccountPin::new(
            self.account,
            sdk::PublicKey::decode(&invitation.root).map_err(db_error)?,
            self.history.checkpoint.as_sdk().map_err(db_error)?,
            invitation.family,
        )
        .map_err(db_error)?;
        let previous = pin
            .verify_historical_device(&self.history.certificate, &self.history.roster)
            .map_err(db_error)?;
        if previous.device_id() != invitation.device
            || previous.generation().checked_add(1) != Some(invitation.generation)
            || self.request.predecessor.version < self.history.checkpoint.version
            || (self.request.predecessor.version == self.history.checkpoint.version
                && self.request.predecessor != self.history.checkpoint)
            || !self.roster(invitation)?.members().any(|member| {
                member
                    == (
                        previous.device_id(),
                        previous.generation(),
                        previous.credential_digest(),
                    )
            })
        {
            return Err(Error::Internal);
        }
        Ok(previous)
    }

    pub(super) fn current(
        &self,
        root: &Root,
        invitation: &Invitation,
        family: [u8; 32],
    ) -> Result<sdk::VerifiedDevice, Error> {
        root.admits(invitation, family)?;
        if root
            .members
            .iter()
            .filter(|member| member.device == invitation.device)
            .count()
            != 1
            || !root.members.iter().any(|member| {
                member.device == invitation.device && member.certificate == self.history.certificate
            })
        {
            return Err(Error::Conflict(
                "Original device generation or credential changed",
            ));
        }
        self.previous(invitation)
    }
}

impl Operation {
    pub(super) fn verify_request(
        &self,
        root: &Root,
        family: [u8; 32],
        wire: &[u8],
        now: u64,
    ) -> Result<sdk::VerifiedEnrollmentRequest, Error> {
        let intent = self.invitation.intent().map_err(db_error)?;
        match &self.replacement {
            Some(replacement) => {
                let previous = replacement.current(root, &self.invitation, family)?;
                sdk::VerifiedEnrollmentRequest::verify_replacement(wire, &intent, &previous, now)
                    .map_err(|_| Error::Invalid("Replacement requires a fresh key and proof of the approved next generation"))
            }
            None => sdk::VerifiedEnrollmentRequest::verify(wire, &intent, now)
                .map_err(|_| Error::Invalid("Request does not prove the approved device intent")),
        }
    }
}

impl Store {
    /// Authorize a new invitation for exactly the next generation of a currently
    /// listed device. Old credentials may be expired; account authorization and
    /// the independently selected current roster remain mandatory.
    pub fn invite_device_replacement(
        &mut self,
        account: &Account,
        request: &DeviceReplacementRequest,
    ) -> Result<Invitation, Error> {
        self.action(|store| {
            store.authorized(account)?;
            if !store.enrollment_replacements {
                return Err(Error::Conflict(
                    "Device replacement requires an explicit account-store upgrade",
                ));
            }
            if request.request_id == [0; 32] || request.enrollment == [0; 32] {
                return Err(Error::Invalid("Replacement identities must be nonzero"));
            }
            request
                .predecessor
                .as_sdk()
                .map_err(|_| Error::Invalid("Replacement predecessor checkpoint"))?;
            if let Some(saved) = store.invitation_for_request(account, request.request_id)? {
                if saved
                    .replacement
                    .as_ref()
                    .is_none_or(|original| original.request != *request)
                {
                    return Err(Error::Conflict("Original replacement request differs"));
                }
                return Ok(saved.invitation);
            }
            let original = store.operation(account, request.enrollment)?;
            let Phase::Issued { response, .. } = &original.phase else {
                return Err(Error::Conflict(
                    "Replacement requires an original issued enrollment",
                ));
            };
            let issued: IssuedEnrollment = decode(response, MAX_RECORD)?;
            let root = store.root(account)?;
            root.admits_authority(&original.invitation, store.family()?)?;
            let info = root.info(store.family()?)?;
            let roster = info
                .roster
                .as_ref()
                .ok_or(Error::Conflict("Current device roster is absent"))?;
            if roster.checkpoint != request.predecessor {
                return Err(Error::Conflict(
                    "Explicitly selected replacement roster changed",
                ));
            }
            let member = root
                .members
                .iter()
                .find(|m| m.device == original.invitation.device)
                .ok_or(Error::Conflict("Original device is no longer listed"))?;
            let history = store.current_certificate_snapshot(
                account,
                history::CredentialHistory {
                    enrollment: request.enrollment,
                    revision: info.revision,
                },
                &issued,
                &member.certificate,
            )?;
            let pin = sdk::AccountPin::new(
                info.account,
                sdk::PublicKey::decode(&info.public_key).map_err(db_error)?,
                history.checkpoint.as_sdk().map_err(db_error)?,
                info.family,
            )
            .map_err(db_error)?;
            let previous = pin
                .verify_historical_device(&history.certificate, &history.roster)
                .map_err(db_error)?;
            if previous.generation() != original.invitation.generation {
                return Err(Error::Conflict(
                    "Selected enrollment is not the current device generation",
                ));
            }
            let generation = previous
                .generation()
                .checked_add(1)
                .filter(|g| *g != u64::MAX)
                .ok_or(Error::Capacity)?;
            let now = now()?;
            let invitation = Invitation {
                operation: random()?,
                request_id: request.request_id,
                application: account.application_id,
                root_revision: info.revision,
                root: info.public_key,
                family: info.family,
                device: original.invitation.device,
                generation,
                valid_from: now,
                valid_until: now.checked_add(3600).ok_or(Error::Capacity)?,
                deadline: now.checked_add(300).ok_or(Error::Capacity)?,
                predecessor: Some(request.predecessor),
            };
            let intent = Intent {
                request: request.clone(),
                account: info.account,
                history,
                current_roster: roster.bytes.clone(),
            };
            intent.current(&root, &invitation, store.family()?)?;
            store.persist_invitation(account, &invitation, Some(intent), None)?;
            Ok(invitation)
        })
    }
}
