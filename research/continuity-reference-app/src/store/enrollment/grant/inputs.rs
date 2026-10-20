// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

pub(super) struct Target {
    pub(super) root: Root,
    pub(super) pin: sdk::AccountPin,
    pub(super) certificate: Vec<u8>,
    pub(super) roster: Vec<u8>,
}
pub(super) fn shape(value: &CredentialGrantRequest) -> Result<(), Error> {
    let r = &value.retained;
    if r.schema != "qperiapt-retained-credential-request/1"
        || r.root_revision == 0
        || [
            r.application,
            r.enrollment,
            r.operation,
            r.journal,
            r.original_owner,
            value.successor_extension,
        ]
        .contains(&[0; 32])
        || [
            value.original_extension,
            value.previous_extension,
            r.current_policy_authorization,
        ]
        .contains(&Some([0; 32]))
    {
        return Err(Error::Invalid("Retained grant identity or schema"));
    }
    for checkpoint in [
        r.original_policy,
        r.current_policy,
        r.previous_checkpoint,
        value.target_checkpoint,
    ] {
        checkpoint
            .as_sdk()
            .map_err(|_| Error::Invalid("Retained grant checkpoint"))?;
    }
    if r.current_policy.version < r.original_policy.version
        || (r.current_policy.version == r.original_policy.version
            && r.current_policy != r.original_policy)
        || value.target_checkpoint.version <= r.previous_checkpoint.version
    {
        return Err(Error::Invalid("Retained grant checkpoint order"));
    }
    for bytes in [
        &r.original_certificate,
        &r.previous_certificate,
        &r.original_roster,
        &r.previous_roster,
    ] {
        if bytes.is_empty() || bytes.len() > 16384 {
            return Err(Error::Invalid("Retained grant public input bounds"));
        }
    }
    encode(value, 64 * 1024)?;
    Ok(())
}

impl Store {
    fn selected_extension(
        &self,
        account: &Account,
        enrollment: [u8; 32],
        id: [u8; 32],
        revision: u64,
    ) -> Result<IssuedCredentialExtension, Error> {
        let bytes = self
            .extension(account, id)?
            .ok_or(Error::Conflict("Selected credential extension is absent"))?;
        let value: IssuedCredentialExtension = decode(&bytes, MAX_RECORD)?;
        if value.request.request_id != id
            || value.request.enrollment != enrollment
            || value.root_revision != revision
        {
            return Err(Error::Conflict(
                "Selected extension belongs to another enrollment or root",
            ));
        }
        Ok(value)
    }
    fn selected_certificate(
        &self,
        account: &Account,
        request: &CredentialGrantRequest,
        original: &IssuedEnrollment,
        selection: Option<[u8; 32]>,
    ) -> Result<Vec<u8>, Error> {
        Ok(match selection {
            None => original.certificate.clone(),
            Some(id) => {
                self.selected_extension(
                    account,
                    request.retained.enrollment,
                    id,
                    request.retained.root_revision,
                )?
                .certificate
            }
        })
    }
    fn extension_descends(
        &self,
        account: &Account,
        request: &CredentialGrantRequest,
        mut child: Option<[u8; 32]>,
        ancestor: Option<[u8; 32]>,
    ) -> Result<(), Error> {
        for _ in 0..=MAX_OPERATIONS {
            if child == ancestor {
                return Ok(());
            }
            let id = child.ok_or(Error::Conflict(
                "Selected credential is not in the original extension chain",
            ))?;
            child = self
                .selected_extension(
                    account,
                    request.retained.enrollment,
                    id,
                    request.retained.root_revision,
                )?
                .request
                .previous_extension;
        }
        Err(Error::Internal)
    }
    pub(super) fn grant_inputs(
        &self,
        account: &Account,
        request: &CredentialGrantRequest,
        original: &Operation,
        response: &[u8],
        at: u64,
    ) -> Result<Target, Error> {
        let retained = &request.retained;
        if retained.application != account.application_id
            || retained.root_revision != original.invitation.root_revision
        {
            return Err(Error::Conflict(
                "Retained request belongs to another account or root",
            ));
        }
        let issued: IssuedEnrollment = decode(response, MAX_RECORD)?;
        if issued.operation != retained.enrollment || issued.root_revision != retained.root_revision
        {
            return Err(Error::Internal);
        }
        let root = self.root(account)?;
        root.admits_authority(&original.invitation, self.family()?)?;
        let info = root.info(self.family()?)?;
        let current = info
            .roster
            .as_ref()
            .ok_or(Error::Conflict("Current roster is absent"))?;
        if current.checkpoint != request.target_checkpoint {
            return Err(Error::Conflict("Selected target roster changed"));
        }
        self.extension_descends(
            account,
            request,
            Some(request.successor_extension),
            request.previous_extension,
        )?;
        self.extension_descends(
            account,
            request,
            request.previous_extension,
            request.original_extension,
        )?;
        if self.selected_certificate(account, request, &issued, request.original_extension)?
            != retained.original_certificate
            || self.selected_certificate(account, request, &issued, request.previous_extension)?
                != retained.previous_certificate
        {
            return Err(Error::Conflict(
                "Retained credential differs from selected host issuance",
            ));
        }
        let target = self.selected_extension(
            account,
            retained.enrollment,
            request.successor_extension,
            retained.root_revision,
        )?;
        if !root
            .members
            .iter()
            .any(|m| m.device == original.invitation.device && m.certificate == target.certificate)
        {
            return Err(Error::Conflict(
                "Target credential is no longer the current member",
            ));
        }
        let public = sdk::PublicKey::decode(&info.public_key).map_err(db_error)?;
        let previous_pin = sdk::AccountPin::new(
            info.account,
            public.clone(),
            retained
                .previous_checkpoint
                .as_sdk()
                .map_err(|_| Error::Invalid("Previous checkpoint"))?,
            info.family,
        )
        .map_err(db_error)?;
        previous_pin
            .verify_historical_device(&retained.previous_certificate, &retained.previous_roster)
            .map_err(|_| Error::Invalid("Reported predecessor signatures or membership"))?;
        let pin = sdk::AccountPin::new(
            info.account,
            public,
            current.checkpoint.as_sdk().map_err(db_error)?,
            info.family,
        )
        .map_err(db_error)?;
        let live = pin
            .verify_device(&target.certificate, &current.bytes, at)
            .map_err(|_| Error::Conflict("Target credential or roster is not current"))?;
        if live.device_id() != original.invitation.device
            || live.generation() != original.invitation.generation
        {
            return Err(Error::Conflict("Target device identity changed"));
        }
        Ok(Target {
            root,
            pin,
            certificate: target.certificate,
            roster: current.bytes.clone(),
        })
    }
}
