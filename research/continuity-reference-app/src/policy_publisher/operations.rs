// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::{store::*, *};

impl Publisher {
    /// Persist an exact request before signing, then its exact result before release.
    /// An issued retry returns historical bytes even after expiry; it grants no current permission.
    pub fn issue(
        &mut self,
        operation: [u8; 32],
        request: Request,
        now: u64,
    ) -> Result<Publication, Error> {
        self.action(|owner| {
            if operation == [0; 32] {
                return Err(Error::Invalid("Publication operation must be nonzero"));
            }
            let mut config = owner.config()?;
            let existing = owner.record(operation)?;
            if let Some(record) = &existing {
                if record.request != request {
                    return Err(Error::Conflict("Original policy request differs"));
                }
                match &record.state {
                    State::Issued { .. } => return owner.result(operation),
                    State::Cancelled {} => {
                        return Err(Error::Conflict("Original policy operation was cancelled"))
                    }
                    State::Pending {} => {}
                }
            }
            let signer = owner.open_signer(&config)?;
            let runtime = config.sdk.verify()?;
            if request.bootstrap_mode == BootstrapMode::ReusableBoth
                && !runtime.is_enabled().map_err(fail)?
            {
                return Err(Error::Invalid(
                    "Disabled SDK policy cannot authorize reusable bootstrap",
                ));
            }
            let mut record = match existing {
                Some(record) => record,
                None => {
                    if !matches!(config.cursor, Cursor::Idle {}) {
                        return Err(Error::Conflict(
                            "Original policy publication is still pending",
                        ));
                    }
                    let version = config
                        .version
                        .checked_add(1)
                        .filter(|v| *v <= MAX_OPERATIONS)
                        .ok_or(Error::Capacity)?;
                    request.parameters(version, now)?;
                    check_anchor(
                        &request,
                        &signer.public_key().map_err(fail)?.encode(),
                        &config.sdk.root,
                    )?;
                    let record = Record {
                        operation,
                        version,
                        request,
                        state: State::Pending {},
                    };
                    config.version = version;
                    config.cursor = Cursor::Pending { operation };
                    let tx = transaction(&owner.db)?;
                    put_record(&tx, &record)?;
                    put_config(&tx, &config)?;
                    tx.commit().map_err(fail)?;
                    #[cfg(test)]
                    boundary("policy-intent-committed", &operation)?;
                    record
                }
            };
            if !matches!(config.cursor, Cursor::Pending { operation: saved } if saved == operation)
                || config.version != record.version
            {
                return Err(Error::Internal);
            }
            let parameters = record.request.parameters(record.version, now)?;
            check_anchor(
                &record.request,
                &signer.public_key().map_err(fail)?.encode(),
                &config.sdk.root,
            )?;
            let issued = signer
                .issue_session_policy(&runtime, parameters)
                .map_err(fail)?;
            let checkpoint = issued.checkpoint();
            sdk::PolicyPin::new(
                signer.policy_family().map_err(fail)?,
                signer.public_key().map_err(fail)?,
                checkpoint,
            )
            .map_err(fail)?
            .verify(issued.as_bytes(), runtime, now)
            .map_err(fail)?;
            record.state = State::Issued {
                digest: checkpoint.digest(),
                policy: issued.as_bytes().to_vec(),
            };
            #[cfg(test)]
            boundary("policy-signed-before-commit", issued.as_bytes())?;
            config.cursor = Cursor::Idle {};
            let tx = transaction(&owner.db)?;
            put_record(&tx, &record)?;
            put_config(&tx, &config)?;
            tx.commit().map_err(fail)?;
            #[cfg(test)]
            boundary("policy-result-committed", issued.as_bytes())?;
            let result = owner.result(operation)?;
            if result.policy != issued.as_bytes() {
                return Err(Error::Internal);
            }
            Ok(result)
        })
    }
    /// Retrieve only an original completed publication. Historical data is not a live grant.
    pub fn result(&self, operation: [u8; 32]) -> Result<Publication, Error> {
        let config = self.config()?;
        let record = self
            .record(operation)?
            .ok_or(Error::Conflict("Original publication is missing"))?;
        let State::Issued { digest, policy } = record.state else {
            return Err(Error::Conflict("Original publication has no issued result"));
        };
        let SignerPhase::Ready { public, family } = &config.signer else {
            return Err(Error::Internal);
        };
        let checkpoint =
            sdk::PolicyCheckpoint::from_trusted_state(record.version, digest).map_err(fail)?;
        let historical = sdk::PolicyPin::new(
            *family,
            sdk::PublicKey::decode(public).map_err(fail)?,
            checkpoint,
        )
        .map_err(fail)?
        .verify_historical(&policy)
        .map_err(fail)?;
        // Compare authenticated historical metadata with the retained request;
        // no fabricated timestamp activates an expired protocol policy here.
        let validity = sdk::Validity::new(record.request.valid_from, record.request.valid_until)
            .map_err(fail)?;
        let anchor = record.request.anchor.pin()?.map(|pin| pin.binding());
        let modes = record.request.bootstrap_mode.allowed()?;
        if historical.validity() != validity
            || historical.application_send_budget().messages() != record.request.send_budget
            || historical.anchor_requirement().binding() != anchor
            || historical.allowed_modes() != modes
            || historical.sdk_binding() != config.sdk.verify()?.policy_binding().map_err(fail)?
        {
            return Err(Error::Internal);
        }
        Ok(Publication {
            operation,
            version: record.version,
            digest,
            request: record.request,
            policy,
        })
    }
    /// Explicitly terminate only the original pending intent. Its version/identity stay consumed.
    pub fn cancel(&mut self, operation: [u8; 32]) -> Result<(), Error> {
        self.action(|owner| {
            let mut config = owner.config()?;
            let mut record = owner.record(operation)?.ok_or(Error::Conflict("Original publication is missing"))?;
            if matches!(record.state, State::Cancelled {}) { return Ok(()); }
            if !matches!(record.state, State::Pending {})
                || !matches!(config.cursor, Cursor::Pending { operation: saved } if saved == operation) {
                return Err(Error::Conflict("Issued policy cannot be cancelled"));
            }
            record.state = State::Cancelled {}; config.cursor = Cursor::Idle {};
            let tx = transaction(&owner.db)?;
            put_record(&tx, &record)?; put_config(&tx, &config)?; tx.commit().map_err(fail)
        })
    }
}
fn check_anchor(request: &Request, policy_root: &[u8], sdk_root: &[u8]) -> Result<(), Error> {
    if let Some(pin) = request.anchor.pin()? {
        let key = pin.public_key().encode();
        if key.get(..1952) == policy_root.get(..1952)
            || key.get(1952..) == policy_root.get(1952..)
            || key.get(..1952) == Some(sdk_root)
        {
            return Err(Error::Invalid("Witness and policy keys must be distinct"));
        }
    }
    Ok(())
}
