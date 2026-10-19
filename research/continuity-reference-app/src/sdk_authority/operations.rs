// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::{store::*, *};

impl AuthorityStore {
    /// Sign an exact original document whose version must be the next allocated value.
    /// Every reservation, including cancellation, remains in the durable ledger.
    pub fn issue(&mut self, operation: [u8; 32], document: Vec<u8>) -> Result<Publication, Error> {
        self.action(|owner| {
            if operation == [0; 32] {
                return Err(Error::Invalid("SDK publication operation must be nonzero"));
            }
            let mut config = owner.config()?;
            let existing = owner.record(operation)?;
            if let Some(record) = &existing {
                if record.document != document {
                    return Err(Error::Conflict("Original SDK policy document differs"));
                }
                match record.state {
                    State::Issued { .. } => return owner.result(operation),
                    State::Cancelled {} => {
                        return Err(Error::Conflict("Original SDK publication was cancelled"))
                    }
                    State::Pending {} => {}
                }
            }
            let signer = owner.open_signer(&config)?;
            let mut record = match existing {
                Some(record) => record,
                None => {
                    if !matches!(config.cursor, Cursor::Idle {}) {
                        return Err(Error::Conflict("Original SDK publication is still pending"));
                    }
                    let version = config.version.checked_add(1).ok_or(Error::Conflict(
                        "SDK policy versions exhausted; independent authority recovery required",
                    ))?;
                    if document_version(&document)? != version {
                        return Err(Error::Invalid(
                            "SDK policy must use the next allocated version",
                        ));
                    }
                    let record = Record {
                        operation,
                        version,
                        document,
                        state: State::Pending {},
                    };
                    config.version = version;
                    config.cursor = Cursor::Pending { operation };
                    let tx = transaction(&owner.db)?;
                    put_record(&tx, &record)?;
                    put_config(&tx, &config)?;
                    tx.commit().map_err(fail)?;
                    #[cfg(test)]
                    boundary("sdk-policy-intent-committed", &operation)?;
                    record
                }
            };
            if !matches!(config.cursor,Cursor::Pending { operation:saved } if saved == operation)
                || config.version != record.version
                || document_version(&record.document)? != record.version
            {
                return Err(Error::Internal);
            }
            let signature = signer.sign_policy(&record.document).map_err(fail)?;
            let root = signer.public_key().map_err(fail)?;
            // This verifies newly issued bytes under the retained root. It is not
            // a consumer reopening its state with a missing rollback checkpoint.
            let runtime = Runtime::from_signed_policy(
                &record.document,
                &signature,
                &root,
                None,
                Limits::default(),
            )
            .map_err(fail)?;
            let state = runtime.trusted_state().encode().to_vec();
            let input = SdkInput {
                root: root.to_vec(),
                document: record.document.clone(),
                signature: signature.clone(),
                state: state.clone(),
            };
            input.verify()?;
            record.state = State::Issued {
                signature,
                trusted_state: state,
            };
            #[cfg(test)]
            boundary("sdk-policy-signed-before-commit", &input.signature)?;
            config.cursor = Cursor::Idle {};
            let tx = transaction(&owner.db)?;
            put_record(&tx, &record)?;
            put_config(&tx, &config)?;
            tx.commit().map_err(fail)?;
            #[cfg(test)]
            boundary("sdk-policy-result-committed", &input.signature)?;
            let result = owner.result(operation)?;
            if result.input != input {
                return Err(Error::Internal);
            }
            Ok(result)
        })
    }
    /// Recover the exact committed public result without requiring private signer files.
    pub fn result(&self, operation: [u8; 32]) -> Result<Publication, Error> {
        let config = self.config()?;
        let record = self
            .record(operation)?
            .ok_or(Error::Conflict("Original SDK publication is missing"))?;
        let State::Issued {
            signature,
            trusted_state,
        } = record.state
        else {
            return Err(Error::Conflict(
                "Original SDK publication has no issued result",
            ));
        };
        let Phase::Ready { root } = config.phase else {
            return Err(Error::Internal);
        };
        let input = SdkInput {
            root,
            document: record.document,
            signature,
            state: trusted_state,
        };
        let runtime = input.verify()?;
        if record.version > config.version || runtime.trusted_state().version() != record.version {
            return Err(Error::Internal);
        }
        Ok(Publication {
            operation,
            version: record.version,
            input,
        })
    }
    /// Cancel only the original pending request. The operation and version stay consumed.
    pub fn cancel(&mut self, operation: [u8; 32]) -> Result<(), Error> {
        self.action(|owner| {
            let mut config = owner.config()?;
            let mut record = owner.record(operation)?.ok_or(Error::Conflict("Original SDK publication is missing"))?;
            if matches!(record.state,State::Cancelled {}) { return Ok(()); }
            if !matches!(record.state,State::Pending {})
                || !matches!(config.cursor,Cursor::Pending { operation:saved } if saved == operation) {
                return Err(Error::Conflict("Issued SDK policy cannot be cancelled"));
            }
            record.state = State::Cancelled {};config.cursor = Cursor::Idle {};
            let tx = transaction(&owner.db)?;put_record(&tx,&record)?;put_config(&tx,&config)?;tx.commit().map_err(fail)
        })
    }
}
