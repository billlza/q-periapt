// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Retained original policy/witness association and the native authority registry owner.
use super::*;
use crate::account_authority::{Association, AssociationRequest, Initialization};
use crate::witness::Pin;
mod bootstrap;
mod cutover;
mod gate;
mod schema;
pub(super) use gate::Guard;

pub(super) const AUTHORITIES: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("account_authorities");
pub(super) const CUTOVERS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("account_root_cutovers");
pub(super) const RETIRED_ROOTS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("retired_account_roots");

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AssociationRecord {
    application: [u8; 32],
    request: AssociationRequest,
    root: Root,
    source: history::CredentialSnapshot,
    registry: [u8; 32],
    phase: RegistryPhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    active: Option<[u8; 32]>,
}
#[derive(Clone, Copy, Serialize, Deserialize)]
enum RegistryPhase {
    Wrapping,
    Registry,
    Ready,
}
impl AssociationRecord {
    fn selected(&self, family: [u8; 32]) -> Result<(sdk::VerifiedDevice, sdk::AnchorPin), Error> {
        let root = self.root.info(family)?;
        if self.application == [0; 32]
            || self.root.application != self.application
            || self.request.request_id == [0; 32]
            || self.request.enrollment == [0; 32]
            || self.registry == [0; 32]
            || self.root.authority != Some(self.registry)
            || self.active == Some([0; 32])
            || self.request.root.revision != root.revision
            || self.request.root.account != root.account
            || root.roster.as_ref().map(|r| r.checkpoint) != Some(self.request.roster)
        {
            return Err(Error::Internal);
        }
        let device = sdk::AccountPin::new(
            root.account,
            sdk::PublicKey::decode(&root.public_key).map_err(db_error)?,
            self.source.checkpoint.as_sdk().map_err(db_error)?,
            family,
        )
        .map_err(db_error)?
        .verify_historical_device(&self.source.certificate, &self.source.roster)
        .map_err(db_error)?;
        let (_, witness) = self
            .request
            .policy
            .pins
            .verify_historical(&self.request.policy.materials, family)?;
        Ok((
            device,
            witness.ok_or(Error::Invalid(
                "Account authority requires an independently selected required-witness policy",
            ))?,
        ))
    }
    fn describe(&self, pin: &sdk::AnchorPin) -> Association {
        Association {
            schema: "qperiapt-account-authority/1".into(),
            application: self.application,
            request: self.request.clone(),
            witness: Pin {
                identity: *pin.identity().as_bytes(),
                key: pin.public_key().encode(),
            },
            initialization: if matches!(self.phase, RegistryPhase::Ready) {
                Initialization::Initialized
            } else {
                Initialization::Preparing
            },
        }
    }
}
fn save(tx: &redb::WriteTransaction, record: &AssociationRecord) -> Result<(), Error> {
    tx.open_table(AUTHORITIES)
        .map_err(db_error)?
        .insert(
            record.application.as_slice(),
            encode(record, MAX_ROOT)?.as_slice(),
        )
        .map_err(db_error)?;
    Ok(())
}
impl Store {
    fn admits_authority_association(&self, account: &Account) -> Result<(), Error> {
        self.authorized(account)?;
        if !self.account_authorities {
            return Err(Error::Conflict(
                "Account authority requires explicit schema-10 upgrade",
            ));
        }
        Ok(())
    }
    fn authority_record(&self, account: &Account) -> Result<Option<AssociationRecord>, Error> {
        let tx = self.db.begin_read().map_err(db_error)?;
        let table = tx.open_table(AUTHORITIES).map_err(db_error)?;
        let record = table
            .get(account.application_id.as_slice())
            .map_err(db_error)?
            .map(|v| decode::<AssociationRecord>(v.value(), MAX_ROOT))
            .transpose()?;
        if record
            .as_ref()
            .is_some_and(|r| r.application != account.application_id)
        {
            return Err(Error::Internal);
        }
        Ok(record)
    }
    /// Independently bind the original host root and signed required-witness
    /// policy before any replacement plan is accepted. This grants no device use.
    pub fn associate_account_authority(
        &mut self,
        account: &Account,
        request: &AssociationRequest,
    ) -> Result<Association, Error> {
        self.action(|store| {
            store.admits_authority_association(account)?;
            if request.request_id == [0; 32]
                || request.enrollment == [0; 32]
                || request.root.account == [0; 32]
                || request.root.revision == 0
            {
                return Err(Error::Invalid(
                    "Nonzero original authority association identities required",
                ));
            }
            request
                .roster
                .as_sdk()
                .map_err(|_| Error::Invalid("Original roster checkpoint"))?;
            encode(request, MAX_RECORD)?;
            let mut record = if let Some(record) = store.authority_record(account)? {
                if record.request != *request {
                    return Err(Error::Conflict(
                        "Original account authority association differs",
                    ));
                }
                record
            } else {
                let mut root = store.root(account)?;
                if root.authority.is_some() {
                    return Err(Error::Internal);
                }
                let info = root.info(store.family()?)?;
                if info.revision != request.root.revision
                    || info.account != request.root.account
                    || info.roster.as_ref().map(|r| r.checkpoint) != Some(request.roster)
                {
                    return Err(Error::Conflict("Selected original root or roster changed"));
                }
                let operation = store.operation(account, request.enrollment)?;
                if operation.invitation.root_revision != info.revision
                    || operation.invitation.root != info.public_key
                    || operation.invitation.family != info.family
                {
                    return Err(Error::Conflict(
                        "Historical enrollment belongs to another root",
                    ));
                }
                let Phase::Issued { response, .. } = &operation.phase else {
                    return Err(Error::Conflict(
                        "Authority association requires an original issued enrollment",
                    ));
                };
                let issued: IssuedEnrollment = decode(response, MAX_RECORD)?;
                if issued.operation != request.enrollment || issued.root_revision != root.revision {
                    return Err(Error::Internal);
                }
                let registry = *sdk::AccountAuthorityIdentity::generate()
                    .map_err(db_error)?
                    .as_bytes();
                root.authority = Some(registry);
                let record = AssociationRecord {
                    application: account.application_id,
                    request: request.clone(),
                    root,
                    source: history::CredentialSnapshot {
                        certificate: issued.certificate,
                        roster: issued.roster,
                        checkpoint: issued.checkpoint,
                    },
                    registry,
                    phase: RegistryPhase::Wrapping,
                    active: None,
                };
                record.selected(store.family()?)?;
                let tx = transaction(&store.db)?;
                if tx
                    .open_table(AUTHORITIES)
                    .map_err(db_error)?
                    .len()
                    .map_err(db_error)?
                    >= super::super::MAX_ACCOUNTS
                {
                    return Err(Error::Capacity);
                }
                save(&tx, &record)?;
                save_root(&tx, &record.root)?;
                tx.commit().map_err(db_error)?;
                #[cfg(test)]
                test_boundary("authority-association-retained", &record.registry)?;
                record
            };
            let (device, pin) = record
                .selected(store.family()?)
                .map_err(|e| Error::internal("retained authority association", e))?;
            store.prepare_authority_registry(&mut record, &device, &pin)?;
            Ok(record.describe(&pin))
        })
    }
    /// Historical association only. Missing/corrupt state is never an empty profile.
    pub fn account_authority(&mut self, account: &Account) -> Result<Association, Error> {
        self.action(|store| {
            store.admits_authority_association(account)?;
            let record = store
                .authority_record(account)?
                .ok_or(Error::Conflict("Original account authority is absent"))?;
            let (_, pin) = record
                .selected(store.family()?)
                .map_err(|e| Error::internal("retained authority association", e))?;
            Ok(record.describe(&pin))
        })
    }
}
