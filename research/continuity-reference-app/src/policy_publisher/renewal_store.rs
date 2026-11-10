// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Bounded original renewal decisions in the existing protected publisher.
use super::{renewal::*, store::*, *};
use crate::enrollment::RootInfo;
use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};

pub(super) const RENEWALS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("policy_renewal_approvals");

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    pub request: RenewalRequest,
    pub account: RootInfo,
    pub phase: Phase,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", deny_unknown_fields)]
pub(super) enum Phase {
    Pending { statement: [u8; 32] },
    Issued { result: IssuedRenewal },
    Closed,
}
impl Publisher {
    /// Explicit atomic schema-1 to schema-2 upgrade. It retains every existing
    /// publication, identity, pending cursor and original signing-key path.
    pub fn enable_renewals(&mut self) -> Result<(), Error> {
        self.action(|owner| {
            let mut config = owner.config()?;
            if config.schema == 2 {
                return owner.renewals_enabled();
            }
            let tx = transaction(&owner.db)?;
            tx.open_table(RENEWALS).map_err(fail)?;
            config.schema = 2;
            put_config(&tx, &config)?;
            #[cfg(test)]
            boundary("policy-renewal-upgrade-before", b"schema2")?;
            tx.commit().map_err(fail)?;
            #[cfg(test)]
            boundary("policy-renewal-upgrade-after", b"schema2")?;
            owner.renewals_enabled()
        })
    }
    pub(super) fn renewals_enabled(&self) -> Result<(), Error> {
        if self.config()?.schema != 2 {
            return Err(Error::Conflict(
                "Policy renewals require explicit schema-2 upgrade",
            ));
        }
        let tx = self.db.begin_read().map_err(fail)?;
        let table = tx.open_table(RENEWALS).map_err(fail)?;
        if table.len().map_err(fail)? > MAX_OPERATIONS {
            return Err(Error::Capacity);
        }
        Ok(())
    }
    pub(super) fn renewal_record(&self, operation: [u8; 32]) -> Result<Option<Record>, Error> {
        self.renewals_enabled()?;
        let tx = self.db.begin_read().map_err(fail)?;
        let table = tx.open_table(RENEWALS).map_err(fail)?;
        let record = table
            .get(operation.as_slice())
            .map_err(fail)?
            .map(|v| decode::<Record>(v.value()))
            .transpose()?;
        if let Some(record) = &record {
            record.request.shape()?;
            if record.request.retained.scope.operation != operation
                || matches!(&record.phase, Phase::Pending { statement } if *statement == [0; 32])
                || matches!(&record.phase, Phase::Issued { result } if result.operation != operation || result.statement == [0; 32])
            {
                return Err(Error::Internal);
            }
        }
        Ok(record)
    }
    pub(super) fn save_renewal(
        &self,
        record: &Record,
        previous: Option<&Record>,
    ) -> Result<(), Error> {
        self.renewals_enabled()?;
        let bytes = encode(record)?;
        let tx = transaction(&self.db)?;
        {
            let mut table = tx.open_table(RENEWALS).map_err(fail)?;
            let actual = table
                .get(record.request.retained.scope.operation.as_slice())
                .map_err(fail)?
                .map(|v| decode::<Record>(v.value()))
                .transpose()?;
            if actual.as_ref() != previous {
                return Err(Error::Conflict("Original policy approval changed"));
            }
            if previous.is_none() && table.len().map_err(fail)? >= MAX_OPERATIONS {
                return Err(Error::Capacity);
            }
            table
                .insert(
                    record.request.retained.scope.operation.as_slice(),
                    bytes.as_slice(),
                )
                .map_err(fail)?;
        }
        let stage = match &record.phase {
            Phase::Pending { .. } => "policy-renewal-pending",
            Phase::Issued { .. } => "policy-renewal-issued",
            Phase::Closed => "policy-renewal-closed",
        };
        #[cfg(test)]
        boundary(&format!("{stage}-before"), &bytes)?;
        tx.commit().map_err(fail)?;
        #[cfg(test)]
        boundary(&format!("{stage}-after"), &bytes)?;
        #[cfg(not(test))]
        let _ = stage;
        Ok(())
    }
}
