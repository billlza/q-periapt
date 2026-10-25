// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Keep the selected witness and exact journal image in one transaction.
use super::*;
use redb::ReadableTable;

pub(in crate::durable::write_intent) struct Guard(Option<Fence>);
#[derive(Clone, Copy)]
pub(in crate::durable::write_intent) enum Selection<'a> {
    Client(Option<&'a crate::AnchorClient>),
    Adopted(&'a WitnessJournalAdoptionPlan),
}
impl Guard {
    pub(in crate::durable::write_intent) fn read(
        table: &impl ReadableTable<&'static str, &'static [u8]>,
        key: &JournalKey,
        client: Option<&crate::AnchorClient>,
    ) -> Result<Self, DurableError> {
        Self::read_selected(table, key, Selection::Client(client))
    }
    pub(in crate::durable::write_intent) fn read_selected(
        table: &impl ReadableTable<&'static str, &'static [u8]>,
        key: &JournalKey,
        selection: Selection<'_>,
    ) -> Result<Self, DurableError> {
        let saved = table.get(ROW).map_err(storage)?;
        let Some(saved) = saved else {
            return match selection {
                Selection::Client(client)
                    if !client.is_some_and(crate::AnchorClient::is_transferred) =>
                {
                    Ok(Self(None))
                }
                _ => Err(DurableError::Suspended),
            };
        };
        let fence = Fence::decode(key, saved.value())?;
        let receipt = fence.receipt.as_deref().ok_or(DurableError::Suspended)?;
        match selection {
            Selection::Client(client) => client
                .ok_or(DurableError::Suspended)?
                .check_journal_selection(&fence.request, receipt)?,
            Selection::Adopted(plan) => {
                if fence.request != plan.request {
                    return Err(DurableError::Conflict);
                }
                plan.verify_receipt(receipt)?;
                plan.scope().validity().check(fence.prepared_at)?;
            }
        }
        let image = table
            .get("image")
            .map_err(storage)?
            .ok_or(DurableError::Corrupt)?;
        let pending = table.get("pending").map_err(storage)?;
        if fence.image != image_hash(image.value())
            || fence.pending != pending.as_ref().map(|p| codec::pending_digest(p.value()))
        {
            return Err(DurableError::Conflict);
        }
        Ok(Self(Some(fence)))
    }
    pub(in crate::durable::write_intent) fn rows(&self) -> u64 {
        u64::from(self.0.is_some())
    }
    pub(in crate::durable::write_intent) fn update(
        self,
        table: &mut redb::Table<'_, &'static str, &'static [u8]>,
        key: &JournalKey,
    ) -> Result<(), DurableError> {
        if let Some(mut fence) = self.0 {
            fence.image = image_hash(
                table
                    .get("image")
                    .map_err(storage)?
                    .ok_or(DurableError::Corrupt)?
                    .value(),
            );
            fence.pending = table
                .get("pending")
                .map_err(storage)?
                .as_ref()
                .map(|p| codec::pending_digest(p.value()));
            table
                .insert(ROW, fence.encode(key)?.as_slice())
                .map_err(storage)?;
        }
        Ok(())
    }
}
