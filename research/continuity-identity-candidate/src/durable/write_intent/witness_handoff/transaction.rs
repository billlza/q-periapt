// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
impl Owners {
    fn save(
        &self,
        previous: Option<&Fence>,
        next: &Fence,
        admit: impl FnOnce() -> Result<(), DurableError>,
        stage: &'static str,
    ) -> Result<(), DurableError> {
        let old = previous.map(|f| f.encode(&self.key)).transpose()?;
        let wire = next.encode(&self.key)?;
        let tx = transaction(&self.db)?;
        {
            let mut table = tx.open_table(TABLE).map_err(storage)?;
            let image = table
                .get("image")
                .map_err(storage)?
                .ok_or(DurableError::Corrupt)?;
            if image_hash(image.value()) != next.image {
                return Err(DurableError::Conflict);
            }
            drop(image);
            let pending = table.get("pending").map_err(storage)?;
            if pending.as_ref().map(|p| codec::pending_digest(p.value())) != next.pending
                || table.get(ROW).map_err(storage)?.as_ref().map(|r| r.value()) != old.as_deref()
                || table.len().map_err(storage)?
                    != 1 + u64::from(pending.is_some()) + u64::from(previous.is_some())
            {
                return Err(DurableError::Conflict);
            }
            drop(pending);
            table.insert(ROW, wire.as_slice()).map_err(storage)?;
        }
        admit()?;
        #[cfg(all(test, unix))]
        tests::boundary(stage, false);
        tx.commit().map_err(DurableError::CommitUncertain)?;
        #[cfg(all(test, unix))]
        tests::boundary(stage, true);
        let _ = stage;
        if self.read()?.encode(&self.key)? != wire {
            return Err(DurableError::Corrupt);
        }
        Ok(())
    }
    pub(super) fn prepare(
        self,
        mut clock: impl FnMut() -> Result<u64, DurableError>,
    ) -> Result<WitnessJournalAdoption, DurableError> {
        match self.read() {
            Ok(_) => return Ok(WitnessJournalAdoption { active: Some(self) }),
            Err(DurableError::Absent) => {}
            Err(error) => return Err(error),
        }
        let (image, pending) = self.snapshot()?;
        let now = clock()?;
        self.plan.approved.check_admission(now)?;
        let next = Fence::new(&image, pending.as_ref(), &self.plan, now);
        next.check(&image, pending.as_ref())?;
        self.save(
            None,
            &next,
            || {
                let commit_time = clock()?;
                if commit_time < now {
                    return Err(Error::Scope.into());
                }
                Ok(self.plan.approved.check_admission(commit_time)?)
            },
            "prepare",
        )?;
        Ok(WitnessJournalAdoption { active: Some(self) })
    }
}
impl WitnessJournalAdoption {
    /// Select the exact target authorization durably without changing the
    /// original sealed image, pending bytes or operation IDs. Its admission time
    /// is verified historically; this does not extend any traffic permission.
    /// Any error closes this owner and may follow commit. Reopen this same plan;
    /// exact retries return the first committed decision without another write.
    pub fn adopt_authorization(
        &mut self,
        wire: &[u8],
    ) -> Result<WitnessJournalAdoptionState, DurableError> {
        let result = (|| {
            let owner = self.active.as_ref().ok_or(DurableError::Closed)?;
            let original = owner.read()?;
            owner.plan.verify_receipt(wire)?;
            if let Some(saved) = &original.receipt {
                if saved != wire {
                    return Err(DurableError::Conflict);
                }
            } else {
                let mut next = original.clone();
                next.receipt = Some(wire.to_vec());
                owner.save(Some(&original), &next, || Ok(()), "adopt")?;
            }
            Ok(WitnessJournalAdoptionState::Adopted)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
}
