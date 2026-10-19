// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

impl Store {
    /// Explicit schema-2 to schema-3 upgrade. Existing records and key files are not rewritten.
    /// Schema-2 closed operations lack retained request bodies and remain terminal.
    pub fn enable_enrollment_reapproval(&mut self) -> Result<(), Error> {
        self.alive()?;
        self.family()?;
        if self.enrollment_reapproval {
            return Ok(());
        }
        self.action(|store| {
            let tx = transaction(&store.db)?;
            {
                let mut config = tx.open_table(CONFIG).map_err(db_error)?;
                if config
                    .get("schema")
                    .map_err(db_error)?
                    .is_none_or(|v| v.value() != "2")
                {
                    return Err(Error::Internal);
                }
                tx.open_table(REAPPROVALS).map_err(db_error)?;
                config.insert("schema", "3").map_err(db_error)?;
            }
            #[cfg(test)]
            test_boundary("reapproval-upgrade-before-commit", b"schema3")?;
            tx.commit().map_err(db_error)?;
            #[cfg(test)]
            test_boundary("reapproval-upgrade-after-commit", b"schema3")?;
            Ok(())
        })?;
        self.enrollment_reapproval = true;
        Ok(())
    }
}
