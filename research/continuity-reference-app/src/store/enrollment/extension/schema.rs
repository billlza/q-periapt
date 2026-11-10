// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

impl Store {
    /// Explicit schema-3 to schema-4 upgrade. Preserve all original account,
    /// enrollment and reapproval records; opening never enables this operation.
    pub fn enable_enrollment_extensions(&mut self) -> Result<(), Error> {
        self.alive()?;
        if self.enrollment_extensions {
            return Ok(());
        }
        if !self.enrollment_reapproval {
            return Err(Error::Conflict(
                "Enable schema-3 reapproval before credential extension",
            ));
        }
        self.action(|store| {
            let tx = transaction(&store.db)?;
            {
                let mut config = tx.open_table(CONFIG).map_err(db_error)?;
                if config
                    .get("schema")
                    .map_err(db_error)?
                    .is_none_or(|v| v.value() != "3")
                {
                    return Err(Error::Internal);
                }
                tx.open_table(EXTENSIONS).map_err(db_error)?;
                config.insert("schema", "4").map_err(db_error)?;
            }
            #[cfg(test)]
            test_boundary("extension-upgrade-before-commit", b"schema4")?;
            tx.commit().map_err(db_error)?;
            #[cfg(test)]
            test_boundary("extension-upgrade-after-commit", b"schema4")?;
            Ok(())
        })?;
        self.enrollment_extensions = true;
        Ok(())
    }
}
