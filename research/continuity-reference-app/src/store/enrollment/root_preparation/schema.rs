// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
impl Store {
    /// Explicit schema7-to8 admission. No current root or private file is replaced.
    pub fn enable_root_preparations(&mut self) -> Result<(), Error> {
        self.alive()?;
        if self.root_preparations {
            return Ok(());
        }
        if !self.enrollment_replacements {
            return Err(Error::Conflict(
                "Enable device replacements before root preparation",
            ));
        }
        self.action(|store| {
            let tx = transaction(&store.db)?;
            {
                let mut config = tx.open_table(CONFIG).map_err(db_error)?;
                if config
                    .get("schema")
                    .map_err(db_error)?
                    .is_none_or(|v| v.value() != "7")
                {
                    return Err(Error::Internal);
                }
                tx.open_table(PREPARATIONS).map_err(db_error)?;
                tx.open_table(CORRELATIONS).map_err(db_error)?;
                config.insert("schema", "8").map_err(db_error)?;
            }
            #[cfg(test)]
            test_boundary("root-preparation-upgrade-before-commit", b"schema8")?;
            tx.commit().map_err(db_error)?;
            #[cfg(test)]
            test_boundary("root-preparation-upgrade-after-commit", b"schema8")?;
            Ok(())
        })?;
        self.root_preparations = true;
        Ok(())
    }
}
