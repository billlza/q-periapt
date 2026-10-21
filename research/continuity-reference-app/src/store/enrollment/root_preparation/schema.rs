// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
impl Store {
    /// Explicit schema8-to9 admission of a candidate's original enrollment.
    pub fn enable_root_successors(&mut self) -> Result<(), Error> {
        self.alive()?;
        if self.root_successors {
            return Ok(());
        }
        if !self.root_preparations {
            return Err(Error::Conflict(
                "Enable root preparations before successor enrollment",
            ));
        }
        self.action(|store| {
            let tx = transaction(&store.db)?;
            {
                let mut config = tx.open_table(CONFIG).map_err(db_error)?;
                if config
                    .get("schema")
                    .map_err(db_error)?
                    .is_none_or(|v| v.value() != "8")
                {
                    return Err(Error::Internal);
                }
                config.insert("schema", "9").map_err(db_error)?;
            }
            #[cfg(test)]
            test_boundary("root-successor-upgrade-before-commit", b"schema9")?;
            tx.commit().map_err(db_error)?;
            #[cfg(test)]
            test_boundary("root-successor-upgrade-after-commit", b"schema9")?;
            Ok(())
        })?;
        self.root_successors = true;
        Ok(())
    }
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
