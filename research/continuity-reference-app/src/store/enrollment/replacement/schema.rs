// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
impl Store {
    /// Explicit schema6-to7 admission for replacement-kind operation records.
    /// Existing accounts, roots, decisions and key files remain byte-identical.
    pub fn enable_device_replacements(&mut self) -> Result<(), Error> {
        self.alive()?;
        if self.enrollment_replacements {
            return Ok(());
        }
        if !self.policy_approvals {
            return Err(Error::Conflict(
                "Enable policy approvals before device replacement",
            ));
        }
        self.action(|store| {
            let tx = transaction(&store.db)?;
            {
                let mut config = tx.open_table(CONFIG).map_err(db_error)?;
                if config
                    .get("schema")
                    .map_err(db_error)?
                    .is_none_or(|v| v.value() != "6")
                {
                    return Err(Error::Internal);
                }
                config.insert("schema", "7").map_err(db_error)?;
            }
            #[cfg(test)]
            test_boundary("replacement-upgrade-before-commit", b"schema7")?;
            tx.commit().map_err(db_error)?;
            #[cfg(test)]
            test_boundary("replacement-upgrade-after-commit", b"schema7")?;
            Ok(())
        })?;
        self.enrollment_replacements = true;
        Ok(())
    }
}
