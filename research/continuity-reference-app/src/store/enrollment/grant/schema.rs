// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
impl Store {
    pub fn enable_credential_grants(&mut self) -> Result<(), Error> {
        self.alive()?;
        if self.credential_grants {
            return Ok(());
        }
        if !self.enrollment_extensions {
            return Err(Error::Conflict(
                "Enable schema-4 credential extension before retained grants",
            ));
        }
        self.action(|store| {
            let tx = transaction(&store.db)?;
            {
                let mut config = tx.open_table(CONFIG).map_err(db_error)?;
                if config
                    .get("schema")
                    .map_err(db_error)?
                    .is_none_or(|v| v.value() != "4")
                {
                    return Err(Error::Internal);
                }
                tx.open_table(GRANTS).map_err(db_error)?;
                config.insert("schema", "5").map_err(db_error)?;
            }
            #[cfg(test)]
            test_boundary("grant-upgrade-before-commit", b"schema5")?;
            tx.commit().map_err(db_error)?;
            #[cfg(test)]
            test_boundary("grant-upgrade-after-commit", b"schema5")?;
            Ok(())
        })?;
        self.credential_grants = true;
        Ok(())
    }
}
