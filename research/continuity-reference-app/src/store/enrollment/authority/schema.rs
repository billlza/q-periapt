// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
impl Store {
    pub fn enable_account_authorities(&mut self) -> Result<(), Error> {
        self.alive()?;
        if self.account_authorities {
            return Ok(());
        }
        if !self.root_successors {
            return Err(Error::Conflict(
                "Enable root successors before account authority",
            ));
        }
        self.action(|store| {
            let tx = transaction(&store.db)?;
            {
                let mut config = tx.open_table(CONFIG).map_err(db_error)?;
                if config
                    .get("schema")
                    .map_err(db_error)?
                    .is_none_or(|v| v.value() != "9")
                {
                    return Err(Error::Internal);
                }
                tx.open_table(AUTHORITIES).map_err(db_error)?;
                tx.open_table(CUTOVERS).map_err(db_error)?;
                tx.open_table(RETIRED_ROOTS).map_err(db_error)?;
                config.insert("schema", "10").map_err(db_error)?;
            }
            #[cfg(test)]
            test_boundary("authority-upgrade-before-commit", b"schema10")?;
            tx.commit().map_err(db_error)?;
            #[cfg(test)]
            test_boundary("authority-upgrade-after-commit", b"schema10")?;
            Ok(())
        })?;
        self.account_authorities = true;
        Ok(())
    }
}
