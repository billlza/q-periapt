// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
impl Store {
    /// Explicit schema-5 to schema-6 upgrade; no accounts, keys, certificates,
    /// existing decisions or policy families are replaced.
    pub fn enable_policy_approvals(&mut self) -> Result<(), Error> {
        self.alive()?;
        if self.policy_approvals {
            return Ok(());
        }
        if !self.credential_grants {
            return Err(Error::Conflict(
                "Enable schema-5 credential grants before policy approvals",
            ));
        }
        self.action(|store| {
            let tx = transaction(&store.db)?;
            {
                let mut config = tx.open_table(CONFIG).map_err(db_error)?;
                if config
                    .get("schema")
                    .map_err(db_error)?
                    .is_none_or(|v| v.value() != "5")
                {
                    return Err(Error::Internal);
                }
                tx.open_table(POLICY_APPROVALS).map_err(db_error)?;
                config.insert("schema", "6").map_err(db_error)?;
            }
            #[cfg(test)]
            test_boundary("policy-approval-upgrade-before-commit", b"schema6")?;
            tx.commit().map_err(db_error)?;
            #[cfg(test)]
            test_boundary("policy-approval-upgrade-after-commit", b"schema6")?;
            Ok(())
        })?;
        self.policy_approvals = true;
        Ok(())
    }
}
