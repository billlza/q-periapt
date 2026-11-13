// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Shared retirement and format rules for credential and roster transactions.
use super::*;

impl Entry {
    pub(in crate::anchor::store) fn roster_floor(&self) -> u64 {
        self.renewal_floor
            .max(
                self.renewal
                    .as_ref()
                    .map_or(0, CredentialRenewalRecord::roster_floor),
            )
            .max(
                self.independent_roster
                    .as_ref()
                    .map_or(0, RosterRefresh::roster_floor),
            )
    }

    pub(in crate::anchor::store) fn has_roster_credential_composition(&self) -> bool {
        self.independent_roster.is_some()
            && (self.renewal.is_some()
                || self.renewal_floor != 0
                || self.renewal_ack.is_some()
                || self.credential_owner != self.subject.owner
                || self.credential_authorization.is_some()
                || self.policy_authorization.is_some()
                || self.policy_floor != 0)
    }
}
