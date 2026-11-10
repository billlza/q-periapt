// SPDX-License-Identifier: Apache-2.0 OR MIT
//! An authenticated source reference is distinct from resolved source bytes.
use super::*;

#[derive(Clone)]
pub(in crate::anchor::store::handoff::import) enum Source {
    Inline(Vec<u8>),
    Archived([u8; 32]),
}
impl Source {
    pub(in crate::anchor::store::handoff::import) fn captured(bytes: &[u8]) -> Self {
        if is_capture(bytes) {
            Self::Archived(source_commitment(bytes))
        } else {
            Self::Inline(bytes.to_vec())
        }
    }
    pub(in crate::anchor::store::handoff::import) fn is_archived(&self) -> bool {
        matches!(self, Self::Archived(_))
    }
    pub(in crate::anchor::store::handoff::import) fn commitment(&self) -> [u8; 32] {
        match self {
            Self::Inline(bytes) => source_commitment(bytes),
            Self::Archived(value) => *value,
        }
    }
    pub(in crate::anchor::store::handoff::import) fn inline(&self) -> Option<&[u8]> {
        match self {
            Self::Inline(bytes) => Some(bytes),
            Self::Archived(_) => None,
        }
    }
    pub(in crate::anchor::store::handoff::import) fn admit(
        &self,
        approval: &AnchorHandoffTargetApproval,
    ) -> Result<(), DurableError> {
        if self.commitment() != approval.plan.commitment {
            return Err(Error::Scope.into());
        }
        if let Self::Inline(bytes) = self {
            if is_capture(bytes) || bytes.len() > MAX_IMAGE - 32 {
                return Err(DurableError::Corrupt);
            }
        }
        Ok(())
    }
    pub(in crate::anchor::store::handoff::import) fn check_payload(
        &self,
        approval: &AnchorHandoffTargetApproval,
        bytes: &[u8],
    ) -> Result<(), DurableError> {
        self.admit(approval)?;
        match self {
            Self::Inline(expected) if expected == bytes => Ok(()),
            Self::Archived(_) => admit_bytes(approval, bytes),
            _ => Err(DurableError::Conflict),
        }
    }
    pub(in crate::anchor::store::handoff::import) fn resolve(
        &self,
        db: &Database,
        approval: &AnchorHandoffTargetApproval,
    ) -> Result<Vec<u8>, DurableError> {
        self.admit(approval)?;
        match self {
            Self::Inline(bytes) => Ok(bytes.clone()),
            Self::Archived(_) => read(&db.begin_read().map_err(storage)?, approval),
        }
    }
}
