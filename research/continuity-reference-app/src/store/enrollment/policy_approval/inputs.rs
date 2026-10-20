// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

impl Store {
    pub(super) fn policy_context(
        &self,
        account: &Account,
        request: &PolicyApprovalRequest,
    ) -> Result<Operation, Error> {
        self.authorized(account)?;
        if !self.policy_approvals {
            return Err(Error::Conflict(
                "Policy approvals require explicit schema-6 upgrade",
            ));
        }
        request.shape()?;
        let original = self.operation(account, request.retained.enrollment)?;
        if request.retained.application != account.application_id
            || request.retained.root_revision != original.invitation.root_revision
            || !matches!(original.phase, Phase::Issued { .. })
        {
            return Err(Error::Conflict(
                "Policy approval requires its original account issuance",
            ));
        }
        Ok(original)
    }
    pub(super) fn policy_inputs(
        &self,
        account: &Account,
        request: &PolicyApprovalRequest,
        operation: &Operation,
    ) -> Result<(Root, RootInfo), Error> {
        let Phase::Issued { response, .. } = &operation.phase else {
            return Err(Error::Internal);
        };
        let original: IssuedEnrollment = decode(response, MAX_RECORD)?;
        let history = CredentialHistory {
            enrollment: request.retained.enrollment,
            revision: request.retained.root_revision,
        };
        self.extension_descends(
            account,
            history,
            request.current_extension,
            request.original_extension,
        )?;
        if self.selected_certificate(account, history, &original, request.original_extension)?
            != request.retained.original_certificate
            || self.selected_certificate(account, history, &original, request.current_extension)?
                != request.retained.current_certificate
        {
            return Err(Error::Conflict(
                "Policy credential differs from selected host issuance",
            ));
        }
        let root = self.root(account)?;
        root.admits_authority(&operation.invitation, self.family()?)?;
        if !root.members.iter().any(|member| {
            member.device == operation.invitation.device
                && member.certificate == request.retained.current_certificate
        }) {
            return Err(Error::Conflict(
                "Policy approval device is no longer the current member",
            ));
        }
        let info = root.info(self.family()?)?;
        let current = info
            .roster
            .as_ref()
            .ok_or(Error::Conflict("Current roster is absent"))?;
        if current.checkpoint != request.retained.scope.current_roster
            || current.bytes != request.retained.current_roster
        {
            return Err(Error::Conflict("Policy approval current roster changed"));
        }
        Ok((root, info))
    }
}
