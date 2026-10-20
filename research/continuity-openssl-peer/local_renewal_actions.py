"""Process-harness calls for one original local credential renewal."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from qperiapt_continuity_reference.local_renewal import LocalRenewal
from qperiapt_continuity_reference.wire import require


def run(action, arguments, now, path, scope, key, context, client, observer, directory=None):
    expected = 4 if action == "local_account_prepare_files" else (3 if action == "local_renewal_prepare" else 1)
    require(len(arguments) == expected,
            "local renewal worker arguments")
    owner = LocalRenewal.open(path, scope, key, context, arguments[0], client=client, observer=observer)
    try:
        if action == "local_account_prepare_files":
            from account_renewal_actions import prepare
            require(directory is not None, "account grant fixture directory absent")
            return prepare(owner, arguments, directory, now)
        if action == "local_renewal_prepare":
            return owner.prepare(arguments[1], arguments[2], now)
        if action == "local_renewal_commit":
            return owner.commit(now)
        if action == "local_renewal_close":
            return owner.close_proposal()
        if action == "local_renewal_status":
            return owner.status()
        require(action == "local_renewal_recover", "unknown local renewal worker action")
        return owner.recover()
    finally:
        owner.close()


def run_local(action, arguments, now, path, scope, key, context, observer, directory=None):
    from qperiapt_continuity_reference.local_credential import LocalCredentialRenewal
    expected = 4 if action == "local_account_stage_files" else (3 if action == "local_credential_stage" else 1)
    require(len(arguments) == expected,
            "local credential worker arguments")
    owner = LocalCredentialRenewal.open(path, scope, key, context, arguments[0], observer=observer)
    try:
        if action == "local_account_stage_files":
            from account_renewal_actions import stage
            require(directory is not None, "account grant fixture directory absent")
            return stage(owner, arguments, directory, now)
        if action == "local_credential_stage":
            return owner.stage(arguments[1], arguments[2], now)
        if action == "local_credential_commit":
            return owner.commit(now)
        if action == "local_credential_expire":
            return owner.reconcile_expired(now)
        require(action == "local_credential_status", "unknown local credential worker action")
        return owner.status()
    finally:
        owner.close()
