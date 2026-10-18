"""Process-harness calls for one original local credential renewal."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from peer.local_renewal import LocalRenewal
from peer.wire import require


def run(action, arguments, now, path, scope, key, context, client, observer):
    require(len(arguments) == (3 if action == "local_renewal_prepare" else 1),
            "local renewal worker arguments")
    owner = LocalRenewal.open(path, scope, key, context, arguments[0], client=client, observer=observer)
    try:
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


def run_local(action, arguments, now, path, scope, key, context, observer):
    from peer.local_credential import LocalCredentialRenewal
    require(len(arguments) == (3 if action == "local_credential_stage" else 1),
            "local credential worker arguments")
    owner = LocalCredentialRenewal.open(path, scope, key, context, arguments[0], observer=observer)
    try:
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
