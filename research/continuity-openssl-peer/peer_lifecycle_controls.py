"""Genuine-grant and authenticated-state counterexamples, not alternate issuers."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import replace
from qperiapt_continuity_reference.renewal import verify
from qperiapt_continuity_reference.state_codec import encode, decode
from qperiapt_continuity_reference.wire import require


def grant_controls(ctx, wire, operation, target, refuses):
    original=ctx.devices[1]
    def check(value=wire, expected=target, policy=ctx.policy_digest, device=original, now=210):
        return verify(value,device,ctx.family,policy,expected,now=now)
    for size in (0,7,8,9,len(wire)-1):
        refuses('grant-truncated-'+str(size),lambda size=size:check(wire[:size]))
    refuses('grant-trailing-byte',lambda:check(wire+b'\0'))
    for offset in (0,8,9,14,54,150,len(wire)-1):
        changed=wire[:offset]+bytes([wire[offset]^1])+wire[offset+1:]
        refuses('grant-mutated-'+str(offset),lambda changed=changed:check(changed))
    refuses('grant-wrong-independent-target',lambda:check(expected=bytes(40)))
    refuses('grant-wrong-original-policy',lambda:check(policy=bytes(32)))
    refuses('grant-cannot-renew-local-owner',lambda:check(device=ctx.devices[0]))
    refuses('grant-target-expired',lambda:check(now=300),'expired or premature authority')
    value=check();require(value.operation==operation,'grant original operation')
    # The certificate and target roster alone cannot authorize replacement of
    # an observed same-generation credential without the signed renewal grant.
    from qperiapt_continuity_reference.identity_state import IdentityState
    same_account=replace(ctx,devices=(ctx.devices[1],ctx.devices[1]))
    refuses('same-account-cannot-bypass-local-coordination',lambda:IdentityState.initial(same_account),'local account coordinator')
    initial=IdentityState.initial(ctx)
    refuses('plain-roster-cannot-substitute-for-grant',
            lambda:initial.update_roster(value.successor_roster.wire,target,210),'requires renewal grant')


def stored_controls(owner,ctx,refuses):
    with owner._state(operational=False) as (snapshot,state):
        require(state.peer_authority is not None and state.format_version==5,'adopted peer state absent')
        saved=encode(state);require(saved==snapshot.payload,'canonical saved peer state')
        for offset in (41,42,82,85,86,100):
            altered=saved[:offset]+bytes([saved[offset]^0xff])+saved[offset+1:]
            refuses('stored-peer-metadata-'+str(offset),lambda altered=altered:decode(altered,ctx))
        prior=state.format_version
        try:
            for version in (1,2,3,4):
                state.format_version=version
                refuses('authority-downgrade-'+str(version),lambda:encode(state),'requires snapshot version five')
        finally:state.format_version=prior
        from qperiapt_continuity_reference.durable import Session
        derived=replace(ctx,current_peer=state.peer_authority)
        refuses('derived-peer-view-is-not-open-authority',lambda:Session._scope(derived,owner._journal.scope),'derived session authority')
