"""Cancel the original handoff owner or registry at actual publication points."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
import json
import os
from qperiapt_continuity_reference.account_authority import AccountAuthority
from qperiapt_continuity_reference.client_root_recovery import RootRecovery
from qperiapt_continuity_reference.wire import require
from root_successor_cuts import implementation_receipt

CASES=tuple((action,phase) for action in ('owner','registry')
            for phase in ('close','prepare','bind','parent','child'))


def exercise(owner,registry,original,plan,receipt,freeze,*,closure,case,private,now):
    require(case in CASES,'root transition cancellation case')
    action,phase=case
    stage='committed:intent' if phase in ('close','prepare','bind') else 'published:root-fence'
    occurrence={'close':1,'prepare':2,'bind':3,'parent':1,'child':1}[phase]
    family,pin=registry.family,registry.witness
    observed=0;stopped=None;later=[];nested=None
    directories=tuple(private/name for name in ('client','session','account-registry','root-target','replan/root-target'))
    def files():
        return {str(p):hashlib.sha256(p.read_bytes()).hexdigest()
                for directory in directories for p in directory.rglob('*') if p.is_file()}

    def stop(value):
        nonlocal observed,stopped,nested
        if stopped is not None:later.append(value);return
        prefix='registry:' if phase in ('close','prepare','bind') else (
            'client-device:registration-store:' if phase=='parent' else 'root-child:')
        if value!=prefix+stage:return
        observed+=1
        if observed!=occurrence:return
        before=files()
        try:owner.transition_after_noncommit(plan,receipt,freeze,now,closure=closure)
        except ValueError as error:nested=str(error)
        else:raise ValueError('nested root transition admitted')
        require(nested=='local renewal operation already in progress' and files()==before,
                'nested transition changed state or wrong refusal')
        (owner if action=='owner' else registry).close()
        stopped=files()

    previous=registry._journal._directory.observer
    def registry_event(value):
        if previous is not None:previous(value)
        stop('registry:'+value)
    registry._journal._directory.observer=registry_event
    returned=None;failure=None
    try:returned=owner.transition_after_noncommit(plan,receipt,freeze,now,closure=closure,observer=stop)
    except (ValueError,OSError) as error:failure={'type':type(error).__name__,'message':str(error)}
    finally:
        if returned is not None:returned.close()
    require(stopped is not None and observed==occurrence,'root transition cancellation boundary not reached')
    after=files();changed=sorted(p for p in after.keys()|stopped.keys() if after.get(p)!=stopped.get(p))
    report={'action':action,'phase':phase,'stage':stage,'occurrence':occurrence,
            'returned_owner':returned is not None,'failure':failure,'nested_refusal':nested,
            'events_after_close':later,'changed_after_close':changed,'captured':stopped,'after':after,
            'implementation':implementation_receipt()}
    with os.fdopen(os.open(private/'transition-cancel.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w') as out:
        json.dump(report,out,indent=2);out.write('\n');out.flush();os.fsync(out.fileno())
    require(returned is None and failure is not None and 'closed' in failure['message'],
            'root transition cancellation did not refuse the result')
    require(not changed and not later,'root transition continued after cancellation')
    owner.close();registry.close()
    host=(private/'host-key-and-id').read_bytes();registered=(private/'registry-key-and-id').read_bytes()
    registry=AccountAuthority.open(private/'account-registry',registered[:32],registered[32:],family,pin)
    try:
        returned=RootRecovery.resume_transition(private/'client',host[32:],host[:32],registry,original,
                                                plan,receipt,freeze,now,closure=closure)
        owner.close()
        returned.status()  # Once returned, the new owner has an independent lifetime.
        report['returned_owner_independent']=True
        return returned,registry,report
    except BaseException:registry.close();raise
