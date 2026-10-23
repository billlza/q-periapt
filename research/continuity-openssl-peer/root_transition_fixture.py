"""Close an original frozen target and hand its real fences to a fresh approval."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import replace
import hashlib
import json
from cryptography.exceptions import InvalidSignature
from qperiapt_continuity_reference.client_root_recovery import RootRecovery
from qperiapt_continuity_reference.enrollment_client import EnrollmentClient
from qperiapt_continuity_reference.wire import require
from qperiapt_continuity_reference.witness import TcpTransport
from root_retirement_fixture import control,field,pair
from root_target_fixture import prepare


def exercise(recovery,registry,plan,freeze,*,bridge,now,client_path,identity,key,session_path,context,observation,refuse,closure,cut=None):
    private=client_path.parent
    paths=(client_path/'registration',session_path)
    def originals():
        return {str(path/name):hashlib.sha256((path/name).read_bytes()).hexdigest()
                for path in paths for name in ('head','intent','authority') if (path/name).exists()}
    before=originals();old_decision=plan.bind(freeze)
    old_target={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in (private/'root-target').rglob('*') if p.is_file()}
    _,image=recovery._image();inputs=image.child.inputs
    directory=private/'replan';directory.mkdir(mode=0o700)
    fresh=bridge.call('replan-fresh-advertisement',45,now.to_bytes(8,'big'))
    next_plan=replace(prepare(directory,recovery._binding.application,inputs.pins,inputs.materials,context,now,fresh),
                      freeze_operation=plan.freeze_operation)
    approved=directory/'root-target/approved-public.json'
    retained=json.loads(approved.read_bytes());retained['plan']=next_plan.wire().hex()
    approved.write_text(json.dumps(retained,indent=2)+'\n')
    command=58 if closure=='plan' else 59
    request=control(plan)+(field(old_decision.wire()) if closure=='decision' else b'')
    canonical,receipt=pair(bridge.call('replan-original-closure',command,request))
    if closure=='plan':plan.verify_plan(canonical);plan.verify_closed(receipt)
    else:old_decision.verify_decision(canonical);old_decision.verify_closed(receipt)
    bridge.call('replan-witness-reopen',32,b'',b'witness reopened')
    repeated,again=pair(bridge.call('replan-original-closure-retry',command,request))
    require(repeated==canonical,'replan closure changed original expectations')
    if closure=='plan':plan.verify_closed(again)
    else:old_decision.verify_closed(again)
    receipt=again
    bridge.call('replan-closed-target-cannot-commit',51,control(plan)+field(old_decision.wire()),status=2,
                expected=b'root decision already closed')
    canonical,next_freeze=pair(bridge.call('replan-next-original-freeze',50,control(next_plan)))
    next_plan.verify_plan(canonical)
    require(plan.bind(freeze).subjects()==next_plan.bind(next_freeze).subjects(), 'replan changed original snapshot')
    old_operation=plan.operation
    def reopen():return RootRecovery.open(client_path,identity,key,registry,old_operation)
    def all_formal():
        return {str(p):hashlib.sha256(p.read_bytes()).hexdigest()
                for directory in (*paths,private/'account-registry') for p in directory.iterdir()
                if p.is_file() and not p.name.startswith('.stage-')}
    untouched=all_formal();bad=bytearray(receipt);bad[-65]^=1
    try:recovery.transition_after_noncommit(next_plan,bytes(bad),next_freeze,now,closure=closure)
    except InvalidSignature:pass
    else:raise ValueError('changed closure signature admitted')
    require(all_formal()==untouched,'invalid closure changed original state')
    recovery=reopen()
    changed=replace(next_plan,freeze_operation=bytes([next_plan.freeze_operation[0]^1])+next_plan.freeze_operation[1:])
    refuse('replan-changed-freeze-refused',lambda:recovery.transition_after_noncommit(changed,receipt,next_freeze,now,closure=closure),
           'root original freeze request')
    require(all_formal()==untouched,'changed freeze mutated original state')
    recovery=reopen()
    cut_record=None
    try:
        if cut is None:
            recovery=recovery.transition_after_noncommit(next_plan,receipt,next_freeze,now,closure=closure)
        else:
            from root_transition_cuts import exercise as interrupt
            recovery,registry,cut_record=interrupt(recovery,registry,old_operation,next_plan,receipt,next_freeze,
                closure=closure,cut=cut,private=private,now=now)
        require(recovery.inspect_child(now)==observation and originals()==before,'replan changed original child')
        require(registry.operation(old_operation)[1]=='Closed' and registry.operation(next_plan.operation)[1]=='Pending',
                'replan registry phases differ')
        refuse('replan-still-suspended',lambda:registry.admit(registry.operation(old_operation)[0]),'account authority suspended')
        fences={str(p/'root-fence'):hashlib.sha256((p/'root-fence').read_bytes()).hexdigest() for p in paths}
        recovery.close()
        recovery=RootRecovery.resume_transition(client_path,identity,key,registry,old_operation,next_plan,receipt,next_freeze,now,closure=closure)
        require(fences=={str(p/'root-fence'):hashlib.sha256((p/'root-fence').read_bytes()).hexdigest() for p in paths},
                'exact replan retry changed fences')
        recovery.close()
        refuse('replan-old-owner-refused',lambda:reopen(),'root fence original owner or operation differs')
        recovery=RootRecovery.open(client_path,identity,key,registry,next_plan.operation)
        decision,retired=pair(bridge.call('replan-next-retirement',51,control(next_plan)+field(next_plan.bind(next_freeze).wire())))
        next_plan.bind(next_freeze).verify_decision(decision);next_plan.bind(next_freeze).verify_retirement(retired)
        selected=recovery.retain_witness_retirement(retired,now=now)
        require(selected.revision==2 and selected.account==next_plan.successor.account,'replan selected wrong target')
        target=directory/'root-target';host=(target/'host-key-and-id').read_bytes()
        client=recovery.activate_successor(EnrollmentClient.open(target/'client',host[32:],host[:32]),now,
                                           transport=TcpTransport(bridge.address))
        from root_successor_peer_fixture import exercise as communicate
        peer=communicate(client,recovery,registry,next_plan,bridge=bridge,now=now,path=target/'client',host=host,mode='peer',refuse=refuse)
        require(originals()==before and old_target=={str(p):hashlib.sha256(p.read_bytes()).hexdigest()
                for p in (private/'root-target').rglob('*') if p.is_file()},'replan altered original business or closed target')
        return {'completed':True,'closure':closure,'original_operation':old_operation.hex(),
                'next_operation':next_plan.operation.hex(),'registry_revision':selected.revision,
                'original_formal_bytes_unchanged':True,'closed_target_unchanged':True,'snapshot_preserved':True,
                'process_cut':cut_record,
                'next_peer':peer,'fence_hashes':{str(p/'root-fence'):hashlib.sha256((p/'root-fence').read_bytes()).hexdigest() for p in paths},
                'scope':'Actual native signed closure and same frozen snapshot, explicit independent next approval, original parent/child fence transfer, exact retry and successor traffic. Actual process cuts recorded separately. No power-loss, mobile or PCS claim.'}
    finally:recovery.close();registry.close()
