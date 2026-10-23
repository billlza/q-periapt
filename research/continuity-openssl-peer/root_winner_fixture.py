"""Adopt an actual native committed competitor using independent host approval."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import replace
import hashlib
import os
from cryptography.exceptions import InvalidSignature
from qperiapt_continuity_reference.account_authority import AccountAuthority
from qperiapt_continuity_reference.account_root_protocol import CommittedAdoption
from qperiapt_continuity_reference.client_root_recovery import RootRecovery
from qperiapt_continuity_reference.enrollment_client import EnrollmentClient
from qperiapt_continuity_reference.wire import require
from qperiapt_continuity_reference.witness import TcpTransport
from root_retirement_fixture import control,field,pair
from root_target_fixture import prepare


def reject_changed_history(registry):
    from qperiapt_continuity_reference.account_authority_state import Image,PREPARING,COMMITTED
    original=registry._image;last=original.replacements[-1];before=original.replacements[:-1]
    family,pin=registry.family,registry.witness;rejected=[]
    mutations={
        'missing-loss':replace(original,replacements=(last,)),
        'unresolved-loss':replace(original,replacements=(replace(before[0],phase=PREPARING),*before[1:],last)),
        'missing-origin':replace(original,replacements=(*before,replace(last,original_operation=None))),
        'changed-origin':replace(original,replacements=(*before,replace(last,original_operation=b'\xff'*32))),
        'fabricated-preparation':replace(original,replacements=(*before,replace(last,expectation=before[0].expectation))),
        'unmarked-adoption':replace(original,replacements=(*before,replace(last,phase=COMMITTED))),
        'missing-decision':replace(original,replacements=(*before,replace(last,bound=b''))),
        'duplicate-winner':replace(original,replacements=(*original.replacements,last)),
        'changed-revision':replace(original,replacements=(*before,replace(last,revision=last.revision+1))),
    }
    for label,changed in mutations.items():
        try:changed.encode(family,pin)
        except ValueError:rejected.append(label)
        else:raise ValueError('invalid adopted history accepted: '+label)
    raw=original.encode(family,pin)
    require(Image.read(raw,family,pin).encode(family,pin)==raw,'new adoption codec roundtrip')
    try:Image.read(b'QPRFAA01'+raw[8:],family,pin)
    except ValueError:rejected.append('adoption-under-old-schema')
    else:raise ValueError('adoption was hidden in old history schema')
    return rejected


def exercise(recovery,registry,plan,*,bridge,now,client_path,identity,key,session_path,context,observation,refuse,mode,cut=None,cancellation=None,unactivated=None):
    continuing=mode in ('bound-reuse-continue','bound-reuse-restart')
    retiring=mode.startswith('bound-reuse-unactivated')
    private=client_path.parent;bound=mode.startswith('bound');reuse=mode.endswith('reuse') or continuing or retiring
    paths=(client_path/'registration',session_path)
    def business():
        return {str(p/name):hashlib.sha256((p/name).read_bytes()).hexdigest()
                for p in paths for name in ('head','intent','authority') if (p/name).exists()}
    def formal():
        return {str(p):hashlib.sha256(p.read_bytes()).hexdigest()
                for d in (*paths,client_path/'configuration',private/'account-registry')
                for p in d.iterdir() if p.is_file()}
    before=business();_,image=recovery._image();inputs=image.child.inputs
    if reuse:
        winner=replace(plan,operation=os.urandom(32),freeze_operation=plan.freeze_operation if bound else os.urandom(32))
        target=private/'root-target'
    else:
        directory=private/'winner';directory.mkdir(mode=0o700)
        fresh=bridge.call('winner-fresh-advertisement',45,now.to_bytes(8,'big'))
        winner=prepare(directory,recovery._binding.application,inputs.pins,inputs.materials,context,now,fresh)
        if bound:winner=replace(winner,freeze_operation=plan.freeze_operation)
        target=directory/'root-target'
    bridge.call('winner-current-clock',33,now.to_bytes(8,'big'),b'witness clock set')
    canonical,frozen=pair(bridge.call('winner-actual-freeze',50,control(winner)))
    winner.verify_plan(canonical);decision=winner.bind(frozen)
    if not bound:bridge.call('winner-losing-freeze-refused',50,control(plan),status=2)
    actual,retirement=pair(bridge.call('winner-actual-commit',51,control(winner)+field(decision.wire())))
    decision.verify_decision(actual);decision.verify_retirement(retirement)
    actual,noncommit=pair(bridge.call('winner-original-loss',58,control(plan)))
    plan.verify_plan(actual);plan.verify_closed(noncommit)
    adoption=CommittedAdoption(plan,decision,noncommit,retirement);adoption.verify()
    original_operation=plan.operation
    def reopen():return RootRecovery.open(client_path,identity,key,registry,original_operation)
    untouched=formal();bad=bytearray(retirement);bad[-65]^=1
    try:recovery.adopt_committed_winner(replace(adoption,retirement=bytes(bad)),now)
    except InvalidSignature:pass
    else:raise ValueError('changed committed winner signature admitted')
    require(formal()==untouched,'invalid winner changed original state');recovery=reopen()
    wrong=replace(adoption,winner=replace(decision,plan=replace(winner,operation=os.urandom(32))))
    refuse('winner-unapproved-operation-refused',lambda:recovery.adopt_committed_winner(wrong,now),'root terminal signed scope')
    require(formal()==untouched,'unapproved winner changed original state');recovery=reopen()
    if mode=='cross-application':
        other_application=os.urandom(32)
        other=registry.associate(other_application,winner.successor,winner.certificate,winner.listing)
        parents={p:h for p,h in formal().items() if not p.startswith(str(private/'account-registry')+'/')}
        try:
            refuse('winner-cross-application-root-refused',lambda:recovery.adopt_committed_winner(adoption,now),
                   'authority operation or root reuse')
            require(parents=={p:h for p,h in formal().items() if not p.startswith(str(private/'account-registry')+'/')},
                    'registry refusal followed parent mutation')
            require(registry.current(other_application)==other and registry.operation(original_operation)[1]=='Closed',
                    'cross-application refusal changed other mapping or lost original closure')
            refuse('winner-refusal-does-not-invent-history',lambda:registry.replacement(winner.operation),
                   'original account root operation absent')
            return {'completed':True,'mode':mode,'refused_before_parent_change':True,
                    'other_mapping_preserved':True,'original_loss_retained':True,'no_fabricated_preparation':True,
                    'scope':'Actual signed winner rejected because its root already belongs to another application; no successor communication is claimed.'}
        finally:recovery.close();registry.close()
    process_cut=cancel_record=None
    try:
        if cut is not None:
            from root_winner_cuts import exercise as interrupt
            recovery,registry,process_cut=interrupt(recovery,registry,adoption,cut=cut,private=private,target=target,now=now)
        elif cancellation is not None:
            from root_transition_cancel import winner as cancel_winner
            recovery,registry,cancel_record=cancel_winner(recovery,registry,adoption,case=cancellation,private=private,now=now)
        else:recovery=recovery.adopt_committed_winner(adoption,now)
        require(recovery.inspect_child(now)==observation and business()==before,'winner adoption changed original business')
        selected=registry.current(recovery._binding.application)
        require(selected.revision==2 and selected.account==winner.successor.account,'wrong committed winner selected')
        require(registry.operation(original_operation)[1]=='Closed','original loss was not retained')
        refuse('winner-has-no-fabricated-preparation',lambda:registry.operation(winner.operation),'adopted winner has no local preparation')
        require(registry.replacement(winner.operation)[1:]==('Committed',decision.wire()),'adopted history differs')
        status=recovery.status();require(status['plan'] is None and status['approved_winner']==decision.wire(),
                                        'winner recovery fabricated a plan')
        require(registry._image.encode(registry.family,registry.witness).startswith(b'QPRFAA02'),'adoption schema not retained')
        history_refusals=reject_changed_history(registry)
        captured=formal();recovery=recovery.adopt_committed_winner(adoption,now)
        require(formal()==captured,'exact returned-owner adoption changed state')
        family,pin=registry.family,registry.witness;recovery.close();registry.close()
        registered=(private/'registry-key-and-id').read_bytes()
        registry=AccountAuthority.open(private/'account-registry',registered[:32],registered[32:],family,pin)
        recovery=RootRecovery.resume_adoption(client_path,identity,key,registry,original_operation,adoption,now)
        require(formal()==captured,'original adoption reopen changed state')
        host=(target/'host-key-and-id').read_bytes()
        target_before={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in target.rglob('*') if p.is_file()}
        requests=len(bridge.records)
        refuse('winner-history-does-not-extend-permission',lambda:recovery.activate_successor(
            EnrollmentClient.open(target/'client',host[32:],host[:32]),winner.policy.validity.end+1,
            transport=TcpTransport(bridge.address)),'expired or premature authority')
        require(target_before=={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in target.rglob('*') if p.is_file()}
                and len(bridge.records)==requests,'expired winner changed target or dispatched')
        recovery=RootRecovery.open(client_path,identity,key,registry,winner.operation)
        if retiring:
            from root_unactivated_fixture import exercise as retire_unactivated
            recovery,registry,result=retire_unactivated(recovery,registry,winner,bridge=bridge,client_path=client_path,
                identity=identity,key=key,target=target,refuse=refuse,kind='adopted',boundary=unactivated)
            require(business()==before,'unactivated successor retirement changed original retired business')
            return result
        client=recovery.activate_successor(EnrollmentClient.open(target/'client',host[32:],host[:32]),now,
                                           transport=TcpTransport(bridge.address))
        from root_successor_peer_fixture import exercise as communicate
        peer=communicate(client,recovery,registry,winner,bridge=bridge,now=now,path=target/'client',host=host,
                         mode='peer',refuse=refuse)
        continuation=None
        if continuing:
            from root_winner_continuation import exercise as continue_root
            recovery,registry,continuation=continue_root(recovery,registry,adoption,peer,bridge=bridge,now=now,
                client_path=client_path,identity=identity,key=key,refuse=refuse)
        require(business()==before,'winner traffic changed original retired business')
        return {'completed':True,'mode':mode,'original_bound':bound,'reused_original_inactive_target':reuse,
                'original_operation':original_operation.hex(),'winner_operation':winner.operation.hex(),
                'registry_revision':selected.revision,'no_fabricated_preparation':True,
                'history_refusals':history_refusals,'expired_winner_refused_before_io':True,
                'process_cut':process_cut,'cancellation':cancel_record,
                'original_formal_bytes_unchanged':True,'exact_retry_unchanged':True,
                **({'continuation':continuation} if continuation is not None else {}),
                'fence_hashes':{str(p/'root-fence'):hashlib.sha256((p/'root-fence').read_bytes()).hexdigest() for p in paths},
                'peer':peer,'scope':'Independent explicit approval of an actual native committed competitor, original signed noncommit, versioned adoption intent and original parent/child retirement, reopen and real successor traffic. Fixed test authority; no power-loss/mobile/PCS claim.'}
    finally:recovery.close();registry.close()
