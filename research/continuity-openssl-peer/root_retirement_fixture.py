"""Actual native signed freeze/retirement and original independent local fences."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
import os
from cryptography.exceptions import InvalidSignature
from qperiapt_continuity_reference.client_root_recovery import RootRecovery
from qperiapt_continuity_reference.durable import Session
from qperiapt_continuity_reference.registration import RegistrationJournal
from qperiapt_continuity_reference.registration_session import selected_parts
from qperiapt_continuity_reference.registration_state import Image
from qperiapt_continuity_reference.wire import Reader, require
from qperiapt_continuity_reference.witness_journal import WitnessJournal


def field(raw): return len(raw).to_bytes(4, 'big') + raw


def control(plan):
    return (plan.previous_root.raw + plan.successor.account + plan.successor.root.raw
            + plan.successor.checkpoint() + plan.policy.checkpoint()[:8]
            + field(plan.certificate) + field(plan.listing) + plan._parts()[2] + plan.genesis + field(plan.wire()))


def pair(wire):
    r=Reader(wire);result=[r.take(r.integer(4)) for _ in range(2)];r.finish();return result


def exercise(recovery,registry,plan,*,bridge,now,client_path,identity,key,session_path,context,observation,refuse,mode,cut=None,successor=None):
    def reopen():return RootRecovery.open(client_path,identity,key,registry,plan.operation)
    paths=(client_path/'registration',session_path)
    def originals():
        return {str(path/name):hashlib.sha256((path/name).read_bytes()).hexdigest()
                for path in paths for name in ('head','intent','authority') if (path/name).exists()}
    before=originals();request=control(plan)
    bridge.call('root-current-clock',33,now.to_bytes(8,'big'),b'witness clock set')
    canonical,freeze=pair(bridge.call('root-original-freeze',50,request))
    plan.verify_plan(canonical);decision=plan.bind(freeze)
    selected=[row for row in decision.subjects() if row.subject==observation.subject]
    require(len(selected)==1,'native freeze lacks original subject')
    observed=selected[0]
    require(observed.head==observation.local_head or observed.head==observation.target,
            'native frozen head differs from original retained operation')
    bad=bytearray(freeze);bad[-65]^=1
    try:recovery.bind_freeze(bytes(bad),now=now)
    except InvalidSignature as error:invalid_freeze=type(error).__name__
    else:raise ValueError('invalid native freeze signature accepted')
    require(originals()==before and all(not (p/'root-fence').exists() for p in paths),
            'invalid freeze changed original state')
    recovery=reopen()
    cut_record=None
    try:
        if cut is not None and cut[0]=='bind':
            from root_retirement_cuts import exercise as process_cut
            recovery,registry,cut_record=process_cut(recovery,registry,plan,freeze,cut=cut,private=client_path.parent,
                                                     identity=identity,key=key,now=now)
        require(recovery.bind_freeze(freeze,now=now)==decision.wire(),'independent bound decision differs')
        require(originals()==before and all((p/'root-fence').is_file() for p in paths),'root freeze changed head or omitted fence')
        _,image=recovery._image();scope,child_key=selected_parts(key,recovery._registration.scope.identity,image,context)
        parent_scope=recovery._registration.scope;intent=recovery._intent
        recovery.close()
        refuse('fenced-raw-registration',lambda:RegistrationJournal.open(client_path/'registration',parent_scope,key,
               lambda raw:Image.decode(raw,intent)),'original account root is fenced')
        refuse('fenced-raw-session',lambda:WitnessJournal(session_path,scope,child_key,Session._validator(context),
               context.witness,None),'original account root is fenced')
        recovery=reopen();require(recovery.inspect_child(now)==observation,'fence changed retained child metadata')
        native_decision,retired=pair(bridge.call('root-original-retirement',51,request+field(decision.wire())))
        decision.verify_decision(native_decision);decision.verify_retirement(retired)
        pending_fences={str(p/'root-fence'):(p/'root-fence').read_bytes() for p in paths}
        bad=bytearray(retired);bad[-65]^=1
        try:recovery.retain_witness_retirement(bytes(bad),now=now)
        except InvalidSignature as error:invalid_retirement=type(error).__name__
        else:raise ValueError('invalid native retirement signature accepted')
        require(pending_fences=={str(p/'root-fence'):(p/'root-fence').read_bytes() for p in paths}
                and originals()==before,'invalid retirement changed original records')
        refuse('invalid-retirement-retains-suspension',lambda:registry.current(recovery._binding.application),
               'account authority suspended')
        recovery=reopen()
        if cut is not None and cut[0]=='retire':
            from root_retirement_cuts import exercise as process_cut
            recovery,registry,cut_record=process_cut(recovery,registry,plan,retired,cut=cut,private=client_path.parent,
                                                     identity=identity,key=key,now=now)
        current=recovery.retain_witness_retirement(retired,now=now)
        require(current.account==plan.successor.account and current.revision==2
                and registry.current(current.application)==current,'original root registry selection differs')
        retained={str(p/'root-fence'):hashlib.sha256((p/'root-fence').read_bytes()).hexdigest() for p in paths}
        require(originals()==before,'retirement changed original head, intent or authority')
        activated=None
        if successor is not None:
            from root_successor_fixture import exercise as activate_original
            recovery,activated=activate_original(recovery,registry,plan,bridge=bridge,now=now,client_path=client_path,
                identity=identity,key=key,refuse=refuse,mode=successor)
            require(originals()==before,'successor activation changed retired original state')
        recovery.close();recovery=reopen()
        require(recovery.inspect_child(now)==observation,'retirement hid original pending state')
        bridge.call('root-witness-reopen',32,b'',b'witness reopened')
        # Current permission expires; exact retirement/freeze history remains available.
        later=plan.policy.validity.end+1
        bridge.call('root-historical-clock',33,later.to_bytes(8,'big'),b'witness clock set')
        repeated_plan,repeated_freeze=pair(bridge.call('root-historical-freeze',50,request))
        plan.verify_plan(repeated_plan);require(plan.bind(repeated_freeze).wire()==decision.wire(),'freeze history changed')
        repeated_decision,repeated_retired=pair(bridge.call('root-historical-retirement',51,request+field(decision.wire())))
        decision.verify_decision(repeated_decision);decision.verify_retirement(repeated_retired)
        require(recovery.retain_witness_retirement(repeated_retired,now=later)==current,'retirement incremented registry twice')
        require(originals()==before and retained=={str(p/'root-fence'):hashlib.sha256((p/'root-fence').read_bytes()).hexdigest()
                for p in paths},'equivalent signed retry rewrote original local records')
        require(recovery.inspect_child(later)==observation,'expired historical inspection changed old state')
        if mode=='steady' and cut is None:
            from qperiapt_continuity_reference.private_files import PrivateDirectory
            from qperiapt_continuity_reference.root_child_snapshot import _View
            from qperiapt_continuity_reference.root_fence import open_parent
            for label,source,changed in (('parent',paths[0],'root-fence'),('child',paths[1],'head')):
                fault=client_path.parent/('root-fault-'+label);fault.mkdir(mode=0o700)
                for name in ('head','intent','authority','root-fence'):
                    if not (source/name).exists():continue
                    raw=(source/name).read_bytes()
                    if name==changed:
                        altered=bytearray(raw);altered[-1]^=1;raw=bytes(altered)
                    with os.fdopen(os.open(fault/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb') as out:
                        out.write(raw);out.flush();os.fsync(out.fileno())
                if label=='parent':
                    refused=lambda:open_parent(fault,parent_scope,key,lambda raw:Image.decode(raw,intent),
                                               recovery._access,registry.witness,None)
                    reason='root fence authentication'
                else:
                    refused=lambda:_View(fault,scope,child_key,context,recovery._access,False)
                    reason='root fence original state changed'
                refuse('corrupted-root-'+label,refused,reason)
                lease=PrivateDirectory(fault)
                try:lease.check()
                finally:lease.close()
            require(originals()==before and retained=={str(p/'root-fence'):hashlib.sha256((p/'root-fence').read_bytes()).hexdigest()
                    for p in paths},'isolated corruption changed original root state')
        return {'completed':True,'native_signed_freeze':True,'native_signed_retirement':True,
                'invalid_freeze_refused':invalid_freeze,
                'invalid_retirement_refused':invalid_retirement,'mode':mode,
                'process_cut':cut_record,
                'successor':activated,
                'original_subject':observed.subject.hex(),'frozen_head':observed.head.wire().hex(),
                'frozen_last_command':None if observed.last is None else observed.last.hex(),
                'local_head':observation.local_head.wire().hex(),'pending_kind':observation.pending_kind,
                'parent_and_child_retirement_retained':True,'original_formal_bytes_unchanged':True,
                'registry_revision':current.revision,'historical_retry_time':later,'fence_hashes':retained,
                'scope':'Actual independent successor preparation, native complete signed freeze/retirement, original local fences before registry selection. No successor traffic activation, closure/replan or mobile/release claim.'}
    finally:recovery.close();registry.close()
