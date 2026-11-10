"""Expire a selected inactive target, then retire it through the original stores."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from contextlib import closing
from dataclasses import replace
import hashlib
import os
from pathlib import Path
from cryptography.exceptions import InvalidTag
from qperiapt_continuity_reference.client_root_recovery import RootRecovery
from qperiapt_continuity_reference.enrollment_client import EnrollmentClient
from qperiapt_continuity_reference.wire import require
from qperiapt_continuity_reference.witness import TcpTransport
from root_retirement_fixture import control,field,pair
from root_target_fixture import prepare


def exercise(recovery,registry,plan,*,bridge,client_path,identity,key,target,refuse,kind,boundary=None):
    now=181;private=client_path.parent;host=(target/'host-key-and-id').read_bytes()
    require(len(host)==64 and plan.policy.validity.end==400,'unactivated retirement fixture inputs')
    selected=registry.current(recovery._binding.application);predecessor=recovery._access.observation()[3]
    require(selected.revision==2 and selected.account==plan.successor.account,'unactivated selected root differs')
    _,source_image=recovery._image()
    old_context=source_image.child.inputs.original(source_image.child.context,now)
    def reopen():return RootRecovery.open(client_path,identity,key,registry,plan.operation)
    def target_owner():return EnrollmentClient.open(target/'client',host[32:],host[:32])
    def files():return {str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in target.rglob('*') if p.is_file()}
    def original():return {str(p):hashlib.sha256(p.read_bytes()).hexdigest()
                          for directory in (client_path,private/'session') for p in directory.rglob('*') if p.is_file()}
    original_before=original();before=files();requests=len(bridge.records)
    refuse('expired-unactivated-successor-denied',lambda:recovery.activate_successor(
        target_owner(),now,transport=TcpTransport(bridge.address)),'expired or premature authority')
    require(files()==before and len(bridge.records)==requests,'expired activation changed original state or dispatched')
    recovery=reopen();bridge.call('unactivated-retirement-clock',33,now.to_bytes(8,'big'),b'witness clock set')
    with closing(target_owner()) as client:
        _,image=client._registration._image();inputs=image.child.inputs
        context=inputs.original(image.child.context,now)
        require(context.devices[0].validity.end==180,'credential expiry not isolated')
    following=private/'unactivated-following';following.mkdir(mode=0o700)
    fresh=bridge.call('unactivated-fresh-root-materials',45,now.to_bytes(8,'big'))
    later=prepare(following,selected.application,inputs.pins,inputs.materials,context,now,fresh,root_revision=3)
    next_target=following/'root-target';next_host=(next_target/'host-key-and-id').read_bytes()
    denied=[]
    def reject(label,path,who,secret,chosen,reason):
        nonlocal recovery
        previous=files();registry_head=hashlib.sha256((private/'account-registry/head').read_bytes()).hexdigest()
        try:recovery.retire_unactivated_successor(path,who,secret,chosen,now)
        except (ValueError,InvalidTag,OSError) as error:
            require(reason is None or reason in str(error),'unexpected unactivated retirement refusal')
            denied.append({'case':label,'error':str(error),'type':type(error).__name__})
        else:raise ValueError('unactivated retirement accepted '+label)
        require(files()==previous and hashlib.sha256((private/'account-registry/head').read_bytes()).hexdigest()==registry_head,
                'invalid successor retirement mutated original state')
        recovery=reopen()
    reject('wrong-previous-root',target/'client',host[32:],host[:32],replace(later,previous_root=plan.previous_root),
           'next retirement changes original selected successor')
    reject('wrong-target',next_target/'client',next_host[32:],next_host[:32],later,'original prepared successor authority differs')
    reject('wrong-storage-key',target/'client',host[32:],bytes([host[0]^1])+host[1:32],later,None)
    owner=None
    try:
        boundary_record=None
        if boundary is not None:
            from root_unactivated_boundaries import exercise as interrupt
            owner,registry,boundary_record=interrupt(recovery,registry,plan.operation,later,
                private=private,target=target,now=now,case=boundary)
        else:owner=recovery.retire_unactivated_successor(target/'client',host[32:],host[:32],later,now)
        recovery.close()
        require(owner.status()['root_adoption_pending'],'retirement silently activated expired successor')
        changed=[p for p in before.keys()|files().keys() if before.get(p)!=files().get(p)
                 and not Path(p).name.startswith('.stage-')]
        require(changed==[str(target/'client/configuration/head')],'unactivated retirement changed original business or keys')
        retained=files();owner.close();owner=RootRecovery.resume_successor_retirement(client_path,identity,key,registry,
            plan.operation,target/'client',host[32:],host[:32],later,now)
        require(files()==retained,'unactivated preparation retry changed original state')
        observation=owner.inspect_child(now)
        request=field(predecessor)+control(later)
        canonical,freeze=pair(bridge.call('unactivated-root-freeze',54,request));later.verify_plan(canonical)
        decision=later.bind(freeze);require(owner.bind_freeze(freeze,now=now)==decision.wire(),'unactivated frozen target differs')
        actual,retirement=pair(bridge.call('unactivated-root-retirement',55,request+field(decision.wire())))
        decision.verify_decision(actual);decision.verify_retirement(retirement)
        current=owner.retain_witness_retirement(retirement,now=now)
        require(current.revision==3 and registry.current(current.application)==current,'unactivated retirement lost next selection')
        require(owner.inspect_child(now)==observation,'retiring unactivated target changed business observation')
        with closing(owner.activate_successor(EnrollmentClient.open(next_target/'client',next_host[32:],next_host[:32]),now,
                                             transport=TcpTransport(bridge.address))) as client:
            with client.session(now,transport=TcpTransport(bridge.address)) as child:
                require(child.status()=='Waiting','fresh successor emitted unsolicited traffic')
        from root_unactivated_peer import exercise as communicate
        peer=communicate(owner,registry,plan,later,predecessor,inputs,bridge=bridge,now=now,target=next_target,
                         refuse=refuse,old_context=old_context)
        captured=files();owner.close();owner=RootRecovery.resume_successor_retirement(client_path,identity,key,registry,
            plan.operation,target/'client',host[32:],host[:32],later,now)
        require(files()==captured and registry.current(current.application)==current,'committed retirement retry changed root selection')
        require(original()==original_before,'unactivated retirement changed original source installation')
        lifetime=None
        if boundary is None:
            from root_unactivated_boundaries import registry_lifetime
            registry,lifetime=registry_lifetime(owner,registry,plan.operation,later,
                private=private,target=target,now=now)
        owner.close();owner=None;recovery=reopen()
        captured_registry=hashlib.sha256((private/'account-registry/head').read_bytes()).hexdigest()
        bridge.call('unactivated-historical-clock',33,(401).to_bytes(8,'big'),b'witness clock set')
        _,historic=pair(bridge.call('unactivated-historical-retirement',51,control(plan)+field(predecessor)))
        require(recovery.retain_witness_retirement(historic,now=401)==selected
                and registry.current(current.application)==current
                and hashlib.sha256((private/'account-registry/head').read_bytes()).hexdigest()==captured_registry,
                'historical inactive target retirement changed latest selection')
        refuse('unactivated-history-cannot-restore-old-root',lambda:registry.admit(selected),'account authority checkpoint differs')
        result={'completed':True,'kind':kind,'registry_revision':3,'expired_credential_end':180,'policy_end':400,'now':now,
                'original_operation':plan.operation.hex(),'next_operation':later.operation.hex(),
                'restricted_preparation_only_changes_configuration':True,'negative_preflight':denied,
                'boundary':boundary_record,'registry_lifetime':lifetime,'historical_retirement_preserves_later_selection':True,
                'exact_preparation_and_commit_retries_unchanged':True,'original_source_files_unchanged':True,
                'retired_target_files':captured,'original_files':original_before,'peer':peer,
                'scope':'Original never-activated root2 retires under a separately approved root3; installed restricted owner, real native witness and root3 traffic in original native journal. No same-key pre-handshake renewal, powerloss, general policy expiry or PCS claim.'}
        return recovery,registry,result
    except BaseException:
        registry.close();raise
    finally:
        if owner is not None:owner.close()
