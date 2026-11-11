"""Restricted retirement of an exact selected successor that never activated."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from contextlib import ExitStack
from dataclasses import replace
from .account_authority import AccountAuthority
from .account_authority_state import Checkpoint
from .account_binding import Binding
from .account_root_protocol import Plan,_target_statement
from .account_root_record import retained_expectation
from .client_configuration import Configuration
from .client_root_adoption import _retained
from .enrollment_client import scope
from .journal import Journal,Conflict
from .private_files import PrivateDirectory
from .registration import RegistrationJournal
from .registration_state import Image
from .registration_session import selected_parts,validate_intent_context
from .root_adoption_journal import _OriginalSuccessor,verify_original_genesis
from .root_child_snapshot import _View,open_child
from .root_fence import _Parent,read
from .durable import Session
from .state_codec import decode
from .wire import require


def _history(owner,registry,now):
    _,phase,wire,decision=owner._access.observation()
    require(phase=='Committed','successor retirement requires original committed selection')
    retained=retained_expectation(registry.witness,wire);descriptor=retained.check_decision(decision)
    expected=Checkpoint(owner._binding.application,owner._binding.revision+1,descriptor.account)
    parent=read(owner._registration,owner._access,registry.witness,2)
    require(parent is not None and parent.receipt is not None,'original parent retirement missing')
    _,image=owner._image()
    if image.child is not None:
        child,_=open_child(owner,image,now)
        try:
            fence=read(child,owner._access,registry.witness,1)
            require(fence is not None and fence.receipt is not None,'original child retirement missing')
        finally:child.close()
    return retained,expected


def resume(cls,path,client_id,key,registry,operation,target_path,target_id,target_key,plan,now,*,observer,check):
    require(type(registry) is AccountAuthority and type(plan) is Plan,'original registry and independent next plan required')
    require(type(now) is int and 0<=now<1<<64,'explicit successor retirement time required')
    owner_check=check
    def check():
        if owner_check is not None:owner_check()
        registry._alive()
    def observe(stage):
        if observer is not None:observer(stage)
        check()
    with registry._checked_recovery(check),ExitStack() as cleanup:
        original=cls.open(path,client_id,key,registry,operation);cleanup.callback(original.close)
        retained,expected=_history(original,registry,now)
        require(plan.previous_root==retained.target.successor and plan.witness==registry.witness
                and plan.policy.family==registry.family,'next retirement changes original selected successor')
        approved=plan.wire()
        try:previous=registry.operation(plan.operation)
        except Conflict:previous=None
        if previous is None:
            lease=registry.admit(expected);binding=lease.binding
        else:
            require(previous[0]==expected and previous[1] in ('Preparing','Pending','Committed')
                    and previous[2]==approved,'next retirement differs from original preparation')
            lease=None
            binding=Binding(original._binding.registry,expected.application,expected.revision,expected.account)
        root=PrivateDirectory(target_path);cleanup.callback(root.close)
        configuration=Journal(target_path/'configuration',scope(target_id),target_key,Configuration.read)
        cleanup.callback(configuration.close)
        saved=Configuration.read(_retained(configuration).payload)
        authority,invitation=saved.inputs()
        require(saved.ready and authority.application==expected.application and authority.root==retained.target.successor
                and authority.family==registry.family,'original prepared successor authority differs')
        require(saved.root_binding is None or (saved.root_binding==binding and saved.root_adoption),
                'original prepared successor association differs')
        if saved.root_binding is None:
            require(configuration._admit().read('intent') is None,'unbound successor configuration remains pending')
        intent=invitation.intent
        access=None if previous is None or saved.root_binding is None else registry._recovery_access(binding,plan.operation)
        arguments=(target_path/'registration',intent.scope(saved.registration),target_key,
                   lambda raw:Image.decode(raw,intent))
        parent=(RegistrationJournal(*arguments) if access is None else
                _Parent(*arguments,access,registry.witness,None,None))
        cleanup.callback(parent.close)
        image=Image.decode(_retained(parent).payload,intent)
        require(image.admission is not None and image.child is not None and image.confirmation is None,
                'successor retirement requires original prepared child')
        require(image.root_binding in (None,binding) and (not saved.root_ready or image.root_binding==binding),
                'successor retirement registration binding differs')
        context=image.child.inputs.original(image.child.context,now)
        validate_intent_context(intent,image,context)
        require(context.witness is not None and context.witness.pin==registry.witness,'successor retirement witness differs')
        current,admission=image.effective(intent)
        actual,_=_target_statement(registry.witness,retained.target.operation,retained.target.previous,
            admission.pin(current),admission.certificate,admission.roster,context.original_policy,
            admission.journal,retained.target.genesis)
        require(actual==retained.target.unbound(),'successor signed target differs from approved target')
        child_scope,child_key=selected_parts(target_key,parent.scope.identity,image,context)
        genesis=retained.target.subject+retained.target.genesis
        child=(_View(image.child.path,child_scope,child_key,context,access,not saved.root_ready) if access is not None else
               _OriginalSuccessor(image.child.path,child_scope,child_key,Session._validator(context),context.witness,
                                  None,root_lease=lease if saved.root_binding is not None else None,expected_genesis=genesis))
        cleanup.callback(child.close)
        directory=child._admit();wire=directory.read('head');require(wire is not None,'original successor child absent')
        verify_original_genesis(child,wire,child._decode(wire),genesis)
        if saved.root_binding is None:require(directory.read('intent') is None,'unbound successor child remains pending')
        snapshot=_retained(child)
        pending=directory.read('intent')
        if pending is not None:
            _,_,target,_=child._decode_intent(pending)
            verify_original_genesis(child,target,snapshot,genesis)
        state=decode(snapshot.payload,context)
        try:require(state.traffic is None and state.operation._reply is None,'successor retirement found advanced business state')
        finally:state.close()
        check()
        registry.begin_preparation(expected,plan)
        # Only configuration metadata changes. The child and registration retain
        # their exact images, pending bytes and keys for restricted retirement.
        configuration._directory.observer=lambda stage:observe('successor-retirement:'+stage)
        snapshot=configuration.read()
        require(Configuration.read(snapshot.payload)==saved,'original successor configuration changed')
        if saved.root_binding is None:
            saved=replace(saved,root_binding=binding,root_ready=False,root_adoption=True)
            configuration.update(snapshot.digest,saved.wire())
        require(Configuration.read(configuration.read().payload)==saved,'successor retirement association readback')
        check()
        cleanup.close();check()
        # Borrow cancellation only while opening. Retaining check afterwards
        # would keep the registry alive through the returned journal observer.
        opening=[check]
        def observe_result(stage):
            if observer is not None:observer(stage)
            if opening[0] is not None:opening[0]()
        result=cls.open(target_path,target_id,target_key,registry,plan.operation,observer=observe_result)
        try:
            check();opening[0]=None;return result
        except BaseException:result.close();raise
