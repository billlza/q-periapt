"""Restricted original-parent recovery after an approved root preparation.

This owner exposes historical metadata and signed freeze/noncommit recording.
It owns no traffic facade and never turns recovery access into a live lease.
It can inspect the original witnessed child without replay, retain signed
retirement before registry selection, and admit the exact prepared successor.
Peer handshake and traffic still use the normal client and current permission.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import replace
from contextlib import ExitStack
import threading
import weakref
from .account_authority import AccountAuthority
from .account_authority_state import Checkpoint
from .account_root_record import RetainedPlan
from .journal import Journal
from .owner_guard import coordinated
from .private_files import PrivateDirectory
from .registration_state import Image,PHASES
from .wire import require


def _close_owners(owners):
    with ExitStack() as cleanup:
        for owner in owners:cleanup.callback(owner.close)
        owners.clear()


class RootRecovery:
    def __init__(self):
        self._lock=threading.RLock();self._busy=False;self._owners=[]
        self._root=None;self._configuration=None;self._registration=None;self._access=None
        self._key=None
        self._transition=None
        self._finalizer=weakref.finalize(self,_close_owners,self._owners)

    @classmethod
    def open(cls,path,client_id,key,registry,operation,*,observer=None):
        return cls._open(path,client_id,key,registry,operation,observer=observer,transition=None)

    @classmethod
    def _open(cls,path,client_id,key,registry,operation,*,observer,transition):
        from .enrollment_client import Configuration,scope
        require(type(registry) is AccountAuthority,'original account registry required')
        owner=cls()
        try:
            owner._root=PrivateDirectory(path);owner._owners.append(owner._root)
            owner._configuration=Journal.open(path/'configuration',scope(client_id),key,Configuration.read)
            owner._owners.append(owner._configuration)
            configuration=Configuration.read(owner._configuration.read().payload)
            require(configuration.ready and configuration.root_binding is not None,'original root-associated client required')
            owner._access=registry._recovery_access(configuration.root_binding,operation)
            owner._transition=transition
            owner._registry=weakref.ref(registry);owner._binding=configuration.root_binding
            owner._adoption_pending=configuration.root_adoption and not configuration.root_ready
            owner._authority,original=configuration.inputs();owner._intent=original.intent
            owner._key=key
            require(owner._intent.family==registry.family,'original root recovery family')
            _,_,plan,_=owner._access.observation()
            require(RetainedPlan(registry.witness,plan).target.previous==owner._intent.root,'original root recovery issuer')
            original_owner=weakref.ref(owner)
            def observe(stage):
                if observer is not None:observer(stage)
                current=original_owner();require(current is not None,'closed original root recovery')
                current._alive()
            owner._observe=observe
            owner._configuration._directory.observer=lambda stage:observe('client-config:'+stage)
            intent=owner._intent
            from .root_fence import open_parent
            owner._registration=open_parent(path/'registration',owner._intent.scope(configuration.registration),key,
                lambda raw:Image.decode(raw,intent),owner._access,registry.witness,
                lambda stage:observe('client-device:registration-store:'+stage),transition=transition)
            owner._owners.append(owner._registration)
            owner._reconcile_association(configuration)
            owner._alive();return owner
        except BaseException:owner.close();raise

    def _alive(self):
        require(self._root is not None and self._access is not None,'closed original root recovery')
        self._root.check();self._access.check()

    def _image(self):
        self._alive();snapshot=self._registration.read();image=Image.decode(snapshot.payload,self._intent)
        require((image.child is not None and image.root_binding in (None,self._binding)) if self._adoption_pending
                else image.root_binding==self._binding,'original registration root binding differs')
        self._alive();return snapshot,image

    def _reconcile_association(self,configuration):
        from .enrollment_client import Configuration
        self._alive();snapshot=self._registration.read();image=Image.decode(snapshot.payload,self._intent)
        require(image.admission is not None,'original accepted registration absent')
        if self._adoption_pending:
            require(image.child is not None and image.root_binding in (None,self._binding),
                    'original partial root adoption differs')
            return  # Restricted metadata only; never complete an uninspected child migration.
        if configuration.root_ready:
            require(image.root_binding==self._binding,'completed client root association lost registration binding')
            return
        require(image.root_binding in (None,self._binding),'conflicting original registration root binding')
        if image.root_binding is None:
            require(image.child is None,'unbound child appeared during original association')
            self._registration.update(snapshot.digest,replace(image,root_binding=self._binding).encode(self._intent))
        self._image()
        snapshot=self._configuration.read()
        require(Configuration.read(snapshot.payload)==configuration,'original client root association changed')
        self._configuration.update(snapshot.digest,replace(configuration,root_ready=True).wire())
        require(Configuration.read(self._configuration.read().payload)==replace(configuration,root_ready=True),
                'original client root recovery readback')

    @coordinated
    def status(self):
        try:
            _,image=self._image();expected,state,plan,decision=self._access.observation()
            result={'checkpoint':expected,'operation':self._access.operation,'root_state':state,
                    'registration_phase':PHASES[image.phase()],'signing_id':image.identity,
                    'journal':image.admission.journal,'child_present':image.child is not None,
                    'confirmed_session':None if image.confirmation is None else image.confirmation.session,
                    'root_adoption_pending':self._adoption_pending,
                    'plan':plan,'decision':decision}
            self._alive();return result
        except BaseException:self.close();raise

    @coordinated
    def inspect_child(self,now):
        """Authenticate original witnessed state and pending work; never replay it."""
        try:
            from .root_child_snapshot import original_child
            _,image=self._image()
            result=original_child(self,image,now);self._alive();return result
        except BaseException:self.close();raise

    @coordinated
    def bind_freeze(self,receipt,*,now=None):
        try:
            self._alive();registry=self._registry();require(registry is not None,'closed account authority recovery owner')
            result=registry.bind_freeze(self._access.operation,receipt)
            self._retain_bound(now);self._alive();return result
        except BaseException:self.close();raise

    def _retain_bound(self,now,receipt=None):
        from .root_fence import retain
        from .root_child_snapshot import open_child,inspect
        _,image=self._image();registry=self._registry()
        require(registry is not None,'closed account authority recovery owner')
        if image.child is not None:
            require(type(now) is int and 0 <= now < 1 << 64,'explicit root recovery time required for original child')
            journal,context=open_child(self,image,now)
            try:
                journal._directory.observer=lambda stage:self._observe('root-child:'+stage)
                observation=inspect(journal,context)
                child=retain(journal,self._access,registry.witness,1,receipt=receipt,observation=observation)
                if receipt is not None:receipt=child.receipt
            finally:journal.close()
        # Recheck the original parent after child I/O before adding its fence.
        self._image()
        return retain(self._registration,self._access,registry.witness,2,receipt=receipt)

    @coordinated
    def retain_witness_retirement(self,receipt,*,now=None):
        """Retain exact child and parent retirement before selecting the successor."""
        try:
            self._alive();registry=self._registry();require(registry is not None,'closed account authority recovery owner')
            _,phase,original,decision=self._access.observation()
            require(phase!='Closed' and decision,'original bound root operation required')
            RetainedPlan(registry.witness,original).verify_retirement(decision,receipt)
            parent=self._retain_bound(now,receipt)
            result=registry.commit_retirement(self._access.operation,decision,parent.receipt)
            self._alive();return result
        except BaseException:self.close();raise

    @coordinated
    def activate_successor(self,target,now,*,transport):
        """Consume the exact prepared target and return its root-bound client.

        Interrupted binding resumes with RootAdoption.open on that same target.
        No bootstrap flight is emitted here; subsequent communication uses the
        normal client and its current admission checks. Until successful return,
        closing this recovery owner also closes the consumed successor owner.
        """
        from .client_root_adoption import RootAdoption
        from .enrollment_client import EnrollmentClient
        from .client_root_successor import prepare
        from .root_child_snapshot import open_child
        from .root_fence import read
        require(type(target) in (EnrollmentClient,RootAdoption),'original successor owner required')
        pending=ExitStack()
        pending.callback(target.close);self._owners.append(pending)
        try:
            require(type(now) is int and 0<=now<1<<64,'explicit successor activation time required')
            self._alive();registry=self._registry();require(registry is not None,'closed account authority owner')
            _,phase,original,decision=self._access.observation()
            require(phase=='Committed','successor requires committed original root retirement')
            retained=RetainedPlan(registry.witness,original);descriptor=retained.check_decision(decision)
            expected=Checkpoint(self._binding.application,self._binding.revision+1,descriptor.account)
            registry.admit(expected)
            _,image=self._image()
            parent=read(self._registration,self._access,registry.witness,2)
            require(parent is not None and parent.receipt is not None,'original parent retirement missing')
            if image.child is not None:
                child,_=open_child(self,image,now)
                try:
                    fence=read(child,self._access,registry.witness,1)
                    require(fence is not None and fence.receipt is not None,'original child retirement missing')
                finally:child.close()
            adopted=prepare(target,registry,expected,retained,now,transport)
            pending.callback(adopted.close);self._alive()
            client=adopted.commit(now,transport=transport)
            pending.callback(client.close);self._alive()
            with client.session(now,transport=transport) as session:
                require(session.status()=='Waiting','successor activation found advanced business state')
            self._alive();registry.admit(expected);client._alive()
            pending.pop_all()  # The returned client now belongs to the caller.
            return client
        except BaseException:
            self.close();raise
        finally:
            pending.close()
            if pending in self._owners:self._owners.remove(pending)

    @coordinated
    def retain_noncommit(self,receipt):
        try:
            self._alive();registry=self._registry();require(registry is not None,'closed account authority recovery owner')
            result=registry.close_plan(self._access.operation,receipt);self._alive();return result
        except BaseException:self.close();raise

    @coordinated
    def transition_after_noncommit(self,plan,receipt,freeze,now,*,closure='plan',observer=None):
        """Consume this owner and transfer its existing fences to an approved plan.

        An error may follow registry or fence publication. Resume the same inputs
        on the same path with resume_transition; never create replacement state.
        """
        try:
            self._image();registry=self._registry()
            require(registry is not None,'closed account authority owner')
            path,identity,key,operation=self._root.path,self._configuration.scope.identity,self._key,self._access.operation
            self.close()
            return type(self).resume_transition(path,identity,key,registry,operation,plan,receipt,freeze,now,
                                                closure=closure,observer=observer)
        except BaseException:self.close();raise

    @classmethod
    def resume_transition(cls,path,client_id,key,registry,operation,plan,receipt,freeze,now,*,closure='plan',observer=None):
        """Resume one explicitly approved closure-bound handoff, without traffic."""
        from .account_root_protocol import Plan
        from .enrollment_client import Configuration,scope
        from .root_fence import _Transition,read
        from .root_child_snapshot import open_child,inspect
        require(type(registry) is AccountAuthority and type(plan) is Plan,'fresh independently approved root plan required')
        require(type(now) is int and 0<=now<1<<64,'explicit root transition time required')
        expected,phase,original,decision=registry.operation(operation)
        require(phase!='Committed' and decision,'original bound noncommitted preparation required')
        retained=RetainedPlan(registry.witness,original)
        if closure=='plan':retained.verify_closed(receipt)
        elif closure=='decision':retained.verify_decision_closure(decision,receipt)
        else:raise ValueError('explicit root closure kind required')
        target=RetainedPlan(registry.witness,plan.wire());bound=plan.bind(freeze).wire()
        before,after=retained.check_decision(decision),target.check_decision(bound)
        require(plan.operation!=operation and target.decoded[0]==retained.decoded[0]
                and before.preparation==after.preparation and before.observations==after.observations
                and before.family==after.family,'root transition changes original frozen snapshot')
        configuration=Journal.open(path/'configuration',scope(client_id),key,Configuration.read)
        try:
            saved=Configuration.read(configuration.read().payload)
            require(saved.ready and saved.root_ready and saved.root_binding is not None,
                    'root transition requires original complete root association')
            old_access=registry._recovery_access(saved.root_binding,operation)
        finally:configuration.close()
        if closure=='plan':registry.close_plan(operation,receipt)
        else:registry.close_decision(operation,decision,receipt)
        registry.begin_preparation(expected,plan);registry.bind_freeze(plan.operation,freeze)
        current=registry._recovery_access(saved.root_binding,plan.operation)
        transition=_Transition(old_access,current,registry.witness,receipt,closure)
        owner=cls._open(path,client_id,key,registry,plan.operation,observer=observer,transition=transition)
        try:
            _,image=owner._image()
            require(read(owner._registration,current,registry.witness,2,transition=transition) is not None,
                    'root transition requires an existing original parent fence')
            with ExitStack() as cleanup:
                child=None
                if image.child is not None:
                    child,context=open_child(owner,image,now);cleanup.callback(child.close)
                    child._directory.observer=lambda stage:owner._observe('root-child:'+stage)
                    inspect(child,context)
                    require(read(child,current,registry.witness,1,transition=transition) is not None,
                            'root transition requires an existing original child fence')
                transition.retain(owner._registration,2)
                if child is not None:transition.retain(child,1)
                owner._alive()
        finally:owner.close()
        return cls.open(path,client_id,key,registry,plan.operation,observer=observer)

    def close(self):
        with self._lock:
            self._root=None;self._access=None;self._registration=None;self._configuration=None;self._key=None;self._transition=None
            self._finalizer()

    def __enter__(self):self._alive();return self
    def __exit__(self,*_error):self.close()


def begin(client,registry,plan):
    from .enrollment_client import Configuration
    from .account_root_protocol import Plan
    client._alive();require(type(registry) is AccountAuthority,'original account registry required')
    require(type(plan) is Plan,'independently approved original root plan required')
    configuration=Configuration.read(client._configuration.read().payload)
    require(configuration.root_binding is not None and configuration.root_ready,'original complete root association required')
    binding=configuration.root_binding
    binding.check(client._root_lease)
    expected=Checkpoint(binding.application,binding.revision,binding.account)
    binding.check(registry.admit(expected))
    require(plan.previous_root==client._authority.root,'root preparation changes original issuer')
    path=client._root.path;client_id=client._configuration.scope.identity;key=client._registration._key
    try:
        registry.begin_preparation(expected,plan)
    finally:client.close()
    return RootRecovery.open(path,client_id,key,registry,plan.operation)
