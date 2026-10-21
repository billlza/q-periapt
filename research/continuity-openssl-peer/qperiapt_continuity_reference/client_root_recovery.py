"""Restricted original-parent recovery after an approved root preparation.

This owner exposes historical metadata and signed freeze/noncommit recording.
It owns no traffic facade and never turns recovery access into a live lease.
Child inspection, retirement retention and successor activation are separate.
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
from .registration import RegistrationJournal
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
        self._finalizer=weakref.finalize(self,_close_owners,self._owners)

    @classmethod
    def open(cls,path,client_id,key,registry,operation,*,observer=None):
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
            owner._registry=weakref.ref(registry);owner._binding=configuration.root_binding
            owner._adoption_pending=configuration.root_adoption and not configuration.root_ready
            owner._authority,original=configuration.inputs();owner._intent=original.intent
            require(owner._intent.family==registry.family,'original root recovery family')
            _,_,plan,_=owner._access.observation()
            require(RetainedPlan(registry.witness,plan).target.previous==owner._intent.root,'original root recovery issuer')
            original_owner=weakref.ref(owner)
            def observe(stage):
                if observer is not None:observer(stage)
                current=original_owner();require(current is not None,'closed original root recovery')
                current._alive()
            owner._configuration._directory.observer=lambda stage:observe('client-config:'+stage)
            intent=owner._intent
            owner._registration=RegistrationJournal.open(path/'registration',owner._intent.scope(configuration.registration),key,
                lambda raw:Image.decode(raw,intent),observer=lambda stage:observe('client-device:registration-store:'+stage))
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
    def bind_freeze(self,receipt):
        try:
            self._alive();registry=self._registry();require(registry is not None,'closed account authority recovery owner')
            result=registry.bind_freeze(self._access.operation,receipt);self._alive();return result
        except BaseException:self.close();raise

    @coordinated
    def retain_noncommit(self,receipt):
        try:
            self._alive();registry=self._registry();require(registry is not None,'closed account authority recovery owner')
            result=registry.close_plan(self._access.operation,receipt);self._alive();return result
        except BaseException:self.close();raise

    def close(self):
        with self._lock:
            self._root=None;self._access=None;self._registration=None;self._configuration=None
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
