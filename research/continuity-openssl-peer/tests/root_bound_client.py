#!/usr/bin/env python3
"""Original client/registration root association and guarded local storage.

Explicit signed test issuers are reused from enrollment_exchange. No live root
retirement, native wire interop, physical power loss or PCS is claimed here.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
from dataclasses import replace
import gc
import json
import os
from pathlib import Path
import signal
import sys
import time
import unittest
import weakref

sys.path.insert(0,str(Path(__file__).resolve().parent))
import enrollment_client as support
fixture=support.fixture
from qperiapt_continuity_reference.account_authority import AccountAuthority
from qperiapt_continuity_reference.enrollment_client import EnrollmentClient,Configuration
from qperiapt_continuity_reference.journal import Journal,Scope
from qperiapt_continuity_reference.registration import Registration
from qperiapt_continuity_reference.wire import SigningKey,digest,require
from qperiapt_continuity_reference.witness import Pin,Profile
from qperiapt_continuity_reference.witness_journal import WitnessJournal
from qperiapt_continuity_reference.private_files import DirectoryBusy
from qperiapt_continuity_reference.client_root_recovery import RootRecovery
from account_root_fixture import RootFixture

STAGES=('stage-synced:intent','published:intent','committed:intent','stage-synced:head',
        'published:head','committed:head','removed:intent','committed:removal')
cuts=[];refusals=[]


class RootClientChecks(unittest.TestCase):
    issue_for=fixture.ExchangeChecks.issue_for
    roster=fixture.ExchangeChecks.roster
    begin=support.ClientChecks.begin
    accept=support.ClientChecks.accept
    state=support.ClientChecks.state

    def setUp(self):
        support.ClientChecks.setUp(self)
        self.registry_path=fixture.args.private_output/(self._testMethodName+'.registry')
        self.registry_path.mkdir(mode=0o700)
        self.registry_key=os.urandom(32);self.registry_identity=os.urandom(32)
        self.witness=Pin(os.urandom(32),SigningKey().public())
        self.registry=AccountAuthority.provision(self.registry_path,self.registry_key,self.registry_identity,self.family,self.witness)
        self.recovery=None
        with os.fdopen(os.open(fixture.args.private_output/(self._testMethodName+'.registry-key'),
                              os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb') as out:
            out.write(self.registry_key+self.registry_identity);out.flush();os.fsync(out.fileno())

    def tearDown(self):
        if self.recovery is not None:self.recovery.close()
        self.registry.close();support.ClientChecks.tearDown(self)

    def ready(self):
        self.client=self.begin();self.issue_for(self.client.request(self.now));self.accept()
        return self.client.status()

    def reopen_registry(self):
        self.registry=AccountAuthority.open(self.registry_path,self.registry_key,self.registry_identity,self.family,self.witness)

    def refuse(self,name,action,reason):
        with self.assertRaisesRegex(ValueError,reason):action()
        refusals.append(name)

    def recovery_plan(self):
        # Reuse actual prepared native target/policy inputs, with a separately
        # approved test predecessor and fresh operation IDs. Native terminal
        # signatures for the old predecessor do not apply to this plan.
        require(fixture.args.root_fixture is not None,'root recovery tests require public native target fixture')
        public=RootFixture(fixture.args.root_fixture);target=public.selected('replan')
        trust=public.public('replan/root-trust.json')['successor']
        self.family=target.policy.family;self.witness=target.witness
        self.policy_pins=trust['policy']['pins'];self.policy_materials=trust['policy']['materials']
        self.start=max(self.start,target.policy.validity.start);self.end=min(self.end,target.policy.validity.end)
        require(self.start<=self.now<self.end,'native target fixture is not current for original client acceptance')
        self.authority_json=dict(self.authority_json,family=list(self.family))
        self.authority=fixture.exchange.HostAuthority.from_trusted(fixture.wire(self.authority_json))
        self.offer_json=dict(self.offer_json,family=list(self.family),valid_from=self.start,valid_until=self.end,
                             deadline=min(self.now+300,self.end))
        self.offer=fixture.exchange.HostInvitation.decode(fixture.wire(self.offer_json),self.authority)
        self.registry.close();self.registry_path=fixture.args.private_output/(self._testMethodName+'.recovery-registry')
        self.registry_path.mkdir(mode=0o700);self.registry_key=os.urandom(32);self.registry_identity=os.urandom(32)
        with os.fdopen(os.open(fixture.args.private_output/(self._testMethodName+'.recovery-registry-key'),
                              os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb') as out:
            out.write(self.registry_key+self.registry_identity);out.flush();os.fsync(out.fileno())
        self.registry=AccountAuthority.provision(self.registry_path,self.registry_key,self.registry_identity,self.family,self.witness)
        return replace(target,previous_root=self.root.public(),operation=os.urandom(32),freeze_operation=os.urandom(32))

    def test_preparation_consumes_client_and_reopens_restricted_original(self):
        plan=self.recovery_plan();original=self.ready();self.client.bind_account_root(self.registry)
        old_request=self.client.request
        self.recovery=self.client.prepare_account_root(self.registry,plan)
        status=self.recovery.status();self.assertEqual(status['root_state'],'Preparing')
        self.assertEqual(status['signing_id'],original['signing_id']);self.assertEqual(status['journal'],original['journal'])
        self.refuse('consumed-original-client',lambda:old_request(self.now),'closed enrollment client')
        with self.assertRaises(DirectoryBusy):
            EnrollmentClient.open(self.client_path,self.local_id,self.key,account_authority=self.registry)
        self.recovery.close()
        self.refuse('suspended-normal-client',lambda:EnrollmentClient.open(self.client_path,self.local_id,self.key,account_authority=self.registry),
                    'account authority suspended')
        self.recovery=RootRecovery.open(self.client_path,self.local_id,self.key,self.registry,plan.operation)
        self.assertEqual(self.recovery.status(),status)
        self.registry.close();self.refuse('closed-registry-recovery',self.recovery.status,'closed account authority owner')
        self.reopen_registry();self.recovery=RootRecovery.open(self.client_path,self.local_id,self.key,self.registry,plan.operation)
        self.assertEqual(self.recovery.status(),status)

    def test_recovery_access_is_not_a_live_lease_and_gc_releases_parent(self):
        plan=self.recovery_plan();self.ready();self.client.bind_account_root(self.registry)
        self.recovery=self.client.prepare_account_root(self.registry,plan)
        directory=fixture.args.private_output/(self._testMethodName+'.forbidden');directory.mkdir(mode=0o700)
        self.refuse('recovery-is-not-live-lease',lambda:Journal.create(directory,Scope(b'A'*32,b'B'*32,b'C'*32),
                    self.key,b'no business work',lambda raw:None,root_lease=self.recovery._access),'live account root lease required')
        self.assertEqual(list(directory.iterdir()),[])
        status=self.recovery.status();reference=weakref.ref(self.recovery);self.recovery=None;gc.collect()
        self.assertIsNone(reference())
        self.recovery=RootRecovery.open(self.client_path,self.local_id,self.key,self.registry,plan.operation)
        self.assertEqual(self.recovery.status(),status)

    def test_wrong_original_operation_is_read_only(self):
        plan=self.recovery_plan();self.ready();self.client.bind_account_root(self.registry)
        self.recovery=self.client.prepare_account_root(self.registry,plan);self.recovery.close();saved=self.state()
        self.refuse('wrong-original-recovery-operation',lambda:RootRecovery.open(self.client_path,self.local_id,self.key,self.registry,os.urandom(32)),
                    'original account root operation absent')
        self.assertEqual(self.state(),saved)
        self.recovery=RootRecovery.open(self.client_path,self.local_id,self.key,self.registry,plan.operation)
        self.assertEqual(self.recovery.status()['root_state'],'Preparing')

    def test_root_preparation_rejects_other_registry_before_approval(self):
        plan=self.recovery_plan();self.ready();self.client.bind_account_root(self.registry)
        alternate=fixture.args.private_output/(self._testMethodName+'.alternate');alternate.mkdir(mode=0o700)
        other=AccountAuthority.provision(alternate,os.urandom(32),os.urandom(32),self.family,self.witness)
        try:
            other.associate(self.authority.application,self.current.pin(self.offer),self.certificate,self.current.wire)
            expected=self.registry.current(self.authority.application);saved=self.state()
            self.refuse('prepare-other-registry',lambda:self.client.prepare_account_root(other,plan),'original root registry lease required')
            self.refuse('other-registry-not-prepared',lambda:other.operation(plan.operation),'original account root operation absent')
            self.assertEqual(self.registry.current(self.authority.application),expected)
            self.assertEqual(self.state(),saved)
        finally:other.close()

    def test_another_original_freeze_cannot_retarget_recovery(self):
        from account_root_fixture import bytes_field
        plan=self.recovery_plan();self.ready();self.client.bind_account_root(self.registry)
        self.recovery=self.client.prepare_account_root(self.registry,plan);original=self.recovery.status()
        public=RootFixture(fixture.args.root_fixture)
        receipt=bytes_field(public.public('replan/freeze-retry/account-root-freeze.json')['receipt'])
        self.refuse('other-predecessor-freeze',lambda:self.recovery.bind_freeze(receipt),'root original freeze request')
        self.recovery=RootRecovery.open(self.client_path,self.local_id,self.key,self.registry,plan.operation)
        self.assertEqual(self.recovery.status(),original)

    def test_suspended_original_partial_association_recovers_without_live_permission(self):
        plan=self.recovery_plan();original=self.ready();old_seed=self.client._registration._image()[1].seed
        reached=[]
        def prepare_after_config(stage):
            if stage=='client-config:committed:removal':
                reached.append(stage)
                expected=self.registry.current(self.authority.application)
                self.registry.begin_preparation(expected,plan)
                raise OSError('original association acknowledgement lost after root preparation')
        self.client._observer=prepare_after_config
        with self.assertRaisesRegex(OSError,'acknowledgement lost'):self.client.bind_account_root(self.registry)
        self.assertEqual(reached,['client-config:committed:removal'])
        self.recovery=RootRecovery.open(self.client_path,self.local_id,self.key,self.registry,plan.operation)
        status=self.recovery.status();self.assertEqual(status['signing_id'],original['signing_id'])
        self.assertEqual(status['journal'],original['journal']);self.assertEqual(status['root_state'],'Preparing')
        self.assertEqual(self.recovery._image()[1].seed,old_seed)
        configuration=Configuration.read(self.recovery._configuration.read().payload);self.assertTrue(configuration.root_ready)
        self.recovery.close();self.recovery=RootRecovery.open(self.client_path,self.local_id,self.key,self.registry,plan.operation)
        self.refuse('recovered-association-stays-suspended',lambda:self.registry.current(self.authority.application),'account authority suspended')

    def test_original_association_reopens_only_with_exact_registry(self):
        before=self.ready();binding=self.client.bind_account_root(self.registry)
        saved=self.state();self.assertEqual(self.client.bind_account_root(self.registry),binding)
        self.assertEqual(self.state(),saved)
        config=Configuration.read(self.client._configuration.read().payload)
        self.assertTrue(config.root_ready);self.assertEqual(config.root_binding,binding)
        self.client.close()
        self.refuse('client-missing-registry',lambda:EnrollmentClient.open(self.client_path,self.local_id,self.key),'original account registry required')
        self.assertEqual(self.state(),saved)
        self.refuse('raw-registration-missing-lease',lambda:Registration.open(self.client_path/'registration',config.registration,
                    self.key,self.offer.intent),'original root registry lease required')
        self.assertEqual(self.state(),saved)
        self.registry.close();self.reopen_registry()
        self.client=EnrollmentClient.open(self.client_path,self.local_id,self.key,account_authority=self.registry)
        self.assertEqual(self.client.status(),before)
        self.assertEqual(self.client.bind_account_root(self.registry),binding)

    def test_same_account_in_another_registry_is_not_the_original(self):
        self.ready();self.client.bind_account_root(self.registry);self.client.close();saved=self.state()
        alternate=fixture.args.private_output/(self._testMethodName+'.alternate');alternate.mkdir(mode=0o700)
        other=AccountAuthority.provision(alternate,os.urandom(32),os.urandom(32),self.family,self.witness)
        try:
            other.associate(self.authority.application,self.current.pin(self.offer),self.certificate,self.current.wire)
            self.refuse('substituted-registry',lambda:EnrollmentClient.open(self.client_path,self.local_id,self.key,account_authority=other),
                        'original root registry lease required')
        finally:other.close()
        self.assertEqual(self.state(),saved)
        self.client=EnrollmentClient.open(self.client_path,self.local_id,self.key,account_authority=self.registry)

    def test_registry_close_revokes_retained_client_and_registration(self):
        self.ready();binding=self.client.bind_account_root(self.registry)
        registration=self.client._registration;retained=self.client.request;saved=self.state()
        self.registry.close()
        self.refuse('client-cached-operation',lambda:retained(self.now),'closed account authority owner')
        self.refuse('registration-cached-operation',registration.status,'closed registration owner')
        self.assertEqual(self.state(),saved)
        self.reopen_registry()
        self.client=EnrollmentClient.open(self.client_path,self.local_id,self.key,account_authority=self.registry)
        self.assertEqual(self.client.bind_account_root(self.registry),binding)

    def test_local_and_inactive_witness_headers_require_original_lease(self):
        self.ready();self.client.bind_account_root(self.registry)
        lease=self.registry.admit(self.registry.current(self.authority.application))
        scope=Scope(os.urandom(32),os.urandom(32),os.urandom(32))
        directory=fixture.args.private_output/(self._testMethodName+'.journal');directory.mkdir(mode=0o700)
        key=os.urandom(32);payload=b'QPTEST01original root-bound state'
        def validate(raw):require(raw==payload,'original tagged test payload')
        owner=Journal.create(directory,scope,key,payload,validate,root_lease=lease)
        self.assertEqual((directory/'head').read_bytes()[:8],b'QPREFJ02');owner.close()
        self.refuse('raw-local-journal-missing-lease',lambda:Journal.open(directory,scope,key,validate),'original root registry lease required')
        owner=Journal.open(directory,scope,key,validate,root_lease=lease)
        self.assertEqual(owner.read().payload,payload);owner.close()
        witness_dir=fixture.args.private_output/(self._testMethodName+'.witness');witness_dir.mkdir(mode=0o700)
        profile=Profile(self.witness,scope.owner,bytes(self.policy_pins['policy_digest']),
                        digest(b'AUTHORITY',self.account+self.current.pin(self.offer).checkpoint()+self.family))
        genesis=WitnessJournal.provision(witness_dir,scope,key,payload,validate,profile,root_lease=lease)
        self.assertEqual((witness_dir/'head').read_bytes()[:8],b'QPREFW02')
        self.refuse('inactive-witness-missing-lease',lambda:WitnessJournal.recover_genesis(witness_dir,scope,key,validate,profile),
                    'original root registry lease required')
        self.assertEqual(WitnessJournal.recover_genesis(witness_dir,scope,key,validate,profile,root_lease=lease),genesis)
        original=(directory/'head').read_bytes();owner=Journal.open(directory,scope,key,validate,root_lease=lease)
        self.registry.close();self.refuse('raw-journal-owner-revoked',owner.read,'closed account authority owner')
        self.assertEqual((directory/'head').read_bytes(),original)

    def test_actual_association_process_cuts_reconcile_original_records(self):
        base=self.client_path
        for phase,prefix,occurrence in (('configuration','client-config:',1),
                ('registration','client-device:registration-store:',1),('ready','client-config:',2)):
            for index,stage in enumerate(STAGES):
                self.client_path=Path(str(base)+'-'+phase+'-'+str(index));self.client_path.mkdir(mode=0o700)
                original=self.ready();self.client.close();self.registry.close()
                marker=fixture.args.private_output/(self.client_path.name+'.cut')
                pid=os.fork()
                if pid==0:
                    observed=0
                    def stop(value):
                        nonlocal observed
                        if value!=prefix+stage:return
                        observed+=1
                        if observed!=occurrence:return
                        with os.fdopen(os.open(marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w') as out:
                            json.dump({'phase':phase,'stage':stage,'pid':os.getpid()},out);out.flush();os.fsync(out.fileno())
                        os.kill(os.getpid(),signal.SIGKILL)
                    try:
                        self.reopen_registry()
                        self.client=EnrollmentClient.open(self.client_path,self.local_id,self.key,observer=stop)
                        self.client.bind_account_root(self.registry)
                    except BaseException:
                        import traceback
                        traceback.print_exc();os._exit(71)
                    os._exit(72)
                deadline=time.monotonic()+30
                while True:
                    finished,status=os.waitpid(pid,os.WNOHANG)
                    if finished:break
                    if time.monotonic()>=deadline:
                        os.kill(pid,signal.SIGKILL);os.waitpid(pid,0)
                        self.fail(f'original process cut timed out: {phase}/{stage}')
                    time.sleep(.01)
                self.assertTrue(os.WIFSIGNALED(status),f'cut not reached: {phase}/{stage}: {status}')
                self.assertEqual(os.WTERMSIG(status),signal.SIGKILL)
                self.assertEqual(json.loads(marker.read_bytes()),{'phase':phase,'stage':stage,'pid':pid})
                cuts.append({'phase':phase,'stage':stage,'signal':'SIGKILL','pid':pid})
                self.reopen_registry()
                if phase=='configuration' and index==0:
                    # The first configuration intent was never published. Keep
                    # its orphan and explicitly retry this original association.
                    self.client=EnrollmentClient.open(self.client_path,self.local_id,self.key)
                else:self.client=EnrollmentClient.open(self.client_path,self.local_id,self.key,account_authority=self.registry)
                binding=self.client.bind_account_root(self.registry)
                self.assertEqual(self.client.status(),original)
                self.client.close()
                self.client=EnrollmentClient.open(self.client_path,self.local_id,self.key,account_authority=self.registry)
                self.assertEqual(self.client.bind_account_root(self.registry),binding);self.client.close()


sources={str(path):hashlib.sha256(path.read_bytes()).hexdigest()
         for path in (fixture.implementation/'qperiapt_continuity_reference').glob('*.py')}
sources.update({str(Path(path)):hashlib.sha256(Path(path).read_bytes()).hexdigest()
                for path in (__file__,support.__file__,fixture.__file__)})
public_inputs={} if fixture.args.root_fixture is None else {
    str(path):hashlib.sha256(path.read_bytes()).hexdigest() for path in fixture.args.root_fixture.rglob('*.json')}
result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(RootClientChecks))
unchanged=all(hashlib.sha256(Path(path).read_bytes()).hexdigest()==expected for path,expected in sources.items())
unchanged=unchanged and all(hashlib.sha256(Path(path).read_bytes()).hexdigest()==expected for path,expected in public_inputs.items())
report={'completed':result.wasSuccessful() and unchanged,'tests':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),
        'refusals':refusals,'process_cuts':cuts,'private_fixtures':str(fixture.args.private_output),
        'source_files':sources,
        'public_input_hashes':public_inputs,
        'scope':'Selected client/registration association, guarded storage and restricted original-parent recovery. Native prepared target/policy inputs with separately approved test predecessor and operation IDs; no native terminal receipt applies to that altered plan. No child retirement or successor activation claim.'}
with (fixture.args.private_output/'RESULT.json').open('x') as out:json.dump(report,out,indent=2);out.write('\n')
print(json.dumps({key:report[key] for key in ('completed','tests','failures','errors','private_fixtures')}))
raise SystemExit(0 if report['completed'] else 1)
