#!/usr/bin/env python3
"""Independent retained account-root selection and original process recovery.

This suite does not claim EnrollmentClient/session fencing or live successor
activation. It uses public native signatures and private isolated registries.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import argparse
from dataclasses import replace
import gc
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

parser=argparse.ArgumentParser(description=__doc__)
for name in ('operator-output','implementation-root','provider-root','output'):
    parser.add_argument('--'+name,type=Path,required=True)
parser.add_argument('--scope',choices=('development','installed'),required=True)
parser.add_argument('--child',type=Path)
parser.add_argument('--operation',choices=('create','prepare','bind','close','retire'))
parser.add_argument('--stage')
args=parser.parse_args();implementation=args.implementation_root.resolve(strict=True)
sys.path.insert(0,str(implementation))
from qperiapt_continuity_reference.provider import load_provider
provider,_=load_provider(args.provider_root)
from cryptography.exceptions import InvalidSignature,InvalidTag
from qperiapt_continuity_reference import account_authority as authority
from qperiapt_continuity_reference.account_authority_state import Checkpoint,Image
from qperiapt_continuity_reference.account_root_record import RetainedPlan
from qperiapt_continuity_reference.journal import Journal,Scope
from qperiapt_continuity_reference.private_files import PrivateDirectory,MAX_FILE,MAX_DIRECTORY_BYTES
from qperiapt_continuity_reference.storage_budget import MAX_STATE,MAX_AUTHORITY_STATE,MAX_POLICY_STATE
from qperiapt_continuity_reference.wire import require
from qperiapt_continuity_reference.witness import Pin
sys.path.insert(0,str(Path(__file__).resolve().parent))
from account_root_fixture import RootFixture,bytes_field
from account_authority_support import Case,Inputs,OriginalInputs,STAGES,crash,child,private_json

require(Path(authority.__file__).resolve().is_relative_to(implementation),'registry module escaped selected package')
fixture=RootFixture(args.operator_output);inputs=Inputs(fixture)
if args.child:
    child(args,inputs)
    raise AssertionError('child returned')
require(args.output.is_absolute() and not args.output.exists(),'fresh absolute test output required')
args.output.mkdir(mode=0o700)
private_root=Path(tempfile.mkdtemp(prefix='qperiapt-original-root-registry-')).resolve()
require(not private_root.is_relative_to(args.output),'private registry fixture must be outside public output')
refusals=[];cuts=[]


class AuthorityChecks(unittest.TestCase):
    def case(self,suffix='',selected=inputs):
        case=Case(private_root/(self._testMethodName+suffix),selected)
        self.addCleanup(case.close);return case

    def refuse(self,label,action):
        with self.assertRaises((ValueError,InvalidSignature,InvalidTag,OSError)):action()
        refusals.append(label)

    def test_closed_operation_keeps_original_mapping_suspended(self):
        c=self.case();c.open(create=True);expected=c.associate();lease=c.owner.admit(expected)
        c.owner.begin_preparation(expected,inputs.first)
        self.refuse('pending-current',lambda:c.owner.current(c.application))
        self.refuse('pending-association',c.associate)
        self.refuse('pending-cached-lease',lease.check)
        c.owner.bind_freeze(inputs.first.operation,inputs.freeze)
        c.owner.close_plan(inputs.first.operation,inputs.closed)
        self.assertEqual(c.owner.operation(inputs.first.operation)[0],expected)
        self.refuse('closed-current',lambda:c.owner.current(c.application))
        self.refuse('closed-cached-lease',lease.check)
        c.close();c.open()
        self.refuse('reopened-closed-admission',lambda:c.owner.admit(expected))
        c.owner.begin_preparation(expected,inputs.next)
        self.assertEqual(c.owner.bind_freeze(inputs.next.operation,inputs.next_freeze),inputs.decision)
        selected=c.owner.commit_retirement(inputs.next.operation,inputs.decision,inputs.retired)
        self.assertEqual(selected,Checkpoint(c.application,2,inputs.next.successor.account))
        c.owner.admit(selected).check();c.close();c.open()
        self.assertEqual(c.owner.current(c.application),selected)
        self.refuse('reopened-old-admission',lambda:c.owner.admit(expected))

    def test_rejected_input_preserves_owner_and_lease(self):
        c=self.case();c.open(create=True);expected=c.associate();lease=c.owner.admit(expected)
        bad=bytearray(inputs.first.certificate);bad[-1]^=1
        self.refuse('unsigned-target',lambda:c.owner.begin_preparation(expected,replace(inputs.first,certificate=bytes(bad))))
        self.refuse('wrong-application',lambda:c.owner.begin_preparation(replace(expected,application=b'Z'*32),inputs.first))
        self.refuse('wrong-previous-account',lambda:c.owner.begin_preparation(replace(expected,account=b'Z'*32),inputs.first))
        self.refuse('retained-bytes-not-fresh-approval',lambda:c.owner.begin_preparation(expected,RetainedPlan(inputs.first.witness,inputs.first.wire())))
        lease.check();self.assertEqual(c.owner.current(c.application),expected)
        c.owner.begin_preparation(expected,inputs.first)
        original=c.owner.operation(inputs.first.operation)
        self.refuse('overlapping-plan',lambda:c.owner.begin_preparation(expected,inputs.next))
        self.refuse('reused-operation-retarget',lambda:c.owner.begin_preparation(expected,replace(inputs.first,journal=b'Z'*32)))
        bad=bytearray(inputs.freeze);bad[-1]^=1
        self.refuse('bad-freeze-signature',lambda:c.owner.bind_freeze(inputs.first.operation,bytes(bad)))
        self.refuse('closure-not-freeze',lambda:c.owner.bind_freeze(inputs.first.operation,inputs.closed))
        self.assertEqual(c.owner.operation(inputs.first.operation),original)
        c.owner.close_plan(inputs.first.operation,inputs.closed)
        self.refuse('closed-operation-cannot-rebind',lambda:c.owner.bind_freeze(inputs.first.operation,inputs.freeze))
        self.refuse('closed-operation-cannot-retire',lambda:c.owner.commit_retirement(inputs.first.operation,inputs.decision,inputs.retired))

    def test_retirement_reconciles_original_unbound_intent_only_once(self):
        c=self.case();expected=c.setup('retire');c.open()
        self.refuse('other-operation-retirement',lambda:c.owner.commit_retirement(inputs.first.operation,inputs.decision,inputs.retired))
        bad=bytearray(inputs.retired);bad[-1]^=1
        self.refuse('bad-retirement',lambda:c.owner.commit_retirement(inputs.next.operation,inputs.decision,bytes(bad)))
        self.refuse('closure-not-retirement',lambda:c.owner.commit_retirement(inputs.next.operation,inputs.decision,inputs.closed))
        selected=c.owner.commit_retirement(inputs.next.operation,inputs.decision,inputs.retired)
        lease=c.owner.admit(selected);head=(c.path/'head').read_bytes()
        self.assertEqual(c.owner.begin_preparation(expected,inputs.next),'Committed')
        self.assertEqual(c.owner.commit_retirement(inputs.next.operation,inputs.decision,inputs.retired),selected)
        lease.check();self.assertEqual((c.path/'head').read_bytes(),head)
        self.refuse('retirement-cannot-close',lambda:c.owner.close_plan(inputs.next.operation,inputs.closed))

    def test_exact_closure_requires_retained_bound_preparation(self):
        exact=OriginalInputs(fixture,'close');c=self.case(selected=exact)
        c.open(create=True);expected=c.associate();c.owner.begin_preparation(expected,exact.first)
        decision=bytes_field(fixture.public('close/bind/account-root-decision.json')['proposal'])
        proof=exact.proof('closed/account-root-outcome.json')
        self.refuse('unbound-exact-closure',lambda:c.owner.close_decision(exact.first.operation,decision,proof))
        c.owner.bind_freeze(exact.first.operation,exact.freeze)
        self.refuse('exact-is-not-plan-closure',lambda:c.owner.close_plan(exact.first.operation,proof))
        self.assertEqual(c.owner.close_decision(exact.first.operation,decision,proof),'Closed')
        c.close();c.open()
        self.assertEqual(c.owner.close_decision(exact.first.operation,decision,proof),'Closed')
        self.refuse('exact-closed-current',lambda:c.owner.current(c.application))

    def test_authenticated_freeze_constrains_later_replan(self):
        changed=replace(inputs.next,freeze_operation=b'Z'*32)
        for bound in (False,True):
            c=self.case('-'+str(bound));c.open(create=True);expected=c.associate()
            c.owner.begin_preparation(expected,inputs.first)
            if bound:c.owner.bind_freeze(inputs.first.operation,inputs.freeze)
            c.owner.close_plan(inputs.first.operation,inputs.closed);c.close();c.open()
            if bound:
                self.refuse('replan-cannot-forget-authenticated-freeze',lambda:c.owner.begin_preparation(expected,changed))
                self.assertEqual(c.owner.begin_preparation(expected,inputs.next),'Preparing')
            else:self.assertEqual(c.owner.begin_preparation(expected,changed),'Preparing')

    def test_original_creation_recovery_uses_reserved_intent(self):
        for n,stage in enumerate(STAGES):
            c=self.case('-'+str(n));cuts.append(crash(c,'create',stage,args))
            if stage in STAGES[:4]:self.refuse('initial-active-open-'+stage,c.open)
            c.open(initial=True);expected=c.associate();c.owner.admit(expected).check()
            c.close();c.open();c.owner.admit(expected).check()

    def test_lease_is_per_application_and_parent_owned(self):
        c=self.case();c.open(create=True);expected=c.associate()
        other=c.owner.associate(b'Z'*32,inputs.first.successor,inputs.first.certificate,inputs.first.listing)
        unaffected=c.owner.admit(other);original=c.owner.admit(expected)
        c.owner.begin_preparation(expected,inputs.next);unaffected.check()
        self.refuse('original-only-revoked',original.check)
        c.owner.commit_retirement(inputs.next.operation,inputs.decision,inputs.retired);unaffected.check()
        c.close();self.refuse('parent-close-revokes',unaffected.check)
        c.open();lease=c.owner.admit(other);c.owner=None;gc.collect()
        self.refuse('parent-drop-revokes',lease.check)
        c.open();c.owner.admit(other).check()

    def test_original_configuration_path_and_missing_state(self):
        c=self.case();c.open(create=True);expected=c.associate();c.close()
        family=inputs.first.policy.family;pin=inputs.first.witness
        variants=((b'Z'*32,c.identity,family,pin),(c.key,b'Z'*32,family,pin),
                  (c.key,c.identity,b'Z'*32,pin),(c.key,c.identity,family,Pin(b'Z'*32,pin.key)))
        for n,parameters in enumerate(variants):
            self.refuse('wrong-original-configuration-'+str(n),lambda:authority.AccountAuthority.open(c.path,*parameters))
        copied=c.root/'copied';shutil.copytree(c.path,copied)
        self.refuse('relocated-registry',lambda:authority.AccountAuthority.open(copied,c.key,c.identity,family,pin))
        empty=c.root/'missing';empty.mkdir(mode=0o700)
        self.refuse('missing-is-not-creation',lambda:authority.AccountAuthority.open(empty,c.key,c.identity,family,pin))
        self.refuse('empty-is-not-initial-recovery',lambda:authority.AccountAuthority.open(empty,c.key,c.identity,family,pin,initial=True))
        self.assertEqual(list(empty.iterdir()),[])
        self.refuse('existing-is-not-first-use',lambda:c.open(create=True))
        c.open();c.owner.admit(expected).check()

    def test_reentrant_close_and_storage_error_revoke_owner(self):
        for event in ('close','io'):
            c=self.case('-'+event);c.setup('prepare');lease=None
            def observe(stage):
                if stage=='published:intent':
                    self.refuse('during-write-'+event,lease.check)
                    if event=='close':c.owner.close()
                    else:raise OSError('isolated injected publication failure')
            c.open(observer=observe);expected=c.associate();lease=c.owner.admit(expected)
            self.refuse('write-failure-'+event,lambda:c.owner.begin_preparation(expected,inputs.first))
            self.refuse('failed-owner-'+event,lambda:c.owner.current(c.application))
            c.close();c.open();self.assertEqual(c.owner.operation(inputs.first.operation)[1],'Preparing')
            self.refuse('recovered-fence-'+event,lambda:c.owner.admit(expected))

    def test_registry_allocation_does_not_increase_business_payload(self):
        self.assertEqual(Journal.max_payload,2*1024*1024);self.assertEqual(MAX_FILE,MAX_STATE+4096)
        self.assertLess(3*(MAX_AUTHORITY_STATE+4096),MAX_DIRECTORY_BYTES)
        c=self.case();self.refuse('no-intermediate-new-allocation',lambda:PrivateDirectory(c.path,max_file=MAX_POLICY_STATE+4097))
        journal=Journal.create(c.path,Scope(b'A'*32,b'B'*32,b'C'*32),c.key,b'initial',lambda raw:None)
        self.addCleanup(journal.close);prior=journal.read()
        self.refuse('unchanged-business-ceiling',lambda:journal.update(prior.digest,b'X'*(MAX_STATE+1)))

    def test_retained_codec_bounds_and_original_decision_binding(self):
        c=self.case();c.open(create=True);expected=c.associate()
        c.owner.begin_preparation(expected,inputs.next)
        image=c.owner._image;raw=image.encode(c.owner.family,c.owner.witness)
        for n,changed in enumerate((b'',raw[:-1],raw+b'\0',b'bad-tag!'+raw[8:])):
            self.refuse('registry-codec-'+str(n),lambda:Image.read(changed,c.owner.family,c.owner.witness))
        self.refuse('association-capacity',lambda:replace(image,initial=image.initial*65).encode(c.owner.family,c.owner.witness))
        self.refuse('operation-capacity',lambda:replace(image,replacements=image.replacements*257).encode(c.owner.family,c.owner.witness))
        retained=RetainedPlan(inputs.next.witness,inputs.next.wire())
        for n,changed in enumerate((b'',retained.original[:-1],retained.original+b'\0',b'Z'*8193)):
            self.refuse('retained-plan-'+str(n),lambda:RetainedPlan(inputs.next.witness,changed).wire())
        for offset in (8,40,len(inputs.decision)-1):
            changed=bytearray(inputs.decision);changed[offset]^=1
            self.refuse('retained-decision-'+str(offset),lambda:retained.verify_retirement(bytes(changed),inputs.retired))
        self.refuse('unbound-is-not-retirement',lambda:retained.verify_retirement(inputs.next._parts()[1],inputs.retired))
        self.assertEqual(c.owner.commit_retirement(inputs.next.operation,inputs.decision,inputs.retired).revision,2)

    def test_real_sigkill_at_every_publication_boundary(self):
        for operation in ('prepare','bind','close','retire'):
            for n,stage in enumerate(STAGES):
                c=self.case('-'+operation+'-'+str(n));expected=c.setup(operation)
                cuts.append(crash(c,operation,stage,args));c.open()
                before=stage=='stage-synced:intent'
                if operation=='prepare' and before:
                    c.owner.admit(expected).check()
                    self.refuse('unpublished-operation-absent',lambda:c.owner.operation(inputs.first.operation))
                elif operation=='retire' and not before:
                    selected=c.owner.current(c.application);self.assertEqual(selected.revision,2)
                    self.assertEqual(selected.account,inputs.next.successor.account);c.owner.admit(selected).check()
                else:
                    self.refuse(operation+'-'+stage+'-old-fence',lambda:c.owner.admit(expected))
                # Recover/retry the original public operation; no new IDs or store reset.
                result=c.apply(operation)
                if operation=='retire':self.assertEqual(result.revision,2)
                else:self.refuse(operation+'-'+stage+'-retry-fence',lambda:c.owner.admit(expected))
                if operation=='bind':self.assertEqual(result,inputs.first.bind(inputs.freeze).wire())
                if operation=='close':self.assertEqual(result,'Closed')
                c.close()


sources={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((implementation/'qperiapt_continuity_reference').glob('*.py'))}
test_sources={str(Path(__file__).with_name(name)):hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
              for name in ('account_authority.py','account_authority_support.py','account_root_fixture.py')}
result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(AuthorityChecks))
unchanged=all(hashlib.sha256(Path(p).read_bytes()).hexdigest()==h for p,h in sources.items())
unchanged=unchanged and all(hashlib.sha256(Path(p).read_bytes()).hexdigest()==h for p,h in test_sources.items())
unchanged=unchanged and all(hashlib.sha256((fixture.source/p).read_bytes()).hexdigest()==h for p,h in fixture.inputs.items())
report=dict(completed=result.wasSuccessful() and unchanged,tests=result.testsRun,failures=len(result.failures),errors=len(result.errors),
            source_files=sources,test_source_files=test_sources,public_input_hashes=fixture.inputs,provider=provider.__version__,module_count=len(sources),
            refused=refusals,process_cuts=cuts,scope=args.scope,release_claim_eligible=False,
            private_root=str(private_root),private_keys_or_images_in_artifact=False,
            boundary='Independent original registry and revocable leases only; EnrollmentClient/child journals, live successor admission and PCS remain separate.')
private_json(args.output/'RESULT.json',report)
require(report['completed'],'independent account authority verification failed')
print(json.dumps(dict(completed=True,tests=result.testsRun,refusals=len(refusals),process_cuts=len(cuts),scope=args.scope)))
