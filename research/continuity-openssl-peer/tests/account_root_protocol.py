#!/usr/bin/env python3
"""Installed independent verification of native operator public root statements.

Reads original trusted fixture inputs and public outputs only. It performs no
native calls, private-key reads, clock changes, host decisions or client cutover.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import argparse
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys
import unittest

parser=argparse.ArgumentParser(description=__doc__)
for name in ('operator-output','implementation-root','provider-root','output'):
    parser.add_argument('--'+name,type=Path,required=True)
args=parser.parse_args()
implementation=args.implementation_root.resolve(strict=True)
sys.path.insert(0,str(implementation))
from qperiapt_continuity_reference.provider import load_provider
provider,_=load_provider(args.provider_root)
from cryptography.exceptions import InvalidSignature
from qperiapt_continuity_reference import account_root_protocol as protocol
from qperiapt_continuity_reference.wire import VerificationKey,require
from qperiapt_continuity_reference.witness import Pin

require(Path(protocol.__file__).resolve().is_relative_to(implementation),'independent root module escaped installed package')
require(args.output.is_absolute() and not args.output.exists(),'fresh absolute root verification output required')
args.output.mkdir(mode=0o700)
source=args.operator_output.resolve(strict=True)
sys.path.insert(0,str(Path(__file__).resolve().parent))
from account_root_fixture import RootFixture,bytes_field,wire
fixture=RootFixture(source)
inputs=fixture.inputs;refusals=[]
public=fixture.public;selected=fixture.selected;check_plan=fixture.check_plan;bound=fixture.bound

class RootChecks(unittest.TestCase):
    def refuse(self,label,action):
        with self.assertRaises((ValueError,InvalidSignature)):action()
        refusals.append(label)

    def test_retirement_authenticates_original_target_and_complete_snapshot(self):
        plan=selected('commit');check_plan('commit',plan);decision=bound('commit',plan)
        self.assertGreaterEqual(len(decision.subjects()),1)
        receipt=bytes_field(public('commit/recovered-status.stdout')['receipt'])
        observed=decision.verify_retirement(receipt)
        self.assertEqual(observed.state,'RetiredAccount');self.assertEqual(observed.binding,decision.binding)
        for offset,label in [(4+72,'PQ'),(len(receipt)-1,'classical')]:
            altered=bytearray(receipt);altered[offset]^=1
            self.refuse('retirement-'+label,lambda:decision.verify_retirement(bytes(altered)))
        self.refuse('retirement-is-not-closure',lambda:decision.verify_closed(receipt))

    def test_exact_and_plan_closure_are_distinct_historical_statements(self):
        plan=selected('close');check_plan('close',plan);decision=bound('close',plan)
        closed=bytes_field(public('close/recovered-status.stdout')['receipt'])
        self.assertEqual(decision.verify_closed(closed).state,'ClosedDecision')
        self.refuse('exact-closure-is-not-plan',lambda:plan.verify_closed(closed))
        self.refuse('exact-closure-is-not-retirement',lambda:decision.verify_retirement(closed))
        original=selected('close-plan');check_plan('close-plan',original)
        receipt=bytes_field(public('close-plan/close-retry/account-root-plan-outcome.json')['receipt'])
        self.assertEqual(original.verify_closed(receipt).state,'ClosedPlan')
        self.refuse('plan-closure-is-not-retirement',lambda:decision.verify_retirement(receipt))
        self.refuse('plan-closure-is-not-freeze',lambda:original.bind(receipt))

    def test_replan_retains_original_freeze_and_distinct_verified_target(self):
        original=selected('replan');check_plan('replan',original)
        closed=bytes_field(public('replan/original-plan-closed/account-root-plan-outcome.json')['receipt'])
        original.verify_closed(closed)
        next_plan=selected('replan',True);check_plan('replan',next_plan,'replan-retry/account-root-plan.json')
        self.assertEqual(original._parts()[0],next_plan._parts()[0])
        self.assertNotEqual(original.operation,next_plan.operation);self.assertNotEqual(original.successor.account,next_plan.successor.account)
        decision=bound('replan',next_plan,'same-frozen-root/account-root-freeze.json','new-bound-target/account-root-decision.json')
        receipt=bytes_field(public('replan/new-committed-target/account-root-outcome.json')['receipt'])
        self.assertEqual(decision.verify_retirement(receipt).state,'RetiredAccount')
        self.refuse('new-retirement-is-not-old-closure',lambda:original.verify_closed(receipt))
        self.refuse('old-closure-is-not-new-closure',lambda:next_plan.verify_closed(closed))

    def test_plan_rechecks_independent_expectations_and_signed_metadata(self):
        plan=selected('commit');raw=bytes_field(public('commit/plan/account-root-plan.json')['plan'])
        bad_certificate=bytearray(plan.certificate);bad_certificate[-1]^=1
        bad_listing=bytearray(plan.listing);bad_listing[-1]^=1
        variants={'operation':replace(plan,operation=bytes([71])*32),'freeze':replace(plan,freeze_operation=bytes([72])*32),
            'journal':replace(plan,journal=bytes([73])*32),'head':replace(plan,genesis=bytes([74])*32),
            'previous-root':replace(plan,previous_root=plan.successor.root),
            'witness':replace(plan,witness=Pin(bytes([75])*32,plan.witness.key)),
            'certificate':replace(plan,certificate=bytes(bad_certificate)),'roster':replace(plan,listing=bytes(bad_listing)),
            'policy-metadata':replace(plan,policy=replace(plan.policy,digest=bytes([76])*32))}
        for label,changed in variants.items():self.refuse('plan-'+label,lambda:changed.verify_plan(raw))
        for length in (0,8,len(raw)-1):self.refuse('plan-truncated-'+str(length),lambda:plan.verify_plan(raw[:length]))
        self.refuse('plan-trailing',lambda:plan.verify_plan(raw+b'\0'))

    def test_freeze_rechecks_snapshot_both_signatures_and_original_request(self):
        plan=selected('commit');raw=bytes_field(public('commit/freeze-retry/account-root-freeze.json')['receipt'])
        for offset,label in [(8+8+32,'request'),(8+protocol.REQUEST_BYTES,'count'),(len(raw)-protocol.SIGNED_BYTES-1,'snapshot'),
                             (len(raw)-3373,'PQ'),(len(raw)-1,'classical')]:
            altered=bytearray(raw);altered[offset]^=1
            self.refuse('freeze-'+label,lambda:plan.bind(bytes(altered)))
        for length in (0,8,len(raw)-1):self.refuse('freeze-truncated-'+str(length),lambda:plan.bind(raw[:length]))
        self.refuse('freeze-trailing',lambda:plan.bind(raw+b'\0'))
        other=selected('close');self.refuse('freeze-other-original',lambda:other.bind(raw))

    def test_decision_cannot_substitute_an_unsigned_or_other_target(self):
        plan=selected('commit');decision=bound('commit',plan);raw=decision.wire()
        for offset in (8,40,72,len(raw)-1):
            altered=bytearray(raw);altered[offset]^=1
            self.refuse('decision-altered-'+str(offset),lambda:decision.verify_decision(bytes(altered)))
        self.refuse('unbound-target-is-not-decision',lambda:decision.verify_decision(plan._parts()[1]))

sources={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((implementation/'qperiapt_continuity_reference').glob('*.py'))}
result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(RootChecks))
unchanged=all(hashlib.sha256(Path(p).read_bytes()).hexdigest()==h for p,h in sources.items())
unchanged=unchanged and all(hashlib.sha256((source/p).read_bytes()).hexdigest()==h for p,h in inputs.items())
report=dict(completed=result.wasSuccessful() and unchanged,tests=result.testsRun,failures=len(result.failures),errors=len(result.errors),
    refused=refusals,source_files=sources,public_input_hashes=inputs,provider=provider.__version__,module_count=len(sources),
    scope='Installed independent Python/OpenSSL verifies original native plans, freeze snapshots, dual signatures, retirement and distinct closures across four operator profiles. Public historical evidence only; no durable independent root controller, parent/session fencing, live admission or PCS claim.',release_claim_eligible=False)
with (args.output/'RESULT.json').open('x') as output:json.dump(report,output,indent=2);output.write('\n')
require(report['completed'],'independent root protocol verification failed')
print(json.dumps(dict(completed=True,tests=result.testsRun,refusals=len(refusals),public_inputs=len(inputs),modules=len(sources))))
