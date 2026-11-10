"""Isolated original registry cases and real process-cut driver."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import json
import os
from pathlib import Path
import signal
import subprocess
import sys

from account_root_fixture import bytes_field
from qperiapt_continuity_reference.account_authority import AccountAuthority
from qperiapt_continuity_reference.account_authority_state import Checkpoint
from qperiapt_continuity_reference.wire import require

STAGES=('stage-synced:intent','published:intent','committed:intent',
        'stage-synced:head','published:head','committed:head','removed:intent','committed:removal')


def private_json(path,value):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as output:
        json.dump(value,output);output.write('\n');output.flush();os.fsync(output.fileno())


class OriginalInputs:
    def __init__(self,fixture,profile):
        self.fixture=fixture;self.profile=profile
        self.first=fixture.selected(profile);fixture.check_plan(profile,self.first)
        self.old=fixture.public(profile+'/old-trust.json')
        self.application=bytes(fixture.public(profile+'/fixture.json')['application'])
        self.freeze=self.proof('freeze-retry/account-root-freeze.json')
        require(self.first.policy.family==bytes(self.old['account']['family']),
                'registry test requires one policy family')

    def proof(self,name):return bytes_field(self.fixture.public(self.profile+'/'+name)['receipt'])


class Inputs(OriginalInputs):
    def __init__(self,fixture):
        super().__init__(fixture,'replan')
        self.next=fixture.selected('replan',True)
        fixture.check_plan('replan',self.next,'replan-retry/account-root-plan.json')
        self.next_freeze=self.proof('same-frozen-root/account-root-freeze.json')
        self.closed=self.proof('original-plan-closed/account-root-plan-outcome.json')
        self.retired=self.proof('new-committed-target/account-root-outcome.json')
        self.decision=bytes_field(fixture.public('replan/new-bound-target/account-root-decision.json')['proposal'])
        require(self.first.policy.family==self.next.policy.family==bytes(self.old['account']['family']),
                'registry test requires one policy family')

class Case:
    def __init__(self,root,inputs,*,existing=False):
        self.root=root;self.inputs=inputs;self.path=root/'registry';self.owner=None
        if not existing:
            root.mkdir(mode=0o700);self.path.mkdir(mode=0o700)
            private_json(root/'original.json',{'key':os.urandom(32).hex(),'identity':os.urandom(32).hex()})
        original=json.loads((root/'original.json').read_bytes())
        self.key=bytes.fromhex(original['key']);self.identity=bytes.fromhex(original['identity'])
        self.application=inputs.application

    def open(self,*,create=False,observer=None,**options):
        require(self.owner is None,'test owner already open')
        function=AccountAuthority.provision if create else AccountAuthority.open
        self.owner=function(self.path,self.key,self.identity,self.inputs.first.policy.family,
                            self.inputs.first.witness,observer=observer,**options)
        return self.owner

    def associate(self):
        old=self.inputs.old
        return self.owner.associate(self.application,self.inputs.fixture.pin(old),
                                    bytes_field(old['certificate']),bytes_field(old['account']['roster']['bytes']))

    def close(self):
        if self.owner is not None:self.owner.close();self.owner=None

    def setup(self,operation):
        self.open(create=True);expected=self.associate()
        if operation in ('bind','close','retire'):
            plan=self.inputs.next if operation=='retire' else self.inputs.first
            self.owner.begin_preparation(expected,plan)
        if operation=='close':self.owner.bind_freeze(self.inputs.first.operation,self.inputs.freeze)
        self.close();return expected

    def apply(self,operation):
        owner=self.owner;i=self.inputs
        if operation=='prepare':
            expected=Checkpoint(self.application,1,i.fixture.pin(i.old).account)
            return owner.begin_preparation(expected,i.first)
        if operation=='bind':return owner.bind_freeze(i.first.operation,i.freeze)
        if operation=='close':return owner.close_plan(i.first.operation,i.closed)
        if operation=='retire':return owner.commit_retirement(i.next.operation,i.decision,i.retired)
        raise ValueError('unknown registry test operation')


def crash(case,operation,stage,args):
    cache=case.root/'empty-pycache';cache.mkdir(mode=0o700)
    command=[sys.executable,'-I','-S','-B','-X','pycache_prefix='+str(cache),str(Path(__file__).with_name('account_authority.py')),
             '--operator-output',str(args.operator_output),'--implementation-root',str(args.implementation_root),
             '--provider-root',str(args.provider_root),'--output',str(args.output),'--scope',args.scope,
             '--child',str(case.root),'--operation',operation,'--stage',stage]
    with (args.output/(case.root.name+'.stdout')).open('xb') as stdout,(args.output/(case.root.name+'.stderr')).open('xb') as stderr:
        result=subprocess.run(command,stdout=stdout,stderr=stderr,timeout=30,check=False)
    require(result.returncode==-signal.SIGKILL,'child did not reach original SIGKILL boundary: '+str(case.root))
    require(json.loads((case.root/'cut.json').read_bytes())=={'operation':operation,'stage':stage},'child cut identity')
    return {'operation':operation,'stage':stage,'returncode':result.returncode,'case':str(case.root)}


def child(args,inputs):
    case=Case(args.child,inputs,existing=True)
    def stop(stage):
        if stage==args.stage:
            private_json(case.root/'cut.json',{'operation':args.operation,'stage':stage})
            os.kill(os.getpid(),signal.SIGKILL)
    if args.operation=='create':case.open(create=True,observer=stop)
    else:case.open(observer=stop);case.apply(args.operation)
    raise AssertionError('requested original process cut was not reached')
