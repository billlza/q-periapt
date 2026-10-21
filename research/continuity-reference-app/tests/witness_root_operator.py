#!/usr/bin/env python3
"""Actual witness CLI root operations with isolated native-signed test authority.

This exercises the local trusted operator, not HTTP account authorization,
independent root replacement, installed foreign owners or witness-key handoff.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

parser=argparse.ArgumentParser(description=__doc__)
for name in ('witness','test-artifacts','implementation-root','provider-root','output'):
    parser.add_argument('--'+name,type=Path,required=True)
args=parser.parse_args();sys.path.insert(0,str(args.implementation_root.resolve(strict=True)))
from qperiapt_continuity_reference.provider import load_provider
provider,_=load_provider(args.provider_root)
from qperiapt_continuity_reference.wire import require
sys.path.insert(0,str(Path(__file__).resolve().parent))
from host_replacement_process import Commands
from native_exchange_fixture import b64,save

root=args.output;require(root.is_absolute() and not root.exists(),'fresh absolute root operator output required');root.mkdir(mode=0o700)
rows=[json.loads(line) for line in args.test_artifacts.read_bytes().splitlines()]
require(rows[-1]=={'reason':'build-finished','success':True},'test binary build did not finish successfully')
executables=[Path(row['executable']).resolve(strict=True) for row in rows if row.get('reason')=='compiler-artifact'
             and row.get('executable') and row['target']['name']=='q_periapt_continuity_reference_app' and row['profile']['test']]
require(len(executables)==1,'one selected native test helper required');test_binary=executables[0]
witness=args.witness.resolve(strict=True);binaries={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in (test_binary,witness)}
repository=Path(__file__).resolve().parents[3]
sources=[p for name in ('crates','research/continuity-identity-candidate/src','research/continuity-reference-app/src','research/continuity-reference-app/tests')
         for p in (repository/name).rglob('*') if p.is_file() and p.suffix in ('.rs','.py','.toml','.lock')]
inventory=lambda:{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(sources)}
before=inventory();result=dict(completed=False,kind='qperiapt.witness_root_operator',schema_version=1,source_files=before,native_sha256=binaries,
    provider=provider.__version__,clock='actual OS time',profiles=[],release_claim_eligible=False)
try:
    for profile in ('commit','close','close-plan','replan'):
        directory=root/profile;directory.mkdir(mode=0o700);index=directory/'fixture.json'
        environment=dict(os.environ,QPERIAPT_ROOT_OPERATOR_CLI_OUTPUT=str(index))
        generated=subprocess.run([str(test_binary),'--exact','witness::tests::account_root::process::original_cutover_child','--nocapture'],
            env=environment,capture_output=True,timeout=60)
        save(directory/'fixture.stdout',generated.stdout);save(directory/'fixture.stderr',generated.stderr)
        require(generated.returncode==0 and b'1 passed; 0 failed' in generated.stdout,'root operator fixture failed')
        fixture=json.loads(index.read_bytes());private=Path(fixture['fixture']);require(private.is_absolute(),'fixture path')
        require(generated.stderr==f'Retained witness host fixture: {private}\n'.encode(),'unexpected fixture diagnostics')
        require(fixture['previous_account']!=fixture['successor_account'],'root fixture reused its account')
        for name in ('root-trust.json','root-request.json','expected-plan.json','old-trust.json','old-request.json',
                     'unseen-trust.json','unseen-request.json','next-trust.json',
                     'new-root-trust.json','new-root-request.json','new-target-trust.json'):
            save(directory/name,(private/name).read_bytes())
        keys={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in private.rglob('*') if p.suffix in ('.signer','.wrap')}
        run=Commands(directory);common=[witness];host=[private/'host.redb',b64(bytes(fixture['host_identity']))]
        def invoke(command,label,inputs,*,success=True,lost=False):
            destination=directory/label;destination.mkdir(mode=0o700)
            value=run([*common,command,*host,*inputs,destination],label,success=success,lost_stdout=lost)
            if not success and not lost:
                expected={'bad-plan':b'Error: "Account root plan binding differs"\n',
                          'closed-plan-refused':b'Error: "Original account root plan is permanently closed"\n',
                          'exact-closure-is-not-plan-closure':b'Error: Conflict\n',
                          'closed-commit-refused':b'Error: Protocol(Retired)\n'}[label]
                require((directory/(label+'.stderr')).read_bytes()==expected,'root refusal did not reach its intended boundary')
            return value,destination
        def enroll(name,label,*,success):
            value=run([*common,'enroll',*host,private/(name+'-trust.json'),private/(name+'-request.json')],label,success=success)
            if not success:require((directory/(label+'.stderr')).read_bytes()==b'Error: Protocol(Scope)\n','old-account refusal was not the scope fence')
            return value
        trust=private/'root-trust.json';request=private/'root-request.json'
        plan,plan_dir=invoke('root-plan','plan',[trust,request]);plan_file=plan_dir/'account-root-plan.json'
        require(plan==json.loads(plan_file.read_bytes())==json.loads((private/'expected-plan.json').read_bytes()),'original plan changed')
        altered=dict(plan,binding=[71]*32);bad=directory/'bad-plan.json';save(bad,altered)
        invoke('root-freeze','bad-plan',[bad],success=False)
        enroll('old','old-after-bad-plan',success=True)
        if profile=='close-plan':
            _,lost_dir=invoke('root-plan-close','close-lost',[plan_file],success=False,lost=True)
            closed=json.loads((lost_dir/'account-root-plan-outcome.json').read_bytes())
            recovered,_=invoke('root-plan-close','close-retry',[plan_file])
            require(closed['state']==recovered['state']=='Closed' and closed['binding']==recovered['binding']==plan['binding'],'original plan closure changed')
            invoke('root-freeze','closed-plan-refused',[plan_file],success=False)
            enroll('old','unfrozen-original',success=True)
        else:
            occupied=directory/'occupied';occupied.mkdir(mode=0o700);save(occupied/'original',b'retained')
            run([*common,'root-freeze',*host,plan_file,occupied],'occupied-output',success=False)
            require((occupied/'original').read_bytes()==b'retained'
                    and (directory/'occupied-output.stderr').read_bytes()==b'Error: "Export directory must be empty; retain partial exports and select a new directory"\n',
                    'occupied output was changed or failed for another reason')
            enroll('old','old-before-freeze',success=True)
            _,lost_dir=invoke('root-freeze','freeze-lost',[plan_file],success=False,lost=True)
            first=json.loads((lost_dir/'account-root-freeze.json').read_bytes())
            frozen,frozen_dir=invoke('root-freeze','freeze-retry',[plan_file]);freeze_file=frozen_dir/'account-root-freeze.json'
            require(first['freeze_binding']==frozen['freeze_binding'] and first['plan_binding']==frozen['plan_binding']==plan['binding'],'freeze changed after lost output')
            enroll('old','old-frozen',success=False);enroll('unseen','unseen-frozen',success=False)
            if profile=='replan':
                original_closed,_=invoke('root-plan-close','original-plan-closed',[plan_file])
                require(original_closed['state']=='Closed','original plan lacks permanent non-commit')
                new_trust=private/'new-root-trust.json';new_request=private/'new-root-request.json'
                require(json.loads(new_trust.read_bytes())['successor']['account']['account']!=fixture['successor_account'],
                        'new target reused original candidate')
                _,lost_plan=invoke('root-replan','replan-lost',[new_trust,new_request,plan_file,freeze_file],success=False,lost=True)
                next_plan,next_dir=invoke('root-replan','replan-retry',[new_trust,new_request,plan_file,freeze_file])
                require(next_plan==json.loads((lost_plan/'account-root-plan.json').read_bytes()),'new original plan changed after output loss')
                next_file=next_dir/'account-root-plan.json'
                next_freeze,next_frozen_dir=invoke('root-freeze','same-frozen-root',[next_file])
                require(next_freeze['freeze_binding']==frozen['freeze_binding'],'new target unfroze or replaced original snapshot')
                next_freeze_file=next_frozen_dir/'account-root-freeze.json'
                next_decision,next_bound_dir=invoke('root-bind','new-bound-target',[new_trust,new_request,next_file,next_freeze_file])
                next_bound=next_bound_dir/'account-root-decision.json'
                next_outcome,_=invoke('root-commit','new-committed-target',[new_trust,new_request,next_file,next_freeze_file,next_bound])
                require(next_outcome['state']=='Committed' and next_outcome['binding']==next_decision['binding'],'new target was not committed')
                run([*common,'enroll',*host,private/'new-target-trust.json',new_request],'same-new-successor',success=True)
                enroll('old','old-after-new-root-refused',success=False)
            else:
                decision,bound_dir=invoke('root-bind','bind',[trust,request,plan_file,freeze_file]);bound=bound_dir/'account-root-decision.json'
                unavailable,_=invoke('root-status','unavailable',[bound]);require(unavailable=={'state':'Unavailable','binding':decision['binding']},'precommit inferred success')
                if profile=='commit':
                    _,lost_dir=invoke('root-commit','commit-lost',[trust,request,plan_file,freeze_file,bound],success=False,lost=True)
                    expected='Committed';filename='account-root-outcome.json'
                else:
                    _,lost_dir=invoke('root-close','decision-close-lost',[bound],success=False,lost=True)
                    expected='Closed';filename='account-root-outcome.json'
                lost=json.loads((lost_dir/filename).read_bytes());observed,_=invoke('root-status','recovered-status',[bound])
                require(lost['state']==observed['state']==expected and lost['binding']==observed['binding']==decision['binding'],'original terminal decision changed')
                terminal,_=invoke('root-close','terminal-close',[bound]);require(terminal['state']==expected,'closure rewrote committed history')
                enroll('old','old-terminal-refused',success=False);enroll('unseen','unseen-terminal-refused',success=False)
                if profile=='commit':
                    run([*common,'enroll',*host,private/'next-trust.json',request],'same-successor',success=True)
                else:
                    invoke('root-commit','closed-commit-refused',[trust,request,plan_file,freeze_file,bound],success=False)
                    invoke('root-plan-close','exact-closure-is-not-plan-closure',[plan_file],success=False)
        require(all(hashlib.sha256(Path(p).read_bytes()).hexdigest()==digest for p,digest in keys.items()),'root operator regenerated a key')
        require(run([*common,'pin',*host],'original-witness-pin')==fixture['witness_pin'],'root operator changed witness authority')
        result['profiles'].append(dict(name=profile,commands=run.rows,fixture=str(private),original_keys_unchanged=True))
    require(before==inventory() and all(hashlib.sha256(Path(p).read_bytes()).hexdigest()==digest for p,digest in binaries.items()),'root operator executable or source changed')
    result['completed']=True
except BaseException as error:result['failure']=str(error);raise
finally:save(root/'RESULT.json',result)
print(json.dumps(dict(completed=True,profiles=len(result['profiles']),commands=sum(len(p['commands']) for p in result['profiles']))))
