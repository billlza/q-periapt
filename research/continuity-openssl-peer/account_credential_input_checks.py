#!/usr/bin/env python3
"""Real native grants and original account owners; issuer-envelope boundary checks.

Uses explicit fixture times, not real-time public CLI acceptance. No account
login or host issuer workflow is inferred from these constructed envelopes.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import sys


def scenario(args, count, witnessed):
    from registration_fixture import Fixture
    from shared_account_checks import start, request_arguments
    from qperiapt_continuity_reference.account_request import AccountRequest
    from qperiapt_continuity_reference.credential_inputs import companions
    from qperiapt_continuity_reference.enrollment_exchange import HostAuthority
    from qperiapt_continuity_reference.wire import require
    from traffic_checks import application
    directory=args.output/str(count);directory.mkdir(exist_ok=True)
    selected=argparse.Namespace(**vars(args));selected.output=directory
    f=Fixture(selected,'witness' if witnessed else 'local',account_members=count)
    try:
        journal,session=start(f)
        if witnessed:f.call('witness-clock',33,(170).to_bytes(8,'big'),b'witness clock set')
        message=f.value('original-id','next_id',now=170)
        ciphertext=f.value('original-send','send',(message,b'original account envelope',b'account'),now=170)
        fields=request_arguments(f,count,'native-grants',1)
        request=AccountRequest.read((f.out/'native-grants').read_bytes(),f.context.devices[0],f.context.family,f.context.policy_digest)
        target=fields[1];authority=HostAuthority(os.urandom(32),1,f.intent.root,f.intent.family)
        b64=lambda b:base64.urlsafe_b64encode(b).rstrip(b'=').decode()
        grants=[{'enrollment':list(os.urandom(32)),'operation':list(g.operation),'journal':list(os.urandom(32)),
            'root_revision':1,'statement':list(g.statement),'checkpoint':{'version':int.from_bytes(target[:8],'big'),'digest':list(target[8:])},
            'grant':b64(g.wire)} for g in request.companions]
        encode=lambda rows:json.dumps({'schema':'qperiapt-companion-credential-grants/1','grants':rows}).encode()
        wires,expected=companions(encode(grants),authority,target)
        require(wires==tuple(g.wire for g in request.companions),'companion input changed native wires')
        before=(f.session_path/'head').read_bytes();refusals=[]
        def prepare(rows=grants,statement=request.local.statement,operation=request.local.operation):
            decoded,metadata=companions(encode(rows),authority,target)
            parent=f.owner()
            try:
                with parent.credential_renewal(operation,210,transport=f.transport()) as child:
                    function=child.prepare_account if witnessed else child.stage_account
                    return function(request.local.wire,decoded,target,210,
                                    expected_statement=statement,expected_companions=metadata)
            finally:parent.close()
        def refused(name,action,reason):
            try:action()
            except ValueError as error:
                require(reason in str(error),'wrong refusal '+name+': '+str(error));refusals.append(name)
            else:raise ValueError('missing refusal '+name)
            require((f.session_path/'head').read_bytes()==before and not (f.session_path/'intent').exists(),
                    'rejected issuer input changed or reserved account state')
        refused('local-operation',lambda:prepare(operation=os.urandom(32)),'local renewal original operation differs')
        refused('local-statement',lambda:prepare(statement=os.urandom(32)),'credential issuance statement differs')
        for field in ('operation','statement'):
            changed=[dict(g) for g in grants];changed[0][field]=list(os.urandom(32))
            refused('companion-'+field,lambda:prepare(changed),'companion issuance differs from signed grant')
        changed=[dict(g) for g in grants];changed[0]['root_revision']=2
        refused('root-revision',lambda:prepare(changed),'selected account revision or roster')
        changed=[dict(g) for g in grants];changed[0]['checkpoint']={'version':99,'digest':list(target[8:])}
        refused('target-roster',lambda:prepare(changed),'selected account revision or roster')
        refused('missing-companion',lambda:prepare(grants[:-1]),'account generation, revocation or credential conflict')
        refused('empty-incomplete-set',lambda:prepare([]),'account generation, revocation or credential conflict')
        duplicated=list(grants);duplicated[-1]=grants[0]
        refused('duplicate-device',lambda:prepare(duplicated),'duplicate account request device')
        refused('oversized-set',lambda:prepare([grants[0]]*32),'companion credential schema or capacity')
        changed=[dict(g) for g in grants];changed[0]['unexpected']=True
        refused('unknown-field',lambda:prepare(changed),'exchange field set')
        prepared=prepare()
        if witnessed:
            intent=(f.session_path/'intent').read_bytes()
            require(prepare(list(reversed(grants)))==prepared and (f.session_path/'intent').read_bytes()==intent,
                    'reordered envelope resealed original witness target')
            f.call('native-account-controller',34,prepared,b'Prepared')
            outcome=f.worker('commit','credential_commit',(request.local.operation,),now=210)
            require(outcome=='Applied','account witness commit')
        else:
            require(prepared['status']=='Pending','account local preparation')
            head=(f.session_path/'head').read_bytes()
            require(prepare(list(reversed(grants)))==prepared and (f.session_path/'head').read_bytes()==head,
                    'reordered envelope rewrote original local target')
            outcome=f.worker('commit','credential_commit',(request.local.operation,),now=210)
            require(outcome['status']=='Committed','account local commit')
        require(f.value('resume-original','resume',(message,),now=210)==ciphertext,'account envelope changed original traffic')
        f.call('native-receive',7,application(b'account',ciphertext),b'original account envelope')
        result={'members':count,'witnessed':witnessed,'journal':journal.hex(),'session':session.hex(),
            'operation':request.local.operation.hex(),'companion_grants':len(grants),'earliest_expiry':request.expires_at(),
            'original_ciphertext_sha256':hashlib.sha256(ciphertext).hexdigest(),'refusals':refusals,'reordered_retry_unchanged':True}
        (f.out/'INPUT_CHECKS.json').write_text(json.dumps(result,indent=2)+'\n');return result
    finally:f.close()


def main():
    sys.path.append(str(Path(__file__).resolve().parent))
    from run import arguments
    from qperiapt_continuity_reference.provider import load_provider
    args=arguments();args.output=args.output.resolve();args.native=args.native.resolve();args.provider_root=args.provider_root.resolve()
    crypto,backend=load_provider(args.provider_root)
    sources=[*sorted(Path(__file__).resolve().parent.glob('*.py')),*sorted((Path(__file__).resolve().parent/'qperiapt_continuity_reference').glob('*.py'))]
    inventory=lambda:{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
    before=inventory();args.output.mkdir()
    result={'completed':False,'release_claim_eligible':False,'source_files':before,'native_sha256':hashlib.sha256(args.native.read_bytes()).hexdigest(),
        'scope':'Native-signed3/32-member account grants, original local/witness owners, input metadata and original traffic. Fixture times170/210; public CLI and authenticated host account integration remain separate.'}
    try:
        result['profiles']=[scenario(args,n,w) for n in (3,32) for w in (False,True)]
        assert before==inventory();result['completed']=True
    except BaseException as error:result['failure']=str(error);raise
    finally:(args.output/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'completed':True,'profiles':4,'refusals':sum(len(p['refusals']) for p in result['profiles'])}))


if __name__=='__main__':main()
