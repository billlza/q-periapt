#!/usr/bin/env python3
"""Reject substituted initial images before recovery writes or witness dispatch.

Uses the original private target of a completed retirement fixture. All altered
envelopes are new isolated files; the original source fixtures remain unchanged.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import argparse
import base64
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sys


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('implementation-root','provider-root','retirement-result','output'):
        parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();args.implementation_root=args.implementation_root.resolve(strict=True)
    sys.path.insert(0,str(args.implementation_root))
    from qperiapt_continuity_reference.provider import load_provider
    load_provider(args.provider_root)
    from qperiapt_continuity_reference.account_authority import AccountAuthority
    from qperiapt_continuity_reference.account_root_record import RetainedPlan
    from qperiapt_continuity_reference import account_binding
    from qperiapt_continuity_reference.bootstrap import Initiator
    from qperiapt_continuity_reference.durable import Session
    from qperiapt_continuity_reference.enrollment_client import EnrollmentClient
    from qperiapt_continuity_reference.registered_owner import _Signer
    from qperiapt_continuity_reference.registration_session import selected,validate_context
    from qperiapt_continuity_reference.root_adoption_journal import _OriginalSuccessor
    from qperiapt_continuity_reference.state_codec import State,encode
    from qperiapt_continuity_reference.wire import VerificationKey,require
    from qperiapt_continuity_reference.witness import Pin
    from qperiapt_continuity_reference.witness_journal import WitnessJournal
    sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
    read=lambda p:json.loads(p.read_bytes())
    args.output.mkdir(mode=0o700)
    result=read(args.retirement_result);require(result['completed'],'retirement fixture incomplete')
    profile=result['profiles'][0]
    parent=next(Path(p).parent for p in profile['fence_hashes'] if Path(p).parent.name=='registration')
    private=parent.parent.parent;target=private/'root-target'
    def originals():
        return {str(p):sha(p) for p in private.rglob('*') if p.is_file() and p.name in ('head','intent','authority','root-fence')}
    before=originals();public=read(target/'approved-public.json')
    require(not list(target.rglob('intent')) and not (private/'account-registry/intent').exists(),
            'origin test refuses pending original fixture')
    raw=public['policy_pins']['witness']['key'];raw=base64.urlsafe_b64decode(raw+'='*(-len(raw)%4))
    pin=Pin(bytes(public['policy_pins']['witness']['identity']),VerificationKey(raw))
    registered=(private/'registry-key-and-id').read_bytes();host=(target/'host-key-and-id').read_bytes()
    require(len(registered)==len(host)==64,'original fixture key/id shape')
    family=bytes(public['authority']['family']);application=bytes(public['authority']['application'])
    cases=[]
    with AccountAuthority.open(private/'account-registry',registered[:32],registered[32:],family,pin) as registry:
        current=registry.current(application);lease=registry.admit(current)
        hint=RetainedPlan(pin,bytes.fromhex(public['plan']))
        _,phase,original,bound=registry.operation(hint.target.operation)
        require(phase=='Committed' and original==hint.original,'original committed operation differs')
        descriptor=RetainedPlan(pin,original).check_decision(bound)
        genesis=descriptor.subject+descriptor.genesis
        with closing(EnrollmentClient.open(target/'client',host[32:],host[:32])) as client:
            parent=client._registration;_,image=parent._image()
            require(image.child is not None and not image.active,'inactive original target required')
            now=210 if profile['mode'].startswith('credential') else 170
            context=image.child.inputs.original(image.child.context,now);validate_context(parent,image,context)
            scope,key=selected(parent,image,context)
            journal=WitnessJournal(image.child.path,scope,key,Session._validator(context),context.witness,None)
            try:
                wire=journal._admit().read('head');snapshot=journal._decode(wire)
                require(snapshot.revision==1 and snapshot.digest==descriptor.genesis,'original target genesis differs')
                def sealed(revision,payload,binding):
                    header=account_binding.header(journal._image_prefix(),revision,binding)
                    return header+journal._cipher.encrypt(payload,[header])
                alternative=State.initial(Initiator._prepare_for_journal(context,_Signer(parent),now),now)
                try:other=encode(alternative)
                finally:alternative.close()
                require(other!=snapshot.payload,'independent initial state unexpectedly identical')
                bound_wire=sealed(2,snapshot.payload,lease)
                bad_intent=journal._intent(1,snapshot.digest,sealed(2,other,lease))
                specifications=(
                    ('wrong-genesis',wire,None,genesis[:-1]+bytes([genesis[-1]^1]),None,None,'approved genesis'),
                    ('wrong-subject',wire,None,bytes([genesis[0]^1])+genesis[1:],None,None,'subject or authority'),
                    ('different-initial-state',sealed(1,other,None),None,genesis,None,None,'approved genesis'),
                    ('ordinary-unbound-write',sealed(2,snapshot.payload,None),None,genesis,None,None,'advanced state'),
                    ('changed-binding-intent',wire,bad_intent,genesis,lease,None,'approved genesis'),
                    ('advanced-bound-state',sealed(3,snapshot.payload,lease),None,genesis,lease,None,'advanced state'),
                    ('missing-registry',bound_wire,None,genesis,None,None,'original root registry lease'),
                    ('authority-record',wire,None,genesis,None,b'isolated changed authority','subject or authority'))
                for label,head,pending,expected,binding,authority,reason in specifications:
                    directory=args.output/label;directory.mkdir(mode=0o700)
                    for name,value in (('head',head),('intent',pending),('authority',authority)):
                        if value is None:continue
                        with os.fdopen(os.open(directory/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb') as out:
                            out.write(value);out.flush();os.fsync(out.fileno())
                    files={p.name:p.read_bytes() for p in directory.iterdir()}
                    owner=_OriginalSuccessor(directory,scope,key,Session._validator(context),context.witness,None,
                                              root_lease=binding,expected_genesis=expected)
                    try:
                        try:owner._recover(False)
                        except ValueError as error:require(reason in str(error),'wrong origin refusal: '+str(error))
                        else:raise ValueError('substituted successor admitted: '+label)
                    finally:owner.close()
                    require({p.name:p.read_bytes() for p in directory.iterdir()}==files,'origin refusal wrote files')
                    cases.append(label)
                # Positive codec readbacks do not query a witness or return traffic permission.
                journal.close()
                owner=_OriginalSuccessor(image.child.path,scope,key,Session._validator(context),context.witness,None,
                                          root_lease=lease,expected_genesis=genesis)
                try:
                    require(owner._decode(wire).payload==snapshot.payload,'original codec readback')
                    require(owner._decode(bound_wire).payload==snapshot.payload,'binding-only codec readback')
                finally:owner.close()
            finally:journal.close()
    require(originals()==before,'origin checks changed original fixture')
    sources={str(p):sha(p) for p in (args.implementation_root/'qperiapt_continuity_reference').glob('*.py')}
    sources[str(Path(__file__).resolve())]=sha(Path(__file__))
    report={'completed':True,'refusals':cases,'positive_codec_readbacks':2,'original_files_unchanged':True,
            'source_files':sources,'retirement_result_sha256':sha(args.retirement_result),
            'scope':'Actual encrypted initial images and authenticated altered binding intents; all eight refusals occur before witness use or store mutation. Positive cases are codec checks only.'}
    (args.output/'RESULT.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'completed':True,'refusals':len(cases),'positive_codec_readbacks':2}))


if __name__=='__main__':main()
