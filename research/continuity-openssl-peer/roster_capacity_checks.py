#!/usr/bin/env python3
"""Full original business state across registered G/G/R/G and exact R recovery."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys


def codec_controls(f, state, payload):
    from dataclasses import replace
    from qperiapt_continuity_reference.state_codec import encode, decode
    from qperiapt_continuity_reference.storage_budget import (
        MAX_ACCOUNT_STATE, MAX_SHARED_STATE, MAX_STATE,
        MAX_ACCOUNT_COORDINATION, MAX_ACCOUNT_ROSTER_COORDINATION)
    from qperiapt_continuity_reference.wire import require
    require(state.format_version == 10 and encode(state) == payload, 'full R canonical roundtrip')
    require(MAX_SHARED_STATE - MAX_ACCOUNT_STATE == 193
            and MAX_ACCOUNT_ROSTER_COORDINATION - MAX_ACCOUNT_COORDINATION == 193,
            'R allowance must remain fixed lifecycle metadata')
    f.refuses('R-cannot-select-nine', lambda: encode(replace(state, format_version=9)),
              'roster requires explicit snapshot format')
    f.refuses('R-wire-cannot-downgrade', lambda: decode(b'QPREFS09' + payload[8:], f.context),
              'roster requires explicit snapshot format')
    f.refuses('R-missing-marker', lambda: encode(replace(state,
              account_renewal=replace(state.account_renewal, roster=None))),
              'roster requires explicit snapshot format')
    scope=state.account_renewal.roster
    wrong=replace(scope, policy=(2).to_bytes(8,'big') + scope.policy[8:])
    f.refuses('R-cannot-adopt-policy-version', lambda: encode(replace(state,
              account_renewal=replace(state.account_renewal, roster=wrong))),
              'original independently verified policy')
    f.refuses('R-metadata-cannot-expand-business', lambda: decode(
              payload[:8]+(MAX_STATE+1).to_bytes(4,'big')+payload[12:],f.context),
              'shared-account snapshot field capacity')
    f.refuses('R-aggregate-bound', lambda: decode(payload+bytes(MAX_SHARED_STATE+1-len(payload)),f.context),
              'shared-account snapshot scope or capacity')


def scenario(args, witnessed):
    from registration_fixture import Fixture
    from shared_account_checks import start, request_arguments
    from account_capacity_fixture import fill
    from local_budget_controls import inventory
    from qperiapt_continuity_reference.account_request import AccountRequest
    from qperiapt_continuity_reference.wire import require
    from traffic_checks import application
    output=args.output/('required' if witnessed else 'local'); output.mkdir()
    selected=argparse.Namespace(**vars(args)); selected.output=output
    f=Fixture(selected,'witness' if witnessed else 'local',account_members=32,enrolled_peer=True)
    parent=None
    try:
        journal,session=start(f)
        filled=fill(f)
        native_identity=None
        def native(cycle,now):
            nonlocal native_identity
            result=f.call(f'native-maintenance-{cycle}',40,cycle.to_bytes(8,'big')+now.to_bytes(8,'big'))
            require(len(result)==72 and result[32:64]==session and result[64:]==now.to_bytes(8,'big'),
                    'native original maintenance receipt')
            if native_identity is None: native_identity=result[:32]
            require(result[:32]==native_identity,'native original journal changed')
        def commit_group(name,gargs,now):
            if witnessed:
                f.call(name+'-clock',33,now.to_bytes(8,'big'),b'witness clock set')
                proposal=f.value(name+'-prepare','credential_account_prepare_files',gargs,now=now)
                f.call(name+'-approval',34,proposal,b'Prepared')
            else:
                f.worker(name+'-stage','credential_account_stage_files',gargs,now=now)
            result=f.worker(name+'-commit','credential_commit',(gargs[0],),now=now)
            require(result=='Applied' if witnessed else result['status']=='Committed','complete original G')
        for cycle,now in [(1,210),(2,310)]:
            commit_group(f'g-{cycle}',request_arguments(f,32,f'grants-{cycle}',cycle),now)
            native(cycle,now)
        public=f.public/'account'
        operation=os.urandom(32)
        rargs=(operation,(public/'roster-4').read_bytes(),(public/'checkpoint-4').read_bytes())
        before=(f.session_path/'head').read_bytes()
        if witnessed:
            f.worker('full-R-intent-cut','roster_prepare',rargs,now=310,cut='session-store:committed:intent')
            intent=(f.session_path/'intent').read_bytes()
            proposal=f.value('full-R-original-preparation','roster_prepare',rargs,now=310)
            require((f.session_path/'head').read_bytes()==before and (f.session_path/'intent').read_bytes()==intent,
                    'full R preparation installed or replaced target')
            f.call('full-R-independent-approval',39,proposal,b'Prepared')
            f.bridge.arm('after',16)
            f.worker('full-R-lost-commit','roster_commit',(operation,),now=310,refusal='truncated witness reply')
            f.worker('full-R-terminal-cut','roster_recover',(operation,),now=310,cut='roster:terminal-durable')
            require(f.worker('full-R-original-recovery','roster_recover',(operation,),now=310)=='Applied',
                    'full original R result')
            target=intent[429:-32]
        else:
            f.worker('full-R-atomic-cut','roster_refresh',rargs,now=310,cut='session-store:committed:intent')
            intent=(f.session_path/'intent').read_bytes()
            require(f.worker('full-R-original-recovery','roster_status',(operation,),now=310)=='Applied',
                    'full local R result')
            target=intent[52:-32]
        require((f.session_path/'head').read_bytes()==target and not (f.session_path/'intent').exists(),
                'full R recovery changed original sealed target')
        native(4,310)
        parent=f.owner()
        with parent.session(310,transport=f.transport()) as owner:
            with owner._owner._state(operational=False) as (snapshot,state):
                require(inventory(state)==filled['inventory'],'full R changed original business records')
                codec_controls(f,state,snapshot.payload)
                payload_size=len(snapshot.payload)
            require(owner.resume(filled['first_id'],now=310)==filled['first_wire']
                    and owner.resume(filled['last_id'],now=310)==filled['last_wire'],
                    'full R changed original ciphertext')
            f.refuses('R-allocation-cannot-fund-send',lambda:owner.send(owner.next_id(now=310),b'x',b'',now=310),
                      'reserved final traffic capacity')
        parent.close(); parent=None
        # The complete follow-up grant must name the actually installed R4.
        checkpoint=(public/'checkpoint-18').read_bytes()
        request=AccountRequest.parse((public/'grant-18-1').read_bytes(),
                    [(public/f'grant-18-{i}').read_bytes() for i in range(2,32)],
                    f.context.devices[0],f.context.family,f.context.policy_digest,checkpoint)
        data=request.encode(); (f.out/'after-R-grants').write_bytes(data)
        commit_group('G-after-full-R',(request.local.operation,checkpoint,b'after-R-grants',hashlib.sha256(data).digest()),355)
        native(18,355)
        f.call('native-original-service-reopen',12,expected=b'reopened')
        parent=f.owner()
        with parent.session(355,transport=f.transport()) as owner:
            with owner._owner._state(operational=False) as (_,state):
                require(state.format_version==10 and inventory(state)==filled['inventory'],
                        'later G lost R format or full original records')
            require(owner.resume(filled['first_id'],now=355)==filled['first_wire']
                    and owner.resume(filled['last_id'],now=355)==filled['last_wire'],
                    'later G changed original ciphertext')
        parent.close(); parent=None
        f.call('native-first-original-decrypt',7,application(b'',filled['first_wire']),filled['plain'])
        f.call('native-last-original-decrypt',7,application(b'',filled['last_wire']),filled['last_plain'])
        registration=f.worker('original-registration-retained','registration_status',now=355)
        require(registration['journal']==journal.hex() and registration['signing_id']==f.observations['signing_id'],
                'full maintenance replaced original enrollment')
        result={'witnessed':witnessed,'members':32,'traffic_bytes':filled['traffic_bytes'],'rows':filled['rows'],
                'original_inventory':filled['inventory'],'roster_payload_bytes':payload_size,'roster_intent_bytes':len(intent),
                'journal':journal.hex(),'native_journal':native_identity.hex(),'session':session.hex(),
                'original_message_sha256':hashlib.sha256(filled['first_wire']).hexdigest(),
                'original_last_message_sha256':hashlib.sha256(filled['last_wire']).hexdigest(),
                'workers':len(f.driver.operations),'process_kills':sum('signal' in row for row in f.driver.operations),
                'refusals':f.refusals,'native_trusted_time':355}
        (f.out/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
        return result
    finally:
        if parent is not None: parent.close()
        f.close()


def main():
    sys.path.append(str(Path(__file__).resolve().parent))
    from run import arguments
    from qperiapt_continuity_reference.provider import load_provider
    args=arguments()
    args.output,args.native,args.provider_root=args.output.resolve(),args.native.resolve(),args.provider_root.resolve()
    crypto,backend=load_provider(args.provider_root)
    from qperiapt_continuity_reference.wire import require
    root=Path(__file__).resolve().parent
    def sources():
        paths=[*sorted((root/'qperiapt_continuity_reference').glob('*.py')),*sorted(root.glob('*.py')),
               *sorted((root/'native/src').glob('*.rs')),root/'native/Cargo.toml',root/'native/Cargo.lock',root/'requirements.txt']
        return {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    before=sources(); native=hashlib.sha256(args.native.read_bytes()).hexdigest(); args.output.mkdir()
    report={'source_files':before,'native_sha256':native,
            'provider':{'cryptography':crypto.__version__,'openssl':backend.openssl_version_text()}}
    (args.output/'INPUTS.json').write_text(json.dumps(report,indent=2)+'\n')
    report['profiles']=[scenario(args,witnessed) for witnessed in (False,True)]
    require(sources()==before and hashlib.sha256(args.native.read_bytes()).hexdigest()==native,
            'full roster qualification inputs changed')
    (args.output/'RESULT.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps([{k:r[k] for k in ('witnessed','traffic_bytes','rows','workers','process_kills')} for r in report['profiles']]))


if __name__=='__main__':
    main()
