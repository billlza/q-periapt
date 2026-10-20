#!/usr/bin/env python3
"""Original registered common-account R, actual native witness and process recovery."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys


def scenario(args, count, witnessed):
    from registration_fixture import Fixture
    from shared_account_checks import start, request_arguments
    from qperiapt_continuity_reference.account_request import AccountRequest
    from qperiapt_continuity_reference.roster_protocol import Proposal
    from qperiapt_continuity_reference.wire import require
    from traffic_checks import application
    output = args.output / (('required-' if witnessed else 'local-') + str(count))
    output.mkdir()
    selected = argparse.Namespace(**vars(args)); selected.output = output
    f = Fixture(selected, 'witness' if witnessed else 'local', account_members=count, enrolled_peer=True)
    try:
        journal, session = start(f)
        public = f.public / 'account'
        native_identity = None
        def native_maintenance(cycle, now):
            nonlocal native_identity
            receipt = f.call(f'native-maintenance-{cycle}-{now}', 40,
                             cycle.to_bytes(8, 'big') + now.to_bytes(8, 'big'))
            require(len(receipt) == 72 and receipt[32:64] == session
                    and int.from_bytes(receipt[64:], 'big') == now, 'native original maintenance receipt')
            if native_identity is None: native_identity = receipt[:32]
            require(receipt[:32] == native_identity, 'native original journal changed')

        message = f.value('old-id', 'next_id', now=170)
        original = f.value('old-message', 'send', (message, b'original account session', b'roster'), now=170)
        offer = f.value('old-pq-offer', 'prepare_rekey_offer', now=170)
        for cycle, now in [(1, 210), (2, 310)]:
            request = request_arguments(f, count, f'complete-{cycle}', cycle)
            if witnessed:
                f.call(f'clock-{cycle}',33,now.to_bytes(8,'big'),b'witness clock set')
                proposal = f.value(f'prepare-g-{cycle}','credential_account_prepare_files',request,now=now)
                f.call(f'approve-g-{cycle}',34,proposal,b'Prepared')
                require(f.worker(f'commit-g-{cycle}','credential_commit',(request[0],),now=now)=='Applied','original G applied')
            else:
                f.worker(f'stage-g-{cycle}','credential_account_stage_files',request,now=now)
                require(f.worker(f'commit-g-{cycle}','credential_commit',(request[0],),now=now)['status']=='Committed','original G committed')
            native_maintenance(cycle, now)
        native_maintenance(4, 310)
        operation = os.urandom(32)
        rargs = (operation,(public/'roster-4').read_bytes(),(public/'checkpoint-4').read_bytes())
        original_head = (f.session_path/'head').read_bytes()
        if witnessed:
            f.worker('r-intent-process-cut','roster_prepare',rargs,now=310,cut='session-store:committed:intent')
            intent = (f.session_path/'intent').read_bytes()
            require(intent[:8]==b'QPRFRI01','typed R intent')
            proposal = f.value('same-r-preparation','roster_prepare',rargs,now=310)
            p = Proposal.decode(proposal)
            require(p.scope.operation==operation and p.scope.previous==(public/'checkpoint-3').read_bytes()
                    and p.scope.target==rargs[2],'actual R predecessor/target')
            require((f.session_path/'head').read_bytes()==original_head and (f.session_path/'intent').read_bytes()==intent,
                    'R preparation must not install or reseal target')
            f.worker('pending-r-denies-session','next_id',now=310,refusal='roster coordination remains pending')
            f.worker('unapproved-r-refused','roster_commit',(operation,),now=310,refusal='roster has no exact terminal')
            f.call('independent-r-approval',39,proposal,b'Prepared')
            f.bridge.arm('after',16)
            f.worker('lost-r-commit','roster_commit',(operation,),now=310,refusal='truncated witness reply')
            require((f.session_path/'intent').read_bytes()==intent,'lost R result replaced original target')
            f.worker('r-terminal-process-cut','roster_recover',(operation,),now=351,cut='roster:terminal-durable')
            f.call('original-witness-reopen',32,expected=b'witness reopened')
            require(f.worker('r-expired-historical-recovery','roster_recover',(operation,),now=351)=='Applied','original historical R')
            require((f.session_path/'head').read_bytes()==intent[429:-32]
                    and not (f.session_path/'intent').exists(),'R recovery changed original sealed target')
            # Historical cleanup did not move trusted SDK time backwards. Fresh
            # traffic remains refused at the actual expired local credential.
            f.worker('expired-local-release-refused','next_id',now=351,refusal='expired or premature authority')
        else:
            f.worker('r-atomic-process-cut','roster_refresh',rargs,now=310,cut='session-store:committed:intent')
            intent = (f.session_path/'intent').read_bytes()
            require(intent[:8]==b'QPREFI01','local R ordinary exact intent')
            require(f.worker('r-original-local-recovery','roster_status',(operation,),now=310)=='Applied','atomic original R')
            require((f.session_path/'head').read_bytes()==intent[52:-32],'local R original exact target')
        require(f.worker('r-completion-readback','roster_status',(operation,),now=355)=='Applied','retained original R')
        # A new complete G names R4, while the original R receipt remains.
        grant = (public/'grant-18-1').read_bytes()
        companions = [(public/f'grant-18-{i}').read_bytes() for i in range(2,count)]
        checkpoint = (public/'checkpoint-18').read_bytes()
        request = AccountRequest.parse(grant,companions,f.context.devices[0],f.context.family,f.context.policy_digest,checkpoint)
        data=request.encode(); (f.out/'after-r-grants').write_bytes(data)
        gargs=(request.local.operation,checkpoint,b'after-r-grants',hashlib.sha256(data).digest())
        if witnessed:
            f.call('clock-after-r',33,(355).to_bytes(8,'big'),b'witness clock set')
            proposal=f.value('g-after-r-prepare','credential_account_prepare_files',gargs,now=355)
            f.call('g-after-r-independent-approval',34,proposal,b'Prepared')
            require(f.worker('g-after-r-commit','credential_commit',(gargs[0],),now=355)=='Applied','G after R')
        else:
            f.worker('g-after-r-stage','credential_account_stage_files',gargs,now=355)
            require(f.worker('g-after-r-commit','credential_commit',(gargs[0],),now=355)['status']=='Committed','G after R')
        native_maintenance(18, 355)
        f.call('native-refuses-clock-rollback',40,(18).to_bytes(8,'big')+(310).to_bytes(8,'big'),
               b'"native trusted time rollback"',status=2)
        f.call('native-original-enrollment-reopen',12,expected=b'reopened')
        require(f.worker('format-with-original-r','storage_format',now=355)==10,'explicit R format lost')
        require(f.worker('original-r-after-g','roster_status',(operation,),now=355)=='Applied','G erased original R')
        require(f.value('same-original-ciphertext','resume',(message,),now=355)==original,'R/G replaced original ciphertext')
        require(f.value('same-original-pq-offer','prepare_rekey_offer',now=355)==offer,'R/G replaced retained PQ contribution')
        f.call('native-original-decrypt',7,application(b'roster',original),b'original account session')
        response=f.call('native-original-rekey-response',14,offer)
        final=f.value('original-rekey-final','accept_rekey_response',(response,),now=355)
        receipt=f.call('native-original-rekey-receipt',15,final)
        require(f.worker('original-rekey-confirmed','accept_rekey_receipt',(receipt,),now=355)==1,'original rekey')
        identity=f.value('new-epoch-id','next_id',now=355)
        fresh=f.value('new-epoch-message','send',(identity,b'after account roster maintenance',b'roster'),now=355)
        f.call('native-new-epoch-decrypt',7,application(b'roster',fresh),b'after account roster maintenance')
        latest=f.worker('original-registration-retained','registration_status',now=355)
        require(latest['journal']==journal.hex() and latest['signing_id']==f.observations['signing_id'],'original registration replaced')
        result={'members':count,'witnessed':witnessed,'journal':journal.hex(),'session':session.hex(),
                'original_message_sha256':hashlib.sha256(original).hexdigest(),'original_offer_sha256':hashlib.sha256(offer).hexdigest(),
                'native_journal':native_identity.hex(), 'native_trusted_time':355,
                'workers':len(f.driver.operations),'process_kills':sum('signal' in r for r in f.driver.operations),
                'scope':'Real registered independent Python owner, actual native witness when required, original G/G/R/G and original retained session. Both original enrolled endpoints advance explicit trusted time150..355 through G/G/R/G; native original service/session reopened at355. Not wall-clock/device expiry or PCS.'}
        (f.out/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
        return result
    finally:
        f.close()


def main():
    sys.path.append(str(Path(__file__).resolve().parent))
    from run import arguments
    from qperiapt_continuity_reference.provider import load_provider
    args=arguments()
    args.output,args.native,args.provider_root=args.output.resolve(),args.native.resolve(),args.provider_root.resolve()
    crypto, backend = load_provider(args.provider_root)
    from qperiapt_continuity_reference.wire import require
    root = Path(__file__).resolve().parent
    paths = [*sorted((root / "qperiapt_continuity_reference").glob("*.py")), *sorted(root.glob("*.py")),
             *sorted((root / "native/src").glob("*.rs")), root / "native/Cargo.toml", root / "native/Cargo.lock",
             root / "requirements.txt"]
    def sources():
        return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
    before = sources()
    native = hashlib.sha256(args.native.read_bytes()).hexdigest()
    args.output.mkdir()
    report = {"source_files": before, "native_sha256": native,
              "provider": {"cryptography": crypto.__version__, "openssl": backend.openssl_version_text()}}
    (args.output / "INPUTS.json").write_text(json.dumps(report, indent=2) + "\n")
    report["profiles"] = [scenario(args,count,witnessed) for count in (3,32) for witnessed in (False,True)]
    require(before == sources() and native == hashlib.sha256(args.native.read_bytes()).hexdigest(),
            "roster qualification inputs changed")
    (args.output / 'RESULT.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report["profiles"]))


if __name__=='__main__':
    main()
