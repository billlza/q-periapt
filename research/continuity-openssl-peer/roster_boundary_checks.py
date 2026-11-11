#!/usr/bin/env python3
"""Real registered R before G, Closed floors, overlap and hostile public inputs."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys


def scenario(args, witnessed, before_g):
    from registration_fixture import Fixture
    from shared_account_checks import start, request_arguments
    from qperiapt_continuity_reference.roster_protocol import Proposal
    from qperiapt_continuity_reference.wire import require
    output = args.output / (('required' if witnessed else 'local') + ('-initial' if before_g else '-closed'))
    output.mkdir()
    selected = argparse.Namespace(**vars(args)); selected.output = output
    f = Fixture(selected, 'witness' if witnessed else 'local', account_members=3)
    try:
        journal, session = start(f)
        message = f.value('original-id', 'next_id', now=170)
        original = f.value('original-outbox', 'send', (message,b'original roster boundary',b'roster'), now=170)
        public = f.public / 'account'
        now = 170 if before_g else 310
        if not before_g:
            for cycle, at in [(1,210),(2,310)]:
                gargs = request_arguments(f,3,f'g-{cycle}',cycle)
                if witnessed:
                    f.call(f'clock-{cycle}',33,at.to_bytes(8,'big'),b'witness clock set')
                    proposal = f.value(f'g-prepare-{cycle}','credential_account_prepare_files',gargs,now=at)
                    f.call(f'g-approve-{cycle}',34,proposal,b'Prepared')
                else:
                    f.worker(f'g-stage-{cycle}','credential_account_stage_files',gargs,now=at)
                result=f.worker(f'g-commit-{cycle}','credential_commit',(gargs[0],),now=at)
                require(result=='Applied' if witnessed else result['status']=='Committed','complete original G')
        version = 9 if before_g else 4
        operation=os.urandom(32)
        rargs=(operation,(public/f'roster-{version}').read_bytes(),(public/f'checkpoint-{version}').read_bytes())
        original_head=(f.session_path/'head').read_bytes()
        if witnessed:
            proposal=f.value('r-prepare','roster_prepare',rargs,now=now)
            intent=(f.session_path/'intent').read_bytes()
            require(f.value('r-same-retry','roster_prepare',rargs,now=now)==proposal
                    and (f.session_path/'intent').read_bytes()==intent,'R retry replaced original target')
            require(f.worker('unapproved-status','roster_status',(operation,),now=now)=='Unavailable','unknown R became a grant')
            f.worker('unapproved-recovery','roster_recover',(operation,),now=now)
            require((f.session_path/'head').read_bytes()==original_head,'unknown R installed target')
            if not before_g:
                f.worker('g-cannot-overwrite-r','credential_account_prepare_files',gargs,now=now,refusal='intent authentication')
            other=(os.urandom(32),rargs[1],rargs[2])
            f.worker('other-r-cannot-overwrite','roster_prepare',other,now=now,refusal='another roster or credential remains pending')
            require((f.session_path/'intent').read_bytes()==intent,'overlap changed original R intent')
            for name,wire in [('truncated',proposal[:-1]),('trailing',proposal+b'\0'),('tag',b'QPRWNP02'+proposal[8:])]:
                f.refuses('proposal-'+name,lambda wire=wire:Proposal.decode(wire),'roster proposal')
            f.call('r-controller-approval',39,proposal,b'Prepared')
            require(f.worker('r-commit','roster_commit',(operation,),now=now)=='Applied','original R apply')
        else:
            require(f.worker('r-apply','roster_refresh',rargs,now=now)=='Applied','original local R')
        require(f.value('same-outbox','resume',(message,),now=now)==original,'R changed retained original outbox')
        applied_head=(f.session_path/'head').read_bytes()
        same=(operation,(public/'roster-6').read_bytes(),(public/'checkpoint-6').read_bytes())
        f.worker('same-operation-different-target','roster_prepare' if witnessed else 'roster_refresh',same,
                 now=now,refusal='different original roster target')
        stale=(os.urandom(32),(public/'roster-1').read_bytes(),(public/'checkpoint-1').read_bytes())
        f.worker('stale-roster-refused','roster_prepare' if witnessed else 'roster_refresh',stale,
                 now=now,refusal='roster')
        require((f.session_path/'head').read_bytes()==applied_head,'rejected R changed installed image')
        if witnessed and not before_g:
            closing=os.urandom(32)
            close_args=(closing,(public/'roster-6').read_bytes(),(public/'checkpoint-6').read_bytes())
            proposal=f.value('r6-prepare','roster_prepare',close_args,now=now)
            held_intent=(f.session_path/'intent').read_bytes()
            require(f.worker('old-r-recovery-cannot-commit-r6','roster_recover',(operation,),now=now)=='Applied'
                    and (f.session_path/'head').read_bytes()==applied_head
                    and (f.session_path/'intent').read_bytes()==held_intent,'old R recovery touched pending R6')
            f.call('r6-controller-approval',39,proposal,b'Prepared')
            f.bridge.arm('after',18)
            f.worker('r6-lost-close','roster_close',(closing,),now=now,refusal='truncated witness reply')
            require(f.worker('r6-original-recovery','roster_recover',(closing,),now=now)=='Closed','original closed result')
            require((f.session_path/'head').read_bytes()==applied_head,'Closed target became current')
            f.worker('r6-floor-cannot-reuse','roster_prepare',(os.urandom(32),close_args[1],close_args[2]),
                     now=now,refusal='roster successor retired')
            require(f.value('closed-retains-outbox','resume',(message,),now=now)==original,'Closed R changed original outbox')
            require(f.worker('original-applied-r-retained','roster_status',(operation,),now=now)=='Applied','Closed R erased active R receipt')
        # Corrupt only this now-completed fixture's authenticated control. Retain
        # the rejected bytes and entire original private installation for diagnosis.
        if witnessed:
            path=f.session_path/'authority'; original_control=path.read_bytes()
            (f.private/'rejected-authority-original').write_bytes(original_control)
            corrupted=bytearray(original_control); corrupted[-1]^=1
            path.write_bytes(corrupted)
            f.worker('control-mac-refused','roster_status',(operation,),now=now,refusal='authority control authentication')
        result={'before_g':before_g,'witnessed':witnessed,'journal':journal.hex(),'session':session.hex(),
                'public_refusals':f.refusals,'workers':len(f.driver.operations),
                'original_message_sha256':hashlib.sha256(original).hexdigest()}
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
    report["profiles"] = [scenario(args,witnessed,before_g) for before_g in (True,False) for witnessed in (False,True)]
    require(before == sources() and native == hashlib.sha256(args.native.read_bytes()).hexdigest(),
            "roster qualification inputs changed")
    (args.output / 'RESULT.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report["profiles"]))


if __name__=='__main__':
    main()
