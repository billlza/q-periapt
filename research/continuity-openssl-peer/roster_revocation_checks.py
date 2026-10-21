#!/usr/bin/env python3
"""Remove the real common-account traffic peer without resetting its session."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
import json
import os
from pathlib import Path
import sys


def remove_peer(f, message, journal, *, policy_version=None):
    from qperiapt_continuity_reference.wire import require
    from traffic_checks import application
    public=f.public/'account'
    ad=b'actual removed peer'
    def peer_message(label,plaintext):
        identity=f.call(label+'-id',8)
        return identity,f.call(label+'-ciphertext',9,identity+application(ad,plaintext))
    before_id,before_wire=peer_message('live-native-peer',b'accepted before roster removal')
    require(f.worker('live-native-peer-received','receive',(before_wire,ad),now=355)
            ==[before_id.hex(),b'accepted before roster removal'.hex()],
            'actual live peer identity and plaintext must be accepted first')
    operation=os.urandom(32)
    rargs=(operation,(public/'roster-19').read_bytes(),(public/'checkpoint-19').read_bytes())
    if f.bridge:
        proposal=f.value('remove-peer-prepare','roster_prepare',rargs,now=355)
        intent=(f.session_path/'intent').read_bytes()
        controller = proposal if policy_version is None else proposal + policy_version.to_bytes(8, 'big')
        f.call('remove-peer-independent-approval',39,controller,b'Prepared')
        f.bridge.arm('after',16)
        f.worker('remove-peer-lost-commit','roster_commit',(operation,),now=355,refusal='truncated witness reply')
        f.worker('remove-peer-ack-cut','roster_recover',(operation,),now=355,cut='roster:acknowledged')
        require(f.worker('remove-peer-original-recovery','roster_recover',(operation,),now=355)=='Applied',
                'original peer removal result')
        target=intent[429:-32]
    else:
        f.worker('remove-peer-atomic-cut','roster_refresh',rargs,now=355,cut='session-store:committed:intent')
        intent=(f.session_path/'intent').read_bytes()
        require(f.worker('remove-peer-original-recovery','roster_status',(operation,),now=355)=='Applied',
                'original local peer removal result')
        target=intent[52:-32]
    require((f.session_path/'head').read_bytes()==target and not (f.session_path/'intent').exists(),
            'peer removal recovery changed original target')
    # The remote endpoint still owns its old key and its own R18 snapshot. Its
    # ability to encrypt does not let an R19 receiver accept that removed peer.
    after_id,after_wire=peer_message('removed-native-peer',b'fresh ciphertext from removed device')
    require(after_id!=before_id,'removed peer must produce a fresh original message identity')
    denials=[('removed-peer-denies-next-id','next_id',()),
             ('removed-peer-denies-old-output','resume',(message,)),
             ('removed-peer-denies-old-input','receive',(before_wire,ad)),
             ('removed-peer-denies-fresh-input','receive',(after_wire,ad))]
    for label,action,arguments in denials:
        f.worker(label,action,arguments,now=355,refusal='peer original identity revoked')
        require((f.session_path/'head').read_bytes()==target,'revoked operation changed original head')
    require(f.worker('removal-outcome-still-observable','roster_status',(operation,),now=355)=='Applied',
            'peer revocation hid original administrative outcome')
    f.worker('root-signed-old-generation-resurrection-refused','roster_prepare' if f.bridge else 'roster_refresh',
             (os.urandom(32),(public/'roster-20').read_bytes(),(public/'checkpoint-20').read_bytes()),
             now=355,refusal='account generation, revocation or credential conflict')
    require((f.session_path/'head').read_bytes()==target and not (f.session_path/'intent').exists(),
            'rejected resurrection changed original R19')
    current=f.worker('removed-peer-original-registration','registration_status',now=355)
    require(current['journal']==journal.hex() and current['signing_id']==f.observations['signing_id'],
            'peer revocation replaced the owning enrollment')
    return {'kind':'actual_common_account_peer_removal','target_version':19,
            'positive_native_receive':True,'denied_operations':[row[0] for row in denials],
            'same_generation_resurrection_refused':True,'original_enrollment_retained':True,
            'before_wire_sha256':hashlib.sha256(before_wire).hexdigest(),
            'after_wire_sha256':hashlib.sha256(after_wire).hexdigest(),
            'target_sha256':hashlib.sha256(target).hexdigest(),
            'scope':'Receiver enforces its independently adopted current roster. Remote encryption capability and past plaintext are not erased.'}


def main():
    sys.path.append(str(Path(__file__).resolve().parent))
    from run import arguments
    from qperiapt_continuity_reference.provider import load_provider
    args=arguments()
    args.output,args.native,args.provider_root=args.output.resolve(),args.native.resolve(),args.provider_root.resolve()
    crypto,backend=load_provider(args.provider_root)
    from qperiapt_continuity_reference.wire import require
    from roster_refresh_checks import scenario
    root=Path(__file__).resolve().parent
    def sources():
        files=[*sorted((root/'qperiapt_continuity_reference').glob('*.py')),*sorted(root.glob('*.py')),
               *sorted((root/'native/src').glob('*.rs')),root/'native/Cargo.toml',root/'native/Cargo.lock',root/'requirements.txt']
        return {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    before=sources(); native=hashlib.sha256(args.native.read_bytes()).hexdigest();args.output.mkdir()
    report={'source_files':before,'native_sha256':native,
            'provider':{'cryptography':crypto.__version__,'openssl':backend.openssl_version_text()}}
    (args.output/'INPUTS.json').write_text(json.dumps(report,indent=2)+'\n')
    report['profiles']=[scenario(args,count,witnessed,after_renewal=remove_peer)
                        for count in (3,32) for witnessed in (False,True)]
    require(before==sources() and native==hashlib.sha256(args.native.read_bytes()).hexdigest(),
            'peer revocation inputs changed')
    (args.output/'RESULT.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps([{k:r[k] for k in ['members','witnessed','workers','process_kills']} for r in report['profiles']]))


if __name__=='__main__':
    main()
