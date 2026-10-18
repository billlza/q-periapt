#!/usr/bin/env python3
"""Real near-capacity journal: a reservation must fit its eventual ciphertext."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("provider-root","native","output"):p.add_argument("--"+name,type=Path,required=True)
    args=p.parse_args();peer=Path(__file__).resolve().parent;sys.path.append(str(peer))
    from provider import load_provider
    crypto,backend=load_provider(args.provider_root)
    from peer.wire import SigningKey,require
    from peer.durable import Session,owner_binding
    from peer.journal import Scope,MAX_STATE
    from peer.traffic_codec import encode_traffic
    from fixture_inputs import load
    from run import Counterpart
    from traffic_checks import application
    output=args.output.resolve();output.mkdir();(output/'native').mkdir()
    private=Path(tempfile.mkdtemp(prefix='qperiapt-rekey-capacity-')).resolve()
    require(not private.is_relative_to(output),'private capacity fixture inside output')
    (output/'private-fixture-path').write_text(str(private)+'\n')
    native=Counterpart(args.native.resolve(),output/'native')
    owner=None
    try:
        signer=SigningKey();require(native.transfer(signer.public().raw)==b'\1ready','native enrollment')
        _,_,context=load(output/'native/public',150)
        require(context.send_budget==1024,'signed capacity-test budget')
        key=os.urandom(32);scope=Scope(os.urandom(32),owner_binding(context),context.digest)
        fd=os.open(private/'configuration',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'wb')as stream:stream.write(key+scope.wire());stream.flush();os.fsync(stream.fileno())
        path=private/'session';path.mkdir(mode=0o700)
        owner=Session.create(path,scope,key,context,signer,150)
        reply=native.command('response',4,owner.initial(150),1)
        final=owner.finish(reply,150);session=native.command('complete',5,final,1)
        require(owner.activate(170)==session,'activate independent')
        native.command('activate',6,b'',1,session)
        plaintext=bytes(range(256))*64
        for _ in range(64):owner.send(owner.next_id(170),plaintext,b'',170)
        offer=owner.prepare_rekey_offer(signer,170)
        response=native.command('rekey-response',14,offer,1)
        final=owner.accept_rekey_response(response,signer,170)
        receipt=native.command('rekey-receipt',15,final,1)
        require(owner.accept_rekey_receipt(receipt,170)==1,'confirm capacity epoch')
        for _ in range(58):owner.send(owner.next_id(170),plaintext,b'',170)
        with owner._state()as(_snapshot,state):
            traffic_bytes=2+sum(len(encode_traffic(t))for t in state.traffic.epochs.values())
        cap=MAX_STATE-65536
        # Pending record adds ID32 + two length prefixes8 + plaintext. The
        # committed row adds index8 + receipt32 + length4 + frame109 + plaintext.
        boundary=cap-traffic_bytes-40
        require(113<=boundary<=16384,'capacity fixture did not reach target boundary')
        identity=owner.next_id(170);before=(path/'head').read_bytes()
        failure=None
        try:owner.send(identity,b'x'*boundary,b'',170)
        except ValueError as error:failure=str(error)
        require(failure is not None,'infeasible final reservation admitted')
        after=(path/'head').read_bytes()
        observation={'pending_plaintext_bytes':boundary,'traffic_bytes_before':traffic_bytes,'traffic_cap':cap,
                     'would_fit_pending_record':traffic_bytes+40+boundary==cap,
                     'final_row_excess':traffic_bytes+153+boundary-cap,'refusal':failure,
                     'head_unchanged':before==after,'before_head_sha256':hashlib.sha256(before).hexdigest(),
                     'after_head_sha256':hashlib.sha256(after).hexdigest()}
        (output/'ADMISSION.json').write_text(json.dumps(observation,indent=2)+'\n')
        require(before==after,'rejected reservation changed durable head')
        require(failure=='reserved final traffic capacity','wrong capacity refusal')
        require(owner.next_id(170)==identity,'capacity refusal consumed slot')
        accepted=b'y'*(boundary-113)
        wire=owner.send(identity,accepted,b'',170)
        owner.close();owner=Session.open(path,scope,key,context)
        require(owner.resume(identity,170)==wire,'exact-fit ciphertext not recoverable')
        native.command('receive-exact-fit',7,application(b'',wire),1,accepted)
        with owner._state()as(_snapshot,state):
            actual=2+sum(len(encode_traffic(t))for t in state.traffic.epochs.values())
            require(actual==cap and state.pending is None,'exact-fit committed capacity')
        native.command('close',3,b'',1,b'closed');require(native.process.wait(timeout=5)==0,'native close')
        sources=[*sorted((peer/'peer').glob('*.py')),*sorted(peer.glob('*.py')),*sorted((peer/'native/src').glob('*.rs')),peer/'native/Cargo.toml',peer/'native/Cargo.lock',peer/'requirements.txt']
        report={'scope':'Real two-epoch journal at its reserved-control capacity; no mocked state or weakened cap',
                'full_size_outbox_messages':122,'signed_budget':1024,'admission':observation,
                'exact_fit_plaintext_bytes':len(accepted),'exact_fit_committed_and_reopened':True,
                'native_commands':native.commands,'provider':{'cryptography':crypto.__version__,'openssl':backend.openssl_version_text()},
                'source_files':{str(p.relative_to(peer)):hashlib.sha256(p.read_bytes()).hexdigest()for p in sources},
                'private_keys_or_images_uploaded':False}
        (output/'RESULT.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps({'full_size_messages':122,'boundary':boundary,'exact_fit':len(accepted),'head_unchanged':True}))
    finally:
        if owner is not None:owner.close()
        native.close()


if __name__=='__main__':main()
