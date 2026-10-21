#!/usr/bin/env python3
"""Actual witnessed bootstrap, traffic, exact recovery and rollback rejection."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile


def main():
    sys.path.append(str(Path(__file__).resolve().parent))
    from run import arguments, Counterpart
    args = arguments()
    from qperiapt_continuity_reference.provider import load_provider
    crypto, backend = load_provider(args.provider_root)
    provider = {"cryptography": crypto.__version__, "openssl": backend.openssl_version_text()}
    from cryptography.exceptions import InvalidSignature
    from fixture_inputs import load, load_witness_pin
    from qperiapt_continuity_reference.bootstrap import Initiator
    from qperiapt_continuity_reference.durable import Session, owner_binding
    from qperiapt_continuity_reference.journal import Journal, Scope
    from qperiapt_continuity_reference.witness import Client, TcpTransport, Operation, Head, verify
    from qperiapt_continuity_reference.witness_session import WitnessSession
    from qperiapt_continuity_reference.wire import SigningKey, require
    from signing_fixture import write
    from session_driver import SessionDriver
    from traffic_checks import application
    from witness_fixture import Bridge
    root = Path(__file__).resolve().parent
    files = [*sorted((root/'qperiapt_continuity_reference').glob('*.py')), *sorted(root.glob('*.py')), *sorted((root/'native/src').glob('*.rs')),
             root/'native/Cargo.toml', root/'native/Cargo.lock', root/'requirements.txt']
    sources = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    out = args.output.resolve(); out.mkdir(); (out/'native').mkdir()
    private = Path(tempfile.mkdtemp(prefix='qperiapt-witnessed-peer-')).resolve()
    require(not private.is_relative_to(out), 'private fixture inside output')
    (out/'private-fixture-path').write_text(str(private)+'\n')
    native = Counterpart(args.native.resolve(), out/'native', send_budget=4, required_witness=True)
    bridge = None
    refusals = []
    def refuses(name, action, reason=None):
        try:
            action()
        except Exception as error:
            require(isinstance(error, (ValueError, InvalidSignature, OSError)), 'unexpected control exception: '+repr(error))
            require(reason is None or reason in str(error), 'wrong refusal: '+name+': '+str(error))
            refusals.append({'case': name, 'type': type(error).__name__, 'error': str(error)})
        else:
            raise ValueError('missing refusal: '+name)
    try:
        signer = SigningKey(); require(native.transfer(signer.public().raw) == b'\1ready', 'native ready')
        public = out/'native/public'; pin = load_witness_pin(public)
        _, _, ctx = load(public, 150, witness_pin=pin)
        require(ctx.digest == (public/'expected-context').read_bytes(), 'actual required context')
        refuses('required-policy-without-pin', lambda: load(public, 150), 'required-witness')
        refuses('volatile-required-owner', lambda: Initiator(ctx, signer, 150), 'volatile owner')
        scope = Scope(os.urandom(32), owner_binding(ctx), ctx.digest); key = os.urandom(32)
        config = private/'configuration'
        with os.fdopen(os.open(config, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600), 'wb') as f:
            f.write(key+scope.wire()); f.flush(); os.fsync(f.fileno())
        signer_path = private/'signer'; write(signer_path, signer)
        path = private/'session'; path.mkdir(mode=0o700)
        refuses('local-required-owner', lambda: Session.create(path, scope, key, ctx, signer, 150), 'required witness')
        retained = private/'retained-coordination'; retained.mkdir(mode=0o700)
        marker = b'original coordination'
        with os.fdopen(os.open(retained/'authority', os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600), 'wb') as stream:
            stream.write(marker); stream.flush(); os.fsync(stream.fileno())
        refuses('witness-genesis-cannot-replace-coordination',
                lambda: WitnessSession.provision(retained, scope, key, ctx, signer, 150), 'existing witnessed creation')
        require(not (retained/'head').exists() and not (retained/'intent').exists()
                and (retained/'authority').read_bytes() == marker, 'genesis changed retained coordination')
        bridge = Bridge(native, out)
        driver = SessionDriver(out, args.provider_root.resolve(), public, config, path, signer_path,
                               witness_address=bridge.address[0]+':'+str(bridge.address[1]))
        worker = driver.run
        def value(name, action, arguments=(), **kw):
            return bytes.fromhex(worker(name, action, arguments, **kw))
        def new_client(transport=None):
            return Client(pin, ctx.witness.subject(scope.identity), signer, transport or TcpTransport(bridge.address))
        def open_owner(observer=None):
            return WitnessSession.open(path, scope, key, ctx, client=new_client(), observer=observer)
        worker('creation-intent-kill', 'witness_provision', now=150, cut='committed:intent')
        genesis = value('recover-original-genesis', 'witness_genesis')
        require(genesis == value('repeat-original-genesis', 'witness_genesis'), 'original genesis changed')
        worker('unenrolled-refusal', 'initial', now=150, refusal='truncated witness reply')
        bridge.call('trusted-enrollment', 30, genesis, b'enrolled')
        start = len(bridge.records)
        opening = open_owner()
        opening.close()
        opening_queries = [row['kind'] for row in bridge.records[start:]]
        require(opening_queries == [1], 'opening repeated an already authenticated witness query')
        from witness_controls import check_release_admission, check_release_head
        release_queries = check_release_admission(open_owner, bridge, refuses)
        release_queries['current-permission-wrong-head'] = check_release_head(args, private, out, refuses)
        initial = value('initial', 'initial', now=150)
        reply = bridge.call('bootstrap-response', 4, initial)
        worker('final-witness-kill', 'finish', (reply,), now=150, cut='witness:advanced')
        final = value('original-final-recovery', 'finish', (reply,), now=150)
        session = bridge.call('bootstrap-complete', 5, final)
        worker('activation-publication-kill', 'activate', cut='committed:head')
        require(value('activation-recovery', 'activate') == session, 'session changed')
        bridge.call('native-activate', 6, expected=session)
        backup = private/'old-backup'; backup.mkdir(mode=0o700)
        (backup/'head').write_bytes((path/'head').read_bytes()); (backup/'head').chmod(0o600)
        # A saved send reservation may be committed remotely with no returned receipt.
        identity = value('lost-send-id', 'next_id')
        bridge.arm('after', 2)
        worker('lost-witness-response', 'send', (identity, b'original unknown send', b'witness'), refusal='truncated witness reply')
        pending = (path/'intent').read_bytes()
        bridge.call('expire-witness-authority', 33, (201).to_bytes(8,'big'), b'witness clock set')
        status = worker('expired-exact-recovery-status', 'status', (identity,))
        require(status == 'Reserved', 'expired original reservation not retained')
        worker('expired-output-refusal', 'resume', (identity,), refusal='witness current authority denied')
        bridge.call('restore-fixture-time', 33, (150).to_bytes(8,'big'), b'witness clock set')
        wire = value('original-send-resume', 'resume', (identity,))
        require(value('original-send-replay', 'resume', (identity,)) == wire, 'lost reply changed ciphertext')
        bridge.call('native-receive', 7, application(b'witness', wire), b'original unknown send')
        ack = bridge.call('native-consume', 10, identity)
        require(worker('accept-ACK', 'accept_acknowledgement', (ack,)) == 1, 'consumed prefix')
        bridge.call('trusted-enrollment-exact-retry', 30, genesis, b'enrolled')
        bridge.call('reopen-actual-witness', 32, expected=b'witness reopened')
        require(worker('acknowledged-after-witness-reopen', 'status', (identity,)) == 'Acknowledged', 'witness reopen changed status')
        refuses('restored-old-image', lambda: WitnessSession.open(backup, scope, key, ctx, client=new_client()), 'head differs')
        refuses('local-reader-required-image', lambda: Journal.open(path, scope, key, Session._validator(ctx)), 'journal identity')
        refuses('advanced-state-not-genesis', lambda: WitnessSession.recover_genesis(path, scope, key, ctx), 'advanced')
        # No dispatch also retains the exact original local intent.
        second = value('undispatched-send-id', 'next_id')
        bridge.arm('before', 2)
        worker('undispatched-send', 'send', (second,b'not dispatched',b'witness'), refusal='truncated witness reply')
        second_wire = value('undispatched-resume', 'resume', (second,))
        bridge.call('second-receive', 7, application(b'witness',second_wire), b'not dispatched')
        ack = bridge.call('second-consume', 10, second)
        require(worker('second-ACK','accept_acknowledgement',(ack,)) == 2, 'second prefix')
        # Real current-epoch traffic remains possible across both directions.
        reverse_id = bridge.call('reverse-id', 8)
        reverse = bridge.call('reverse-send', 9, reverse_id+application(b'witness',b'native witnessed reply'))
        require(worker('reverse-receive','receive',(reverse,b'witness')) == [reverse_id.hex(),b'native witnessed reply'.hex()], 'reverse plaintext')
        reverse_ack = value('reverse-consume','consume',(reverse_id,))
        bridge.call('reverse-ACK',11,reverse_ack,(1).to_bytes(8,'big'))
        # Three complete PQ rekeys use the same witnessed independent owner.
        for epoch in range(1,4):
            tag='rekey-'+str(epoch)
            if epoch%2:
                offer=value(tag+'-offer','prepare_rekey_offer')
                response=bridge.call(tag+'-response',14,offer)
                final=value(tag+'-final','accept_rekey_response',(response,))
                receipt=bridge.call(tag+'-receipt',15,final)
                require(worker(tag+'-confirm','accept_rekey_receipt',(receipt,))==epoch,'independent epoch')
            else:
                offer=bridge.call(tag+'-offer',17)
                response=value(tag+'-response','respond_rekey_offer',(offer,))
                final=bridge.call(tag+'-final',18,response)
                receipt=value(tag+'-receipt','finish_rekey',(final,))
                bridge.call(tag+'-confirm',19,receipt,epoch.to_bytes(8,'big'))
            require(worker(tag+'-progress','rekey_progress')==[epoch,epoch,epoch,0],'confirmed epoch')
        from witness_controls import check_controls
        transport_cases = check_controls(pin, ctx.witness.subject(scope.identity), signer, bridge, out, refuses)
        # Captured and corrupted replies cannot authorize even a read.
        record=next(row for row in bridge.records if row.get('delivery')=='sent')
        old_reply=(out/(record['case']+'.reply')).read_bytes()
        stale=new_client(lambda _wire,_deadline:old_reply)
        refuses('captured-reply-new-challenge',lambda:stale.exchange(Operation.query()),'attempt/scope')
        refuses('closed-client-after-replay',lambda:stale.exchange(Operation.query()),'closed witness')
        bridge.arm('corrupt',1)
        worker('corrupted-witness-signature','status',refusal='InvalidSignature')
        # Fence after an irrevocable local send commit; release must still fail.
        third=value('fenced-send-id','next_id')
        def observer(stage):
            if stage=='protocol:send-committed':
                snapshot=owner._journal._decode((path/'head').read_bytes())
                result=new_client().exchange(Operation.fence(Head(1,snapshot.revision,snapshot.digest)))
                require(result.outcome==2 and result.head.fence==2,'external writer fence')
        owner=open_owner(observer)
        try:
            refuses('fence-before-output',lambda:owner.send(third,b'committed but withheld',b'witness',170),'head differs')
        finally:
            owner.close()
        refuses('fenced-original-reopen',lambda:open_owner(),'head differs')
        saved_bridge=bridge; bridge.close(); bridge=None
        require(sources=={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in files},'sources changed during qualification')
        report={'provider':provider,'source_files':sources,'native_sha256':hashlib.sha256(args.native.read_bytes()).hexdigest(),
                'worker_operations':driver.operations,'native_commands':native.commands,'refusals':refusals,
                'epochs':3,'genesis':genesis.hex(),'session':session.hex(),'lost_intent_sha256':hashlib.sha256(pending).hexdigest(),
                'process_kills':3,'transport_controls':transport_cases,'scope':'Required witness with actual Rust provider and both journal owners; loopback byte bridge is test orchestration, not separate-host deployment. No witness rollback, renewal/migration, power loss, erasure or PCS proof claim.'}
        # Retain public challenges, exact commands, signed replies and failure cuts.
        report['witness_attempts']=saved_bridge.records
        report['opening_request_kinds']=opening_queries
        report['release_request_kinds']=release_queries
        (out/'RESULT.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps({k:v for k,v in report.items() if k not in ('source_files','worker_operations','native_commands','witness_attempts','refusals')}))
    finally:
        if bridge is not None:
            (out/'ATTEMPTS.json').write_text(json.dumps(bridge.records,indent=2)+'\n')
            bridge.close()
        native.close()


if __name__=='__main__':
    main()
