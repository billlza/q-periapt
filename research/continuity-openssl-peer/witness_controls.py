"""Negative signed-wire, close and bounded-TCP controls for the witnessed owner."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import socket
import threading
import time

from qperiapt_continuity_reference.wire import SigningKey, VerificationKey, MAX_U64, require
from qperiapt_continuity_reference.witness import Client, Head, Operation, Pin, TcpTransport, verify


def check_controls(pin, subject, signer, bridge, output, refuses):
    row = next(x for x in bridge.records if x.get('delivery') == 'sent' and x['kind'] == 1)
    wire = (output/(row['case']+'.request')).read_bytes()
    reply = (output/(row['case']+'.reply')).read_bytes()
    body = wire[4:301]; operation = Operation.query()
    require(verify(pin,subject,operation,body,reply).outcome == 1, 'original witness query')
    wrong = Pin(pin.identity, SigningKey().public())
    refuses('wrong-witness-public-key',lambda:verify(wrong,subject,operation,body,reply))
    for offset in (4, 12, 44, 140, 172, 204, 205, 253, 254, 286, len(reply)-1):
        altered=reply[:offset]+bytes([reply[offset]^1])+reply[offset+1:]
        refuses('signed-reply-tamper-'+str(offset),lambda altered=altered:verify(pin,subject,operation,body,altered))
    for size in (0, 3, 4, 281, len(reply)-1):
        refuses('truncated-reply-'+str(size),lambda size=size:verify(pin,subject,operation,body,reply[:size]))
    refuses('reply-trailing-byte',lambda:verify(pin,subject,operation,body,reply+b'\0'))
    refuses('mutating-query-padding',lambda:Operation(1,b'\1'+bytes(95)), 'query padding')
    refuses('boolean-command-kind',lambda:Operation(True,bytes(96)), 'kind type')
    refuses('unknown-command-kind',lambda:Operation(255,bytes(96)), 'unsupported')
    refuses('authority-zero-commitment',lambda:Operation.authority(bytes(32)), 'field shape')
    refuses('counter-exhaustion',lambda:Operation.advance(Head(1,MAX_U64-1,b'x'*32),b'y'*32),'generation')
    refuses('same-image-advance',lambda:Operation.advance(Head(1,1,b'x'*32),b'x'*32),'transition')
    refuses('implicit-DNS-transport',lambda:TcpTransport(('unconfigured.invalid',1234)))
    # A reentrant close in the host transport must not release even a valid reply.
    client=None
    def close_during(wire, _deadline):
        response=bridge.call('close-during-exchange',31,wire)
        client.close()
        return response
    client=Client(pin,subject,signer,close_during)
    refuses('closed-during-valid-reply',lambda:client.exchange(Operation.query()),'closed witness client during')
    for timeout in (0,61,float('inf'),float('nan'),True):
        refuses('invalid-timeout-'+str(timeout),lambda timeout=timeout:Client(pin,subject,signer,close_during,timeout),'timeout')
    transport_cases=[]
    for mode in ('oversized','truncated','trickle'):
        listener=socket.socket(); listener.bind(('127.0.0.1',0)); listener.listen(1); listener.settimeout(2)
        address=listener.getsockname(); errors=[]; events=[]
        def serve():
            try:
                with listener.accept()[0] as stream:
                    stream.settimeout(2)
                    request=bytearray()
                    while len(request)<3678:
                        part=stream.recv(3678-len(request)); require(bool(part),'test request truncated');request.extend(part)
                    if mode=='oversized': stream.sendall((1<<30).to_bytes(4,'big'))
                    elif mode=='truncated': stream.sendall((3659).to_bytes(4,'big')+b'x')
                    else:
                        stream.sendall((3659).to_bytes(4,'big'))
                        for _ in range(6):
                            time.sleep(0.03)
                            try: stream.sendall(b'x')
                            except (BrokenPipeError, ConnectionResetError):
                                events.append('client_closed_after_total_deadline');break
            except BaseException as error:
                errors.append(error)
        thread=threading.Thread(target=serve);thread.start()
        start=time.monotonic()
        try:
            client=Client(pin,subject,signer,TcpTransport(address),timeout=0.08 if mode=='trickle' else 1)
            refuses('TCP-'+mode,lambda:client.exchange(Operation.query()))
            refuses('TCP-'+mode+'-closed-owner',lambda:client.exchange(Operation.query()),'closed witness')
        finally:
            thread.join(timeout=3);listener.close()
        require(not thread.is_alive() and not errors,'TCP control server failed')
        elapsed=time.monotonic()-start
        require(elapsed<1 if mode=='trickle' else elapsed<2,'bounded TCP refusal')
        transport_cases.append({'mode':mode,'elapsed_seconds':elapsed,'events':events})
    return transport_cases


def check_release_admission(open_owner, bridge, refuses):
    """A signed authority reply proves the same exact head as a separate query."""
    observations = {}
    for label, operational, authority, fault, reason in (
            ('current-release', True, None, None, None),
            ('historical-release', False, None, None, None),
            ('wrong-release-authority', True, b'x' * 32, None, 'witness current authority denied'),
            ('lost-release-response', True, None, 'after', 'truncated witness reply'),
            ('corrupted-release-response', True, None, 'corrupt', None)):
        owner = open_owner()
        try:
            before = len(bridge.records)
            if fault is not None: bridge.arm(fault, 4)
            def release(): owner._journal.release(operational, authority)
            if label in ('current-release', 'historical-release'):
                release()
            else:
                refuses(label, release, reason)
                require(owner._journal._directory is None and owner._journal.client.signer is None,
                        'failed release left a live journal or witness signer')
            kinds = [row['kind'] for row in bridge.records[before:]]
            require(kinds == ([4] if operational else [1]), 'release repeated a separately authenticated head query')
            observations[label] = kinds
        finally:
            owner.close()
    return observations


def check_release_head(args, private, output, refuses):
    """A separate real fixture admits permission but has fenced the local head."""
    import json
    import os
    from run import Counterpart
    from fixture_inputs import load, load_witness_pin
    from witness_fixture import Bridge
    from qperiapt_continuity_reference.durable import owner_binding
    from qperiapt_continuity_reference.journal import Scope
    from qperiapt_continuity_reference.witness_session import WitnessSession
    # One generation cannot register a second unrelated journal. Give this
    # irreversible fence control its own actual native identity and witness.
    out = output / 'release-head-control'; out.mkdir(); (out / 'native').mkdir()
    native = Counterpart(args.native.resolve(), out / 'native', required_witness=True)
    bridge = owner = None
    try:
        signer = SigningKey(); require(native.transfer(signer.public().raw) == b'\1ready', 'release control native ready')
        public = out / 'native/public'; pin = load_witness_pin(public)
        _, _, context = load(public, 150, witness_pin=pin)
        bridge = Bridge(native, out)
        scope = Scope(os.urandom(32), owner_binding(context), context.digest)
        key = os.urandom(32); path = private / 'release-head-control'; path.mkdir(mode=0o700)
        genesis = WitnessSession.provision(path, scope, key, context, signer, 150)
        bridge.call('release-head-enrollment', 30, genesis.wire(), b'enrolled')
        subject = context.witness.subject(scope.identity)
        def client(): return Client(pin, subject, signer, TcpTransport(bridge.address))
        owner = WitnessSession.open(path, scope, key, context, client=client())
        original = (path / 'head').read_bytes()
        snapshot = owner._journal.read()
        expected = Head(1, snapshot.revision, snapshot.digest)
        fenced = client().exchange(Operation.fence(expected))
        require(fenced.outcome == 2 and fenced.head.fence == 2, 'release control did not fence actual witness')
        before = len(bridge.records)
        refuses('release-current-permission-wrong-head', lambda: owner._journal.release(True), 'head differs')
        records = bridge.records[before:]
        require([r['kind'] for r in records] == [4], 'wrong head did not reach combined release check')
        row = records[0]
        request = (out / (row['case'] + '.request')).read_bytes()
        reply = (out / (row['case'] + '.reply')).read_bytes()
        checked = verify(pin, subject, Operation.authority(context.witness.authority), request[4:301], reply)
        require(checked.outcome == 5 and checked.head == fenced.head and checked.head != expected,
                'control was not a valid authority-current reply with a different head')
        require((path / 'head').read_bytes() == original and not (path / 'intent').exists()
                and owner._journal._directory is None, 'failed release changed local image or retained owner')
        return [4]
    finally:
        try:
            try:
                if owner is not None: owner.close()
            finally:
                if bridge is not None:
                    try:
                        (out / 'ATTEMPTS.json').write_text(json.dumps(bridge.records, indent=2)+'\n')
                    finally:
                        bridge.close()
        finally:
            try:
                native.close()
            finally:
                # This control owns a separate provider from the main scenario.
                # Retain its public command records even when cleanup fails.
                (out / 'NATIVE.json').write_text(json.dumps(native.commands, indent=2)+'\n')
