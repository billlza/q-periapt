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
