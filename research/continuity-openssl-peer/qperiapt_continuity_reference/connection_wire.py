"""Bounded QPCXCH01 framing; routing fields grant no authentication."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from .wire import Reader, require

MAX_FRAME=32768
INITIAL,FINAL,MESSAGE,CONTROL=1,2,3,4
REPLY,READY,ACK,CONTROL_REPLY=129,130,131,132


def frame(kind,body):
    require(type(kind) is int and kind in (INITIAL,FINAL,MESSAGE,CONTROL,REPLY,READY,ACK,CONTROL_REPLY)
            and type(body) is bytes and 0<len(body)<=MAX_FRAME-9,'exchange frame bound')
    return b'QPCXCH01'+bytes([kind])+body


def payload(wire,kind):
    require(type(wire) is bytes and 10<=len(wire)<=MAX_FRAME
            and wire[:9]==b'QPCXCH01'+bytes([kind]),'exchange response frame')
    return wire[9:]


def pair(first,second):
    require(type(first) is bytes and type(second) is bytes and len(first)<=65535
            and len(first)+len(second)+2<=MAX_FRAME-9,'exchange pair bound')
    return len(first).to_bytes(2,'big')+first+second


def split(body):
    require(type(body) is bytes and 2<=len(body)<=MAX_FRAME-9,'exchange pair bound')
    reader=Reader(body); first=reader.take(reader.integer(2))
    return first,body[2+len(first):]


def acknowledgement_epoch(proof):
    require(type(proof) is bytes,'exchange acknowledgement type')
    if len(proof)==81 and proof[:8]==b'QPCMACK1': return 0
    require(len(proof)==89 and proof[:8]==b'QPCMACK2','exchange acknowledgement shape')
    epoch=int.from_bytes(proof[41:49],'big'); require(epoch>0,'exchange epoch acknowledgement')
    return epoch


def request_route(request):
    """Unauthenticated (kind, session-or-None) metadata, never trust inputs."""
    require(type(request) is bytes and 10<=len(request)<=MAX_FRAME and request[:8]==b'QPCXCH01',
            'exchange request frame')
    kind=request[8];body=request[9:]
    if kind in (INITIAL,FINAL):return kind,None
    if kind==MESSAGE:
        ad,ciphertext=split(body)
        require(len(ad)<=1024 and 109<=len(ciphertext)<=16493 and ciphertext[:8]==b'QPCMSG03',
                'exchange message route')
        session=ciphertext[8:40]
    elif kind==CONTROL:
        from .control import inspect
        inspect(body);session=body[76:108]
    else:raise ValueError('unknown exchange request kind')
    require(len(session)==32 and any(session),'exchange session route')
    return kind,session
