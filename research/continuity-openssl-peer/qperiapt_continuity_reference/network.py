"""Explicit bounded TCP for QPCXCH01; inner owners supply authentication.

This carrier does not hide public metadata and is not a TLS fallback. It uses
numeric endpoints, one request per connection, and no implicit I/O retries.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import errno
import ipaddress
import math
import os
import selectors
import socket
import time
from .connection_run import Cancellation,Cancelled
from .connection_wire import MAX_FRAME
from .wire import require


def endpoint(address,*,listen=False):
    require(type(address) is tuple and len(address)==2 and type(address[0]) is str
            and type(address[1]) is int and (0 if listen else 1)<=address[1]<=65535,'numeric TCP endpoint')
    ip=ipaddress.ip_address(address[0])
    require(not ip.is_multicast and (listen or not ip.is_unspecified)
            and str(ip)!='255.255.255.255','TCP endpoint scope')
    return socket.AF_INET if ip.version==4 else socket.AF_INET6


def remaining(deadline,cancel):
    if cancel.is_cancelled(): raise Cancelled('TCP exchange cancelled')
    value=deadline-time.monotonic()
    if value<=0: raise TimeoutError('TCP exchange deadline')
    return value


def frame_size(size):
    require(type(size) is int and 10<=size<=MAX_FRAME,'TCP frame bound')
    return size


class _Channel:
    def __init__(self,stream,selector,cancel):
        self.stream,self.selector,self.cancel=stream,selector,cancel
        self.event=selectors.EVENT_WRITE; selector.register(stream,self.event)

    def ready(self,event,deadline):
        if event!=self.event:
            self.selector.modify(self.stream,event); self.event=event
        while True:
            wait=min(.025,remaining(deadline,self.cancel))
            events=self.selector.select(wait)
            remaining(deadline,self.cancel)
            if events: return

    def send(self,data,deadline):
        pending=memoryview(data)
        while pending:
            self.ready(selectors.EVENT_WRITE,deadline)
            try: sent=self.stream.send(pending)
            except (BlockingIOError,InterruptedError): continue
            require(sent>0,'closed TCP request'); pending=pending[sent:]
        remaining(deadline,self.cancel)

    def read(self,size,deadline):
        result=bytearray()
        while len(result)<size:
            self.ready(selectors.EVENT_READ,deadline)
            try: part=self.stream.recv(size-len(result))
            except (BlockingIOError,InterruptedError): continue
            require(bool(part),'truncated TCP response'); result.extend(part)
        remaining(deadline,self.cancel); return bytes(result)


class TcpTransport:
    """Callable carrier for EnrollmentClient.connect and Connection operations."""
    def __init__(self,address):
        self.family=endpoint(address); self.address=address

    def __call__(self,request,deadline,cancel):
        require(type(request) is bytes and isinstance(cancel,Cancellation),'TCP invocation')
        require(type(deadline) in (int,float) and math.isfinite(deadline),'TCP absolute deadline')
        frame_size(len(request));remaining(deadline,cancel)
        with socket.socket(self.family,socket.SOCK_STREAM) as stream, selectors.DefaultSelector() as selector:
            stream.setblocking(False);stream.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
            channel=_Channel(stream,selector,cancel);phase=min(deadline,time.monotonic()+5)
            error=stream.connect_ex(self.address)
            if error not in (0,errno.EISCONN,errno.EINPROGRESS,errno.EWOULDBLOCK,errno.EALREADY,errno.EINTR):
                raise OSError(error,os.strerror(error))
            if error not in (0,errno.EISCONN):
                while True:
                    channel.ready(selectors.EVENT_WRITE,phase)
                    error=stream.getsockopt(socket.SOL_SOCKET,socket.SO_ERROR)
                    if error: raise OSError(error,os.strerror(error))
                    try: stream.getpeername(); break
                    except OSError as pending:
                        if pending.errno not in (errno.ENOTCONN,errno.EINPROGRESS,errno.EWOULDBLOCK): raise
            remaining(deadline,cancel)
            channel.send(len(request).to_bytes(4,'big')+request,deadline)
            length=frame_size(int.from_bytes(channel.read(4,deadline),'big'))
            return channel.read(length,deadline)
