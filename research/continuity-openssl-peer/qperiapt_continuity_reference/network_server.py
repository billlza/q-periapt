"""Bounded opaque-frame admission, separate from the original cryptographic owner.

Only one complete request executes at a time. Incomplete TCP frames own no SDK
lease, and oldest incomplete connections can be evicted at capacity. A handler
receives the original acceptance deadline; shutdown joins its actual worker.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass,field
import math
import selectors
import socket
import threading
import time
from .connection_run import Cancellation,Run
from .network import endpoint,frame_size
from .wire import require


@dataclass(frozen=True)
class Limits:
    pending:int=8
    per_ip:int=2
    read_timeout:float=2
    operation_timeout:float=30

    def __post_init__(self):
        require(type(self.pending) is int and 1<=self.pending<=64 and type(self.per_ip) is int
                and 1<=self.per_ip<=self.pending,'TCP admission capacity')
        require(all(type(v) in (int,float) and math.isfinite(v) for v in (self.read_timeout,self.operation_timeout))
                and 0<self.read_timeout<=self.operation_timeout<=120,'TCP admission deadlines')


@dataclass
class _Peer:
    stream:socket.socket
    ip:str
    deadline:float
    read_deadline:float
    header:bytearray=field(default_factory=bytearray)
    body:bytearray=field(default_factory=bytearray)
    length:int|None=None
    closed:bool=False


class Server:
    """One explicit listener. close() requests shutdown; serve() joins all work.

    handler(frame, run) must return one response or raise. Busy complete requests
    close without a fabricated response. Host callbacks must bound their own I/O;
    Python cannot forcibly interrupt an arbitrary synchronous callback.
    """
    def __init__(self,address,handler,*,limits=None,cancellation=None):
        require(callable(handler),'TCP handler')
        require(limits is None or isinstance(limits,Limits),'TCP server limits')
        require(cancellation is None or isinstance(cancellation,Cancellation),'TCP server cancellation')
        self.limits=Limits() if limits is None else limits
        self.cancel=Cancellation() if cancellation is None else cancellation
        self._state_lock=threading.Lock();self._running=False;self._used=False;self._handler=handler
        self._listener=socket.socket(endpoint(address,listen=True),socket.SOCK_STREAM)
        try:
            self._listener.setblocking(False);self._listener.bind(address)
            self._listener.listen(self.limits.pending+1)
            bound=self._listener.getsockname();self.address=(bound[0],bound[1])
        except BaseException:
            self._listener.close();raise

    def close(self):
        with self._state_lock:
            self.cancel.cancel()
            if not self._running: self._listener.close();self._used=True

    def serve(self):
        with self._state_lock:
            require(not self._used,'TCP server already used or closed')
            self._used=True;self._running=True
        stats=dict(accepted=0,evicted_incomplete=0,rejected_busy=0,read_errors=0,
                   completed_responses=0,operation_errors=0,last_operation_error=None)
        pending={};active=None;writing=None;marker=object()
        selector=None;executor=None

        def close_peer(peer):
            if peer.closed:return
            pending.pop(peer.stream,None)
            try:
                try:selector.get_key(peer.stream)
                except KeyError:pass  # An executing owner is deliberately unregistered.
                else:selector.unregister(peer.stream)
            finally:peer.stream.close();peer.closed=True

        def failed(error):
            stats['operation_errors']+=1;stats['last_operation_error']=type(error).__name__

        def execute(frame,run):
            run.check();result=self._handler(frame,run);run.check()
            require(type(result) is bytes,'TCP handler response type');frame_size(len(result));return result

        try:
            selector=selectors.DefaultSelector()
            executor=ThreadPoolExecutor(max_workers=1,thread_name_prefix='qperiapt-owner')
            selector.register(self._listener,selectors.EVENT_READ,marker)
            while not self.cancel.is_cancelled():
                now=time.monotonic()
                for peer in list(pending.values()):
                    if now>=peer.read_deadline:stats['read_errors']+=1;close_peer(peer)
                if active is not None:
                    peer,future,run=active
                    if now>=peer.deadline:run.cancellation.cancel();close_peer(peer)
                    if future.done():
                        active=None
                        try:
                            response=future.result();run.check();require(not peer.closed,'closed TCP response')
                        except Exception as error:failed(error);close_peer(peer)
                        else:
                            writing=(peer,memoryview(len(response).to_bytes(4,'big')+response))
                            selector.register(peer.stream,selectors.EVENT_WRITE,peer)
                if writing is not None and now>=writing[0].deadline:
                    failed(TimeoutError('TCP response deadline'));close_peer(writing[0]);writing=None
                events=selector.select(.025)
                # Service available frame bytes before accepting another batch.
                events.sort(key=lambda event:event[0].data is marker)
                for key,mask in events:
                    if self.cancel.is_cancelled():break
                    if key.data is marker:
                        for _ in range(8):
                            try:stream,address=self._listener.accept()
                            except (BlockingIOError,InterruptedError):break
                            stats['accepted']+=1;now=time.monotonic();stream.setblocking(False)
                            try:stream.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
                            except OSError:
                                stats['read_errors']+=1;stream.close();continue
                            same=[p for p in pending.values() if p.ip==address[0]]
                            victim=same[0] if len(same)>=self.limits.per_ip else (next(iter(pending.values())) if len(pending)>=self.limits.pending else None)
                            if victim is not None:stats['evicted_incomplete']+=1;close_peer(victim)
                            peer=_Peer(stream,address[0],now+self.limits.operation_timeout,now+self.limits.read_timeout)
                            pending[stream]=peer;selector.register(stream,selectors.EVENT_READ,peer)
                        continue
                    peer=key.data
                    if peer.closed:continue
                    if writing is not None and writing[0] is peer:
                        if time.monotonic()>=peer.deadline:
                            failed(TimeoutError('TCP response deadline'));close_peer(peer);writing=None;continue
                        try:sent=peer.stream.send(writing[1]);require(sent>0,'closed TCP writer')
                        except (BlockingIOError,InterruptedError):continue
                        except (OSError,ValueError) as error:failed(error);close_peer(peer);writing=None;continue
                        rest=writing[1][sent:]
                        if rest:writing=(peer,rest)
                        else:stats['completed_responses']+=1;close_peer(peer);writing=None
                        continue
                    if time.monotonic()>=peer.read_deadline:
                        stats['read_errors']+=1;close_peer(peer);continue
                    try:
                        if peer.length is None:
                            part=peer.stream.recv(4-len(peer.header));require(bool(part),'truncated TCP header')
                            peer.header.extend(part)
                            if len(peer.header)<4:continue
                            peer.length=frame_size(int.from_bytes(peer.header,'big'))
                        part=peer.stream.recv(peer.length-len(peer.body));require(bool(part),'truncated TCP frame')
                        peer.body.extend(part)
                    except (BlockingIOError,InterruptedError):continue
                    except (OSError,ValueError):
                        stats['read_errors']+=1;close_peer(peer);continue
                    if len(peer.body)<peer.length:continue
                    selector.unregister(peer.stream)
                    if active is not None or writing is not None:
                        stats['rejected_busy']+=1;close_peer(peer);continue
                    try:run=Run.until(peer.deadline)
                    except (OSError,ValueError) as error:failed(error);close_peer(peer);continue
                    active=(peer,executor.submit(execute,bytes(peer.body),run),run)
                    pending.pop(peer.stream)
        finally:
            self.cancel.cancel()
            cleanup_error=None
            peers=list(pending.values())
            if writing is not None:peers.append(writing[0])
            if active is not None:active[2].cancellation.cancel();peers.append(active[0])
            for peer in peers:
                try:close_peer(peer)
                except BaseException as error:
                    if cleanup_error is None:cleanup_error=error
            for resource in (self._listener,selector):
                if resource is None:continue
                try:resource.close()
                except BaseException as error:
                    if cleanup_error is None:cleanup_error=error
            # Keep the worker owned until it actually exits, even after socket
            # cancellation. Never release its slot by detaching a blocked callback.
            try:
                if executor is not None:executor.shutdown(wait=True,cancel_futures=False)
                if active is not None:
                    try:active[1].result()
                    except Exception as error:failed(error)
            finally:
                with self._state_lock:self._running=False
            if cleanup_error is not None:raise cleanup_error
        return stats
