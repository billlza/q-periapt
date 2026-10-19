"""One finite connection invocation with a trusted clock and one-way cancellation."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import math
import threading
import time
from .wire import MAX_U64, require


class Cancelled(RuntimeError):
    """Cancellation was observed; the operation may already have committed."""


class ExchangeLimit(RuntimeError):
    """The explicit request allowance ended; retain this original target."""


class Cancellation:
    def __init__(self): self._event=threading.Event()
    def cancel(self): self._event.set()
    def is_cancelled(self): return self._event.is_set()


class Run:
    """Absolute monotonic deadline, at most 120 seconds, never reset by retries.

    Custom carriers must honor deadline and cancellation while blocked. Synchronous
    callbacks cannot be forcibly interrupted; their late results are withheld.
    The optional wall clock is trusted host input, just like the raw owner's now.
    """
    def __init__(self, timeout=30, *, cancellation=None, clock=None):
        require(type(timeout) in (int,float) and math.isfinite(timeout) and 0<timeout<=120,
                'connection invocation timeout')
        require(cancellation is None or isinstance(cancellation,Cancellation),'connection cancellation token')
        require(clock is None or callable(clock),'connection trusted clock')
        self._deadline=time.monotonic()+timeout
        self._cancellation=Cancellation() if cancellation is None else cancellation
        self._clock=(lambda:int(time.time())) if clock is None else clock

    @property
    def deadline(self): return self._deadline

    @property
    def cancellation(self): return self._cancellation

    def check(self):
        if self._cancellation.is_cancelled(): raise Cancelled('connection invocation cancelled')
        if time.monotonic()>=self._deadline: raise TimeoutError('connection invocation deadline')

    def now(self):
        self.check(); now=self._clock(); self.check()
        require(type(now) is int and 0<=now<MAX_U64,'connection trusted clock value')
        return now
