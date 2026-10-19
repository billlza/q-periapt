"""Serialize original coordination while allowing reentrant close to cancel it."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import functools
from .wire import require


def coordinated(function):
    @functools.wraps(function)
    def call(self, *args, **kwargs):
        with self._lock:
            require(not self._busy, "local renewal operation already in progress")
            self._busy = True
            try:
                return function(self, *args, **kwargs)
            finally:
                self._busy = False
    return call
