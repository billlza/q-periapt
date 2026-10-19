"""Public peer confirmation retained inside the original encrypted registration.

This record is written only after the owned session authenticates READY's ACK.
Decoding a record alone grants no current session authority.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import dataclass
from .wire import require

SIZE = 32 + 81
TAG = b'QPREGC01'
OVERHEAD = len(TAG) + 4 + SIZE


@dataclass(frozen=True)
class Confirmation:
    session: bytes
    proof: bytes

    def wire(self):
        require(type(self.session) is bytes and len(self.session)==32 and any(self.session),
                'connection confirmation session identity')
        require(type(self.proof) is bytes and len(self.proof)==81
                and self.proof.startswith(b'QPCMACK1'+self.session+b'\1'),
                'connection confirmation requires original epoch-zero peer proof')
        return self.session+self.proof

    @classmethod
    def read(cls, reader):
        value=cls(reader.take(32),reader.take(81)); value.wire(); return value
