"""Authenticated original registry binding, separate from session business state."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import dataclass
from .wire import Reader,generation,require
from .witness import fixed

SIZE=96+32+8+32


@dataclass(frozen=True)
class Binding:
    registry: bytes
    application: bytes
    revision: int
    account: bytes

    def wire(self):
        require(type(self.registry) is bytes and len(self.registry)==96,'root registry scope')
        for offset in (0,32,64):fixed(self.registry[offset:offset+32],32)
        fixed(self.application,32);fixed(self.account,32)
        require(type(self.revision) is int,'root registry revision type')
        return self.registry+self.application+generation(self.revision).to_bytes(8,'big')+self.account

    @classmethod
    def read(cls,wire):
        require(type(wire) is bytes and len(wire)==SIZE,'root binding size')
        r=Reader(wire);value=cls(r.take(96),r.take(32),r.integer(8),r.take(32));r.finish()
        require(value.wire()==wire,'root binding canonical encoding');return value

    def check(self,lease):
        from .account_authority import Lease
        require(type(lease) is Lease and lease.binding==self,'original root registry lease required')
        lease.check()


def check(lease):
    if lease is not None:
        from .account_authority import Lease
        require(type(lease) is Lease,'live account root lease required')
        lease.check()


def header(prefix,revision,lease):
    check(lease)
    suffix=b'' if lease is None else lease.binding.wire()
    tag=prefix[:8] if lease is None else prefix[:6]+b'02'
    return tag+prefix[8:]+suffix+revision.to_bytes(8,'big')


def read_header(wire,prefix,lease,*,scope_error='journal identity/owner/context'):
    check(lease)
    offset=len(prefix)
    if wire[:8]==prefix[:6]+b'02':
        require(wire[:offset]==prefix[:6]+b'02'+prefix[8:],'root-bound journal scope')
        Binding.read(wire[offset:offset+SIZE]).check(lease);offset+=SIZE
    else:
        require(lease is None,'expected original root-bound journal')
        require(wire[:offset]==prefix,scope_error)
    require(len(wire)>=offset+24,'journal header and authentication tag')
    return wire[:offset+8],int.from_bytes(wire[offset:offset+8],'big')
