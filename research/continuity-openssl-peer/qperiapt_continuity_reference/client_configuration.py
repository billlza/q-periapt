"""Canonical original client configuration and durable root association phases."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import base64
from dataclasses import dataclass,replace
import json
from .enrollment_exchange import HostAuthority,HostInvitation,decode,encoded,identifier,shape
from .wire import Reader,digest,require
from .account_binding import Binding,SIZE as ROOT_BINDING_SIZE


@dataclass(frozen=True)
class Configuration:
    authority: bytes
    invitation: bytes
    registration: bytes
    ready: bool
    issuance: bytes | None = None
    root_binding: Binding | None = None
    root_ready: bool = False
    root_adoption: bool = False

    def inputs(self):
        authority = HostAuthority.from_trusted(self.authority)
        return authority, HostInvitation.decode(self.invitation, authority)

    def wire(self):
        b64 = lambda value: base64.urlsafe_b64encode(value).rstrip(b'=').decode()
        raw=json.dumps({'schema':'qperiapt-client-configuration/2',
                           'authority':b64(self.authority), 'invitation':{'original':b64(self.invitation),
                           'issuance':None if self.issuance is None else b64(self.issuance)},
                           'registration':list(self.registration), 'ready':self.ready},
                          separators=(',', ':')).encode()
        require(type(self.root_ready) is bool and (self.root_binding is not None or not self.root_ready),
                'client root association phase')
        require(type(self.root_adoption) is bool and (self.root_binding is not None or not self.root_adoption),
                'client root adoption phase')
        if self.root_binding is None:return raw
        authority,_=self.inputs()
        require(self.ready and self.root_binding.application==authority.application
                and self.root_binding.account==digest(b'ACCOUNT',authority.root.raw),'client root association scope')
        tag=b'QPCLRT02' if self.root_adoption else b'QPCLRT01'
        return tag+self.root_binding.wire()+bytes([self.root_ready])+len(raw).to_bytes(4,'big')+raw

    @classmethod
    def read(cls, raw):
        require(type(raw) is bytes and len(raw)<=72*1024,'client configuration capacity')
        if raw[:8] in (b'QPCLRT01',b'QPCLRT02'):
            r=Reader(raw);tag=r.take(8);binding=Binding.read(r.take(ROOT_BINDING_SIZE));ready=r.integer(1)
            require(ready in (0,1),'client root association phase')
            size=r.integer(4);require(size<=72*1024,'client configuration capacity');inner=r.take(size);r.finish()
            require(inner[:8] not in (b'QPCLRT01',b'QPCLRT02'),'nested client root association')
            value=replace(cls.read(inner),root_binding=binding,root_ready=bool(ready),root_adoption=tag==b'QPCLRT02')
            require(value.wire()==raw,'client root association canonical encoding');return value
        value = decode(raw, 'schema authority invitation registration ready', 72 * 1024)
        require(value['schema'] in ('qperiapt-client-configuration/1', 'qperiapt-client-configuration/2')
                and type(value['ready']) is bool, 'client configuration schema or phase')
        invitation, issuance = value['invitation'], None
        if value['schema'] == 'qperiapt-client-configuration/2':
            shape(invitation, 'original issuance')
            issuance = None if invitation['issuance'] is None else encoded(invitation['issuance'], 16384)
            invitation = invitation['original']
        result = cls(encoded(value['authority'], 16384), encoded(invitation, 16384),
                     identifier(value['registration']), value['ready'], issuance)
        authority, original = result.inputs()
        if issuance is not None:
            require(result.ready, 'issuance association before client readiness')
            original.same_device(HostInvitation.decode(issuance, authority))
        return result
