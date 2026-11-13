"""Native public-file bridge; independently configured pins never come from a reply.

The enclosing plan is host application configuration, not a signed protocol or
permission. Preparing still requires the original client's accepted credential.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from pathlib import Path
from .authority import Pins
from .cli_files import read_file
from .enrollment_exchange import (decode, shape, identifier, checkpoint, encoded,
                                 host_revision, counter, PolicyInputs, IssuedEnrollment)
from .enrollment_extension import IssuedExtension
from .identity import DevicePin
from .publication import Publication
from .wire import VerificationKey, digest, require


def path(value):
    require(type(value) is str and 0<len(value)<=4096,'absolute publication input path')
    result=Path(value)
    require(result.is_absolute() and '..' not in result.parts,'absolute publication input path')
    return result


def expectation(value,family):
    shape(value,'current device generation');current=value['current']
    shape(current,'revision account public_key family suspended roster')
    host_revision(current['revision'])
    require(type(current['suspended']) is bool,'host issuance suspension flag')
    require(identifier(current['family'])==family,'peer policy family differs')
    root=VerificationKey(encoded(current['public_key'],1985,1985));account=identifier(current['account'])
    require(account==digest(b'ACCOUNT',root.raw),'peer root/account pin differs')
    shape(current['roster'],'checkpoint bytes');version,commitment=checkpoint(current['roster']['checkpoint'])
    return (DevicePin(root,account,version,commitment,identifier(value['device'],16),counter(value['generation'])),
            encoded(current['roster']['bytes'],8192))


def load(plan_path,now):
    """Preflight public files and authenticate a publication before opening a client."""
    plan=decode(read_file(plan_path,16384),
        'schema session_directory peer_trust publication credential policy_pins policy_materials',16384)
    require(plan['schema']=='qperiapt-independent-publication/1','publication plan schema')
    directory=path(plan['session_directory'])
    policy=PolicyInputs.from_trusted(read_file(path(plan['policy_pins']),16384),
                                    read_file(path(plan['policy_materials']),128*1024))
    trust=decode(read_file(path(plan['peer_trust']),128*1024),'schema directory initiator responder')
    require(trust['schema']=='qperiapt-native-peer-trust/1','peer trust schema')
    family=digest(b'POLICY-AUTHORITY',policy.pins.policy_root.raw)
    initiator,roster=expectation(trust['initiator'],family)
    responder,peer_roster=expectation(trust['responder'],family)
    p=policy.pins;pins=Pins(p.sdk_root,p.sdk_state,p.policy_root,p.policy_version,p.policy_digest,
                          initiator,responder,identifier(trust['directory']))
    shape(plan['credential'],'kind path')
    kind=plan['credential']['kind'];require(kind in ('enrollment','extension'),'credential artifact kind')
    raw=read_file(path(plan['credential']['path']),32768)
    # This merely obtains public bytes. Original acceptance/adoption and exact
    # local key/credential binding are enforced by EnrollmentClient.prepare.
    issued=IssuedEnrollment.decode(raw) if kind=='enrollment' else IssuedExtension.decode(raw)
    require(issued.revision==trust['initiator']['current']['revision'],'credential artifact host revision differs')
    enrollment=issued.operation if kind=='enrollment' else issued.approval.enrollment
    publication=Publication.decode(read_file(path(plan['publication']),65536))
    require(publication.roster==peer_roster,'publication differs from independently selected responder roster')
    publication.verify(pins,policy.materials,issued.certificate,roster,now,witness_pin=policy.witness)
    return directory,publication.inputs(pins,policy.materials,issued.certificate,roster,witness_pin=policy.witness),enrollment
