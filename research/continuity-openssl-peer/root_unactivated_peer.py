"""Actual third-root traffic when the committed second root never became a peer."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from qperiapt_continuity_reference.enrollment_client import EnrollmentClient
from qperiapt_continuity_reference.wire import require
from root_retirement_fixture import control,field
from root_successor_peer_fixture import exercise as communicate


def exercise(owner,registry,previous,next_plan,predecessor,inputs,*,bridge,now,target,refuse,old_context):
    material=inputs.materials
    request=control(previous)+field(predecessor)+b''.join(field(p) for p in (
        material.manifest,material.classical_proof,material.pq_proof))
    require(len(request)+1<=32768,'unactivated predecessor control bound')
    native=bridge.native;public=native.cases.parent/'public'
    require(not (public/'root-successor').exists(),'unactivated predecessor already selected')
    bridge.call('unactivated-lineage-truncated',60,request[:-1],status=2)
    bad=bytearray(predecessor);bad[-1]^=1
    bridge.call('unactivated-lineage-uncommitted',60,control(previous)+field(bytes(bad))+b''.join(field(p) for p in (
        material.manifest,material.classical_proof,material.pq_proof)),status=2)
    require(not (public/'root-successor').exists(),'rejected lineage retained metadata')
    bridge.call('unactivated-lineage-retained',60,request,previous.successor.account)
    bridge.call('unactivated-lineage-exact-retry',60,request,previous.successor.account)
    bridge.call('unactivated-lineage-is-not-peer-authority',52,request,status=2,
                expected=b'unactivated predecessor is metadata only')
    require((public/'root-successor/unactivated').read_bytes()==b'QPERIAPT-UNACTIVATED-PREDECESSOR/1',
            'unactivated lineage marker missing')
    original=(native.cases/'complete.output').read_bytes();require(original[:1]==b'\1' and len(original)==33,
                                                                  'original root session receipt absent')
    wire=(native.cases/'receive.input').read_bytes();size=int.from_bytes(wire[:2],'big')
    require(size==len(b'client') and wire[2:2+size]==b'client','original root ciphertext frame differs')
    previous_traffic={'context':old_context.digest.hex(),'session':original[1:].hex(),
                      'first_ad':wire[2:2+size].hex(),'first_ciphertext':wire[2+size:].hex()}
    host=(target/'host-key-and-id').read_bytes()
    result=communicate(EnrollmentClient.open(target/'client',host[32:],host[:32],account_authority=registry),
        owner,registry,next_plan,bridge=bridge,now=now,path=target/'client',host=host,mode='peer',refuse=refuse,
        previous_traffic=previous_traffic)
    result['skipped_unactivated_root']=previous.successor.account.hex()
    result['rejected_ciphertext_root_revision']=1
    result['predecessor_native_peer_executed']=False
    return result
