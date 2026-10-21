"""Public native root statements with separately retained fixture trust."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
import json

from qperiapt_continuity_reference.account_root_protocol import Plan
from qperiapt_continuity_reference.authority import authenticate_historical_policy,verify_sdk
from qperiapt_continuity_reference.enrollment_exchange import PolicyInputs,encoded
from qperiapt_continuity_reference.identity import DevicePin
from qperiapt_continuity_reference.wire import VerificationKey,require
from qperiapt_continuity_reference.witness import Pin


def wire(value):return json.dumps(value,separators=(',',':')).encode()
def bytes_field(value):return encoded(value,128*1024)


class RootFixture:
    def __init__(self,source):self.source=source.resolve(strict=True);self.inputs={}

    def public(self,name):
        raw=(self.source/name).read_bytes();require(len(raw)<=1024**2,'public root fixture bound')
        self.inputs[name]=hashlib.sha256(raw).hexdigest();return json.loads(raw)

    def pin(self,trust):
        account=trust['account'];listing=account['roster']['checkpoint']
        return DevicePin(VerificationKey(bytes_field(account['public_key'])),bytes(account['account']),
                         listing['version'],bytes(listing['digest']),bytes(trust['device']),trust['generation'])

    def selected(self,profile,new=False):
        prefix=profile+'/'
        trust=self.public(prefix+('new-root-trust.json' if new else 'root-trust.json'))
        request=self.public(prefix+('new-root-request.json' if new else 'root-request.json'))
        target=trust['successor'];account=target['account']
        policy=PolicyInputs.from_trusted(wire(target['policy']['pins']),wire(target['policy']['materials']))
        sdk=verify_sdk(policy.pins,policy.materials)
        history=authenticate_historical_policy(policy.pins,policy.materials.policy,witness_pin=policy.witness)
        require(history.sdk==sdk,'original root policy SDK binding')
        stored=self.public(prefix+'fixture.json')['witness_pin']
        witness=Pin(bytes(stored['identity']),VerificationKey(bytes_field(stored['key'])))
        require(policy.witness==witness,'independently retained witness differs')
        plan=Plan(witness,bytes(trust['operation']),bytes(trust['freeze_operation']),VerificationKey(bytes_field(trust['previous_root'])),
                  self.pin(target),bytes_field(target['certificate']),bytes_field(account['roster']['bytes']),history,
                  bytes(target['journal']),bytes(target['genesis_head']))
        require(request['preparation']=='RequiresWitnessEnrollment' and bytes(request['head'])==plan.genesis
                and bytes(request['subject'])==plan._parts()[2],'independently selected prepared target differs')
        return plan

    def check_plan(self,profile,plan,name='plan/account-root-plan.json'):
        value=self.public(profile+'/'+name)
        require(value['schema']=='qperiapt-witness-account-root-plan/1','plan wrapper schema')
        plan.verify_plan(bytes_field(value['plan']))
        require(plan.binding==bytes(value['binding']),'independent plan commitment differs')

    def bound(self,profile,plan,freeze='freeze-retry/account-root-freeze.json',decision='bind/account-root-decision.json'):
        frozen=self.public(profile+'/'+freeze)
        require(bytes(frozen['plan_binding'])==plan.binding,'original freeze plan binding')
        proof=bytes_field(frozen['receipt']);result=plan.bind(proof)
        require(plan._frozen(proof)[1]==bytes(frozen['freeze_binding']),'independent freeze commitment differs')
        record=self.public(profile+'/'+decision)
        require(record['schema']=='qperiapt-witness-account-root-decision/1' and bytes(record['plan_binding'])==plan.binding,'decision original plan wrapper')
        result.verify_decision(bytes_field(record['proposal']))
        require(result.binding==bytes(record['binding']),'independent decision commitment differs')
        return result
