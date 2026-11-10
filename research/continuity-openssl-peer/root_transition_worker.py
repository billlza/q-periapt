#!/usr/bin/env python3
"""Resume one original approved transfer and terminate at its exact publication."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import argparse
import json
import os
from pathlib import Path
import signal
import sys


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('implementation-root','provider-root','configuration','marker'):
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--phase',required=True);parser.add_argument('--cut',required=True)
    args=parser.parse_args();sys.path.insert(0,str(args.implementation_root.resolve(strict=True)))
    from qperiapt_continuity_reference.provider import load_provider
    load_provider(args.provider_root)
    from qperiapt_continuity_reference.account_authority import AccountAuthority
    from qperiapt_continuity_reference.account_root_protocol import Plan
    from qperiapt_continuity_reference.authority import authenticate_historical_policy
    from qperiapt_continuity_reference.client_root_recovery import RootRecovery
    from qperiapt_continuity_reference.enrollment_exchange import PolicyInputs,encoded
    from qperiapt_continuity_reference.identity import DevicePin
    from qperiapt_continuity_reference.private_files import private_regular
    from qperiapt_continuity_reference.wire import VerificationKey,require
    from qperiapt_continuity_reference.witness import Pin
    from evidence_io import parse_strict_json_bytes
    sys.path.append(str(Path(__file__).resolve().parent))
    from root_transition_cuts import CUTS
    from root_successor_cuts import implementation_receipt
    require((args.phase,args.cut) in CUTS,'root transfer worker cut')
    def private(path,maximum):
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            private_regular(os.fstat(fd))
            with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(maximum+1)
            require(len(raw)<=maximum,'root transfer private input capacity');return raw
        finally:os.close(fd)
    config=parse_strict_json_bytes(private(args.configuration,131072),label='root transfer inputs')
    root=Path(config['private']);host=private(root/'host-key-and-id',64);registered=private(root/'registry-key-and-id',64)
    require(len(host)==len(registered)==64,'original root transfer keys')
    # This is the independently approved test-host input, never an incoming plan.
    approval=parse_strict_json_bytes((root/'replan/root-target/approved-public.json').read_bytes(),label='original target approval')
    wire=lambda x:json.dumps(x,separators=(',',':')).encode()
    policy=PolicyInputs.from_trusted(wire(approval['policy_pins']),wire(approval['policy_materials']))
    history=authenticate_historical_policy(policy.pins,policy.materials.policy,witness_pin=policy.witness)
    pin=Pin(bytes.fromhex(config['witness']),VerificationKey(bytes.fromhex(config['witness_key'])))
    require(policy.witness==pin,'original root transfer witness differs')
    selected=approval['current'];invite=approval['invitation'];issued=approval['issued'];head=selected['roster']['checkpoint']
    next_pin=DevicePin(VerificationKey(encoded(selected['public_key'],1985)),bytes(selected['account']),
                       head['version'],bytes(head['digest']),bytes(invite['device']),invite['generation'])
    genesis=bytes.fromhex(approval['genesis'])
    plan=Plan(pin,bytes.fromhex(config['operation']),bytes.fromhex(config['freeze_operation']),
              VerificationKey(bytes.fromhex(config['previous_root'])),next_pin,encoded(issued['certificate'],8192),
              encoded(issued['roster'],8192),history,genesis[:32],genesis[-32:])
    require(plan.wire().hex()==config['plan']==approval['plan'],'approved transfer plan changed')
    count=0
    prefix='registry:' if args.phase in ('close','prepare','bind') else ('client-device:registration-store:' if args.phase=='parent' else 'root-child:')
    occurrence={'close':1,'prepare':2,'bind':3}.get(args.phase,1)
    def stop(stage):
        nonlocal count
        if stage!=prefix+args.cut:return
        count+=1
        if count!=occurrence:return
        marker={'pid':os.getpid(),'phase':args.phase,'stage':args.cut,'occurrence':count,'implementation':implementation_receipt()}
        with os.fdopen(os.open(args.marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w') as stream:
            json.dump(marker,stream);stream.flush();os.fsync(stream.fileno())
        print(json.dumps(marker),flush=True);os.kill(os.getpid(),signal.SIGKILL)
        raise RuntimeError('killed root transfer worker resumed')
    with AccountAuthority.open(root/'account-registry',registered[:32],registered[32:],bytes.fromhex(config['family']),pin,
                               observer=lambda stage:stop('registry:'+stage)) as registry:
        with RootRecovery.resume_transition(root/'client',host[32:],host[:32],registry,bytes.fromhex(config['original']),
              plan,bytes.fromhex(config['receipt']),bytes.fromhex(config['freeze']),config['now'],closure=config['closure'],observer=stop):
            raise RuntimeError('root transfer worker completed without the selected cut')


if __name__=='__main__':main()
