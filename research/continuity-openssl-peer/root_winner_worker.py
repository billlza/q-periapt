#!/usr/bin/env python3
"""Restore exact independent approvals and kill this owner at a selected write."""
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
    from qperiapt_continuity_reference.account_root_protocol import Plan,CommittedAdoption
    from qperiapt_continuity_reference.authority import authenticate_historical_policy
    from qperiapt_continuity_reference.client_root_recovery import RootRecovery
    from qperiapt_continuity_reference.enrollment_exchange import PolicyInputs,encoded
    from qperiapt_continuity_reference.identity import DevicePin
    from qperiapt_continuity_reference.private_files import private_regular
    from qperiapt_continuity_reference.wire import VerificationKey,require
    from qperiapt_continuity_reference.witness import Pin
    from evidence_io import parse_strict_json_bytes,read_regular_snapshot
    sys.path.append(str(Path(__file__).resolve().parent))
    from root_winner_cuts import CUTS
    from root_successor_cuts import implementation_receipt
    require((args.phase,args.cut) in CUTS,'adoption worker cut')
    def private(path,maximum):
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            private_regular(os.fstat(fd))
            with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(maximum+1)
            require(len(raw)<=maximum,'adoption private input capacity');return raw
        finally:os.close(fd)
    config=parse_strict_json_bytes(private(args.configuration,262144),label='original adoption approvals')
    root=Path(config['private']);host=private(root/'host-key-and-id',64);registered=private(root/'registry-key-and-id',64)
    require(len(host)==len(registered)==64,'original adoption key/id size')
    pin=Pin(bytes.fromhex(config['witness']),VerificationKey(bytes.fromhex(config['witness_key'])))
    def approved(label,path):
        raw=read_regular_snapshot(path,maximum=262144,label='original test-host target').data
        value=parse_strict_json_bytes(raw,label='independent target approval')
        wire=lambda x:json.dumps(x,separators=(',',':')).encode()
        policy=PolicyInputs.from_trusted(wire(value['policy_pins']),wire(value['policy_materials']))
        require(policy.witness==pin,'adoption witness differs')
        history=authenticate_historical_policy(policy.pins,policy.materials.policy,witness_pin=pin)
        selected,invite,issued=value['current'],value['invitation'],value['issued'];head=selected['roster']['checkpoint']
        target=DevicePin(VerificationKey(encoded(selected['public_key'],1985)),bytes(selected['account']),
                        head['version'],bytes(head['digest']),bytes(invite['device']),invite['generation'])
        genesis=bytes.fromhex(value['genesis'])
        plan=Plan(pin,bytes.fromhex(config[label+'_operation']),bytes.fromhex(config[label+'_freeze_operation']),
                  VerificationKey(bytes.fromhex(config['previous_root'])),target,encoded(issued['certificate'],8192),
                  encoded(issued['roster'],8192),history,genesis[:32],genesis[-32:])
        require(plan.wire().hex()==config[label+'_plan'],'approved adoption target changed')
        if label=='original':require(plan.wire().hex()==value['plan'],'original losing plan changed')
        return plan
    target=Path(config['winner_approval'])
    require(target in (root/'root-target/approved-public.json',root/'winner/root-target/approved-public.json'),
            'winner target is not the original approved test installation')
    original=approved('original',root/'root-target/approved-public.json');winner=approved('winner',target)
    adoption=CommittedAdoption(original,winner.bind(bytes.fromhex(config['freeze'])),
                              bytes.fromhex(config['noncommit']),bytes.fromhex(config['retirement']))
    adoption.verify()
    occurrences={'close':1,'adoption':2,'selection':3};count=0
    prefix='registry:' if args.phase in occurrences else ('client-device:registration-store:' if args.phase=='parent' else 'root-child:')
    def stop(stage):
        nonlocal count
        if stage!=prefix+args.cut:return
        count+=1
        if count!=occurrences.get(args.phase,1):return
        marker={'pid':os.getpid(),'phase':args.phase,'stage':args.cut,'occurrence':count,'implementation':implementation_receipt()}
        with os.fdopen(os.open(args.marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w') as stream:
            json.dump(marker,stream);stream.flush();os.fsync(stream.fileno())
        print(json.dumps(marker),flush=True);os.kill(os.getpid(),signal.SIGKILL)
        raise RuntimeError('killed adoption worker resumed')
    with AccountAuthority.open(root/'account-registry',registered[:32],registered[32:],bytes.fromhex(config['family']),pin,
                               observer=lambda stage:stop('registry:'+stage)) as registry:
        with RootRecovery.resume_adoption(root/'client',host[32:],host[:32],registry,original.operation,
                                           adoption,config['now'],observer=stop):
            raise RuntimeError('adoption worker completed without the selected cut')


if __name__=='__main__':main()
