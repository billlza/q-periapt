#!/usr/bin/env python3
"""Reconstruct the exact host approval and SIGKILL at one original publication."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import argparse,json,os,signal,sys
from pathlib import Path


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('implementation-root','provider-root','configuration','marker'):parser.add_argument('--'+name,type=Path,required=True)
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
    from evidence_io import parse_strict_json_bytes,read_regular_snapshot
    sys.path.append(str(Path(__file__).resolve().parent))
    from root_unactivated_boundaries import CUTS
    from root_successor_cuts import implementation_receipt
    require((args.phase,args.cut) in CUTS,'unactivated worker boundary')
    def private(path,maximum):
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            private_regular(os.fstat(fd))
            with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(maximum+1)
            require(len(raw)<=maximum,'unactivated input capacity');return raw
        finally:os.close(fd)
    config=parse_strict_json_bytes(private(args.configuration,262144),label='unactivated original approval')
    root=Path(config['private']);target=Path(config['target'])
    require(target==root/'root-target','unactivated worker original target path')
    host=private(root/'host-key-and-id',64);registered=private(root/'registry-key-and-id',64);target_host=private(target/'host-key-and-id',64)
    require(len(host)==len(registered)==len(target_host)==64,'unactivated original key/id shape')
    pin=Pin(bytes.fromhex(config['witness']),VerificationKey(bytes.fromhex(config['witness_key'])))
    raw=read_regular_snapshot(root/'unactivated-following/root-target/approved-public.json',maximum=262144,label='next approved target').data
    value=parse_strict_json_bytes(raw,label='next independent root approval');wire=lambda x:json.dumps(x,separators=(',',':')).encode()
    policy=PolicyInputs.from_trusted(wire(value['policy_pins']),wire(value['policy_materials']))
    require(policy.witness==pin,'unactivated worker witness changed')
    history=authenticate_historical_policy(policy.pins,policy.materials.policy,witness_pin=pin)
    selected,invite,issued=value['current'],value['invitation'],value['issued'];head=selected['roster']['checkpoint']
    device=DevicePin(VerificationKey(encoded(selected['public_key'],1985)),bytes(selected['account']),
                    head['version'],bytes(head['digest']),bytes(invite['device']),invite['generation'])
    genesis=bytes.fromhex(value['genesis'])
    plan=Plan(pin,bytes.fromhex(config['operation']),bytes.fromhex(config['freeze_operation']),
        VerificationKey(bytes.fromhex(config['previous_root'])),device,encoded(issued['certificate'],8192),
        encoded(issued['roster'],8192),history,genesis[:32],genesis[-32:])
    require(plan.wire().hex()==config['plan']==value['plan'],'unactivated next approval changed')
    def stop(stage):
        prefix='registry:' if args.phase=='prepare' else 'successor-retirement:'
        if stage!=prefix+args.cut:return
        marker={'pid':os.getpid(),'phase':args.phase,'stage':args.cut,'implementation':implementation_receipt()}
        with os.fdopen(os.open(args.marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w') as out:
            json.dump(marker,out);out.flush();os.fsync(out.fileno())
        print(json.dumps(marker),flush=True);os.kill(os.getpid(),signal.SIGKILL)
        raise RuntimeError('killed retirement worker resumed')
    with AccountAuthority.open(root/'account-registry',registered[:32],registered[32:],bytes.fromhex(config['family']),pin,
                               observer=lambda stage:stop('registry:'+stage)) as registry:
        with RootRecovery.resume_successor_retirement(root/'client',host[32:],host[:32],registry,
            bytes.fromhex(config['original_operation']),target/'client',target_host[32:],target_host[:32],plan,config['now'],observer=stop):
            raise RuntimeError('retirement worker completed without selected cut')


if __name__=='__main__':main()
