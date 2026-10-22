#!/usr/bin/env python3
"""One original root operation, killed at an actual durable publication boundary."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import argparse
import json
import os
from pathlib import Path
import signal
import sys


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('implementation-root','provider-root','configuration','receipt','marker'):
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--action',choices=('bind','retire'),required=True)
    parser.add_argument('--cut',required=True)
    args=parser.parse_args();sys.path.insert(0,str(args.implementation_root.resolve(strict=True)))
    from qperiapt_continuity_reference.provider import load_provider
    load_provider(args.provider_root)
    from qperiapt_continuity_reference.account_authority import AccountAuthority
    from qperiapt_continuity_reference.client_root_recovery import RootRecovery
    from qperiapt_continuity_reference.private_files import private_regular
    from qperiapt_continuity_reference.wire import VerificationKey,require
    from qperiapt_continuity_reference.witness import Pin
    from evidence_io import parse_strict_json_bytes
    def private(path,maximum):
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            private_regular(os.fstat(fd))
            with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(maximum+1)
            require(len(raw)<=maximum,'root worker input capacity');return raw
        finally:os.close(fd)
    config=parse_strict_json_bytes(private(args.configuration,16384),label='original root cut configuration')
    root=Path(config['private']);host=private(root/'host-key-and-id',64);registered=private(root/'registry-key-and-id',64)
    require(len(host)==len(registered)==64,'original root worker key/id shape')
    pin=Pin(bytes.fromhex(config['witness']),VerificationKey(bytes.fromhex(config['witness_key'])))
    def stop(stage):
        if stage!=args.cut:return
        marker={'pid':os.getpid(),'action':args.action,'stage':stage}
        with os.fdopen(os.open(args.marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w') as stream:
            json.dump(marker,stream);stream.flush();os.fsync(stream.fileno())
        print(json.dumps(marker),flush=True);os.kill(os.getpid(),signal.SIGKILL)
        raise RuntimeError('killed root worker unexpectedly resumed')
    registry=AccountAuthority.open(root/'account-registry',registered[:32],registered[32:],bytes.fromhex(config['family']),pin,
                                   observer=lambda stage:stop('registry:'+stage))
    try:
        with RootRecovery.open(root/'client',host[32:],host[:32],registry,bytes.fromhex(config['operation']),observer=stop) as owner:
            receipt=private(args.receipt,71000)
            if args.action=='bind':owner.bind_freeze(receipt,now=config['now'])
            else:owner.retain_witness_retirement(receipt,now=config['now'])
        raise RuntimeError('root worker completed without reaching selected cut')
    finally:registry.close()


if __name__=='__main__':main()
