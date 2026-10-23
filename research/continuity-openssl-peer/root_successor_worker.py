#!/usr/bin/env python3
"""Execute original successor activation until the selected actual SIGKILL cut."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import argparse
import json
import os
from pathlib import Path
import signal
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('implementation-root', 'provider-root', 'configuration', 'marker'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--phase', required=True); parser.add_argument('--cut', required=True)
    args = parser.parse_args(); sys.path.insert(0, str(args.implementation_root.resolve(strict=True)))
    from qperiapt_continuity_reference.provider import load_provider
    load_provider(args.provider_root)
    from qperiapt_continuity_reference.account_authority import AccountAuthority
    from qperiapt_continuity_reference.client_root_recovery import RootRecovery
    from qperiapt_continuity_reference.enrollment_client import EnrollmentClient
    from qperiapt_continuity_reference.private_files import private_regular
    from qperiapt_continuity_reference.wire import VerificationKey, require
    from qperiapt_continuity_reference.witness import Pin, TcpTransport
    from evidence_io import parse_strict_json_bytes
    sys.path.append(str(Path(__file__).resolve().parent))
    from root_successor_cuts import CUTS, PHASES, implementation_receipt

    def private(path, maximum):
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            private_regular(os.fstat(fd))
            with os.fdopen(fd, 'rb', closefd=False) as stream: raw = stream.read(maximum + 1)
            require(len(raw) <= maximum, 'successor worker input capacity'); return raw
        finally: os.close(fd)

    require((args.phase, args.cut) in CUTS, 'successor worker cut boundary')
    config = parse_strict_json_bytes(private(args.configuration, 16384), label='successor cut inputs')
    root = Path(config['private']); host = private(root / 'host-key-and-id', 64)
    registered = private(root / 'registry-key-and-id', 64)
    target_host = private(root / 'root-target/host-key-and-id', 64)
    require(len(host) == len(registered) == len(target_host) == 64, 'original successor worker key/id shape')
    pin = Pin(bytes.fromhex(config['witness']), VerificationKey(bytes.fromhex(config['witness_key'])))
    prefix, occurrence = PHASES[args.phase]; observed = 0

    def stop(stage):
        nonlocal observed
        if stage != prefix + args.cut: return
        observed += 1
        if observed != occurrence: return
        marker = {'pid': os.getpid(), 'phase': args.phase, 'stage': args.cut, 'occurrence': observed,
                  'implementation': implementation_receipt()}
        with os.fdopen(os.open(args.marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as stream:
            json.dump(marker, stream); stream.flush(); os.fsync(stream.fileno())
        print(json.dumps(marker), flush=True); os.kill(os.getpid(), signal.SIGKILL)
        raise RuntimeError('killed successor worker unexpectedly resumed')

    registry = AccountAuthority.open(root / 'account-registry', registered[:32], registered[32:],
                                     bytes.fromhex(config['family']), pin)
    try:
        with RootRecovery.open(root / 'client', host[32:], host[:32], registry,
                               bytes.fromhex(config['operation'])) as owner:
            target = EnrollmentClient.open(root / 'root-target/client', target_host[32:], target_host[:32], observer=stop)
            with owner.activate_successor(target, config['now'], transport=TcpTransport(tuple(config['address']))):
                raise RuntimeError('successor worker completed without reaching selected cut')
    finally: registry.close()


if __name__ == '__main__': main()
