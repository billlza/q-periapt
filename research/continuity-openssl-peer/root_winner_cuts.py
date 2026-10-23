"""Actual process cuts through original loss, winner adoption and local selection."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
import json
import os
from pathlib import Path
import signal
import sys
from bounded_process import capture_output
from worker_process import command
from root_retirement_cuts import JOURNAL,FENCE
from root_successor_cuts import implementation_receipt
from qperiapt_continuity_reference.account_authority import AccountAuthority
from qperiapt_continuity_reference.client_root_recovery import RootRecovery
from qperiapt_continuity_reference.wire import require

CUTS=tuple((phase,stage) for phase,stages in (
    ('close',JOURNAL),('adoption',JOURNAL),('parent',FENCE),('child',FENCE),('selection',JOURNAL)) for stage in stages)


def exercise(owner,registry,adoption,*,cut,private,target,now):
    require(cut in CUTS,'committed adoption cut boundary')
    family,pin=registry.family,registry.witness
    keys={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in (
        private/'host-key-and-id',private/'registry-key-and-id',private/'root-target/host-key-and-id',
        target/'host-key-and-id')}
    config=private/'winner-inputs.json';marker=private/'winner-cut.json'
    value={'private':str(private),'family':family.hex(),'witness':pin.identity.hex(),'witness_key':pin.key.raw.hex(),
           'previous_root':adoption.original.previous_root.raw.hex(),'winner_approval':str(target/'approved-public.json'),
           'noncommit':adoption.noncommit.hex(),'retirement':adoption.retirement.hex(),
           'freeze':adoption.winner.freeze_receipt.hex(),'now':now}
    for label,plan in (('original',adoption.original),('winner',adoption.winner.plan)):
        value[label+'_operation']=plan.operation.hex();value[label+'_freeze_operation']=plan.freeze_operation.hex()
        value[label+'_plan']=plan.wire().hex()
    with os.fdopen(os.open(config,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w') as out:
        json.dump(value,out);out.flush();os.fsync(out.fileno())
    owner.close();registry.close()
    implementation=implementation_receipt()
    provider=Path(sys.modules['cryptography'].__file__).resolve().parent.parent
    argv=command(Path(__file__).with_name('root_winner_worker.py'),'--implementation-root',implementation['root'],
                 '--provider-root',str(provider),'--configuration',str(config),'--marker',str(marker),
                 '--phase',cut[0],'--cut',cut[1])
    result=capture_output(argv,timeout_seconds=45,maximum_stdout_bytes=16384,maximum_stderr_bytes=16384)
    (private/'winner-cut.stdout').write_bytes(result.stdout);(private/'winner-cut.stderr').write_bytes(result.stderr)
    require(result.returncode==-signal.SIGKILL and not result.stderr,'adoption worker did not reach SIGKILL boundary')
    row=json.loads(marker.read_bytes())
    require(row==json.loads(result.stdout) and (row['phase'],row['stage'])==cut
            and row['implementation']==implementation and row['pid']!=os.getpid(),'adoption worker marker differs')
    require(all(hashlib.sha256(Path(p).read_bytes()).hexdigest()==h for p,h in keys.items()),'adoption replaced original keys')
    process=row|{'returncode':result.returncode,'preserved_keys':keys}
    (private/'winner-process.json').write_text(json.dumps(process|{'argv':argv},indent=2)+'\n')
    host=(private/'host-key-and-id').read_bytes();registered=(private/'registry-key-and-id').read_bytes()
    registry=AccountAuthority.open(private/'account-registry',registered[:32],registered[32:],family,pin)
    try:
        owner=RootRecovery.resume_adoption(private/'client',host[32:],host[:32],registry,
                                           adoption.original.operation,adoption,now)
        return owner,registry,process
    except BaseException:registry.close();raise
