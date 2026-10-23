"""Actual SIGKILL boundaries for closure, next approval and both original fences."""
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
    ('close',JOURNAL),('prepare',JOURNAL),('bind',JOURNAL),('parent',FENCE),('child',FENCE)) for stage in stages)


def exercise(owner,registry,original,plan,receipt,freeze,*,closure,cut,private,now):
    require(cut in CUTS,'root transfer cut boundary')
    family,pin=registry.family,registry.witness
    keys={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in (
        private/'host-key-and-id',private/'registry-key-and-id',private/'root-target/host-key-and-id',
        private/'replan/root-target/host-key-and-id')}
    config=private/'transition-inputs.json';marker=private/'transition-cut.json'
    value={'private':str(private),'family':family.hex(),'witness':pin.identity.hex(),'witness_key':pin.key.raw.hex(),
           'original':original.hex(),'previous_root':plan.previous_root.raw.hex(),'operation':plan.operation.hex(),
           'freeze_operation':plan.freeze_operation.hex(),'plan':plan.wire().hex(),'receipt':receipt.hex(),
           'freeze':freeze.hex(),'now':now,'closure':closure}
    with os.fdopen(os.open(config,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w') as out:
        json.dump(value,out);out.flush();os.fsync(out.fileno())
    owner.close();registry.close()
    implementation=implementation_receipt()
    provider=Path(sys.modules['cryptography'].__file__).resolve().parent.parent
    argv=command(Path(__file__).with_name('root_transition_worker.py'),'--implementation-root',implementation['root'],
                 '--provider-root',str(provider),'--configuration',str(config),'--marker',str(marker),
                 '--phase',cut[0],'--cut',cut[1])
    result=capture_output(argv,timeout_seconds=45,maximum_stdout_bytes=16384,maximum_stderr_bytes=16384)
    (private/'transition-cut.stdout').write_bytes(result.stdout);(private/'transition-cut.stderr').write_bytes(result.stderr)
    require(result.returncode==-signal.SIGKILL and not result.stderr,'root transfer worker did not reach SIGKILL boundary')
    row=json.loads(marker.read_bytes())
    require(row==json.loads(result.stdout) and (row['phase'],row['stage'])==cut
            and row['implementation']==implementation and row['pid']!=os.getpid(),'root transfer marker differs')
    require(all(hashlib.sha256(Path(p).read_bytes()).hexdigest()==h for p,h in keys.items()),'root transfer replaced keys')
    process=row|{'returncode':result.returncode,'preserved_keys':keys}
    (private/'transition-process.json').write_text(json.dumps(process|{'argv':argv},indent=2)+'\n')
    host=(private/'host-key-and-id').read_bytes();registered=(private/'registry-key-and-id').read_bytes()
    registry=AccountAuthority.open(private/'account-registry',registered[:32],registered[32:],family,pin)
    try:
        owner=RootRecovery.resume_transition(private/'client',host[32:],host[:32],registry,original,
                                              plan,receipt,freeze,now,closure=closure)
        return owner,registry,process
    except BaseException:registry.close();raise
