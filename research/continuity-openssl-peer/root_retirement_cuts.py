"""Fresh-process cuts; no fork while the real native witness bridge is running."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import json
import os
from pathlib import Path
import signal
import sys
from bounded_process import capture_output
from qperiapt_continuity_reference.account_authority import AccountAuthority
from qperiapt_continuity_reference.client_root_recovery import RootRecovery
from qperiapt_continuity_reference.wire import require
from worker_process import command

JOURNAL=('stage-synced:intent','published:intent','committed:intent','stage-synced:head',
         'published:head','committed:head','removed:intent','committed:removal')
FENCE=('stage-synced:root-fence','published:root-fence','committed:root-fence')
CUTS=tuple((action,prefix+stage) for action in ('bind','retire')
           for prefix,stages in (('registry:',JOURNAL),('root-child:',FENCE),('client-device:registration-store:',FENCE))
           for stage in stages)


def exercise(owner,registry,plan,receipt,*,cut,private,identity,key,now):
    action,stage=cut;require(cut in CUTS,'root cut boundary')
    family,pin=registry.family,registry.witness
    config=private/'root-cut-inputs.json';receipt_path=private/'root-cut-receipt.bin';marker=private/'root-cut.json'
    value={'private':str(private),'family':family.hex(),'witness':pin.identity.hex(),'witness_key':pin.key.raw.hex(),
           'operation':plan.operation.hex(),'now':now}
    for path,raw in ((config,json.dumps(value).encode()),(receipt_path,receipt)):
        with os.fdopen(os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb') as out:
            out.write(raw);out.flush();os.fsync(out.fileno())
    owner.close();registry.close()
    implementation=Path(sys.modules['qperiapt_continuity_reference'].__file__).resolve().parent.parent
    provider=Path(sys.modules['cryptography'].__file__).resolve().parent.parent
    argv=command(Path(__file__).with_name('root_retirement_worker.py'),'--implementation-root',str(implementation),
                 '--provider-root',str(provider),'--configuration',str(config),'--receipt',str(receipt_path),
                 '--marker',str(marker),'--action',action,'--cut',stage)
    result=capture_output(argv,timeout_seconds=30,maximum_stdout_bytes=16384,maximum_stderr_bytes=16384)
    (private/'root-cut.stdout').write_bytes(result.stdout);(private/'root-cut.stderr').write_bytes(result.stderr)
    require(result.returncode==-signal.SIGKILL and not result.stderr,'root worker did not reach exact SIGKILL boundary')
    row=json.loads(marker.read_bytes())
    require(row==json.loads(result.stdout) and row['action']==action and row['stage']==stage
            and type(row['pid']) is int and row['pid']>0,'root cut marker differs')
    with (private/'root-cut-process.json').open('x') as out:
        json.dump({'argv':argv,'returncode':result.returncode,'marker':row},out,indent=2);out.write('\n')
    original=(private/'registry-key-and-id').read_bytes();require(len(original)==64,'original registry key/id changed')
    registry=AccountAuthority.open(private/'account-registry',original[:32],original[32:],family,pin)
    try:
        owner=RootRecovery.open(private/'client',identity,key,registry,plan.operation)
        return owner,registry,row
    except BaseException:registry.close();raise
