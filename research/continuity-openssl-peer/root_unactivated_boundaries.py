"""Original registry/configuration process cuts and consuming-owner cancellation."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import gc,hashlib,json,os,signal,sys,weakref
from pathlib import Path
from bounded_process import capture_output
from worker_process import command
from root_retirement_cuts import JOURNAL
from root_successor_cuts import implementation_receipt
from qperiapt_continuity_reference.account_authority import AccountAuthority
from qperiapt_continuity_reference.client_root_recovery import RootRecovery
from qperiapt_continuity_reference.wire import require

CUTS=tuple((phase,stage) for phase in ('prepare','association') for stage in JOURNAL)
CANCELLATIONS=tuple((action,phase) for action in ('owner','registry') for phase in ('prepare','association'))


def registry_lifetime(owner,registry,original,plan,*,private,target,now):
    """Dropping the borrowed registry must revoke the returned metadata owner."""
    family,pin=registry.family,registry.witness;host=(private/'host-key-and-id').read_bytes()
    registered=(private/'registry-key-and-id').read_bytes();target_host=(target/'host-key-and-id').read_bytes()
    def files():return {str(p):hashlib.sha256(p.read_bytes()).hexdigest()
                       for p in private.rglob('*') if p.is_file()}
    before=files();events=[];owner.close();registry.close()
    def no_write(stage):
        events.append(stage);raise ValueError('settled registry lifetime probe attempted publication: '+stage)
    def open_registry():return AccountAuthority.open(private/'account-registry',registered[:32],registered[32:],family,pin)
    def borrow():
        current=open_registry()
        try:
            returned=RootRecovery.resume_successor_retirement(private/'client',host[32:],host[:32],current,
                original,target/'client',target_host[32:],target_host[:32],plan,now,observer=no_write)
            return returned,weakref.ref(current)
        except BaseException:current.close();raise
    returned,reference=borrow()
    try:
        gc.collect()
        require(reference() is None,'returned metadata owner retained borrowed registry')
        try:returned.status()
        except ValueError as error:require('closed account authority' in str(error),'registry drop produced unrelated refusal')
        else:raise ValueError('returned metadata owner survived registry drop')
    finally:
        returned.close()
        retained=reference()
        if retained is not None:retained.close()
    require(not events and files()==before,'registry lifetime check changed original files')
    return open_registry(),{'registry_collected':True,'returned_owner_revoked':True,
                            'original_files_unchanged':True,'publication_callbacks':events}


def exercise(owner,registry,original,plan,*,private,target,now,case):
    require(case[0] in ('cut','cancel'),'unactivated retirement boundary kind')
    family,pin=registry.family,registry.witness;host=(private/'host-key-and-id').read_bytes()
    registered=(private/'registry-key-and-id').read_bytes();target_host=(target/'host-key-and-id').read_bytes()
    def resume(current):return RootRecovery.resume_successor_retirement(private/'client',host[32:],host[:32],current,
        original,target/'client',target_host[32:],target_host[:32],plan,now)
    if case[0]=='cut':
        require(case[1:] in CUTS,'unactivated retirement cut')
        config=private/'unactivated-cut-inputs.json';marker=private/'unactivated-cut.json'
        value={'private':str(private),'target':str(target),'family':family.hex(),'witness':pin.identity.hex(),
               'witness_key':pin.key.raw.hex(),'original_operation':original.hex(),'previous_root':plan.previous_root.raw.hex(),
               'operation':plan.operation.hex(),'freeze_operation':plan.freeze_operation.hex(),'plan':plan.wire().hex(),'now':now}
        with os.fdopen(os.open(config,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w') as out:
            json.dump(value,out);out.flush();os.fsync(out.fileno())
        keys={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in (
            private/'host-key-and-id',private/'registry-key-and-id',target/'host-key-and-id',target/'issuer',
            private/'unactivated-following/root-target/host-key-and-id',private/'unactivated-following/root-target/issuer')}
        owner.close();registry.close();implementation=implementation_receipt()
        provider=Path(sys.modules['cryptography'].__file__).resolve().parent.parent
        argv=command(Path(__file__).with_name('root_unactivated_worker.py'),'--implementation-root',implementation['root'],
            '--provider-root',str(provider),'--configuration',str(config),'--marker',str(marker),'--phase',case[1],'--cut',case[2])
        process=capture_output(argv,timeout_seconds=45,maximum_stdout_bytes=16384,maximum_stderr_bytes=16384)
        (private/'unactivated-cut.stdout').write_bytes(process.stdout);(private/'unactivated-cut.stderr').write_bytes(process.stderr)
        require(process.returncode==-signal.SIGKILL and not process.stderr,'unactivated retirement worker did not reach cut')
        row=json.loads(marker.read_bytes())
        require(row==json.loads(process.stdout) and (row['phase'],row['stage'])==case[1:]
                and row['implementation']==implementation and row['pid']!=os.getpid(),'unactivated cut marker differs')
        require(all(hashlib.sha256(Path(p).read_bytes()).hexdigest()==d for p,d in keys.items()),'unactivated retirement replaced keys')
        orphans={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in private.rglob('.stage-*')
                 if p.is_file() and p.name!='.stage-head'}
        report=row|{'returncode':process.returncode,'preserved_keys':keys,'preserved_orphans':orphans}
    else:
        require(case[1:] in CANCELLATIONS,'unactivated retirement cancellation')
        action,phase=case[1:];stopped=None;events=[];nested=None
        def files():return {str(p):hashlib.sha256(p.read_bytes()).hexdigest()
                           for directory in (private/'client',private/'session',private/'account-registry',target)
                           for p in directory.rglob('*') if p.is_file()}
        def begin(observer):return owner.retire_unactivated_successor(target/'client',target_host[32:],target_host[:32],plan,now,observer=observer)
        def stop(stage):
            nonlocal stopped,nested
            if stopped is not None:events.append(stage);return
            prefix='registry:' if phase=='prepare' else 'successor-retirement:'
            if stage!=prefix+'committed:intent':return
            before=files()
            try:begin(None)
            except ValueError as error:nested=str(error)
            else:raise ValueError('nested unactivated retirement admitted')
            require(nested=='local renewal operation already in progress' and before==files(),'nested retirement mutated state')
            (owner if action=='owner' else registry).close();stopped=files()
        previous=registry._journal._directory.observer
        def registry_event(stage):
            if previous is not None:previous(stage)
            stop('registry:'+stage)
        registry._journal._directory.observer=registry_event
        result=None;error=None
        try:result=begin(stop)
        except (ValueError,OSError) as failure:error={'type':type(failure).__name__,'message':str(failure)}
        finally:
            if result is not None:result.close()
        require(stopped is not None,'unactivated cancellation boundary not reached')
        after=files();changed=[p for p in after.keys()|stopped.keys() if after.get(p)!=stopped.get(p)]
        report={'action':action,'phase':phase,'returned_owner':result is not None,'failure':error,
                'events_after_close':events,'changed_after_close':changed,'nested_refusal':nested,
                'captured':stopped,'after':after,'implementation':implementation_receipt()}
        (private/'unactivated-cancel.json').write_text(json.dumps(report,indent=2)+'\n')
        require(result is None and error is not None and 'closed' in error['message'],'unactivated cancellation released an owner')
        require(not changed and not events,'unactivated retirement continued after cancellation')
        owner.close();registry.close();orphans=None
    registry=AccountAuthority.open(private/'account-registry',registered[:32],registered[32:],family,pin)
    try:
        returned=resume(registry);owner.close();returned.status()
        if orphans is not None:
            require(all(hashlib.sha256(Path(p).read_bytes()).hexdigest()==d for p,d in orphans.items()),
                    'unactivated retirement discarded original orphan')
        report['returned_owner_independent']=True
        (private/'unactivated-boundary.json').write_text(json.dumps(report,indent=2)+'\n')
        return returned,registry,report
    except BaseException:registry.close();raise
