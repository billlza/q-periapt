"""Original successor admission, exact recovery and optional native peer traffic."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
from pathlib import Path
from qperiapt_continuity_reference.client_root_adoption import RootAdoption
from qperiapt_continuity_reference.client_root_recovery import RootRecovery
from qperiapt_continuity_reference.enrollment_client import EnrollmentClient
from qperiapt_continuity_reference.wire import require
from qperiapt_continuity_reference.witness import TcpTransport


def exercise(recovery,registry,plan,*,bridge,now,client_path,identity,key,refuse,mode,cut=None,cancellation=None,later_cut=None):
    private=client_path.parent/'root-target';host=(private/'host-key-and-id').read_bytes()
    require(len(host)==64,'original successor host identity')
    target_path=private/'client'
    def reopen():return RootRecovery.open(client_path,identity,key,registry,plan.operation)
    def target(*,bound=False,observer=None):
        return EnrollmentClient.open(target_path,host[32:],host[:32],observer=observer,
                                     account_authority=registry if bound else None)
    def transport():return TcpTransport(bridge.address)
    def files():return {str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in private.rglob('*') if p.is_file()}
    before=files();requests=len(bridge.records)
    refuse('expired-successor-does-not-activate',lambda:recovery.activate_successor(target(),401,transport=transport()),
           'expired or premature authority')
    require(files()==before and len(bridge.records)==requests,'expired successor changed target or dispatched')
    recovery=reopen()
    if mode in ('before','after'):
        bridge.arm(mode,2)
        refuse('successor-binding-unknown-'+mode,
               lambda:recovery.activate_successor(target(),now,transport=transport()),'truncated witness reply')
        recovery=reopen()
        original=RootAdoption.open(target_path,host[32:],host[:32],registry)
    elif mode in ('parent','ready'):
        prefix='client-device:registration-store:' if mode=='parent' else 'client-config:'
        seen=0
        def interrupt_parent(stage):
            nonlocal seen
            if stage==prefix+'committed:removal':
                seen+=1
                # Configuration's first transition starts adoption; the second marks ready.
                if mode=='parent' or seen==2:raise OSError('successor parent publication interrupted')
        refuse('successor-binding-parent-'+mode,
               lambda:recovery.activate_successor(target(observer=interrupt_parent),now,transport=transport()),
               'successor parent publication interrupted')
        recovery=reopen();original=RootAdoption.open(target_path,host[32:],host[:32],registry)
    else:original=target()
    client=None
    try:
        cut_record=None;cancel_record=None
        if cut is not None:
            from root_successor_cuts import exercise as process_cut, preserved_orphans
            original.close()
            recovery,registry,cut_record=process_cut(recovery,registry,plan,cut=cut,private=client_path.parent,
                identity=identity,key=key,now=now,address=bridge.address)
            original=(target() if cut==('configuration','stage-synced:intent')
                      else RootAdoption.open(target_path,host[32:],host[:32],registry))
        elif cancellation is not None:
            from root_successor_cancel import exercise as cancel_original
            original.close()
            recovery,registry,cancel_record=cancel_original(recovery,registry,plan,case=cancellation,
                bridge=bridge,now=now,private=client_path.parent,identity=identity,key=key)
            original=RootAdoption.open(target_path,host[32:],host[:32],registry)
        client=recovery.activate_successor(original,now,transport=transport())
        if cancel_record is not None:
            recovery.close()  # A successfully returned client now has its own lifetime.
            require(client.status()['journal']==plan.journal,'returned successor still depends on recovery owner')
            recovery=reopen()
        status=client.status();require(status['journal']==plan.journal,'successor activation changed journal identity')
        with client.session(now,transport=transport()) as session:
            require(session.status()=='Waiting','successor emitted or accepted bootstrap unexpectedly')
        bound=files();client.close();client=None
        client=recovery.activate_successor(target(bound=True),now,transport=transport())
        require(files()==bound,'exact successor activation retry rewrote target files')
        require(client.status()['journal']==plan.journal,'successor retry changed original journal')
        peer=None
        if mode.startswith('peer'):
            from root_successor_peer_fixture import exercise as communicate
            owned,client=client,None
            peer=communicate(owned,recovery,registry,plan,bridge=bridge,now=now,path=target_path,
                             host=host,mode=mode,refuse=refuse)
        if mode in ('peer-root-revocation','peer-root-replacement'):
            from root_successor_authority_fixture import exercise as suspend_successor
            recovery,registry,peer['later_root_preparation']=suspend_successor(
                recovery,registry,plan,bridge=bridge,now=now,client_path=client_path,
                identity=identity,key=key,session=bytes.fromhex(peer['session']),refuse=refuse,
                commit=mode=='peer-root-replacement',cut=later_cut)
        if cut_record is not None:
            require(preserved_orphans(client_path.parent)==cut_record['orphans'],
                    'successor recovery or traffic changed retained orphan files')
            require(all(hashlib.sha256(Path(path).read_bytes()).hexdigest()==expected
                        for path,expected in cut_record['preserved_keys'].items()),'successor recovery replaced original keys')
        return recovery,registry,{'completed':True,'mode':mode,'original_genesis_checked':True,'registry_revision':2,
                         'target_journal':plan.journal.hex(),'target_files_unchanged_on_retry':True,
                         'peer':peer,'process_cut':cut_record,'cancellation':cancel_record,
                         'returned_client_independence_checked':cancel_record is not None,
                         'scope':('Actual successor admission and independent/native peer exchange; see peer for transport and recovery scope.'
                                  if peer is not None else 'Actual current witness admission and original child/parent/config binding; no independent successor peer handshake or traffic yet.')}
    except BaseException:
        recovery.close();registry.close();raise
    finally:
        if client is not None:client.close()
