"""First original successor admission and exact binding recovery; no peer flight."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
from qperiapt_continuity_reference.client_root_adoption import RootAdoption
from qperiapt_continuity_reference.client_root_recovery import RootRecovery
from qperiapt_continuity_reference.enrollment_client import EnrollmentClient
from qperiapt_continuity_reference.wire import require
from qperiapt_continuity_reference.witness import TcpTransport


def exercise(recovery,registry,plan,*,bridge,now,client_path,identity,key,refuse,mode):
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
        def cut(stage):
            nonlocal seen
            if stage==prefix+'committed:removal':
                seen+=1
                # Configuration's first transition starts adoption; the second marks ready.
                if mode=='parent' or seen==2:raise OSError('successor parent publication interrupted')
        refuse('successor-binding-parent-'+mode,
               lambda:recovery.activate_successor(target(observer=cut),now,transport=transport()),
               'successor parent publication interrupted')
        recovery=reopen();original=RootAdoption.open(target_path,host[32:],host[:32],registry)
    else:original=target()
    client=None
    try:
        client=recovery.activate_successor(original,now,transport=transport())
        status=client.status();require(status['journal']==plan.journal,'successor activation changed journal identity')
        with client.session(now,transport=transport()) as session:
            require(session.status()=='Waiting','successor emitted or accepted bootstrap unexpectedly')
        bound=files();client.close();client=None
        client=recovery.activate_successor(target(bound=True),now,transport=transport())
        require(files()==bound,'exact successor activation retry rewrote target files')
        require(client.status()['journal']==plan.journal,'successor retry changed original journal')
        return recovery,{'completed':True,'mode':mode,'original_genesis_checked':True,'registry_revision':2,
                         'target_journal':plan.journal.hex(),'target_files_unchanged_on_retry':True,
                         'scope':'Actual current witness admission and original child/parent/config binding; no independent successor peer handshake or traffic yet.'}
    finally:
        if client is not None:client.close()
