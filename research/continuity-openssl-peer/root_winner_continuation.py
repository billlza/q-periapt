"""Keep adopted history authoritative across another original-state root change."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
from qperiapt_continuity_reference.account_authority import AccountAuthority
from qperiapt_continuity_reference.account_authority_state import Image
from qperiapt_continuity_reference.client_root_recovery import RootRecovery
from qperiapt_continuity_reference.wire import require
from root_retirement_fixture import control,field,pair
from root_successor_authority_fixture import exercise as prepare_later


def exercise(recovery,registry,adoption,peer,*,bridge,now,client_path,identity,key,refuse):
    private=client_path.parent;winner=adoption.winner.plan
    selected=registry.current(recovery._binding.application)
    family,pin=registry.family,registry.witness
    registered=(private/'registry-key-and-id').read_bytes()
    recovery,registry,later=prepare_later(recovery,registry,winner,bridge=bridge,now=now,
        client_path=client_path,identity=identity,key=key,session=bytes.fromhex(peer['session']),
        refuse=refuse,commit=True,previous_traffic=peer)
    try:
        current=registry.current(selected.application);committed=later['commit']
        require(current.revision==3 and current.account.hex()==committed['account'],
                'continued adoption lost the third-root selection')
        def snapshot():
            directories=(client_path,private/'session',private/'account-registry',
                         private/'root-target',private/'later-root')
            require(all(p.is_dir() and not p.is_symlink() for p in directories),
                    'continued adoption original directory absent')
            return {str(p):hashlib.sha256(p.read_bytes()).hexdigest()
                    for directory in directories
                    for p in directory.rglob('*') if p.is_file()}
        before=snapshot()
        recovery=recovery.adopt_committed_winner(adoption,now)
        require(snapshot()==before and registry.current(current.application)==current,
                'replayed adopted intent changed the later selection or original state')
        historical=winner.policy.validity.end+1
        bridge.call('winner-historical-clock',33,historical.to_bytes(8,'big'),b'witness clock set')
        actual,retirement=pair(bridge.call('winner-historical-retirement',51,
                                         control(winner)+field(adoption.winner.wire())))
        adoption.winner.verify_decision(actual);adoption.winner.verify_retirement(retirement)
        require(recovery.retain_witness_retirement(retirement,now=historical)==selected
                and registry.current(current.application)==current and snapshot()==before,
                'historical adopted retirement revived a superseded root')
        refuse('adopted-historical-root-cannot-regain-permission',lambda:registry.admit(selected),
               'account authority checkpoint differs')
        recovery.close();registry.close()
        registry=AccountAuthority.open(private/'account-registry',registered[:32],registered[32:],family,pin)
        recovery=RootRecovery.resume_adoption(client_path,identity,key,registry,adoption.original.operation,
                                              adoption,historical)
        require(registry.current(current.application)==current and snapshot()==before,
                'reopened adopted history changed the later selection or original state')
        refuse('continued-winner-has-no-local-preparation',lambda:registry.operation(winner.operation),
               'adopted winner has no local preparation')
        require(registry.replacement(winner.operation)[1:]==('Committed',adoption.winner.wire())
                and registry.operation(bytes.fromhex(later['operation']))[1]=='Committed',
                'adopted and prepared root history were conflated')
        encoded=registry._image.encode(family,pin)
        require(encoded.startswith(b'QPRFAA02') and Image.read(encoded,family,pin).encode(family,pin)==encoded,
                'continued adoption history is not canonical')
        later.update(historical_adoption_preserves_later_selection=True,historical_retirement_time=historical,
                     registry_reopened_after_later_selection=True,current_registry_revision=current.revision,
                     original_adoption_revision=selected.revision,retained_history_sha256=hashlib.sha256(encoded).hexdigest(),
                     retained_files=snapshot())
        return recovery,registry,later
    except BaseException:
        recovery.close();registry.close();raise
