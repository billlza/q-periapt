#!/usr/bin/env python3
"""Independent joint renewal with real witness outcomes and fresh-process cuts."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile


def exercise(args, label):
    from fixture_inputs import load, load_witness_pin
    from peer.durable import owner_binding
    from peer.journal import Scope
    from peer.wire import SigningKey, require
    from run import Counterpart
    from session_driver import SessionDriver
    from signing_fixture import write
    from traffic_checks import application
    from witness_fixture import Bridge
    from local_renewal_controls import Controls
    out = args.output.resolve() / label; out.mkdir(); (out / 'native').mkdir()
    private = Path(tempfile.mkdtemp(prefix='qperiapt-joint-renewal-')).resolve()
    require(not private.is_relative_to(out), 'private state inside public capture')
    (out / 'private-fixture-path').write_text(str(private) + '\n')
    native = Counterpart(args.native.resolve(), out / 'native', required_witness=True, local_lifecycle=True)
    bridge = None; driver = None
    try:
        signer = SigningKey(); require(native.transfer(signer.public().raw) == b'\1ready', 'native readiness')
        public = out / 'native/public'; pin = load_witness_pin(public)
        _, _, context = load(public, 150, witness_pin=pin)
        scope = Scope(os.urandom(32), owner_binding(context), context.digest); key = os.urandom(32)
        config = private / 'configuration'
        with os.fdopen(os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as stream:
            stream.write(key + scope.wire()); stream.flush(); os.fsync(stream.fileno())
        signer_path = private / 'signer'; write(signer_path, signer)
        path = private / 'session'; path.mkdir(mode=0o700)
        bridge = Bridge(native, out)
        driver = SessionDriver(out, args.provider_root.resolve(), public, config, path, signer_path,
                               witness_address=bridge.address[0] + ':' + str(bridge.address[1]))
        worker = driver.run
        def value(name, action, arguments=(), **options):
            return bytes.fromhex(worker(name, action, arguments, **options))
        def clock(now):
            bridge.call('clock-' + str(now), 33, now.to_bytes(8, 'big'), b'witness clock set')
        def materials(index):
            prefix = 'local-renewal-' + str(index)
            return tuple((public / name).read_bytes() for name in
                         (prefix + '-operation', prefix, 'pin-' + prefix + '-target'))
        genesis = value('provision', 'witness_provision', now=150)
        bridge.call('enrollment', 30, genesis, b'enrolled')
        initial = value('initial', 'initial', now=150)
        reply = bridge.call('bootstrap-reply', 4, initial)
        final = value('finish', 'finish', (reply,), now=150)
        session = bridge.call('complete', 5, final)
        require(value('activate', 'activate') == session, 'session identity')
        bridge.call('native-activate', 6, expected=session)
        original_id = value('original-id', 'next_id')
        original_wire = value('original-send', 'send', (original_id, b'original retained message', b'local'))
        first = materials(1); op = (first[0],)
        controls = Controls(path, scope, key, context, signer, pin, bridge.address)
        controls.grants(first)
        def report(outcome, proposal):
            result = {'outcome': outcome, 'worker_operations': driver.operations, 'native_commands': native.commands,
                      'witness_attempts': bridge.records, 'refusals': controls.results,
                      'process_kills': sum(row.get('signal') == 'SIGKILL' for row in driver.operations),
                      'original_id': original_id.hex(), 'original_ciphertext_sha256': hashlib.sha256(original_wire).hexdigest(),
                      'first_proposal_sha256': hashlib.sha256(proposal).hexdigest() if proposal is not None else None,
                      'scope': 'Actual required witness; independent owner process cuts and same retained private state. Native traffic counterpart clock remains 170. Test clock advancement is not physical clock or full native device renewal.'}
            (out / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')
            return {k: result[k] for k in ('outcome', 'process_kills', 'scope')}
        if label == 'pending-write':
            pending_id = value('pending-send-id', 'next_id')
            bridge.arm('before', 2)
            worker('ordinary-undispatched-write', 'send', (pending_id, b'ordinary pending work', b'local'),
                   refusal='truncated witness reply')
            original_pending = (path / 'intent').read_bytes(); original_head = (path / 'head').read_bytes()
            require(original_pending.startswith(b'QPREFI01'), 'not an ordinary journal intent')
            clock(210)
            worker('renewal-cannot-overwrite-expired-work', 'local_renewal_prepare', first, now=210,
                   refusal='truncated witness reply')
            dispatched = bridge.records[-1]; withheld = bridge.records[-2]
            require(dispatched['kind'] == withheld['kind'] == 2 and withheld['fault'] == 'before'
                    and dispatched['command_id'] == withheld['command_id']
                    and dispatched['delivery'] == 'native_rejected_no_signed_reply'
                    and dispatched['native_status'] == 2, 'ordinary original advance was not refused by native witness')
            require((path / 'intent').read_bytes() == original_pending and (path / 'head').read_bytes() == original_head
                    and not (path / 'authority').exists(), 'root grant replaced unrelated ordinary work')
            return report('OrdinaryWorkRemainsPending', None)
        clock(210)
        old_head = (path / 'head').read_bytes()
        worker('expired-original-send-refused', 'next_id', now=210, refusal='witness current authority denied')

        if label == 'applied':
            worker('initial-control-kill', 'local_renewal_prepare', first, now=210, cut='committed:authority')
            worker('original-intent-kill', 'local_renewal_prepare', first, now=210, cut='committed:intent')
            original_intent = (path / 'intent').read_bytes()
            worker('pending-owner-refused', 'storage_format', refusal='local renewal coordination remains pending')
            before_files = None
            for index in range(3):
                worker('pending-control-stage-kill-' + str(index), 'local_renewal_status', op,
                       cut='stage-synced:authority')
                count = len(list(path.iterdir()))
                require(before_files is None or count == before_files, 'repeated control recovery grew staging files')
                before_files = count
            require(worker('pending-status', 'local_renewal_status', op) == 'Unavailable', 'unapproved is not terminal')
            proposal = value('original-prepare-retry', 'local_renewal_prepare', first, now=210)
            resigned = (public / 'local-renewal-1-resigned').read_bytes()
            require(value('resigned-original-retry', 'local_renewal_prepare', (first[0], resigned, first[2]), now=210)
                    == proposal, 'semantic retry changed original sealed proposal')
            require((path / 'intent').read_bytes() == original_intent, 'original target changed after retry')
        else:
            proposal = value('prepare', 'local_renewal_prepare', first, now=210)
            original_intent = (path / 'intent').read_bytes()
        (out / 'first-proposal').write_bytes(proposal)
        require(worker('unavailable-recovery', 'local_renewal_recover', op) == 'Unavailable', 'missing outcome became closed')
        worker('unprepared-commit-refused', 'local_renewal_commit', op, now=210, refusal='renewal not independently prepared')
        require((path / 'head').read_bytes() == old_head and (path / 'intent').read_bytes() == original_intent,
                'unavailable changed original state')
        worker('wrong-original-operation', 'local_renewal_status', (bytes([1]) * 32,), refusal='original renewal operation unavailable')
        if label == 'unprepared-close':
            worker('unprepared-close-refused', 'local_renewal_close', op, refusal='renewal exact close unavailable')
            clock(401)
            bridge.call('independent-historical-close', 35, proposal, b'Closed')
        else:
            bridge.call('independent-prepare', 34, proposal, b'Prepared')
            require(worker('prepared-status', 'local_renewal_status', op) == 'Prepared', 'prepared outcome')
            controls.prepared(first, proposal)
            bridge.arm('after', 5 if label == 'applied' else 7)
            worker('lost-terminal-response', 'local_renewal_commit' if label == 'applied' else 'local_renewal_close',
                   op, now=210, refusal='truncated witness reply')
            require((path / 'head').read_bytes() == old_head, 'lost reply changed local head')
            bridge.call('reopen-witness', 32, expected=b'witness reopened')
            if label != 'applied':
                clock(401)

        if label == 'applied':
            before_files = None
            for index in range(3):
                worker('target-stage-kill-' + str(index), 'local_renewal_recover', op, cut='stage-synced:head')
                count = len(list(path.iterdir()))
                require(before_files is None or count == before_files, 'repeated target recovery grew staging files')
                before_files = count
            worker('target-published-kill', 'local_renewal_recover', op, cut='committed:head')
            require(hashlib.sha256((path / 'head').read_bytes()).digest() == proposal[-32:], 'not the exact prepared target')
        outcome = 'Applied' if label == 'applied' else 'Closed'
        worker('terminal-record-kill', 'local_renewal_recover', op, cut='renewal:terminal-durable')
        bridge.arm('after', 8)
        worker('lost-acknowledgement', 'local_renewal_recover', op, refusal='truncated witness reply')
        # Acknowledgement prunes the remote record. Only the authentic durable
        # terminal, written before the ACK, permits the same original cleanup.
        require(worker('retained-terminal-status', 'local_renewal_status', op) == outcome, 'lost ACK erased terminal')
        worker('acknowledged-kill', 'local_renewal_recover', op, cut='renewal:acknowledged')
        worker('intent-removal-kill', 'local_renewal_recover', op, cut='removed:intent')
        worker('terminal-pending-owner-refused', 'storage_format', refusal='local renewal coordination remains pending')
        worker('completed-kill', 'local_renewal_recover', op, cut='renewal:completed')
        require(worker('ready-terminal-recovery', 'local_renewal_recover', op) == outcome, 'durable completed outcome')
        require(value('historical-original-prepare-retry', 'local_renewal_prepare', first, now=401) == proposal,
                'historical retry changed original proposal')
        second = materials(2)
        if label == 'applied':
            require(worker('format-six', 'storage_format') == 6, 'renewed format')
            controls.adopted(private)
            require(value('original-outbox-recovered', 'resume', (original_id,), now=210) == original_wire,
                    'renewal changed original message')
            bridge.call('native-original-receive', 7, application(b'local', original_wire), b'original retained message')
            ack = bridge.call('native-original-consume', 10, original_id)
            require(worker('original-ACK', 'accept_acknowledgement', (ack,), now=210) == 1, 'original message identity')
            next_id = value('renewed-id', 'next_id', now=210)
            new_wire = value('renewed-send', 'send', (next_id, b'new under local extension', b'local'), now=210)
            bridge.call('native-renewed-receive', 7, application(b'local', new_wire), b'new under local extension')
            ack = bridge.call('native-renewed-consume', 10, next_id)
            worker('renewed-ACK', 'accept_acknowledgement', (ack,), now=210)
            offer = value('renewed-rekey-offer', 'prepare_rekey_offer', now=210)
            response = bridge.call('renewed-rekey-response', 14, offer)
            final = value('renewed-rekey-final', 'accept_rekey_response', (response,), now=210)
            receipt = bridge.call('renewed-rekey-receipt', 15, final)
            require(worker('renewed-rekey-confirm', 'accept_rekey_receipt', (receipt,), now=210) == 1, 'renewed rekey epoch')
            clock(310)
            worker('second-expired-current-refused', 'next_id', now=310, refusal='witness current authority denied')
            second_proposal = value('prepare-second', 'local_renewal_prepare', second, now=310)
            (out / 'second-proposal').write_bytes(second_proposal)
            bridge.call('independent-second-prepare', 34, second_proposal, b'Prepared')
            worker('second-commit-terminal-kill', 'local_renewal_commit', (second[0],), now=310,
                   cut='renewal:terminal-durable')
            clock(401)
            require(worker('expired-policy-terminal-recovery', 'local_renewal_recover', (second[0],), now=401) == 'Applied',
                    'historical terminal cleanup after policy expiry')
            require(hashlib.sha256((path / 'head').read_bytes()).digest() == second_proposal[-32:], 'second original target')
        else:
            require((path / 'head').read_bytes() == old_head, 'closed renewal installed target')
            require(worker('format-five-retained', 'storage_format') == 5, 'closed renewal changed image format')
        worker('expired-business-refused', 'next_id', now=401, refusal='witness current authority denied')
        return report(outcome, proposal)
    finally:
        if driver is not None:
            (out / 'WORKERS.json').write_text(json.dumps(driver.operations, indent=2) + '\n')
        (out / 'NATIVE.json').write_text(json.dumps(native.commands, indent=2) + '\n')
        if bridge is not None:
            (out / 'ATTEMPTS.json').write_text(json.dumps(bridge.records, indent=2) + '\n')
            bridge.close()
        native.close()


def main():
    sys.path.append(str(Path(__file__).resolve().parent))
    from run import arguments
    from provider import load_provider
    args = arguments(); crypto, backend = load_provider(args.provider_root)
    from peer.wire import require
    root = Path(__file__).resolve().parent
    files = [*sorted((root / 'peer').glob('*.py')), *sorted(root.glob('*.py')),
             *sorted((root / 'native/src').glob('*.rs')), root / 'native/Cargo.toml',
             root / 'native/Cargo.lock', root / 'requirements.txt']
    def sources():
        return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest() for path in files}
    original = sources(); args.output.mkdir()
    report = {'source_files': original, 'native_sha256': hashlib.sha256(args.native.read_bytes()).hexdigest(),
              'provider': {'cryptography': crypto.__version__, 'openssl': backend.openssl_version_text()}}
    (args.output / 'INPUTS.json').write_text(json.dumps(report, indent=2) + '\n')
    profiles = ('applied', 'closed', 'unprepared-close', 'pending-write')
    for label in profiles:
        report[label] = exercise(args, label)
    require(sources() == original, 'sources changed during local renewal qualification')
    (args.output / 'RESULT.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({label: report[label] for label in profiles}))


if __name__ == '__main__':
    main()
