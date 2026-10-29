"""Independent required-Witness fixture around the existing browser/native owners."""
import hashlib
import os
import threading
import time

from rust_sdk_profile import require

digest = lambda data: hashlib.sha256(data).hexdigest()


class WitnessQualification:
    def __init__(self, private, public, binary, run, services):
        from witness_cli_exchange import WitnessHost
        self.public, self.services = public, services
        self.report = {'schema_version': 1, 'completed': False, 'commands': [], 'frames': []}
        self.mode = 'normal'; self.subject = None; self.device_key = None
        self.lock = threading.Lock()
        def command(argv, label, *, success=True, json_output=True):
            return run(argv, label, json_output=json_output, recorder=self.report['commands'],
                       expected_exit=0 if success else 1)
        self.host = WitnessHost(private, binary, command)
        self.report['pin'] = self.host.public
        self.report['key_hashes_before'] = self.host.keys()
        require(len(self.report['key_hashes_before']) == 2, 'witness protected key inventory')

    def start(self, label):
        self.host.start(label)
        self.services.append(self.host.service)

    def enroll_native(self, prepared, current, device, journal, certificate):
        self.report['native_genesis'] = prepared
        self.report['native_enrollment'] = self.host.enroll('native', prepared, current, device, journal, certificate)
        self.start('witness-unenrolled')

    def before_activation(self, phase, current, device, certificate, device_key):
        self.device_key = device_key
        prepared = phase('witness-prepare', recorder=self.report['commands'])
        require(prepared['requires_witness'] is True and len(prepared['subject']) == 96
                and prepared['subject'][:32] == prepared['journal'] and len(prepared['head']) == 32,
                'browser required-witness genesis differs')
        self.subject = bytes(prepared['subject'])
        self.report['browser_preparation'] = prepared
        self.report['missing'] = phase('witness-missing', recorder=self.report['commands'])
        require(not self.report['frames'], 'missing witness made a network request')
        self.mode = 'unenrolled'
        self.report['unenrolled'] = phase('witness-unenrolled', recorder=self.report['commands'])
        self.mode = 'normal'
        require(len(self.report['frames']) == 1 and self.report['frames'][0]['result'] == 'no-reply',
                'unenrolled subject did not produce the single actual refusal')
        stopped = self.host.service.stop()
        require(stopped['stats']['operation_errors'] == 1, 'witness did not report the refused operation')
        request = {'preparation': 'RequiresWitnessEnrollment', 'subject': prepared['subject'], 'head': prepared['head']}
        self.host.enroll('browser-wrong-head', request, current, device, bytes(prepared['journal']),
                         certificate, success=False, head=list(os.urandom(32)))
        self.report['browser_enrollment'] = self.host.enroll('browser', request, current, device,
                                                            bytes(prepared['journal']), certificate)
        self.start('witness-active')

    def before_resume(self, phase):
        self.report['crash'] = self.host.service.stop(kill=True)
        before = len(self.report['frames'])
        self.mode = 'offline'
        self.report['offline'] = phase('witness-offline', recorder=self.report['commands'])
        self.mode = 'normal'
        require(len(self.report['frames']) == before + 1 and self.report['frames'][-1]['result'] == 'connection-refused',
                'offline attempt did not observe the actual stopped witness')
        self.report['reopened_pin'] = self.host.run(self.host.command('pin'), 'witness-original-pin')
        require(self.report['reopened_pin'] == self.host.public
                and self.host.keys() == self.report['key_hashes_before'], 'witness restart changed keys')
        self.start('witness-reopened')

    def exchange(self, request):
        from native_exchange_fixture import save
        from qperiapt_continuity_reference.wire import Reader
        from qperiapt_continuity_reference.witness import Operation, TcpTransport, commitment, verify
        started_ns = time.time_ns()
        started = time.perf_counter_ns()
        require(self.lock.acquire(timeout=1), 'concurrent browser witness fixture request')
        try:
            require(self.subject is not None and self.device_key is not None and len(request) == 3674,
                    'witness request precedes prepared browser identity')
            require(len(self.report['frames']) < 1024, 'witness fixture exchange bound')
            body = self.device_key.open(request, 7, 297)
            reader = Reader(body)
            require(reader.take(8) == b'QPANRQ01' and reader.take(32) == self.host.pin.binding
                    and reader.take(96) == self.subject, 'witness request scope differs')
            command, challenge = reader.take(32), reader.take(32)
            operation = Operation(reader.integer(1), reader.take(96)); reader.finish()
            require(command == commitment(b'COMMAND', self.host.pin.binding + self.subject + operation.wire())
                    and any(challenge), 'witness original command or challenge differs')
            number = len(self.report['frames']) + 1
            row = {'sequence': number, 'operation': operation.kind, 'command': list(command),
                   'challenge_sha256': digest(challenge), 'request_sha256': digest(request),
                   'request_dual_signature_verified': True, 'phase': self.mode,
                   'started_unix_ns': started_ns,
                   'request_verification_ms': (time.perf_counter_ns() - started) / 1e6}
            save(self.public / f'witness-{number:03}.request', request)
            transport_started = time.perf_counter_ns()
            try:
                reply = TcpTransport(self.host.address)(request, time.monotonic() + 10)
            except ConnectionRefusedError as error:
                require(self.mode == 'offline' and self.host.service.result['exit'] == -9,
                        'unexpected witness connection refusal')
                row.update(result='connection-refused', errno=error.errno, http_status=503,
                           total_ms=(time.perf_counter_ns() - started) / 1e6)
                self.report['frames'].append(row)
                return 503, b'witness unavailable'
            except ValueError as error:
                require(self.mode == 'unenrolled' and str(error) == 'truncated witness reply'
                        and self.host.service.process.poll() is None, 'unexpected witness protocol failure')
                row.update(result='no-reply', error=str(error), http_status=502,
                           total_ms=(time.perf_counter_ns() - started) / 1e6)
                self.report['frames'].append(row)
                return 502, b'witness returned no receipt'
            require(self.mode == 'normal', 'a deliberately unavailable witness produced a reply')
            transport_finished = time.perf_counter_ns()
            observed = verify(self.host.pin, self.subject, operation, body, reply)
            reply_verified = time.perf_counter_ns()
            save(self.public / f'witness-{number:03}.response', reply)
            row.update(result='verified-reply', response_sha256=digest(reply), http_status=200,
                       reply_dual_signature_verified=True, outcome=observed.outcome,
                       native_roundtrip_ms=(transport_finished - transport_started) / 1e6,
                       reply_verification_ms=(reply_verified - transport_finished) / 1e6,
                       total_ms=(time.perf_counter_ns() - started) / 1e6,
                       head={'fence': observed.head.fence, 'revision': observed.head.revision,
                             'digest': list(observed.head.digest)})
            self.report['frames'].append(row)
            return 200, reply
        finally:
            self.lock.release()

    def finish(self, completed):
        self.report['services'] = [service.result for service in self.host.services]
        self.report['key_hashes_after'] = self.host.keys()
        if completed:
            require(self.report['key_hashes_after'] == self.report['key_hashes_before'],
                    'original witness protected files changed')
            require([r['exit'] for r in self.report['services']] == [0, -9, 0],
                    'witness process lifecycle differs')
            require(len({r['pid'] for r in self.report['services']}) == 3,
                    'witness processes were not replaced')
            challenges = [r['challenge_sha256'] for r in self.report['frames']]
            require(len(challenges) == len(set(challenges)), 'witness reused an old challenge')
        self.report['completed'] = completed
        self.report['scope'] = ('Fresh isolated test operator authorizes the original browser and native genesis. '
            'Actual native witness processes, same protected keys/database, independent request/reply signature verification, '
            'missing carrier, no receipt before enrollment, wrong genesis head, SIGKILL/offline refusal and original session recovery. '
            'Unenrolled EOF is not an authenticated non-commit receipt. No Passkey, remote TLS, device, power-loss or PCS claim.')
        return self.report
