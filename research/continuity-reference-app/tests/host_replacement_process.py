"""Owned real account service and software-Passkey HTTP probe processes.

Only isolated test accounts are created. No account root signer or login bypass
is available to this controller. Cookies and software private keys stay in Rust.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import subprocess
import time

from native_exchange_fixture import b64, save, wire
from qperiapt_continuity_reference.enrollment_exchange import PolicyInputs
from qperiapt_continuity_reference.wire import require


class Commands:
    def __init__(self, root):
        self.root, self.rows = root, []

    def __call__(self, argv, label, *, success=True, json_output=True, lost_stdout=False):
        require(label not in {row['label'] for row in self.rows}, 'duplicate command label')
        command = [str(x) for x in argv]
        if lost_stdout:
            child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            child.stdout.close(); child.stdout = None
            try:
                _, stderr = child.communicate(timeout=60)
            finally:
                if child.poll() is None:
                    child.kill(); child.wait(timeout=5)
            stdout, code = b'', child.returncode
        else:
            result = subprocess.run(command, capture_output=True, timeout=60)
            stdout, stderr, code = result.stdout, result.stderr, result.returncode
        require(len(stdout) <= 1024**2 and len(stderr) <= 1024**2, 'command output bound')
        save(self.root / (label + '.stdout'), stdout)
        save(self.root / (label + '.stderr'), stderr)
        self.rows.append({'label': label, 'exit': code})
        require((code == 0) == success, label + ': unexpected command result: ' + stderr.decode())
        if success:
            require(not stderr, label + ': unexpected diagnostics')
            return json.loads(stdout) if json_output else stdout
        require(not stdout, label + ': failure emitted successful output')
        if lost_stdout:
            require(b'broken pipe' in stderr.lower(), 'commit output was not actually lost')
        return None


class AccountHost:
    def __init__(self, root, binary, family, run):
        self.root, self.binary, self.run = root, binary, run
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0)); self.port = listener.getsockname()[1]
        self.origin = f'http://localhost:{self.port}'
        self.database = root / 'accounts.redb'
        self.process = None; self.services = []; self.current = None
        for command in ('init', 'enable-enrollment', 'enable-reapproval', 'enable-credential-extension',
                        'enable-credential-grants', 'enable-policy-approvals', 'enable-device-replacements'):
            extra = [b64(family)] if command == 'enable-enrollment' else []
            run([binary, command, self.database, self.origin, *extra], 'account-' + command, json_output=False)

    def start(self, label):
        require(self.process is None, 'account service already owned')
        stdout, stderr = (self.root / (label + suffix) for suffix in ('.stdout', '.stderr'))
        with stdout.open('xb') as out, stderr.open('xb') as err:
            self.process = subprocess.Popen([str(self.binary), 'serve', str(self.database), self.origin], stdout=out, stderr=err)
        self.current = (label, stdout, stderr)
        try:
            deadline = time.monotonic() + 20
            expected = ('Reference account application: ' + self.origin + '\n').encode()
            while True:
                require(self.process.poll() is None, 'account service exited before readiness')
                raw = stdout.read_bytes(); require(len(raw) <= 4096, 'account readiness output bound')
                if b'\n' in raw:
                    require(raw == expected, 'account readiness differs'); break
                require(time.monotonic() < deadline, 'account readiness deadline'); time.sleep(.01)
        except BaseException:
            if self.process.poll() is None:
                self.process.kill(); self.process.wait(timeout=5)
            raise

    def stop(self, *, kill=False):
        require(self.process is not None and self.process.poll() is None, 'account service is not live')
        self.process.send_signal(signal.SIGKILL if kill else signal.SIGINT)
        try:
            code = self.process.wait(timeout=20)
        finally:
            if self.process.poll() is None:
                self.process.kill(); self.process.wait(timeout=5)
        label, _, stderr = self.current
        require(code == (-9 if kill else 0) and not stderr.read_bytes(), 'account stop outcome differs')
        self.services.append({'label': label, 'pid': self.process.pid, 'exit': code})
        self.process = None

    def close(self):
        if self.process is not None and self.process.poll() is None:
            self.stop()


class AccountProbe:
    def __init__(self, root, binary, origin):
        self.root, self.counter, self.rows = root, 0, []
        self.stderr = root / 'account-probe.stderr'
        with self.stderr.open('xb') as err:
            self.process = subprocess.Popen([str(binary), origin], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=err)
        os.set_blocking(self.process.stdout.fileno(), False)
        self.reader = selectors.DefaultSelector(); self.reader.register(self.process.stdout, selectors.EVENT_READ)
        self.buffer = bytearray(); self.finished = False

    def command(self, label, command):
        require(not self.finished, 'probe already finished')
        self.counter += 1
        request = {'id': self.counter, 'command': command}
        save(self.root / (label + '.http-request.json'), request)
        self.process.stdin.write(wire(request) + b'\n'); self.process.stdin.flush()
        deadline = time.monotonic() + 30
        while b'\n' not in self.buffer:
            remaining = deadline - time.monotonic(); require(remaining > 0, 'account probe response deadline')
            require(self.reader.select(remaining), 'account probe response timeout')
            part = os.read(self.process.stdout.fileno(), 4096)
            require(bool(part), 'account probe truncated response: ' + self.stderr.read_text())
            self.buffer.extend(part); require(len(self.buffer) <= 1024**2, 'account probe response bound')
        line, _, remainder = self.buffer.partition(b'\n'); self.buffer = bytearray(remainder)
        response = json.loads(line)
        require(set(response) == {'id', 'result'} and response['id'] == self.counter, 'account probe response identity')
        save(self.root / (label + '.http-response.json'), response)
        self.rows.append({'label': label, 'id': self.counter, 'action': command['action']})
        return response['result']

    def register(self, name):
        require(self.command('register-' + name, {'action': 'register', 'account': name}) ==
                {'authenticated': 'registered_software_test_passkey'}, 'software passkey registration')

    def login(self, name, label):
        require(self.command(label, {'action': 'login', 'account': name}) ==
                {'authenticated': 'original_software_test_passkey'}, 'original software passkey login')

    def request(self, name, label, route, body=None, *, status=200, lost=False, raw=False):
        response = self.command(label, {'action': 'request', 'account': name, 'route': route,
                                       'body': body, 'disconnect_before_body': lost})
        require(set(response) == {'status', 'body', 'content_type'} and response['status'] == status,
                label + ': HTTP outcome differs: ' + str(response))
        if lost or status == 204:
            require(response['body'] == '', label + ': unexpected HTTP body'); return None
        return response['body'].encode() if raw else json.loads(response['body'])

    def finish(self):
        require(self.command('probe-finish', {'action': 'finish'}) == {'finished': True}, 'probe completion')
        require(self.process.wait(timeout=10) == 0 and not self.stderr.read_bytes(), 'probe exit')
        self.finished = True; self.reader.close(); self.process.stdin.close(); self.process.stdout.close()

    def close(self):
        if not self.finished:
            if self.process.poll() is None:
                self.process.kill(); self.process.wait(timeout=5)
            self.reader.close(); self.process.stdin.close(); self.process.stdout.close(); self.finished = True


def policy(root, sdk, publisher, witness, run):
    sdk_db, publisher_db = root / 'sdk-authority.redb', root / 'publisher.redb'
    sdk_id, publisher_id = b64(os.urandom(32)), b64(os.urandom(32))
    run([sdk, 'init', sdk_db, sdk_id], 'sdk-init')
    document = (b'schema_version=1\npolicy_version=1\nmin_nist_level=3\ndefault_profile="ContextBound"\n'
                b'allowed_kems=["ML-KEM-768","X25519"]\nallowed_sigs=["ML-DSA-65"]\ndeprecated=[]\n')
    source = root / 'sdk-policy.toml'; save(source, document)
    sdk_export = root / 'sdk-export'; sdk_export.mkdir(mode=0o700)
    run([sdk, 'issue', sdk_db, sdk_id, b64(os.urandom(32)), source, sdk_export], 'sdk-issue')
    authority = run([publisher, 'init', publisher_db, publisher_id,
                     *[sdk_export / n for n in ('sdk-root', 'sdk-state', 'sdk-document', 'sdk-signature')]], 'policy-init')
    now = int(time.time())
    request = {'bootstrap_mode': 'reusable_both', 'valid_from': now, 'valid_until': now + 1800,
               'send_budget': 8, 'anchor': {'kind': 'required', 'identity': list(witness.pin.identity),
                                          'key': b64(witness.pin.key.raw)}}
    path = root / 'policy-request.json'; save(path, request)
    output = root / 'policy-export'; output.mkdir(mode=0o700)
    run([publisher, 'issue', publisher_db, publisher_id, b64(os.urandom(32)), path, output], 'policy-issue')
    for name in ('policy-pins.json', 'policy-materials.json'):
        save(root / name, (output / name).read_bytes())
    selected = PolicyInputs.from_trusted((root / 'policy-pins.json').read_bytes(), (root / 'policy-materials.json').read_bytes())
    require(selected.witness is not None and selected.witness.binding == witness.pin.binding,
            'actual independently provisioned witness differs')
    return bytes(authority['family']), now, selected


def fingerprints(*directories):
    return {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
            for directory in directories for p in Path(directory).rglob('*') if p.is_file()}


class RecordingRelay:
    """Forward actual frames and preserve both refusal and success evidence."""
    def __init__(self, root, upstream):
        import threading
        from qperiapt_continuity_reference.network import TcpTransport
        from qperiapt_continuity_reference.network_server import Server
        self.rows, self.result, self.closed = [], {}, False
        def forward(frame, invocation):
            label = 'replacement-wire-' + str(len(self.rows) + 1)
            save(root / (label + '.request'), frame)
            row = {'label': label, 'kind': frame[8], 'request_sha256': hashlib.sha256(frame).hexdigest()}
            try:
                reply = TcpTransport(upstream)(frame, invocation.deadline, invocation.cancellation)
            except (OSError, ValueError) as error:
                row.update(outcome='refused', error=str(error)); self.rows.append(row)
                save(root / (label + '.refusal.txt'), str(error).encode())
                raise
            save(root / (label + '.response'), reply)
            row.update(outcome='response', response_sha256=hashlib.sha256(reply).hexdigest()); self.rows.append(row)
            return reply
        self.server = Server(('127.0.0.1', 0), forward)
        self.address = self.server.address
        def serve():
            try: self.result['stats'] = self.server.serve()
            except BaseException as error: self.result['error'] = error
        self.thread = threading.Thread(target=serve); self.thread.start()

    def close(self):
        if not self.closed:
            self.server.close(); self.thread.join(timeout=35)
            require(not self.thread.is_alive(), 'replacement relay did not stop')
            self.closed = True
        if 'error' in self.result: raise self.result['error']
        require(set(self.result) == {'stats'}, 'replacement relay result absent')
        return self.result['stats']
