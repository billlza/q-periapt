"""Real native TCP deliveries to the installed browser's durable host consumer."""
from pathlib import Path
import hashlib
import socket
import subprocess
import threading

from bounded_process import capture_output
from evidence_io import parse_strict_json_bytes
from rust_sdk_profile import require, snapshot


class Incoming:
    """One bounded TCP/HTTP carrier exchange; no protocol or application substitute."""
    def __init__(self):
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0)); self.listener.listen(1); self.listener.settimeout(15)
        self.address = self.listener.getsockname()
        self.ready = threading.Event(); self.decision = threading.Event()
        self.request = None; self.response = None; self.error = None
        self.dropped = False; self.http_reads = 0
        self.thread = threading.Thread(target=self._work, name='native-browser-delivery')
        self.thread.start()

    @staticmethod
    def _read(stream, size):
        result = bytearray()
        while len(result) < size:
            value = stream.recv(size - len(result))
            require(bool(value), 'truncated native request'); result.extend(value)
        return bytes(result)

    def _work(self):
        try:
            with self.listener:
                stream, _ = self.listener.accept()
                with stream:
                    stream.settimeout(15)
                    size = int.from_bytes(self._read(stream, 4), 'big')
                    require(10 <= size <= 32768, 'native request frame bound')
                    self.request = self._read(stream, size); self.ready.set()
                    require(self.decision.wait(20), 'browser response deadline')
                    if self.dropped:
                        require(self.response is None, 'response existed at pre-response cut')
                        stream.shutdown(socket.SHUT_RDWR)
                    else:
                        require(self.response is not None, 'browser response absent')
                        stream.sendall(len(self.response).to_bytes(4, 'big') + self.response)
        except BaseException as error:
            self.error = error; self.ready.set()

    def read(self):
        require(self.ready.wait(15), 'native request deadline')
        if self.error is not None: raise self.error
        require(self.request is not None and self.http_reads == 0, 'incoming request is missing or repeated')
        self.http_reads += 1
        return self.request

    def reply(self, value):
        require(self.http_reads == 1 and not self.dropped and self.response is None
                and 10 <= len(value) <= 32768, 'unexpected browser response')
        self.response = value; self.decision.set()

    def drop(self):
        require(self.http_reads == 1 and self.response is None and not self.dropped, 'pre-response cut differs')
        self.dropped = True; self.decision.set()

    def finish(self):
        self.thread.join(timeout=25)
        require(not self.thread.is_alive(), 'native/browser relay retained thread')
        if self.error is not None: raise self.error
        require(self.request is not None and self.http_reads == 1, 'actual incoming request missing')

    def close(self):
        if self.thread.is_alive():
            self.dropped = True; self.decision.set(); self.listener.close()
            self.thread.join(timeout=20)
        require(not self.thread.is_alive(), 'native/browser relay did not close')


def qualify(binary, inputs, private, public, session, server, phase):
    from native_exchange_fixture import save, b64
    directory = public/'reverse'; directory.mkdir()
    logs = public/'logs'; commands = []
    digest = lambda data: hashlib.sha256(data).hexdigest()
    report = {'schema_version': 1, 'completed': False, 'session': session, 'commands': commands,
              'frames': [], 'steps': {}, 'release_claim_eligible': False}

    def invocation(label, action):
        path = private/(label+'.json')
        save(path, dict(inputs, schema='qperiapt-native-outgoing/1', action=action))
        return [str(binary), str(path), b64(bytes(session))]

    def recorded(label, code, expected):
        stdout = snapshot(logs/(label+'.stdout')).data
        stderr = snapshot(logs/(label+'.stderr')).data
        commands.append({'label':label, 'exit':code, 'expected_exit':expected,
                         'stdout_sha256':digest(stdout), 'stderr_sha256':digest(stderr)})
        require(code == expected, 'native outgoing exit differs '+label)
        if expected:
            require(stdout == b'' and b'Transport(' in stderr and b'UnexpectedEof' in stderr,
                    'native failure was not the selected lost response')
            return None
        require(stderr == b'', 'unexpected native outgoing diagnostics '+label)
        return parse_strict_json_bytes(stdout, label='native outgoing '+label)

    def command(label, action):
        label = 'reverse-native-'+label
        result = capture_output(invocation(label, action), timeout_seconds=40,
                                maximum_stdout_bytes=4096, maximum_stderr_bytes=4096)
        save(logs/(label+'.stdout'), result.stdout); save(logs/(label+'.stderr'), result.stderr)
        return recorded(label, result.returncode, 0)

    def delivery(label, message, plaintext, *, cut=False):
        bridge = Incoming(); server.incoming = bridge
        name = 'reverse-native-deliver-'+label
        action = {'operation':'deliver_tcp', 'message':message, 'plaintext':list(plaintext),
                  'associated_data':list(b'installed native/browser'),
                  'address':f'{bridge.address[0]}:{bridge.address[1]}'}
        process = None
        try:
            with (logs/(name+'.stdout')).open('xb') as out, (logs/(name+'.stderr')).open('xb') as err:
                process = subprocess.Popen(invocation(name, action), stdout=out, stderr=err)
            result = phase('receive-'+label, {'message':message}, recorder=commands)
            if cut: bridge.drop()
            bridge.finish()
            code = process.wait(timeout=5)
            outcome = recorded(name, code, 1 if cut else 0)
            require(cut or outcome == {'consumption':'Confirmed'}, 'native consumption not confirmed')
            number = len(report['frames'])+1
            save(directory/f'{number:03}.request', bridge.request)
            frame = {'sequence':number,'request_sha256':digest(bridge.request), 'native_pid':process.pid,
                     'native_exit':code,'response_created':bridge.response is not None,'cut_before_response':cut}
            if bridge.response is not None:
                save(directory/f'{number:03}.response', bridge.response)
                frame['response_sha256'] = digest(bridge.response)
            report['frames'].append(frame); report['steps'][label] = result
        finally:
            if process is not None and process.poll() is None:
                process.kill(); process.wait(timeout=5)
            bridge.close(); server.incoming = None

    try:
        first = command('next-first', {'operation':'next'})['message']
        delivery('first', first, b'native to installed browser epoch one')
        lost = command('next-cut', {'operation':'next'})['message']
        delivery('cut', lost, b'durable browser effect before Worker termination', cut=True)
        before = command('status-cut', {'operation':'status','message':lost})['status']
        require(before == 'Committed', 'sender inferred consumption at the Worker cut')
        delivery('retry', lost, b'durable browser effect before Worker termination')
        after = command('status-retry', {'operation':'status','message':lost})['status']
        require(after == 'Acknowledged', 'original reverse message was not acknowledged')
        last = command('next-last', {'operation':'next'})['message']
        delivery('last', last, b'native to recovered browser after original retry')
        report.update(message_ids={'first':first,'cut':lost,'last':last}, before_retry=before, after_retry=after,
                      completed=True)
    except BaseException as error:
        report['failure']={'type':type(error).__name__,'message':str(error)}
        raise
    finally:
        save(directory/'RESULT.json', report)
    return report
