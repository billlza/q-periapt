"""Kill and reap the native endpoint, then exec it against unchanged private files."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time
from qperiapt_continuity_reference.wire import require


def preserved(public):
    witness = Path((public/'private-witness-path').read_text())
    journal = Path((public/'private-fixture-path').read_text())
    require(journal == Path((public/'root-successor/private-fixture-path').read_text()),
            'restart must keep the original native journal')
    files = [witness/name for name in ('key','witness-id','witness-key-id','device-key-id',
                                     'witness-signer','device-signer','prekey-host-key','prekey-reservation')]
    files += [journal/name for name in ('key','identity')]
    files += [p for p in public.iterdir() if p.is_file()]
    files += [public/'root-successor/control',public/'root-successor/private-fixture-path']
    return {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}


def restart(bridge, now, label):
    native = bridge.native
    require(native.restartable_successor, 'native restart fixture not selected')
    with bridge.lock:
        public = native.cases.parent/'public'
        before = preserved(public)
        old = native.process
        require(old.poll() is None, 'native endpoint ended before requested process cut')
        row = {'case':label, 'old_pid':old.pid, 'signal':'SIGKILL', 'preserved_files':before,
               'completed':False}
        native.restarts.append(row)
        result = native.cases.parent/'PROCESS_RESTARTS.json'
        result.write_text(json.dumps(native.restarts,indent=2)+'\n')
        os.killpg(old.pid, signal.SIGKILL)
        row['old_returncode'] = old.wait(timeout=10)
        old.stdin.close(); old.stdout.close(); native.stderr.close()
        require(row['old_returncode']==-signal.SIGKILL, 'native process did not terminate by SIGKILL')
        require(preserved(public)==before, 'process cut replaced original native keys or public inputs')
        stderr_path = native.cases.parent/('restart-'+str(len(native.restarts))+'.stderr')
        native.stderr = stderr_path.open('xb')
        native.process = subprocess.Popen([str(native.executable),str(public),'--resume-successor',str(now)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=native.stderr,
            bufsize=0, start_new_session=True)
        require(native.process.stdin is not None and native.process.stdout is not None, 'missing restart pipes')
        os.set_blocking(native.process.stdin.fileno(),False)
        os.set_blocking(native.process.stdout.fileno(),False)
        row.update(new_pid=native.process.pid, stderr=str(stderr_path))
        require(native.process.pid != old.pid, 'native restart reused the same process')
        deadline = time.monotonic()+30
        require(native.read(4,deadline)==b'\0\0\0\6' and native.read(6,deadline)==b'\1ready',
                'native restart did not open original fixture')
        require(preserved(public)==before, 'native reopen replaced original keys or inputs')
        row['completed']=True
        result.write_text(json.dumps(native.restarts,indent=2)+'\n')


class SuccessorRestarts:
    def __init__(self, bridge, now, request, context):
        self.bridge,self.now,self.request,self.context=bridge,now,request,context
        self.initial=self.reply=self.final=self.session=None
        self.active=False

    def at(self,label):
        if not self.bridge.native.restartable_successor:return
        restart(self.bridge,self.now,label)
        def call(suffix,command,wire=b'',expected=None,status=1):
            return self.bridge.call('process-restart-'+label+'-'+suffix,command,wire,expected,status)
        call('old-controller',8,status=2,expected=b'resumed fixture only admits its original successor')
        call('unselected-controller',53,b'\x08',status=2,expected=b'successor peer before explicit approval')
        call('wrong-target',52,self.request[:-1],status=2,expected=b'restart cannot select another successor')
        call('select',52,self.request,self.context)
        if self.initial is not None:
            call('original-reply',53,b'\x04'+self.initial,self.reply)
        if self.final is not None:
            call('original-session',53,b'\x05'+self.final,self.session)
        if self.active:
            call('original-activation',53,b'\x06',self.session)
