"""Bounded real native subprocesses and a transactional test application effect."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
import json
import os
import sqlite3
import subprocess
import time
from contextlib import contextmanager
from native_exchange_fixture import save,b64
from qperiapt_continuity_reference.wire import require


class Effects:
    """Test-host SQLite transaction, separate from SDK storage/erasure claims."""
    def __init__(self,path):
        self.path=path; self.calls=0
        os.close(os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600))
        with self.open() as db:
            db.execute('CREATE TABLE deliveries (session BLOB, message BLOB, body BLOB NOT NULL, PRIMARY KEY(session,message))')

    @contextmanager
    def open(self):
        db=sqlite3.connect(self.path)
        try:
            db.execute('PRAGMA synchronous=FULL'); db.execute('PRAGMA fullfsync=ON')
            with db: yield db
        finally: db.close()

    def commit(self,session,message,plaintext):
        self.calls+=1
        with self.open() as db:
            row=db.execute('SELECT body FROM deliveries WHERE session=? AND message=?',(session,message)).fetchone()
            if row is None: db.execute('INSERT INTO deliveries VALUES(?,?,?)',(session,message,plaintext))
            else: require(bytes(row[0])==plaintext,'host effect conflicts with original message')

    def read(self,session,message):
        with self.open() as db:
            row=db.execute('SELECT body FROM deliveries WHERE session=? AND message=?',(session,message)).fetchone()
            require(row is not None,'host effect is absent'); return bytes(row[0])

    def count(self):
        with self.open() as db: return db.execute('SELECT count(*) FROM deliveries').fetchone()[0]


class Driver:
    def __init__(self,root,binary,session,run,commands,refusals):
        self.root,self.binary,self.session,self.run=root,binary,session,run
        self.commands,self.refusals=commands,refusals; self.interruptions=[]; self.requests={}
        original=json.loads((root/'initial.json').read_bytes())
        fields=('device_directory','wrapping_key','invitation','current_root','policy_pins',
                'policy_materials','witness_endpoint','peer_trust','bundle')
        self.context={k:original[k] for k in fields}

    def invocation(self,label,action):
        path=self.root/(label+'.json')
        save(path,dict(self.context,schema='qperiapt-native-outgoing/1',action=action))
        return [self.binary,path,b64(self.session)]

    def command(self,label,action,**kwargs):
        return self.run(self.invocation(label,action),label,**kwargs)

    def next(self,label): return bytes(self.command(label,{'operation':'next'})['message'])

    def status(self,label,message):
        return self.command(label,{'operation':'status','message':list(message)})['status']

    def drive(self,label,action,handler,*,receiver_error=None,lose_reply=False):
        requests=self.root/(label+'-requests'); responses=self.root/(label+'-responses')
        requests.mkdir(mode=0o700); responses.mkdir(mode=0o700)
        argv=self.invocation(label,dict(action,request_directory=str(requests),response_directory=str(responses)))
        with (self.root/(label+'.stdout')).open('wb') as stdout,(self.root/(label+'.stderr')).open('wb') as stderr:
            process=subprocess.Popen([str(x) for x in argv],stdout=stdout,stderr=stderr)
            number=1; stopped=False; observed=[]; deadline=time.monotonic()+40
            try:
                while process.poll() is None:
                    require(time.monotonic()<deadline,'outgoing process exceeded test deadline')
                    source=requests/f'{number:03}.request'
                    if not source.exists(): time.sleep(.005); continue
                    raw=source.read_bytes(); observed.append(raw)
                    try: reply=handler(raw)
                    except BaseException as error:
                        require(receiver_error is not None and isinstance(error,receiver_error),'unexpected independent receiver failure')
                        self.refusals.append(label+'-receiver'); reply=None
                    else: require(receiver_error is None,'expected receiver failure did not occur')
                    if receiver_error is not None or lose_reply:
                        require(process.poll() is None,'sender stopped before selected interruption')
                        marker=f'{process.pid} {label}\n'.encode(); save(self.root/(label+'.ready'),marker)
                        process.kill(); require(process.wait(timeout=5)==-9,'sender interruption was not SIGKILL'); stopped=True
                        self.interruptions.append({'label':label,'pid':process.pid,'exit':-9,
                            'marker_sha256':hashlib.sha256(marker).hexdigest(),'request_sha256':hashlib.sha256(raw).hexdigest()})
                        break
                    # Publish the complete response atomically. The native
                    # reader intentionally rejects visible partial input files.
                    temporary=responses/f'.response-{number}'; destination=responses/f'{number:03}.response'
                    save(temporary,reply); require(not destination.exists(),'response already published')
                    os.rename(temporary,destination)
                    directory=os.open(responses,os.O_RDONLY|os.O_DIRECTORY)
                    try: os.fsync(directory)
                    finally: os.close(directory)
                    number+=1
                status=process.wait(timeout=5)
            finally:
                if process.poll() is None: process.kill(); process.wait(timeout=5)
        self.commands.append({'label':label,'exit':status}); self.requests[label]=observed
        require(observed and status==(-9 if receiver_error is not None or lose_reply else 0),'native outgoing result differs: '+label)
        require(stopped==(receiver_error is not None or lose_reply),'sender interruption missing')
        require(not (self.root/(label+'.stderr')).read_bytes(),'unexpected native outgoing diagnostics')
        return None if stopped else json.loads((self.root/(label+'.stdout')).read_bytes())
