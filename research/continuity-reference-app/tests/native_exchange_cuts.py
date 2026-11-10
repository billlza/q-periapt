"""Deterministic SIGKILL at the real inbox/SDK consumption boundaries."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import signal
import hashlib
import os
import subprocess
import time
from qperiapt_continuity_reference.wire import require


def kill_at(probe, invocation, stage, root, commands):
    label='cut-'+stage; marker=root/(label+'.ready')
    require(not marker.exists(),'probe marker must be new')
    def output(suffix):
        return os.fdopen(os.open(root/(label+suffix),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb')
    with output('.stdout') as stdout, output('.stderr') as stderr:
        child=subprocess.Popen([str(probe),str(invocation),stage,str(marker)],stdout=stdout,stderr=stderr)
        killed=False
        try:
            deadline=time.monotonic()+30
            while not marker.exists():
                require(child.poll() is None,'probe exited before selected barrier')
                require(time.monotonic()<deadline,'probe barrier timeout')
                time.sleep(0.01)
            marked=marker.read_bytes()
            require(marked==f'{child.pid} {stage}\n'.encode(),'probe marker identity differs')
            require(child.poll() is None,'probe was not live at selected barrier')
            child.kill(); status=child.wait(timeout=5)
            require(status == -signal.SIGKILL,'probe did not terminate by SIGKILL'); killed=True
            require(not (root/(label+'.stdout')).read_bytes() and not (root/(label+'.stderr')).read_bytes(),
                    'probe produced unexpected output before kill')
            commands.append({'label':label,'exit':status})
        finally:
            if child.poll() is None: child.kill()
            child.wait(timeout=5)
        require(killed,'probe completion is missing')
        return {'stage':stage,'pid':child.pid,'exit':status,'marker_sha256':hashlib.sha256(marked).hexdigest()}


def exercise(child, session, accepted_journal, root, probe, session_cli, make_invocation,
             exchange, run, commands, frame, pair, payload, b64):
    kills=[]
    operation={'operation':'message','session':list(session)}
    for stage in ('before-effect','after-effect','after-consumption'):
        message=child.next_id(now=int(time.time())); ad=b'inbox-cut'
        plaintext=('original '+stage).encode()
        ciphertext=child.send(message,plaintext,ad,now=int(time.time()))
        request=frame(3,pair(ad,ciphertext)); label='cut-'+stage
        invocation=make_invocation(label,operation,request)
        observation=kill_at(probe,invocation,stage,root,commands)
        with (root/'inbox.redb').open('rb') as file: header=file.read(10)
        require(len(header)==10 and header[9]&4!=0,'protected inbox dropped two-phase commit')
        observation['inbox_flags']=header[9]; kills.append(observation)
        require(not (root/(label+'-output')/'response.bin').exists(),'killed probe released response')
        before=root/(label+'-effect-before.bin')
        run([session_cli,'read-inbox',root/'inbox.redb',b64(accepted_journal),b64(session),b64(message),before],
            label+'-inspect',success=stage!='before-effect')
        if stage=='before-effect': require(not before.exists(),'effect exists before its commit')
        else: require(before.read_bytes()==plaintext,'committed effect was lost at crash')
        require(child.status(message)=='Committed','unacknowledged client operation changed')
        require(child.resume(message,now=int(time.time()))==ciphertext,'client ciphertext changed after peer crash')
        ack=exchange(label+'-retry',operation,request)
        child.accept_acknowledgement(payload(ack,131),now=int(time.time()))
        require(child.status(message)=='Acknowledged','retry did not authenticate consumption')
        after=root/(label+'-effect-after.bin')
        run([session_cli,'read-inbox',root/'inbox.redb',b64(accepted_journal),b64(session),b64(message),after],label+'-readback')
        require(after.read_bytes()==plaintext,'retried host effect differs')
    return kills
