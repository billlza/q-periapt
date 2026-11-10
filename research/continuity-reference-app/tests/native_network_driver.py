"""Owned native service processes and a real one-shot TCP response-loss relay."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import json
import signal
import socket
import subprocess
import threading
import time
from native_exchange_fixture import save
from qperiapt_continuity_reference.network import TcpTransport,frame_size
from qperiapt_continuity_reference.connection_run import Cancellation
from qperiapt_continuity_reference.wire import require


class NativeService:
    def __init__(self,root,label,binary,inputs=None,*,arguments=None,carrier='QPCXCH01/TCP'):
        self.root,self.label=root,label;self.result=None
        require((inputs is None)!=(arguments is None),'select one explicit service configuration')
        if inputs is not None:
            config=dict(inputs,schema='qperiapt-native-service/1',listen='127.0.0.1:0',inbox=str(root/'inbox.redb'))
            self.config=root/(label+'.json');save(self.config,config)
            arguments=['serve',self.config]
        self.stdout=root/(label+'.stdout');self.stderr=root/(label+'.stderr')
        with self.stdout.open('wb') as out,self.stderr.open('wb') as err:
            self.process=subprocess.Popen([str(v) for v in [binary,*arguments]],stdout=out,stderr=err)
        try:
            deadline=time.monotonic()+20
            while True:
                require(self.process.poll() is None,'native service exited before readiness')
                raw=self.stdout.read_bytes();require(len(raw)<=4096,'native readiness output bound')
                if b'\n' in raw:break
                require(time.monotonic()<deadline,'native service readiness deadline');time.sleep(.01)
            ready=json.loads(raw.splitlines()[0]);require(ready['service']=='Listening' and ready['carrier']==carrier,'native service readiness differs')
            host,port=ready['address'].rsplit(':',1)
            require(host=='127.0.0.1' and 0<int(port)<=65535,'unexpected network service address')
            self.address=(host,int(port))
        except BaseException:
            if self.process.poll() is None:self.process.kill();self.process.wait(timeout=5)
            raise

    def stop(self,*,kill=False):
        if self.result is not None:return self.result
        require(self.process.poll() is None,'native service terminated unexpectedly')
        self.process.send_signal(signal.SIGKILL if kill else signal.SIGINT)
        try:status=self.process.wait(timeout=35)
        finally:
            if self.process.poll() is None:self.process.kill();self.process.wait(timeout=5)
        require(status==(-9 if kill else 0) and not self.stderr.read_bytes(),'native service stop disposition')
        lines=self.stdout.read_bytes().splitlines();require(len(lines)==(1 if kill else 2),'native service output inventory')
        self.result={'label':self.label,'pid':self.process.pid,'exit':status}
        if not kill:
            stopped=json.loads(lines[1]);require(stopped['service']=='Stopped','native service stop receipt')
            self.result['stats']=stopped['stats']
        return self.result


class DropResponse:
    """Forward the actual request and read an actual peer reply, then lose it."""
    def __init__(self,upstream,*,timeout=10):
        self.listener=socket.socket();self.listener.bind(('127.0.0.1',0));self.listener.listen(1)
        self.listener.settimeout(timeout);self.address=self.listener.getsockname();self.result={}
        def receive(stream,size):
            value=bytearray()
            while len(value)<size:
                part=stream.recv(size-len(value));require(bool(part),'relay truncated request');value.extend(part)
            return bytes(value)
        def work():
            try:
                with self.listener:
                    stream,_=self.listener.accept()
                    with stream:
                        stream.settimeout(timeout)
                        size=frame_size(int.from_bytes(receive(stream,4),'big'))
                        self.result['request']=receive(stream,size)
                        self.result['response']=TcpTransport(upstream)(self.result['request'],time.monotonic()+timeout,Cancellation())
                        # No substitute ACK, timeout reply or application status.
                        stream.shutdown(socket.SHUT_RDWR)
            except BaseException as error:self.result['error']=error
        self.thread=threading.Thread(target=work);self.thread.start()

    def finish(self):
        self.thread.join(timeout=12);require(not self.thread.is_alive(),'relay did not terminate')
        if 'error' in self.result:raise self.result['error']
        require(set(self.result)=={'request','response'},'relay did not observe a complete real exchange')
        return self.result
