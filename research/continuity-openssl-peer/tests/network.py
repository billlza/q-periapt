#!/usr/bin/env python3
"""Real TCP/resource tests only; opaque echo frames are not crypto evidence."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from pathlib import Path
import json
import socket
import sys
import threading
import time
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parent))
import enrollment_exchange as fixture
from qperiapt_continuity_reference import network_server as implementation
from qperiapt_continuity_reference.network import TcpTransport
from qperiapt_continuity_reference.network_server import Server,Limits
from qperiapt_continuity_reference.connection_run import Cancellation,Cancelled,Run

FRAME=b'QPCXCH01\1x'


class NetworkChecks(unittest.TestCase):
    def setUp(self):self.servers=[];self.release=[]

    def launch(self,handler=lambda frame,_run:frame,*,limits=None,host='127.0.0.1'):
        server=Server((host,0),handler,limits=limits);result={}
        def work():
            try:result['stats']=server.serve()
            except BaseException as error:result['error']=error
        thread=threading.Thread(target=work);thread.start();self.servers.append((server,thread,result))
        return server,thread,result

    def stop(self,item):
        server,thread,result=item;server.close();thread.join(timeout=4)
        self.assertFalse(thread.is_alive(),'actual worker must terminate')
        if 'error' in result:raise result['error']
        return result['stats']

    def tearDown(self):
        for event in self.release:event.set()
        for item in self.servers:self.stop(item)

    def test_real_ipv4_ipv6_roundtrip_and_closed_listener(self):
        for host in ('127.0.0.1','::1'):
            with self.subTest(host=host):
                item=self.launch(host=host);carrier=TcpTransport(item[0].address)
                self.assertEqual(carrier(FRAME,time.monotonic()+2,Cancellation()),FRAME)
                stats=self.stop(item);self.assertEqual(stats['completed_responses'],1)
                with self.assertRaises(OSError):carrier(FRAME,time.monotonic()+1,Cancellation())

    def test_idle_capacity_eviction_admits_a_complete_request(self):
        item=self.launch(limits=Limits(pending=2,per_ip=2,read_timeout=5,operation_timeout=5))
        with socket.create_connection(item[0].address,timeout=1) as first,socket.create_connection(item[0].address,timeout=1) as second:
            start=time.monotonic();self.assertEqual(TcpTransport(item[0].address)(FRAME,start+2,Cancellation()),FRAME)
            self.assertLess(time.monotonic()-start,2)
            self.assertGreaterEqual(self.stop(item)['evicted_incomplete'],1)

    def test_oversized_prefix_never_calls_owner(self):
        calls=[]
        def handler(frame,_run):calls.append(frame);return frame
        item=self.launch(handler)
        with socket.create_connection(item[0].address,timeout=1) as stream:
            stream.sendall(bytes([255])*4);self.assertEqual(stream.recv(1),b'')
        self.assertEqual(calls,[]);self.assertEqual(self.stop(item)['read_errors'],1)

    def test_busy_owner_and_shutdown_keep_actual_worker_owned(self):
        entered=threading.Event();release=threading.Event();self.release.append(release);calls=[]
        def handler(frame,_run):
            calls.append(frame);entered.set()
            if not release.wait(timeout=3):raise TimeoutError('test release absent')
            return frame
        item=self.launch(handler);client_result={}
        def first():
            try:client_result['response']=TcpTransport(item[0].address)(FRAME,time.monotonic()+4,Cancellation())
            except Exception as error:client_result['error']=error
        client=threading.Thread(target=first);client.start()
        try:
            self.assertTrue(entered.wait(timeout=1))
            with self.assertRaises((OSError,ValueError)):TcpTransport(item[0].address)(FRAME,time.monotonic()+1,Cancellation())
            item[0].close();time.sleep(.05);self.assertTrue(item[1].is_alive(),'shutdown detached a live callback')
        finally:release.set();client.join(timeout=4)
        self.assertFalse(client.is_alive());self.assertIn('error',client_result)
        stats=self.stop(item);self.assertEqual(len(calls),1);self.assertEqual(stats['rejected_busy'],1)
        self.assertEqual(stats['completed_responses'],0)

    def test_partial_response_cancellation_closes_socket(self):
        listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(2)
        ready=threading.Event();result={};cancel=Cancellation()
        def peer():
            try:
                with listener:
                    stream,_=listener.accept()
                    with stream:
                        stream.settimeout(2);request=bytearray()
                        while len(request)<14:
                            part=stream.recv(14-len(request))
                            if not part:raise ValueError('missing actual request')
                            request.extend(part)
                        stream.sendall(b'\0\0');ready.set()
                        try:part=stream.recv(1)
                        except (ConnectionResetError,ConnectionAbortedError):result['disconnected']='reset'
                        else:
                            if part:raise ValueError('extra data after cancellation')
                            result['disconnected']='eof'
            except Exception as error:result['server_error']=error;ready.set()
        server=threading.Thread(target=peer);server.start();address=listener.getsockname()
        def request():
            try:result['response']=TcpTransport(address)(FRAME,time.monotonic()+3,cancel)
            except Exception as error:result['client_error']=error
        client=threading.Thread(target=request);client.start()
        try:self.assertTrue(ready.wait(timeout=2))
        finally:cancel.cancel();client.join(timeout=4);server.join(timeout=4)
        self.assertFalse(client.is_alive());self.assertFalse(server.is_alive())
        if 'server_error' in result:raise result['server_error']
        self.assertIsInstance(result.get('client_error'),Cancelled);self.assertIn(result['disconnected'],('eof','reset'))

    def test_enclosing_deadline_and_invalid_limits(self):
        deadline=time.monotonic()+1;self.assertEqual(Run.until(deadline).deadline,deadline)
        for value in (time.monotonic()-1,time.monotonic()+121,float('nan')):
            with self.assertRaises(ValueError):Run.until(value)
        for values in ({'pending':0},{'per_ip':9},{'read_timeout':0},{'operation_timeout':121},{'pending':True}):
            with self.assertRaises(ValueError):Limits(**values)
        with self.assertRaises(ValueError):TcpTransport(('localhost',443))
        with self.assertRaises(ValueError):TcpTransport(('127.0.0.1',0))


if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(NetworkChecks))
    print(json.dumps({'tests':result.testsRun,'successful':result.wasSuccessful(),
        'failures':len(result.failures),'errors':len(result.errors),'skipped':len(result.skipped),
        'expected_failures':len(result.expectedFailures),'unexpected_successes':len(result.unexpectedSuccesses),
        'provider_version':fixture.provider.__version__,'openssl':fixture.backend.openssl_version_text(),
        'implementation':str(Path(implementation.__file__).resolve()),'private_fixtures_retained':str(fixture.args.private_output)}))
    raise SystemExit(0 if result.wasSuccessful() else 1)
