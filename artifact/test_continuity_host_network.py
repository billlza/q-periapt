"""Receipt counterexamples only; synthetic frames do not prove cryptography."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from continuity_host_network import LABELS, REFUSALS, EXCHANGES, NATIVE_EXCHANGES, verify, retain
from evidence_io import read_regular_snapshot


class NetworkReceiptTests(unittest.TestCase):
    def setUp(self):
        self.application=Path('/installed');self.binaries={'/native/session':'a'*64}
        def stats(accepted,completed,evicted=0,errors=0):
            return dict(accepted=accepted,completed_responses=completed,evicted_incomplete=evicted,
                        read_errors=errors,rejected_busy=0,operation_errors=0,last_operation_error=None)
        self.files={}
        def rows(expected):
            rows=[]
            for label,kind in expected:
                row=dict(label=label,kind=kind)
                for side in ('request','response'):
                    identity='tcp-native-2' if label=='tcp-native-3' else label
                    frame=b'QPCXCH01'+bytes([kind+(128 if side=='response' else 0)])+identity.encode()
                    self.files[label+'.'+side]=frame;row[side+'_sha256']=hashlib.sha256(frame).hexdigest()
                rows.append(row)
            return rows
        self.valid=dict(schema_version=1,kind='qperiapt.native_reference_network',completed=True,
            native_sha256=self.binaries.copy(),provider='48.0.1',clock='actual OS time',
            implementation='/installed/qperiapt_continuity_reference/network.py',effects=3,effect_commit_calls=3,confirmed_epoch=2,
            commands=[dict(label=label,exit=1 if label in ('wrong-inbox-journal','network-native-lost') else 0) for label in LABELS],
            refusals=list(REFUSALS),services=[dict(label='network-service-first',pid=11,exit=0,stats=stats(3,3)),
                                            dict(label='network-service-reopened',pid=12,exit=0,stats=stats(14,6,7,1))],
            independent_service=stats(6,6),independent_exchanges=rows(EXCHANGES),native_exchanges=rows(NATIVE_EXCHANGES))
        verify(self.valid,self.binaries,self.application)
        self.files['RESULT.json']=json.dumps(self.valid).encode()
        for label in LABELS:
            for suffix in ('.stdout','.stderr'):self.files[label+suffix]=b''
        for service in self.valid['services']:
            self.files[service['label']+'.stdout']=(json.dumps(dict(service='Listening',carrier='QPCXCH01/TCP',address='127.0.0.1:1234'))+'\n'+
                json.dumps(dict(service='Stopped',stats=service['stats']))+'\n').encode()
            self.files[service['label']+'.stderr']=b''
        for label,retry in (('tcp-lost','tcp-resume-1'),('tcp-native-lost','tcp-native-3')):
            self.files[label+'.request']=self.files[retry+'.request']
            self.files[label+'-upstream.response']=self.files[retry+'.response']

    def reject(self,change):
        bad=copy.deepcopy(self.valid);change(bad)
        with self.assertRaises(ValueError):verify(bad,self.binaries,self.application)

    def test_missing_or_wrong_source_executions_are_refused(self):
        self.reject(lambda r:r.update(commands=[]))
        self.reject(lambda r:r.update(refusals=[]))
        self.reject(lambda r:r.update(native_sha256={}))
        self.reject(lambda r:r.update(implementation='/checkout/network.py'))
        self.reject(lambda r:r['commands'][12].update(exit=0))

    def test_failed_shutdown_idle_starvation_or_owner_errors_are_refused(self):
        self.reject(lambda r:r['services'][0].update(exit=1))
        self.reject(lambda r:r['services'][1].update(pid=11))
        self.reject(lambda r:r['services'][1]['stats'].update(evicted_incomplete=0))
        self.reject(lambda r:r['services'][1]['stats'].update(operation_errors=1))
        self.reject(lambda r:r['independent_service'].update(completed_responses=5))

    def test_missing_retry_changed_bytes_and_duplicate_effects_are_refused(self):
        self.reject(lambda r:r['native_exchanges'].pop())
        self.reject(lambda r:r['native_exchanges'][2].update(request_sha256='0'*64))
        self.reject(lambda r:r.update(effect_commit_calls=4))
        self.reject(lambda r:r.update(effects=True))
        self.reject(lambda r:r.update(confirmed_epoch=True))

    def retain_files(self,files):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);private=root/'private';private.mkdir()
            for name,data in files.items():(private/name).write_bytes(data)
            retain(self.valid,private,root/'public',lambda p:read_regular_snapshot(p,maximum=1024**2,label='synthetic counterexample'))

    def test_original_frames_and_stopped_process_receipts_are_read_back(self):
        self.retain_files(self.files)
        for name in ('tcp-native-3.response','tcp-lost-upstream.response','network-service-first.stdout'):
            files=self.files.copy();files[name]+=b'changed'
            with self.subTest(name=name),self.assertRaises(ValueError):self.retain_files(files)


if __name__=='__main__':unittest.main()
