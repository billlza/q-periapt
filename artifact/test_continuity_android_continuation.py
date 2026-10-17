"""Synthetic linkage/rejection controls; these are not cryptographic executions."""
from pathlib import Path
import tempfile
import unittest
import zipfile

import continuity_android_contract as contract
import continuity_android_continuation as continued
import continuity_android_pending as pending
import continuity_android_policy_renewal as renewal
from continuity_c_witness import commit
from test_continuity_android_pending import process_fixture
from test_continuity_android_policy_renewal import fixture as renewal_fixture
import rust_sdk_profile as sdk


def fixture(directory: Path, label: str) -> bytes:
    carrier, profile, _ = label.split('-')
    stdout = process_fixture(directory, label).replace(pending.PROCESS_TESTS[label].encode(), continued.TESTS[label].encode())
    base = directory / (label + '-continuation'); (directory / (label + '-process-loss')).rename(base)
    policy_root = directory / 'synthetic-policy'; policy_root.mkdir(); renewal_fixture(policy_root, profile)
    source = policy_root / (carrier + '-' + profile)
    def put(name, value):
        path=base/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(value)
    for path in (source/'inputs').rglob('*'):
        if path.is_file():put(str(path.relative_to(source)),path.read_bytes())
    for name, _ in continued.cases(carrier):
        if name in ('policy-rekeyed','policy-fresh-message'):continue
        for suffix in ('','.stdout','.stderr'):put('continued-'+name+suffix,(source/(name+suffix)).read_bytes())
    for name in renewal.public(carrier):
        if name.startswith('inputs/') or name in {n+s for n,_ in renewal.cases(carrier) for s in ('','.stdout','.stderr')}:continue
        if name in ('policy-process-count','policy-effect-before','policy-effect-after'):continue
        put(name,(source/name).read_bytes())
    for target, origin in [('original.request','original.request'),('activated.request','activated.request'),
        ('original-identity-after','original.request'),('genesis','prepared'),('roster-connected','policy-connected'),
        ('roster-unknown','policy-message-unknown'),('roster-effect-before','policy-effect-before'),
        ('continued-policy-effect-before','policy-effect-before'),('continued-policy-effect-after','policy-effect-after')]:put(target,(source/origin).read_bytes())
    session=(source/'policy-connected').read_bytes();message=(source/'policy-message-unknown').read_bytes()[32:]
    put('authority-created',(source/'inputs/authority-checkpoint').read_bytes())
    put('roster-peer-associated',bytes([134])*32+(1).to_bytes(8,'big')+(source/'inputs/trusted-account').read_bytes())
    put('inputs/connection-session',session);put('inputs/connection-message',message)
    authority=commit(b'Q-PERIAPT-CONTINUITY-ANCHOR-AUTHORITY/v1',(source/'inputs/witness-id').read_bytes()+(source/'inputs/witness-public').read_bytes())
    subject=(source/'prepared').read_bytes()[36:132]
    proposal=bytearray((base/'inputs/pending-proposal').read_bytes());proposal[8:40]=authority;proposal[40:136]=subject
    metadata=bytearray((base/'inputs/pending-metadata').read_bytes());metadata[8:361]=proposal[8:361]
    proposal[361:393]=commit(b'Q-PERIAPT-CONTINUITY-PENDING-WRITE-METADATA/v1',metadata)
    binding=commit(b'Q-PERIAPT-CONTINUITY-PENDING-WRITE-RECOVERY/v1',proposal)
    frame=len(metadata).to_bytes(4,'big')+(1).to_bytes(4,'big')+proposal+bytes(3)+binding+metadata+b's'
    for name in ['pending-before-expiry','pending-after-expiry','pending-after-cancel','pending-after-process-cut']:put(name,frame)
    put('inputs/pending-proposal',proposal);put('inputs/pending-metadata',metadata)
    for phase,name in [(1,'query-process-cut'),(2,'confirmation-result-cut')]:put(name,b'QPPCUT01'+bytes([phase])+binding)
    put('process-cut-control',b'QPCCAN01'+b't'*32+binding+b'\1\4\0\x4d')
    advance_name='processed-original-advance' if label.endswith('-applied') else 'unprocessed-original-advance'
    advance=bytearray((base/advance_name).read_bytes());advance[12:140]=authority+subject;put(advance_name,advance)
    trace=bytearray((base/'query-confirmation-transcript').read_bytes())
    for index in range(4):trace[index*7334+13:index*7334+141]=authority+subject
    put('query-confirmation-transcript',trace);put('process-cut-transcript',trace[:7334])
    put('completed',pending.CONTINUED_COMPLETED);put('continued-policy-process-count',(37).to_bytes(8,'big'))
    fresh=session+b'z'*32;put('continued-policy-fresh-message',fresh);put('continued-policy-rekeyed',b'\1')
    for name,mode in [('policy-fresh-message','policy-peer-send'),('policy-rekeyed','policy-peer-rekey')]:
        put('continued-'+name+'.stdout',f'{profile}:{mode}:passed\n'.encode());put('continued-'+name+'.stderr',b'')
    put('continued-policy-fresh-effect',fresh+continued.FRESH_PAYLOAD);put('continued-policy-effect-count',(2).to_bytes(4,'big'))
    for mode,tail in [('message',f'served:2:0:1:0\n{session.hex()}\n{message.hex()}\n'),('rekey','server-rekey-1\n'),
                      ('fresh-message',f'served:2:0:1:1\n{session.hex()}\n{fresh[32:].hex()}\n')]:
        put('traffic-continued-policy-'+mode+'.stdout',b'listening:44333\n'+tail.encode());put('traffic-continued-policy-'+mode+'.stderr',b'')
    return stdout+continued.marker(label).encode()+b'\n'


class ContinuationReaderTests(unittest.TestCase):
    def test_original_recovery_renewal_rekey_and_fresh_effect_are_all_required(self):
        for label in continued.TESTS:
            with self.subTest(label=label),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);stdout=fixture(root,label)
                result=continued.verify_execution(stdout,root,label)[label+'-continuation']
                self.assertEqual(result['foreign_processes'],60 if label.endswith('-applied') else 61)
                self.assertEqual(result['business_effects'],2)
                for name in continued.public(label):self.assertTrue((root/(label+'-continuation')/name).is_file(),name)

    def test_unrelated_identity_missing_permission_or_only_old_traffic_cannot_pass(self):
        label='tls-recoverable-applied'
        for name,value in [('continued-policy-process-count',bytes(8)),('continued-expired-activation',bytes(4)),
            ('continued-final.identity',b'new identity'),('inputs/witness-id',b'x'*32),('continued-policy-rekeyed',b'\0'),
            ('continued-policy-fresh-effect',b'old effect'),('continued-policy-effect-after',b'changed'),
            ('traffic-continued-policy-fresh-message.stdout',b'listening:44333\nserved:2:0:1:0\n'),
            ('traffic-continued-policy-rekey.stderr',b'failed')]:
            with self.subTest(name=name),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);stdout=fixture(root,label);(root/(label+'-continuation')/name).write_bytes(value)
                with self.assertRaises(ValueError):continued.verify_execution(stdout,root,label)

    def test_previous_process_loss_capture_remains_scoped_to_its_old_catalog(self):
        path=sdk.ROOT/'research/sdk-alpha1/evidence/20261015-android-pending-process-loss/CAPTURE.zip'
        with tempfile.TemporaryDirectory() as temporary,zipfile.ZipFile(path) as bundle:
            root=Path(temporary)
            for name in bundle.namelist():
                if name.startswith('host/public-04/'):
                    target=root/name.removeprefix('host/public-04/');target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(bundle.read(name))
            stdout=bundle.read('host/host-run-04.stdout')
            for label in pending.PROCESS_TESTS:pending.verify_execution(stdout,root,label,batch=True,process_loss=True,catalog=contract.PROCESS_PENDING_TESTS)
            with self.assertRaises(ValueError):pending.verify_execution(stdout,root,batch=True,process_loss=True)
