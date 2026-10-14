from pathlib import Path
import json
import shutil
import tempfile
import unittest
import zipfile
import continuity_android_joint_cycle as cycle
import rust_sdk_profile as sdk


class JointCycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temp = tempfile.TemporaryDirectory(); cls.addClassCleanup(temp.cleanup); cls.root = Path(temp.name)
        archive = sdk.ROOT / 'research/sdk-alpha1/evidence/20261014-android-joint-cycle/HOST_CAPTURE.zip'
        with zipfile.ZipFile(archive) as bundle:
            cls.stdout = bundle.read('debug-joint-cycle.stdout')
            for name in bundle.namelist():
                if not name.startswith('routes/'): continue
                path = cls.root / name
                if not path.is_relative_to(cls.root) or '..' in Path(name).parts: raise ValueError('archive member')
                path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(bundle.read(name))
        device = sdk.ROOT / 'research/sdk-alpha1/evidence/20261014-android-joint-cycle/DEVICE_CAPTURE.zip'
        with zipfile.ZipFile(device) as bundle:
            cls.device_stdout = bundle.read('run/execution.stdout')
            cls.device_state = json.loads(bundle.read('device/STATE.json'))
            for name in bundle.namelist():
                if not name.startswith('public/'): continue
                path = cls.root / 'device' / name
                if not path.is_relative_to(cls.root) or '..' in Path(name).parts: raise ValueError('archive member')
                path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(bundle.read(name))

    def verify(self, directory, label, stdout=None):
        carrier, trust = label.split('-')
        return cycle.verify_execution(self.stdout if stdout is None else stdout, directory, carrier, trust, batch=True)

    def mutate(self, label, name, change):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / 'public'; shutil.copytree(self.root / 'routes' / label / 'public', root)
            path = root / label / name; path.write_bytes(change(path.read_bytes()))
            with self.assertRaises(ValueError): self.verify(root, label)

    def test_six_actual_two_generation_routes(self):
        for label in cycle.TESTS:
            result = self.verify(self.root / 'routes' / label / 'public', label)
            self.assertEqual(result['generations'], 2)
            self.assertEqual(result['foreign_processes'], 57 if label.startswith('local-') else 80)
            self.assertEqual(result['real_expiries'], 3)

    def test_accepted_physical_tls_recoverable_route(self):
        result = cycle.verify_execution(self.device_stdout, self.root / 'device/public', 'tls', 'recoverable')
        self.assertEqual(result['foreign_processes'], 80)
        self.assertTrue(self.device_state['completed'] and self.device_state['cleanup'])
        self.assertFalse(self.device_state.get('owned_reverse_ports'))
        self.assertEqual(len(self.device_state['cases']), 80)
        self.assertEqual(len({row['pid'] for row in self.device_state['cases']}), 80)
        self.assertTrue(all(row['process_absent_after_stop'] for row in self.device_state['cases']))

    def test_current_predecessor_cannot_revert_to_original(self):
        label = 'signed-fixed'
        for name in ('cycle-joint-before-stage', 'cycle-joint-staged', 'cycle-joint-history-0', 'cycle-joint-activated'):
            self.mutate(label, name, lambda data: bytes(len(data)))
        for name, offset in (('cycle-joint-request',168), ('cycle-joint-final-request',128),
                             ('cycle-inputs/previous-policy-authorization',0), ('cycle-inputs/policy-previous/policy-digest',0)):
            def flip(data, at=offset):
                value=bytearray(data); value[at]^=1; return bytes(value)
            self.mutate(label,name,flip)

    def test_refusals_and_real_expiry_cannot_be_omitted(self):
        for label in ('local-recoverable', 'tls-fixed'):
            for name in ('cycle-joint-bad-approval','cycle-joint-missing-predecessor','cycle-joint-bad-predecessor'):
                self.mutate(label,name,lambda _:bytes(4))
            self.mutate(label,'cycle-expiry-observation',lambda value:value[:8]+bytes(8))
            self.mutate(label,'cycle-joint-history-1.stderr',lambda _:b'failed')

    def test_both_lost_commits_and_passive_history_are_retained(self):
        label='tls-recoverable'
        for prefix in ('','cycle-'):
            self.mutate(label,prefix+'joint-commit-unknown',lambda _:bytes(4))
            def change_opcode(data):
                value=bytearray(data);value[204]=6;return bytes(value)
            self.mutate(label,prefix+'joint-lost-commit-request',change_opcode)
        sample=(self.root/'routes'/label/'public'/label/'cycle-joint-explicit-close-transcript').read_bytes()[:7334]
        def new_commit(data):
            value=bytearray(sample);value[0]=1;value[205]=5;return data+bytes(value)
        self.mutate(label,'cycle-joint-expired-history-transcript',new_commit)

    def test_message_and_complete_batch_are_required(self):
        label='local-fixed'
        self.mutate(label,'cycle-policy-message-acknowledged',lambda value:value[:-1]+bytes([value[-1]^1]))
        self.mutate(label,'cycle-policy-effect-after',lambda value:value+b'duplicate')
        root=self.root/'routes'/label/'public'
        line=('test '+cycle.TESTS[label]+' ... ok').encode()
        for damaged in (self.stdout.replace(line,b'',1),self.stdout+line+b'\n',self.stdout.replace(b'6 passed; 0 failed',b'5 passed; 1 failed',1)):
            with self.assertRaises(ValueError):self.verify(root,label,damaged)


if __name__ == '__main__': unittest.main()
