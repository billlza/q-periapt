"""Synthetic collector controls; installed native runs provide protocol evidence."""
import json
from pathlib import Path
import tempfile
import unittest
import continuity_setup_witness_faults as faults


class SetupWitnessFaultContractTests(unittest.TestCase):
    def phases(self,carrier):
        plain=[4,4,8,8,12] if carrier=='mutual-tls' else [4,10,14,26,30]
        tls=[0,6,6,18,18] if carrier=='mutual-tls' else [0]*5
        stages=('before_activation','after_activation','before_reconciliation','after_reconciliation','total')
        return dict(schema_version=1,completed=True,carrier=carrier,
            **{kind+'_'+stage:value for kind,values in (('plain',plain),('tls',tls)) for stage,value in zip(stages,values)})

    def test_tls_recovery_requires_encrypted_admission_without_plaintext_fallback(self):
        row=self.phases('mutual-tls')
        self.assertEqual(faults.controller_result(json.dumps(row).encode(),'mutual-tls'),row)
        for key,value in [('plain_after_activation',5),('plain_after_reconciliation',9),('tls_before_activation',1),
                          ('tls_before_reconciliation',7),('tls_after_reconciliation',6),('tls_total',19),
                          ('plain_before_reconciliation',4),('plain_total',8),('carrier','signed-tcp')]:
            with self.subTest(key=key),self.assertRaises(ValueError):
                faults.controller_result(json.dumps(dict(row,**{key:value})).encode(),'mutual-tls')

    def test_signed_carrier_and_controller_must_have_bounded_complete_observations(self):
        row=self.phases('signed-tcp')
        self.assertEqual(faults.controller_result(json.dumps(row).encode(),'signed-tcp'),row)
        for key,value in [('tls_total',1),('plain_before_activation',0),('plain_after_reconciliation',14),
                          ('plain_total',129),('plain_total',True),('schema_version',True),('completed',False),('extra',0)]:
            with self.subTest(key=key),self.assertRaises(ValueError):
                faults.controller_result(json.dumps(dict(row,**{key:value})).encode(),'signed-tcp')
        with self.assertRaises(ValueError):
            faults.controller_result(json.dumps(row).encode()[:-1]+b',"completed":true}','signed-tcp')

    def test_collection_carriers_actions_and_profiles_have_separate_owned_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);binary=root/'identity-input';binary.write_bytes(b'constructor only, never executed')
            paths=[]
            for carrier in ('signed-tcp','mutual-tls'):
                for action in ('exit','io'):
                    for profile in ('debug','release'):
                        matrix=faults.Matrix(root,root,profile,{},binary,binary,binary,binary,
                            carrier=carrier,action=action,expected_library=binary)
                        paths.append(matrix.outside);self.assertTrue(matrix.outside.is_relative_to(root))
            self.assertEqual(len(set(paths)),8)
            for carrier,action,profile in [('local','exit','debug'),('signed-tcp','ignore','debug'),('signed-tcp','exit','../escape')]:
                with self.assertRaises(ValueError):
                    faults.Matrix(root,root,profile,{},binary,binary,binary,binary,carrier=carrier,action=action,expected_library=binary)

    def test_helper_inventory_requires_the_live_controller_and_atomic_publisher(self):
        names=faults.HELPERS|{'setup::'+name for name in faults.setup.setup.TESTS.values()}|{'setup::fixture::'+name for name in faults.setup.NATIVE_TESTS}
        data=('\n'.join(name+': test' for name in sorted(names))+'\n7 tests, 0 benchmarks\n').encode()
        faults.helper_inventory(data)
        for name in faults.HELPERS:
            with self.assertRaises(ValueError):faults.helper_inventory(data.replace((name+': test\n').encode(),b''))
            trace=f'test {name} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 6 filtered out;\n'.encode()
            faults.helper_trace(trace,name)
            with self.assertRaises(ValueError):faults.helper_trace(trace.replace(b'1 passed',b'0 passed'),name)
