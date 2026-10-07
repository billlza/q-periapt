"""Parser controls are synthetic records, not process/crash or cryptographic evidence."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
import continuity_setup_faults as setup


class SetupFaultContractTests(unittest.TestCase):
    def test_collection_profiles_have_independent_owned_directories(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            # Constructor-only filesystem regression, never executed as native code.
            binary=root/'identity-input';binary.write_bytes(b'constructor-only input')
            values=[setup.Matrix(root,root,profile,{},binary,binary,binary,binary,expected_library=binary)
                    for profile in ('debug','release')]
            self.assertNotEqual(values[0].outside,values[1].outside)
            for value in values:
                self.assertTrue(value.outside.is_dir() and value.outside.is_relative_to(root))
                self.assertEqual(value.command_records,{})
            with self.assertRaises(ValueError):
                setup.Matrix(root,root,'../outside',{},binary,binary,binary,binary,expected_library=binary)

    def cases(self):
        common=dict(completed=True,journal='11'*32,next_account='00'*8+'22'*24)
        return [dict(common,cut=0,side='before',syncs=1,observed_phase=2,outcome_observed=True),
                dict(common,cut=1,side='before',syncs=1,observed_phase=1,outcome_observed=False),
                dict(common,cut=1,side='after',syncs=1,observed_phase=2,outcome_observed=False)]

    def test_unknown_results_must_reach_both_persisted_phases(self):
        cases=self.cases()
        self.assertEqual(setup.coverage(cases),dict(syncs=1,cases=3,creating=1,active=2,unknown_active=1,result_seen_before_interruption=0))
        for index,key,value in [(2,'outcome_observed',True),(1,'observed_phase',2),(2,'observed_phase',1),
                                (0,'outcome_observed',False),(1,'outcome_observed',True)]:
            changed=copy.deepcopy(cases);changed[index][key]=value
            with self.subTest(index=index,key=key,value=value),self.assertRaises(ValueError):setup.coverage(changed)

    def test_every_calibrated_before_and_after_cut_is_required(self):
        cases=self.cases()
        for changed in (cases[:-1],cases+[cases[-1]],[],[None]):
            with self.subTest(changed=changed),self.assertRaises(ValueError):setup.coverage(changed)
        for key,value in [('cut',True),('side','afterwards'),('syncs',2),('syncs',True),('observed_phase',True),('outcome_observed',1),('journal','00'*32)]:
            changed=copy.deepcopy(cases);changed[1][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):setup.coverage(changed)

    def test_original_observation_preserves_zero_position_and_empty_children(self):
        row=dict(schema_version=1,phase=1,journal='11'*32,next_account='00'*8+'22'*24,account_absent=True,archives_empty=True)
        self.assertEqual(setup.observation(json.dumps(row).encode()),row)
        for key,value in [('schema_version',True),('phase',True),('phase',0),('phase',3),('journal','00'*32),
                          ('next_account','11'*32),('account_absent',False),('archives_empty',False),('extra',1)]:
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):
                setup.observation(json.dumps(dict(row,**{key:value})).encode())

    def test_helper_inventory_includes_independent_native_observers(self):
        names=setup.HELPERS|{'setup::'+name for name in setup.setup.TESTS.values()}|{'setup::fixture::'+name for name in setup.NATIVE_TESTS}
        data=('\n'.join(name+': test' for name in sorted(names))+'\n7 tests, 0 benchmarks\n').encode()
        setup.helper_inventory(data)
        for broken in (data.replace(b'inspect_setup_fault_case: test\n',b''),data.replace(b'7 tests',b'6 tests')):
            with self.assertRaises(ValueError):setup.helper_inventory(broken)
