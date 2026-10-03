"""Synthetic parser controls; real returned-I/O evidence comes from installed runs."""
import copy
import unittest
import continuity_setup_io as io


class SetupIOContractTests(unittest.TestCase):
    def cases(self):
        plan=[1,2,2,3]
        result=[dict(completed=True,cut=0,side='before',syncs=4,sync_phases=plan,injected_phase=0,response_code=0,
                     observed_phase=2,journal='11'*32,next_account='00'*8+'22'*24)]
        for cut,phase in enumerate(plan,1):
            for side in ('before','after'):
                result.append(dict(result[0],cut=cut,side=side,syncs=cut,sync_phases=plan[:cut],injected_phase=phase,
                    response_code={1:204,2:207,3:0}[phase],observed_phase=1 if cut<=2 else 2))
        return result

    def test_unknown_commit_requires_both_original_durable_phases(self):
        cases=self.cases()
        self.assertEqual(io.coverage(cases),dict(syncs=4,cases=9,opening_errors=2,uncertain_creating=2,uncertain_active=2,close_errors_after_commit=2))
        for phase in (1,2):
            changed=copy.deepcopy(cases)
            for row in changed:
                if row['response_code']==207:row['observed_phase']=phase
            with self.assertRaises(ValueError):io.coverage(changed)

    def test_returned_error_cannot_be_relabelled_as_success_or_close(self):
        for index,key,value in [(1,'response_code',0),(3,'response_code',0),(5,'injected_phase',3),(7,'response_code',207),
                                (0,'sync_phases',[1,2,3]),(1,'observed_phase',2),(1,'cut',True),(1,'syncs',True)]:
            cases=self.cases();cases[index][key]=value
            with self.subTest(index=index,key=key),self.assertRaises(ValueError):io.coverage(cases)
        for cases in (self.cases()[:-1],self.cases()+[self.cases()[-1]],[]):
            with self.assertRaises(ValueError):io.coverage(cases)

    def test_injected_errno_must_be_at_the_exact_selected_sync_and_phase(self):
        data=b'armed-io 2 1\nphase 1 0\nbefore 1 0\nafter 1 0\nphase 2 0\nbefore 2 0\nafter 2 0\ninjected-after 2 5\nphase 3 0\nphase 4 0\ndone 2 0\n'
        self.assertEqual(io.events(data,2,'after',phased=True),dict(syncs=2,sync_phases=[1,2],injected_phase=2,phases=[1,2,3,4]))
        for before,after in [(b'injected-after 2 5\n',b''),(b'injected-after 2 5',b'injected-after 2 28'),
            (b'after 2 0',b'after 2 -1'),(b'phase 3 0\n',b'phase 2 0\n'),
            (b'done 2 0',b'done 3 0'),(b'before 2 0',b'before 3 0'),
            (b'injected-after 2 5\n',b'phase 3 0\ninjected-after 2 5\n'),
            (b'phase 4 0\n',b''),(b'armed-io',b'armed')]:
            with self.subTest(before=before,after=after),self.assertRaises(ValueError):io.events(data.replace(before,after),2,'after',phased=True)
        with self.assertRaises(ValueError):io.events(data,2,'before',phased=True)

    def test_opening_failure_can_skip_activation_but_must_record_disposal(self):
        data=b'armed-io 1 0\nphase 1 0\nbefore 1 0\ninjected-before 1 5\nphase 3 0\nphase 4 0\ndone 1 0\n'
        self.assertEqual(io.events(data,1,'before',phased=True)['phases'],[1,3,4])
        with self.assertRaises(ValueError):io.events(data.replace(b'phase 3 0\n',b''),1,'before',phased=True)
        with self.assertRaises(ValueError):io.events(data.replace(b'phase 1 0\n',b''),1,'before',phased=True)

    def test_unphased_smoke_cannot_replace_a_consumer_phase_trace(self):
        data=b'armed-io 1 0\nbefore 1 0\ninjected-before 1 5\ndone 1 0\n'
        self.assertEqual(io.events(data,1,'before',phased=False)['syncs'],1)
        with self.assertRaises(ValueError):io.events(data,1,'before',phased=True)

    def test_success_response_must_bind_original_account_position(self):
        original={'next_account':'00'*8+'22'*24}
        self.assertEqual(io.response(b'setup-io:207\n',original),207)
        self.assertEqual(io.response(b'setup-io:0\n'+original['next_account'].encode()+b'\n',original),0)
        for data in (b'setup-io:0\n',b'setup-io:207\nextra\n',b'setup-io:205\n',b'setup-io:0\n'+b'1'*64+b'\n'):
            with self.assertRaises(ValueError):io.response(data,original)
