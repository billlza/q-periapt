"""Reject altered theories and incomplete or conditional research results."""
from pathlib import Path
import json
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

import continuity_multi_epoch_search as search


MODEL = b'''theory Example
begin
functions: h/1
rule Produce:
 [ Fr(~x) ] --[ Produced(~x) ]-> [ Out(h(~x)) ]
restriction Equality:
 "All x y #i. Eq(x,y)@i ==> x = y"
lemma helper [reuse,
              use_induction]:
 all-traces
 "All x #i. Produced(x)@i ==> Ex #j. Produced(x)@j"
by sorry
lemma target:
 exists-trace
 "Ex x #i. Produced(x)@i"
by sorry
end
'''


def summary(contract, *, statuses=None, modes=None, source=Path('/input.spthy'), output=Path('/output.spthy')):
    statuses = statuses or {}
    modes = modes or {}
    lines = ['=' * 78, 'summary of summaries:', f'analyzed: {source}',
             f'  output:          {output}', '  processing time: 1.25s']
    lines += [f'  {q.name} ({modes.get(q.name, q.mode)}): {statuses.get(q.name, "verified")} (1 steps)'
              for q in contract.queries]
    return ('\n'.join([*lines, '=' * 78]) + '\n').encode()


class TheoryContract(unittest.TestCase):
    def test_multiline_attributes_and_modes_are_preserved(self):
        contract = search.theory(MODEL)
        self.assertEqual(len(contract.queries), 2)
        self.assertTrue(contract.by_name['helper'].reusable)
        self.assertFalse(contract.by_name['target'].reusable)
        self.assertEqual(contract.by_name['target'].mode, 'exists-trace')

    def test_comments_proof_steps_and_whitespace_do_not_change_contract(self):
        changed = MODEL.replace(b'functions: h/1', b'/* nested /* inner */ comment */\n functions: h/1')
        changed = changed.replace(b'by sorry', b'/* observed proof tree */\nby contradiction')
        self.assertEqual(search.theory(MODEL), search.theory(changed))

    def test_prime_variables_do_not_hide_later_comments(self):
        changed = MODEL.replace(b'Produced(~x)', b"Produced(~x')")
        changed = changed.replace(b'functions: h/1', b"functions: h/1, f'/1 // comment\n")
        self.assertEqual(search.theory(changed), search.theory(changed.replace(b'// comment', b'// changed')))
        self.assertNotEqual(search.theory(MODEL), search.theory(changed))

    def test_rule_restriction_equation_and_formula_mutations_differ(self):
        for before, after in ((b'Out(h(~x))', b'Out(~x)'),
                              (b'x = y', b'x = x'),
                              (b'functions: h/1', b'functions: h/2'),
                              (b'Ex #j. Produced(x)@j', b'Ex #j. Produced(x)@j & #j < #i'),
                              (b'all-traces', b'exists-trace'),
                              (b'use_induction', b'use_induction, reuse')):
            with self.subTest(before=before):
                self.assertNotEqual(search.theory(MODEL), search.theory(MODEL.replace(before, after, 1)))

    def test_hiding_a_reusable_lemma_changes_contract(self):
        changed = MODEL.replace(b'lemma target:', b'lemma target [hide_lemma=helper]:')
        self.assertNotEqual(search.theory(MODEL), search.theory(changed))

    def test_unknown_or_empty_lemma_declaration_is_rejected(self):
        for data in (MODEL.replace(b'lemma target:', b'lemma target ???:'),
                     MODEL.replace(b'"Ex x #i. Produced(x)@i"', b'""'),
                     MODEL.replace(b'lemma target:', b'lemma helper:')):
            with self.subTest(data=data), self.assertRaises(search.SearchContractError):
                search.theory(data)

    def test_operational_rules_after_query_are_rejected(self):
        changed = MODEL.replace(b'lemma target:', b'rule Later: [ ] --> [ ]\nlemma target:')
        with self.assertRaises(search.SearchContractError):
            search.theory(changed)

    def test_unterminated_comment_quote_and_end_fail(self):
        for data in (MODEL + b'/* incomplete', MODEL.replace(b'end\n', b''),
                     MODEL.replace(b'functions: h/1', b'functions: h/1\nend'),
                     MODEL.replace(b'"Ex x #i. Produced(x)@i"', b'"Ex x #i. Produced(x)@i')):
            with self.subTest(data=data), self.assertRaises(search.SearchContractError):
                search.theory(data)

    def test_literal_comment_markers_are_not_deleted_from_query(self):
        changed = MODEL.replace(b'Produced(x)@i"', b"Produced('/* literal */')@i\"")
        self.assertIn("'/* literal */'", search.theory(changed).by_name['target'].formula)

    def test_size_limit_is_enforced_before_parsing(self):
        with self.assertRaises(search.SearchContractError):
            search.theory(b'x' * (search.MAX_BYTES + 1))


class ResultContract(unittest.TestCase):
    def setUp(self):
        self.contract = search.theory(MODEL)
        self.source = Path('/input.spthy')
        self.output = Path('/output.spthy')

    def parse(self, data):
        return search.inventory(data, self.source, self.output, self.contract)

    def test_full_inventory_passes(self):
        rows = self.parse(summary(self.contract))
        self.assertEqual(set(rows), {'helper', 'target'})

    def test_incomplete_target_is_retained_not_marked_verified(self):
        rows = self.parse(summary(self.contract, statuses={'target': 'analysis incomplete'}))
        self.assertEqual(rows['target']['status'], 'analysis incomplete')

    def test_falsified_target_is_distinct_from_incomplete(self):
        rows = self.parse(summary(self.contract, statuses={'target': 'falsified - found trace'}))
        self.assertEqual(rows['target']['status'], 'falsified - found trace')

    def test_unproved_reusable_premise_blocks_conditional_success(self):
        for state in ('analysis incomplete', 'falsified - found trace'):
            with self.subTest(state=state), self.assertRaises(search.SearchContractError):
                self.parse(summary(self.contract, statuses={'helper': state}))

    def test_missing_extra_or_duplicate_result_is_refused(self):
        data = summary(self.contract)
        helper = b'  helper (all-traces): verified (1 steps)\n'
        for changed in (data.replace(helper, b''), data.replace(helper, helper + helper),
                        data.replace(helper, helper + b'  extra (all-traces): verified (1 steps)\n')):
            with self.subTest(changed=changed), self.assertRaises(search.SearchContractError):
                self.parse(changed)

    def test_wrong_mode_and_certificate_paths_fail(self):
        for changed in (summary(self.contract, modes={'target': 'all-traces'}),
                        summary(self.contract, source=Path('/other.spthy')),
                        summary(self.contract, output=Path('/other.spthy'))):
            with self.subTest(changed=changed), self.assertRaises(search.SearchContractError):
                self.parse(changed)

    def test_partial_summary_warning_and_invalid_output_fail(self):
        data = summary(self.contract)
        for changed in (data[:-79], data.replace(b'  processing time: 1.25s', b'unknown'),
                        b'warning: premise changed\n' + data,
                        data.replace(b'analysis incomplete', b'verified') + b'\xff'):
            with self.subTest(changed=changed), self.assertRaises((ValueError, UnicodeError)):
                self.parse(changed)

    def test_strict_json_rejects_duplicate_and_nonfinite(self):
        for data in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}',
                     b'{"a":1e999}', b'{"a":-1e999}', b'{"a":\xff}', b'{'):
            with self.subTest(data=data), self.assertRaises(search.SearchContractError):
                search.strict_json(data)


class CommittedFrontier(unittest.TestCase):
    def test_current_capture_preserves_queries_and_has_full_replay_inventory(self):
        def read(path, maximum):
            data = path.read_bytes()
            self.assertLessEqual(len(data), maximum)
            return data

        member, data, contract = search.load_frontier(search.ROOT, read)
        self.assertEqual(member, 'proof/current.spthy')
        self.assertEqual(search.sha(data), search.MODEL_SHA256)
        with zipfile.ZipFile(search.ROOT / search.CAPTURE / 'CAPTURE.zip') as archive:
            previous = search.theory(archive.read('lineage/previous-34-query.spthy'))
            self.assertEqual(previous.prefix, contract.prefix)
            for name, query in previous.by_name.items():
                self.assertEqual(query, contract.by_name[name])
            self.assertEqual(set(contract.by_name) - set(previous.by_name),
                             {'signed_final_payload_has_public_constructors'})
            prefix = 'runs/p0-snapshot-closure-732/closure-replay'
            terminal = search.strict_json(archive.read(prefix + '-TERMINAL.json'))
            self.assertEqual(terminal['returncode'], 0)
            self.assertFalse(terminal['timed_out'])
            self.assertFalse(terminal['accepted'])
            self.assertEqual(terminal['output_sha256'], search.MODEL_SHA256)
            source = next(arg for arg in terminal['argv']
                          if arg.endswith('.spthy') and not arg.startswith('--'))
            output = next(arg.removeprefix('--output=') for arg in terminal['argv']
                          if arg.startswith('--output='))
            results = search.inventory(archive.read(prefix + '.stdout'),
                                       Path(source), Path(output), contract)
            self.assertEqual(results, terminal['results'])
            self.assertEqual(results[search.ORIGIN]['status'], 'analysis incomplete')
            self.assertEqual(results['multi_epoch_fresh_reservations_recover_symbolic_message_secrecy']['status'],
                             'analysis incomplete')
            self.assertEqual(results['signed_final_payload_has_public_constructors']['status'], 'verified')

    def test_changed_capture_bytes_are_refused(self):
        def changed(path, maximum):
            raw = path.read_bytes()
            self.assertLessEqual(len(raw), maximum)
            if path.name == 'CAPTURE.zip':
                raw = bytes([raw[0] ^ 1]) + raw[1:]
            return raw

        with self.assertRaisesRegex(search.SearchContractError, 'retained capture changed'):
            search.load_frontier(search.ROOT, changed)


class FailedExecutionEvidence(unittest.TestCase):
    def test_nonzero_and_timeout_keep_real_streams_without_acceptance(self):
        import bounded_process
        real_capture = bounded_process.capture_output
        for exit_code in (7, None):
            with self.subTest(exit_code=exit_code), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary).resolve() / 'research'
                program = ("import os,time; os.write(1,b'partial proof output\\n'); "
                           "os.write(2,b'partial prover diagnostic\\n'); " +
                           ("time.sleep(5)" if exit_code is None else "raise SystemExit(7)"))

                def execute(_argv, **options):
                    return real_capture([sys.executable, '-c', program], **options)

                with (mock.patch('formal_toolchain_contract.verify_installed'),
                      mock.patch.object(search, 'load_frontier', return_value=('model', MODEL, search.theory(MODEL))),
                      mock.patch.object(search, 'TIMEOUT', 1),
                      mock.patch('bounded_process.capture_output', side_effect=execute),
                      self.assertRaises((search.SearchContractError, bounded_process.BoundedProcessError))):
                    search.run(output)
                terminal = json.loads((output / '01-baseline-replay.terminal.json').read_text())
                self.assertFalse(terminal['accepted_execution'])
                self.assertIn('failure', terminal)
                self.assertNotIn('results', terminal)
                if exit_code is None:
                    self.assertNotIn('returncode', terminal)
                    self.assertFalse(terminal['streams_complete'])
                    self.assertEqual(terminal['failure']['kind'], 'timeout')
                    self.assertFalse(terminal['failure']['cleanup_ambiguous'])
                else:
                    self.assertEqual(terminal['returncode'], exit_code)
                    self.assertTrue(terminal['streams_complete'])
                for suffix, expected in [('stdout', b'partial proof output\n'),
                                         ('stderr', b'partial prover diagnostic\n')]:
                    raw = (output / ('01-baseline-replay.' + suffix)).read_bytes()
                    self.assertEqual(raw, expected)
                    self.assertEqual(terminal[suffix + '_sha256'], search.sha(raw))
                    self.assertEqual(terminal[suffix + '_bytes'], len(raw))
                report = json.loads((output / 'RESULT.json').read_text())
                self.assertFalse(report['selected_theorem_verified'])
                self.assertFalse(report['release_claim_eligible'])
                self.assertIn('failure', report)


if __name__ == '__main__':
    unittest.main()
