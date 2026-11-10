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
            original = search.theory(archive.read('lineage/original-35-query.spthy'))
            baseline = search.theory(archive.read('lineage/previous-main517.spthy'))
            self.assertEqual(len(original.queries), 35)
            self.assertEqual(len(baseline.queries), 38)
            self.assertEqual(len(contract.queries), 40)
            for prior in (original, baseline):
                self.assertEqual(prior.prefix, contract.prefix)
                for query in prior.queries:
                    current = contract.by_name[query.name]
                    self.assertEqual((query.mode, query.formula), (current.mode, current.formula))
            self.assertEqual([q.name for q in baseline.queries],
                             [q.name for q in contract.queries if q.name in baseline.by_name])
            self.assertEqual(set(contract.by_name) - set(baseline.by_name), {
                'no_strictly_ordered_duplicate_local_phase',
                'local_phase_event_is_unique_per_role_epoch_and_phase',
            })
            terminal = search.strict_json(archive.read('runs/RESULT.json'))
            self.assertEqual(terminal['returncode'], 0)
            self.assertNotIn('failure', terminal)
            self.assertTrue(terminal['complete_replay_accepted'])
            self.assertTrue(terminal['selected_theorem_verified'])
            self.assertTrue(terminal['main_secrecy_verified'])
            self.assertFalse(terminal['release_claim_eligible'])
            self.assertEqual(terminal['output_sha256'], search.MODEL_SHA256)
            source = next(arg for arg in terminal['argv']
                          if arg.endswith('.spthy') and not arg.startswith('--'))
            output = next(arg.removeprefix('--output=') for arg in terminal['argv']
                          if arg.startswith('--output='))
            results = search.inventory(archive.read('runs/stdout'), Path(source), Path(output), contract)
            self.assertEqual(results, terminal['results'])
            self.assertEqual(results[search.MAIN], {'mode': 'all-traces', 'status': 'verified', 'steps': 508})
            self.assertEqual(results[search.ORIGIN]['status'], 'verified')
            reusable = [q.name for q in contract.queries if q.reusable]
            self.assertEqual(len(reusable), 24)
            self.assertTrue(all(results[name]['status'] == 'verified' for name in reusable))
            self.assertEqual(sum(row['mode'] == 'exists-trace' and row['status'] == 'analysis incomplete'
                                 for row in results.values()), 11)
            self.assertEqual(results['initial_epoch_traffic_advances_counter_is_executable']['steps'], 414)
            for stage in ('local-phase-unique-joint-replay-01', 'local-phase-factored-joint-replay-01'):
                failed = search.strict_json(archive.read('attempts/' + stage + '/RESULT.json'))
                self.assertEqual(failed['failure']['kind'], 'timeout')
                self.assertFalse(failed['complete_replay_accepted'])
                self.assertEqual(failed['maximum_seconds'], terminal['maximum_seconds'])
            rejected = search.strict_json(archive.read('attempts/ordered-phase-projection-diagnostic-01/RESULT.json'))
            self.assertIn('failure', rejected)
            self.assertIn(b'invalid proof step', archive.read('attempts/ordered-phase-projection-diagnostic-01/output.spthy'))

    def test_previous_generation_origin_checkpoint_and_failure_remain_intact(self):
        directory = search.ROOT / 'research/sdk-alpha1/evidence/20261030-generation-secret-origin'
        raw = (directory / 'CAPTURE.zip').read_bytes()
        self.assertEqual(search.sha(raw), '9df4eefd5d08098018cba24565b89671c7292bd250dcf8e4c82fc3600e25dd92')
        self.assertEqual(len(raw), 112939)
        model_sha = 'b2c6e233a3b2bb4ca75f8f438f84caca497523a32e6c86f05e467b5710425953'
        with zipfile.ZipFile(directory / 'CAPTURE.zip') as archive:
            data = archive.read('proof/current.spthy')
            self.assertEqual(search.sha(data), model_sha)
            contract = search.theory(data)
            previous = search.theory(archive.read('lineage/previous-35-query.spthy'))
            self.assertEqual(previous.prefix, contract.prefix)
            added = 'reserved_parent_has_hash_constructor'
            self.assertEqual(tuple(q for q in contract.queries if q.name != added), previous.queries)
            self.assertEqual(set(contract.by_name) - set(previous.by_name),
                             {added})
            terminal = search.strict_json(archive.read('runs/RESULT.json'))
            self.assertEqual(terminal['returncode'], 0)
            self.assertNotIn('failure', terminal)
            self.assertTrue(terminal['complete_replay_accepted'])
            self.assertTrue(terminal['selected_theorem_verified'])
            self.assertFalse(terminal['main_multi_epoch_secrecy_verified'])
            self.assertFalse(terminal['release_claim_eligible'])
            self.assertEqual(terminal['output_sha256'], model_sha)
            source = next(arg for arg in terminal['argv']
                          if arg.endswith('.spthy') and not arg.startswith('--'))
            output = next(arg.removeprefix('--output=') for arg in terminal['argv']
                          if arg.startswith('--output='))
            results = search.inventory(archive.read('runs/stdout'),
                                       Path(source), Path(output), contract)
            self.assertEqual(results, terminal['results'])
            self.assertEqual(results[search.ORIGIN]['status'], 'verified')
            self.assertEqual(results[search.ORIGIN]['steps'], 591)
            self.assertEqual(results['multi_epoch_fresh_reservations_recover_symbolic_message_secrecy']['status'],
                             'analysis incomplete')
            self.assertEqual(results[added]['status'], 'verified')
            self.assertEqual(sum(q.reusable for q in contract.queries), 19)
            failed = search.strict_json(archive.read('attempts/copying-gc/RESULT.json'))
            self.assertEqual(failed['input_sha256'], terminal['input_sha256'])
            self.assertEqual(failed['returncode'], 251)
            self.assertFalse(failed['complete_replay_accepted'])
            self.assertIn(b'Heap exhausted', archive.read('attempts/copying-gc/stderr'))
            self.assertEqual([arg.replace('-c100', '-c30') for arg in failed['argv']],
                             terminal['argv'])
            for field in ('maximum_seconds', 'heap_gib', 'workers'):
                self.assertEqual(failed[field], terminal[field])

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

                # The nonzero-exit case tests disposition, not startup speed.
                # Keep a distinct finite budget so a busy runner cannot turn it
                # into the timeout case (which intentionally has no returncode).
                budget = 5 if exit_code is not None else 1
                with (mock.patch('formal_toolchain_contract.verify_installed'),
                      mock.patch.object(search, 'load_frontier', return_value=('model', MODEL, search.theory(MODEL))),
                      mock.patch.object(search, 'TIMEOUT', budget),
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
