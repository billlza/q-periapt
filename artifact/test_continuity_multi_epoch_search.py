"""Reject altered theories and incomplete or conditional research results."""
from pathlib import Path
import unittest

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
        for data in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                search.strict_json(data)


if __name__ == '__main__':
    unittest.main()
