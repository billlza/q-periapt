"""Proof editing must preserve contracts, complete siblings and exact provenance."""
import hashlib
import unittest
import contextlib
import io
import json
from pathlib import Path
import tempfile

from continuity_multi_epoch_search import SearchContractError, theory
from continuity_proof_fragments import Fragment, case_spans, collect_closed, restore, main

MODEL = b'''theory FragmentExample
begin
functions: h/1
rule Produce: [ Fr(~x) ] --[ Produced(~x) ]-> [ Out(h(~x)) ]
lemma helper [reuse]:
 "All x #i. Produced(x)@i ==> Ex #j. Produced(x)@j"
by simplify
lemma target:
 "All x #i. Produced(x)@i ==> Ex #j. Produced(x)@j"
induction
  case empty_trace
  by contradiction
next
  case non_empty_trace
  simplify
    case left
    by sorry
  next
    case right
    simplify
      case repeated
      by sorry
    next
      case preserved
      by contradiction
    qed
  qed
qed
end
'''
DIGEST = hashlib.sha256(MODEL).hexdigest()
LEFT = ('non_empty_trace', 'left')
RIGHT = ('non_empty_trace', 'right', 'repeated')


class FragmentRestoration(unittest.TestCase):
    def test_paths_distinguish_nested_cases(self):
        paths = case_spans(MODEL, 'target')
        self.assertIn(LEFT, paths)
        self.assertIn(RIGHT, paths)
        self.assertEqual(MODEL.decode()[slice(*paths[LEFT])], '    by sorry\n')

    def test_only_original_open_leaf_changes(self):
        fixed = restore(MODEL, DIGEST, 'target', [Fragment(LEFT, '    by contradiction\n')])
        self.assertEqual(fixed, MODEL.replace(b'    by sorry\n', b'    by contradiction\n', 1))
        self.assertEqual(theory(fixed), theory(MODEL))

    def test_multiple_disjoint_fragments_preserve_offsets(self):
        fixed = restore(MODEL, DIGEST, 'target', [Fragment(RIGHT, '      by contradiction\n'),
                                                Fragment(LEFT, '    by contradiction\n')])
        self.assertNotIn(b'by sorry', fixed)
        self.assertIn(b'lemma helper [reuse]:', fixed)
        self.assertEqual(theory(fixed), theory(MODEL))

    def test_collect_only_closed_original_holes_without_copying_helper_holes(self):
        candidate = MODEL.replace(b'by simplify\nlemma target:', b'by sorry\nlemma target:')
        candidate = candidate.replace(b'    by sorry\n', b'    by contradiction\n', 1)
        fragments = collect_closed(MODEL, candidate, 'target')
        self.assertEqual(fragments, (Fragment(LEFT, '    by contradiction\n'),))
        restored = restore(MODEL, DIGEST, 'target', fragments)
        self.assertIn(b'by simplify\nlemma target:', restored)
        self.assertNotIn(b'by sorry\nlemma target:', restored)

    def test_wrong_original_digest_unknown_path_and_closed_case_fail(self):
        for digest, path in [('0'*64, LEFT), (DIGEST, ('unknown',)), (DIGEST, ('empty_trace',))]:
            with self.subTest(path=path), self.assertRaises(SearchContractError):
                restore(MODEL, digest, 'target', [Fragment(path, '    by contradiction\n')])

    def test_empty_duplicate_and_overlapping_edits_fail(self):
        fragment = Fragment(LEFT, '    by contradiction\n')
        for edits in [[], [fragment, fragment], [fragment, Fragment(('non_empty_trace',), 'by contradiction\n')]]:
            with self.subTest(edits=edits), self.assertRaises(SearchContractError):
                restore(MODEL, DIGEST, 'target', edits)

    def test_unfinished_invalid_or_unterminated_fragment_fails(self):
        for proof in ['    by sorry\n', '    by admit\n', '', '    by contradiction',
                      '    by contradiction /* invalid proof step */\n']:
            with self.subTest(proof=proof), self.assertRaises(SearchContractError):
                restore(MODEL, DIGEST, 'target', [Fragment(LEFT, proof)])

    def test_comments_do_not_create_cases_or_holes(self):
        proof = '    /* case forged\n       by sorry */\n    by contradiction\n'
        fixed = restore(MODEL, DIGEST, 'target', [Fragment(LEFT, proof)])
        self.assertNotIn(('forged',), case_spans(fixed, 'target'))

    def test_operational_declaration_or_extra_query_in_fragment_is_rejected(self):
        for addition in ['rule Bypass: [ ] --> [ ]', 'restriction Bypass: "All #i. #i = #i"',
                         'lemma fabricated: "All #i. #i = #i"\nby simplify']:
            with self.subTest(addition=addition), self.assertRaises(SearchContractError):
                restore(MODEL, DIGEST, 'target', [Fragment(LEFT, '    by contradiction\n'+addition+'\n')])

    def test_candidate_contract_change_is_not_a_proof_improvement(self):
        for candidate in [MODEL.replace(b'h/1', b'g/1'), MODEL.replace(b'[reuse]', b'[]'),
                          MODEL.replace(b'lemma target:', b'lemma different:')]:
            with self.subTest(candidate=candidate), self.assertRaises(SearchContractError):
                collect_closed(MODEL, candidate, 'target')

    def test_missing_or_duplicate_case_is_rejected(self):
        with self.assertRaises(SearchContractError):
            case_spans(MODEL, 'absent')
        with self.assertRaises(SearchContractError):
            case_spans(MODEL.replace(b'case right', b'case left'), 'target')
        candidate = MODEL.replace(b'case left', b'case removed')
        with self.assertRaises(SearchContractError):
            collect_closed(MODEL, candidate, 'target')

    def test_malformed_fragment_cannot_redirect_an_unrelated_case(self):
        proof = '    by contradiction\n  next\n    case forged\n    by contradiction\n'
        # An extra sibling must not be silently inserted by a fragment.
        with self.assertRaises(SearchContractError):
            restore(MODEL, DIGEST, 'target', [Fragment(LEFT, proof)])


class FragmentCommand(unittest.TestCase):
    def test_command_retains_full_tree_without_claiming_verification(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original, candidate, output = (root / name for name in ('original.spthy', 'candidate.spthy', 'restored.spthy'))
            original.write_bytes(MODEL)
            candidate.write_bytes(MODEL.replace(b'    by sorry\n', b'    by contradiction\n', 1))
            argv = ['--original', str(original), '--original-sha256', DIGEST,
                    '--candidate', str(candidate), '--lemma', 'target', '--output', str(output)]
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(main(argv), 0)
            report = json.loads(stdout.getvalue())
            self.assertFalse(report['security_proof_verified'])
            self.assertFalse(report['release_claim_eligible'])
            self.assertTrue(report['complete_independent_replay_required'])
            self.assertEqual(report['closed_original_leaves'], 1)
            self.assertEqual(report['restored_sha256'], hashlib.sha256(output.read_bytes()).hexdigest())
            self.assertEqual(theory(output.read_bytes()), theory(MODEL))
            before = output.read_bytes()
            with self.assertRaises(FileExistsError):
                main(argv)
            self.assertEqual(output.read_bytes(), before)

    def test_wrong_identity_does_not_publish_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original, candidate, output = (root / name for name in ('original.spthy', 'candidate.spthy', 'restored.spthy'))
            original.write_bytes(MODEL)
            candidate.write_bytes(MODEL.replace(b'    by sorry\n', b'    by contradiction\n', 1))
            with self.assertRaises(SearchContractError):
                main(['--original', str(original), '--original-sha256', '0'*64,
                      '--candidate', str(candidate), '--lemma', 'target', '--output', str(output)])
            self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
