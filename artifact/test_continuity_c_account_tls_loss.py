"""The TLS loss report must prove exactly one post-commit loss per original phase."""
import json
import copy
from pathlib import Path
import tempfile
import unittest
import continuity_c_account_tls_loss as loss


class TlsLossTests(unittest.TestCase):
    def setUp(self):
        # Parser-only fixture; these rows claim no TLS or cryptographic execution.
        self.rows = [f"{index} {int(index % 3 == 1)} {int(index % 3 != 1)} 3707\n" for index in range(12)]
        self.wire = "".join(self.rows).encode()
        self.stages = "".join(f"{phase} {index * 3} {index * 3 + 3} {index * 3 + 1}\n" for index, phase in enumerate(loss.PHASES)).encode()

    def test_each_loss_requires_its_original_committed_phase(self):
        row = loss.exchanges(self.wire, self.stages)
        self.assertEqual(row['lost_indices'], [1, 4, 7, 10])
        self.assertEqual(row['native_advances'], 4)
        self.assertEqual(row['exchanges'], 12)

    def test_missing_or_precommit_losses_are_refused(self):
        for data in (self.wire.replace(b'1 1 0 3707', b'1 0 0 3707'), self.wire.replace(b'1 1 0 3707', b'1 1 1 3707'),
                     self.wire.replace(b'0 0 1 3707', b'0 1 0 3707'), self.wire[:-1], self.wire + self.wire,
                     self.wire.replace(b'3707', b'0'), self.wire.replace(b'3707', b'262145')):
            with self.subTest(data=data), self.assertRaises(ValueError):
                loss.exchanges(data, self.stages)

    def test_reordered_missing_or_reassigned_phase_cannot_qualify(self):
        for data in (self.stages[:-1], self.stages.split(b'\n', 1)[1], self.stages.replace(b'freeze', b'reservation'),
                     self.stages.replace(b'freeze 3 6 4', b'freeze 0 3 1'),
                     self.stages.replace(b'freeze 3 6 4', b'freeze 3 6 3'),
                     self.stages.replace(b'retirement 9 12 10', b'retirement 9 13 10')):
            with self.subTest(data=data), self.assertRaises(ValueError):
                loss.exchanges(self.wire, data)

    def test_old_or_incomplete_workload_does_not_qualify(self):
        stdout=(f'test {loss.TEST} ... ok\n'+'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out;\n').encode()
        with tempfile.TemporaryDirectory() as folder:
            for data in (b'',stdout+stdout,stdout.replace(b'8 filtered',b'4 filtered'),stdout.replace(b'0 ignored',b'1 ignored')):
                with self.subTest(data=data), self.assertRaisesRegex(ValueError,'completely'):
                    loss.verify_execution(data,Path(folder))

    def test_language_specific_workload_cannot_omit_or_reassign_exchanges(self):
        for language, offset in (("C", 0), ("Swift", 6), ("Kotlin", 5)):
            # Synthetic census only, not a claim of TLS execution.
            row = dict(exchanges=178 + offset, native_advances=36,
                       lost_indices=[130 + offset, 139 + offset, 155 + offset, 167 + offset],
                       stages={phase: dict(first_exchange=a + offset, after_last_exchange=b + offset,
                                           lost_exchange=c + offset)
                               for phase, (a, b, c) in zip(loss.PHASES,
                                   ((121, 131, 130), (136, 140, 139), (149, 156, 155), (164, 168, 167)), strict=True)})
            loss.require_workload(row, language)
            shifted = copy.deepcopy(row)
            shifted['stages']['reservation']['first_exchange'] += 1
            for bad in (dict(row, exchanges=row['exchanges'] - 1), dict(row, native_advances=35), shifted):
                with self.subTest(language=language, row=bad), self.assertRaisesRegex(ValueError, 'workload differs'):
                    loss.require_workload(bad, language)
            with self.assertRaisesRegex(ValueError, 'workload differs'):
                loss.require_workload(row, 'Swift' if language == 'C' else 'C')

    def test_carrier_language_and_completion_cannot_be_relabelled(self):
        stdout=(f'test {loss.TEST} ... ok\n'+'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out;\n').encode()
        base=dict(schema_version=2,language='C',account_layout='peer',completed=True,batch='11'*32,report='22'*32,
                  carrier='q-periapt-anchor/1',lost_advances=4,witness_exchanges=12,release_claim_eligible=False)
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            for row,language in ((base,'Swift'),(base,'Kotlin'),(list(base),'C'),(dict(base,completed=1),'C'),
                  (dict(base,carrier='signed-tcp'),'C'),(dict(base,lost_advances=True),'C'),(dict(base,release_claim_eligible=True),'C')):
                (root/'account-tls-loss-result.json').write_text(json.dumps(row))
                with self.subTest(row=row,language=language),self.assertRaisesRegex(ValueError,'scope differs'):
                    loss.verify_execution(stdout,root,language=language)

    def test_own_cleanup_requires_its_selected_target_and_account_layout(self):
        stdout=(f'test {loss.OWN_TLS_LOSS_TEST} ... ok\n'+'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out;\n').encode()
        peer=dict(schema_version=2,language='C',account_layout='peer',completed=True,batch='11'*32,report='22'*32,
                  carrier='q-periapt-anchor/1',lost_advances=4,witness_exchanges=178,release_claim_eligible=False)
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder); (root/'account-tls-loss-result.json').write_text(json.dumps(peer))
            with self.assertRaisesRegex(ValueError,'scope differs'):
                loss.verify_own_execution(stdout,root)
            with self.assertRaisesRegex(ValueError,'completely'):
                loss.verify_execution(stdout,root)
