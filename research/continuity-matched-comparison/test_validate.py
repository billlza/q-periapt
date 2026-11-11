"""Synthetic trace counterexamples for the checker, not native-run evidence."""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from schedule import MESSAGES, canonical
from validate import verify_native, decode


def fixture():
    rows = [{'event':'configuration','schema':1,'scenario':'one_way','profile':'continuity-32',
             'opportunities':MESSAGES,'frame_cap':8192,'capture_before_opportunity':1,
             'payload_bytes':32,'initial_revisions':[10,10]}]
    for i in range(MESSAGES):
        if i == 1:
            rows.append({'event':'capture','before_opportunity':1,'record_bytes':[100,100],
                         'pending_entropy':[False,False]})
        rows.append({'event':'opportunity','opportunity':i,'owner':0,'request':i})
        if i < 32:
            encoded = (b'QPCMSG03' + bytes(32) + b'\x01' + bytes(8) + i.to_bytes(8,'big')
                       + bytes(32) + (32).to_bytes(4,'big') + bytes(48)).hex()
            logical, kind = f'application-0-{i}', 'application'
            rows.append({'event':'commit','opportunity':i,'owner':0,'request':i,'epoch':0,'index':i,
                         'known':[i>0,i>0],'snapshot_active':i>0})
        elif i in (32,34):
            encoded, logical, kind = b'control-fixture'.hex(), 'control-fixture', 'control'
        else:
            encoded = None
        if encoded:
            rows.append({'event':'emit','opportunity':i,'owner':0,'kind':kind,'logical':logical,'wire':encoded})
            rows.append({'event':'receive','opportunity':i,'source_opportunity':i,'owner':1,
                         'kind':kind,'logical':logical,'wire':encoded,
                         'outcome':'delivered' if kind == 'application' else 'accepted'})
        rows.append({'event':'checkpoint','opportunity':i,'revisions':[11+i,11+i],
                     'sync_data':[i+1,i+1],'confirmed_epochs':[0,0],'sending_epochs':[0,0]})
    rows.append({'event':'checkpoint','opportunity':MESSAGES,'revisions':[10+MESSAGES,10+MESSAGES],
                 'sync_data':[MESSAGES,MESSAGES],'confirmed_epochs':[0,0],'sending_epochs':[0,0]})
    rows.append({'event':'completed','offered':[MESSAGES,0],'uncommitted':[MESSAGES-32,0],
                 'delivered':[0,32],'distinct_new_keys':32,'status':'passed'})
    return rows


class NativeTraceControls(unittest.TestCase):
    def check(self, rows):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'synthetic.jsonl'
            path.write_bytes(b''.join(canonical(row) for row in rows))
            return verify_native(path,'continuity-32','one_way')

    def test_complete_fixture_counts_all_control_retries(self):
        result = self.check(fixture())
        self.assertEqual(result['exact_frame_retransmissions'], {'control':1})
        self.assertEqual(result['application']['committed'], [32,0])
        self.assertEqual(result['application']['delivered_by_sender'], [32,0])
        self.assertEqual(result['exposure'][0]['derived_requests'], list(range(1,32)))

    def test_capture_after_next_opportunity_rejected(self):
        rows = fixture()
        position = next(i for i,r in enumerate(rows) if r['event']=='capture')
        rows[position],rows[position+1] = rows[position+1],rows[position]
        with self.assertRaises(ValueError): self.check(rows)

    def test_fifo_substitution_rejected(self):
        rows = fixture()
        row = next(r for r in rows if r['event']=='commit' and r['opportunity']==1)
        row['request'] = 3
        with self.assertRaises(ValueError): self.check(rows)

    def test_public_epoch_substitution_rejected(self):
        rows = fixture()
        row = next(r for r in rows if r['event']=='emit' and r['opportunity']==1)
        encoded = bytearray.fromhex(row['wire']); encoded[48] = 1
        row['wire'] = encoded.hex()
        with self.assertRaises(ValueError): self.check(rows)

    def test_control_retry_mutation_rejected(self):
        rows = fixture()
        for row in rows:
            if row['event'] in ('emit','receive') and row['opportunity']==34:
                row['wire'] = b'changed-control'.hex()
        with self.assertRaises(ValueError): self.check(rows)

    def test_terminal_transmission_rejected(self):
        rows = fixture()
        row = deepcopy(next(r for r in rows if r['event']=='emit' and r['opportunity']==32))
        row['opportunity'] = MESSAGES
        rows.insert(-2,row)
        with self.assertRaises(ValueError): self.check(rows)

    def test_persistence_regression_rejected(self):
        rows = fixture()
        row = next(r for r in rows if r['event']=='checkpoint' and r['opportunity']==4)
        row['sync_data'][0] = 0
        with self.assertRaises(ValueError): self.check(rows)

    def test_missing_completion_rejected(self):
        with self.assertRaises(ValueError): self.check(fixture()[:-1])

    def test_boolean_counts_rejected(self):
        rows = fixture(); rows[-1]['distinct_new_keys'] = True
        with self.assertRaises(ValueError): self.check(rows)

    def test_duplicate_json_keys_rejected(self):
        with self.assertRaises(ValueError): decode('{"event":"capture","event":"completed"}')


if __name__ == '__main__':
    unittest.main()
