#!/usr/bin/env python3
import unittest
from schedule import (SCENARIOS, Emission, charged_exchange, schedule, sender,
                      verify_trace)


def valid(scenario, count=2048):
    emissions = [Emission(i, sender(scenario, i), f'app-{i}', i.to_bytes(4, 'big'))
                 for i in range(count)]
    by = {x.opportunity: x for x in emissions}
    deliveries = []
    rows = schedule(scenario, count)
    for row in rows[:-1]:
        deliveries.extend((row['opportunity'], i, by[i].frame) for i in row['deliveries'])
        if row['duplicate_last']:
            i = row['opportunity']
            deliveries.append((i, i, by[i].frame))
    deliveries.extend((count, i, by[i].frame) for i in rows[-1]['terminal_delivery_only'])
    return emissions, deliveries


class ScheduleTests(unittest.TestCase):
    def test_seven_complete_schedules(self):
        for name in SCENARIOS:
            e, d = valid(name)
            with self.subTest(scenario=name):
                r = verify_trace(name, 2048, e, d)
                self.assertEqual(r['emissions'], 2048)
                self.assertEqual(r['delivered_frames'], 1843 if name == 'lossy' else
                                 2206 if name == 'duplicates' else 2048)

    def test_explicit_direction_inventory(self):
        self.assertEqual([sum(sender('asymmetric', i) == j for i in range(2048))
                          for j in [0, 1]], [1844, 204])
        self.assertEqual([sum(sender('offline_then_exchange', i) == j for i in range(2048))
                          for j in [0, 1]], [1152, 896])
        self.assertTrue(all(sender('one_way', i) == 0 for i in range(2048)))

    def test_multiple_emissions_rejected(self):
        e, d = valid('alternating')
        with self.assertRaisesRegex(ValueError, 'multiple emissions'):
            verify_trace('alternating', 2048, e + [e[0]], d)

    def test_wrong_direction_rejected(self):
        e, d = valid('one_way')
        e[1] = Emission(1, 1, 'reply', b'reply')
        with self.assertRaisesRegex(ValueError, 'wrong emission direction'):
            verify_trace('one_way', 2048, e, d)

    def test_unemitted_delivery_rejected(self):
        e, d = valid('alternating')
        with self.assertRaisesRegex(ValueError, 'delivery schedule'):
            verify_trace('alternating', 2048, e[:-1], d)

    def test_changed_network_duplicate_rejected(self):
        e, d = valid('duplicates')
        d[1] = (0, 0, b'changed')
        with self.assertRaisesRegex(ValueError, 'frame identity'):
            verify_trace('duplicates', 2048, e, d)

    def test_changed_capture_rejected(self):
        e, d = valid('alternating')
        with self.assertRaisesRegex(ValueError, 'capture coordinate'):
            verify_trace('alternating', 2048, e, d, capture_before=2)

    def test_empty_opportunities_do_not_create_deliveries(self):
        e, d = valid('reordered')
        e = [x for x in e if x.opportunity % 3]
        d = [x for x in d if x[1] % 3]
        verify_trace('reordered', 2048, e, d)

    def test_one_way_free_response_countermodel(self):
        charged = charged_exchange([0] * 16)
        uncharged = charged_exchange([0] * 16, uncharged_replies=True)
        self.assertFalse(charged['complete'])
        self.assertEqual(charged['queued'], [[], [1]])
        self.assertTrue(uncharged['complete'])
        self.assertEqual(len({x['opportunity'] for x in uncharged['emitted']}), 1)
        self.assertEqual(len(uncharged['emitted']), 4)
        self.assertTrue(charged_exchange([0, 1, 0, 1])['complete'])

    def test_boolean_indices_rejected(self):
        with self.assertRaisesRegex(ValueError, 'invalid opportunity'):
            sender('alternating', True)

    def test_changed_protocol_retry_rejected(self):
        e = [Emission(0, 0, 'same-operation', b'first'),
             Emission(2, 0, 'same-operation', b'changed')]
        d = [(0, 0, b'first'), (2, 2, b'changed')]
        with self.assertRaisesRegex(ValueError, 'logical retry'):
            verify_trace('alternating', 3, e, d)

    def test_boolean_delivery_coordinate_rejected(self):
        e, d = valid('alternating', 3)
        d[0] = (False, 0, d[0][2])
        with self.assertRaisesRegex(ValueError, 'invalid delivery fields'):
            verify_trace('alternating', 3, e, d)


if __name__ == '__main__':
    unittest.main(verbosity=2)
