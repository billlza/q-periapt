"""Contract comparison must not turn incomplete or altered descriptors into a pass."""
import copy
import unittest

import continuity_contract as contract
from evidence_io import parse_strict_json_bytes


class ContinuityWireContractTests(unittest.TestCase):
    def setUp(self):
        self.expected = parse_strict_json_bytes(contract.snapshot(contract.BUDGETS).data, label="budgets")

    def test_complete_exact_descriptor_matches(self):
        self.assertEqual(contract.compare(self.expected, copy.deepcopy(self.expected)), self.expected)

    def test_each_limit_change_is_rejected(self):
        for name in contract.LIMITS:
            changed = copy.deepcopy(self.expected)
            changed["maximums"][name] += 1
            with self.subTest(limit=name), self.assertRaisesRegex(ValueError, "compiled contract differs"):
                contract.compare(self.expected, changed)

    def test_boolean_float_empty_and_unknown_limits_are_not_integers(self):
        for value in (True, 1.0, 0, -1, 2**32, "16384"):
            changed = copy.deepcopy(self.expected)
            changed["maximums"]["plaintext_bytes"] = value
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "bounded integer"):
                contract.compare(self.expected, changed)
        for operation in ("remove", "extra"):
            changed = copy.deepcopy(self.expected)
            if operation == "remove":
                del changed["maximums"]["prekey_records"]
            else:
                changed["maximums"]["unsigned_send_default"] = 64
            with self.subTest(operation=operation), self.assertRaisesRegex(ValueError, "limit fields"):
                contract.compare(self.expected, changed)

    def test_profile_commitment_and_unfrozen_boundary_are_independently_checked(self):
        for field, value in (("rekey_profile", self.expected["rekey_profile"] + ";changed"),
                             ("rekey_profile_sha3_256", "0" * 64), ("frozen_product_contract", True),
                             ("schema_version", True), ("signature_context", "bad\0context")):
            changed = copy.deepcopy(self.expected)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                contract.compare(self.expected, changed)
        # A malformed reviewed document is not accepted even if the program copies it.
        changed = copy.deepcopy(self.expected)
        changed["rekey_profile_sha3_256"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "profile commitment"):
            contract.compare(changed, changed)


if __name__ == "__main__":
    unittest.main(warnings="error")
