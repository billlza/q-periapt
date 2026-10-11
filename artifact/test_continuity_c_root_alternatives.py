"""Public route readback validation; actual C process runs remain separate evidence."""
import unittest

import continuity_c_root_alternatives as alternatives


class AlternativeReadbackTests(unittest.TestCase):
    def fixture(self, route):
        files = {
            "public/approved-plan": b"QPAFPL01original",
            "public/bound-proposal": b"QPARPL02next",
            "public/original-noncommit": b"n" * 3449,
            "public/original-target-account": b"a" * 32,
            "public/target-account": b"b" * 32,
            "public/freeze-receipt": b"freeze",
            "public/retirement-receipt": b"retired",
            "public/original-bound-proposal": b"QPARPL02original",
        }
        files["public/alternative-approved"] = (files["public/bound-proposal"]
            if route == "adoption" else b"QPAFPL01next")
        files["public/alternative-receipt"] = b"retired" if route == "adoption" else b"freeze"
        return files

    def test_exact_independent_route_and_inputs(self):
        for route in alternatives.VARIANTS:
            with self.subTest(route=route):
                files = self.fixture(route)
                result = alternatives.verify(lambda name, maximum: files[name], route)
                self.assertTrue(result["exact_approval_retained"])
                self.assertFalse(result["release_claim_eligible"])
                self.assertEqual(result["new_local_winner_preparation"], route != "adoption")
        with self.assertRaises(ValueError):
            alternatives.layout("typo")

    def test_truncated_or_substituted_original_approval_is_rejected(self):
        for route in alternatives.VARIANTS:
            files = self.fixture(route)
            changes = {
                "public/alternative-approved": files["public/approved-plan"],
                "public/alternative-receipt": b"other receipt",
                "public/original-noncommit": b"n" * 3448,
                "public/original-target-account": bytes(32),
            }
            if route != "adoption":
                changes["public/target-account"] = files["public/original-target-account"]
            if route == "bound-transition":
                changes["public/original-bound-proposal"] = files["public/bound-proposal"]
            for name, value in changes.items():
                changed = dict(files, **{name: value})
                with self.subTest(route=route, path=name), self.assertRaises(ValueError):
                    alternatives.verify(lambda name, maximum: changed[name], route)


if __name__ == "__main__":
    unittest.main()
