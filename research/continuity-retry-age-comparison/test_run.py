#!/usr/bin/env python3
"""Controls for the source derivative and independent retry-age verifier."""
from pathlib import Path
import unittest

import run as ablation


def opportunity(owner):
    return {"event": "opportunity", "owner": owner}


def emission(kind, owner=0, logical="application-0-0"):
    return {"event": "emit", "kind": kind, "owner": owner, "logical": logical}


class RetryAgeTests(unittest.TestCase):
    def test_rejects_immediate_retry(self):
        trace = [opportunity(0), emission("application"), opportunity(0), emission("retry")]
        with self.assertRaisesRegex(ValueError, "premature retry"):
            ablation.validate_retry_age(trace, 4)

    def test_other_sender_turns_do_not_mature_retry(self):
        trace = [opportunity(0), emission("application")]+[opportunity(1)]*20
        trace += [opportunity(0), emission("retry")]
        with self.assertRaisesRegex(ValueError, "premature retry"):
            ablation.validate_retry_age(trace, 4)

    def test_exact_age_is_eligible(self):
        trace = [opportunity(0), emission("application")]+[opportunity(0)]*4+[emission("retry")]
        result = ablation.validate_retry_age(trace,4)
        self.assertEqual(result["minimum_observed_sender_turns"],4)
        self.assertEqual(result["retry_emissions"],1)

    def test_every_retry_resets_age(self):
        trace = [opportunity(0), emission("application")]+[opportunity(0)]*4+[emission("retry")]
        trace += [opportunity(0), emission("retry")]
        with self.assertRaisesRegex(ValueError, "premature retry"):
            ablation.validate_retry_age(trace,4)

    def test_rejects_unknown_retry(self):
        with self.assertRaisesRegex(ValueError,"without first"):
            ablation.validate_retry_age([opportunity(0),emission("retry")],4)

    def test_rejects_second_first_emission(self):
        with self.assertRaisesRegex(ValueError,"second first"):
            ablation.validate_retry_age([opportunity(0),emission("application"),
                                        opportunity(0),emission("application")],4)

    def test_each_identity_has_own_age(self):
        trace = [opportunity(0),emission("application")]+[opportunity(0)]*4
        trace += [emission("application",logical="application-0-2"),opportunity(0),
                  emission("retry",logical="application-0-2")]
        with self.assertRaisesRegex(ValueError,"premature retry"):
            ablation.validate_retry_age(trace,4)

    def test_no_retry_is_an_explicit_null_range(self):
        result = ablation.validate_retry_age([opportunity(0),emission("application")],4)
        self.assertEqual(result,{"minimum_sender_turns":4,"retry_emissions":0,
                                 "minimum_observed_sender_turns":None,"maximum_observed_sender_turns":None})

    def test_baseline_accepts_its_original_immediate_rule(self):
        result = ablation.validate_retry_age([opportunity(0),emission("application"),
                                             opportunity(0),emission("retry")],0)
        self.assertEqual(result["retry_emissions"],1)

    def test_invalid_owner_rejected(self):
        for owner in (-1,2,True,"0"):
            with self.subTest(owner=owner), self.assertRaises(ValueError):
                ablation.validate_retry_age([opportunity(owner)],4)


class SourceDerivativeTests(unittest.TestCase):
    def setUp(self):
        self.path=Path(__file__).resolve().parents[1]/"continuity-matched-comparison/native_driver.rs.txt"
        self.original=self.path.read_text()
        self.assertEqual(ablation.sha(self.path),ablation.MATCHED_HASHES[self.path.name])

    def test_only_declared_regions_change(self):
        result=ablation.aged_driver(self.original)
        self.assertIn("const MIN_RETRY_SENDER_TURNS: usize = 4;",result)
        for anchor in ("struct Snapshot", "fn deliver", "fn checkpoint", "fn run", "#[test]"):
            start_old=self.original.index(anchor)
            start_new=result.index(anchor)
            # Entire suffixes are invariant after the queue-choice method.
            if anchor in ("fn deliver", "fn checkpoint", "fn run", "#[test]"):
                self.assertEqual(self.original[start_old:],result[start_new:])
        for begin,end in (("struct Snapshot", "#[derive(Clone, Copy)]"),
                          ("    fn create_application", "    fn choose"),
                          ("    fn queue_control", "    fn create_application")):
            self.assertEqual(self.original[self.original.index(begin):self.original.index(end)],
                             result[result.index(begin):result.index(end)])

    def test_source_anchor_failure_stops_preparation(self):
        altered=self.original.replace("    cursor: usize,", "    cursor: u64,",1)
        with self.assertRaisesRegex(ValueError,"anchor changed"):
            ablation.aged_driver(altered)

    def test_rejects_noninteger_or_unbounded_age(self):
        for age in (0,-1,33,True,4.0,"4"):
            with self.subTest(age=age),self.assertRaisesRegex(ValueError,"invalid retry age"):
                ablation.aged_driver(self.original,age)

    def test_original_file_unchanged(self):
        ablation.aged_driver(self.original)
        self.assertEqual(ablation.sha(self.path),ablation.MATCHED_HASHES[self.path.name])


if __name__=="__main__":
    unittest.main()
