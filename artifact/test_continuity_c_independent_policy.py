"""Reject incomplete, substituted or success-shaped independent lifecycle evidence."""
import unittest
import continuity_c_independent_policy as independent

class IndependentExecutionTests(unittest.TestCase):
    def test_exact_runtime_set_and_scope(self):
        scope = ("\n".join(independent.MARKERS) + "\n").encode()
        evidence = ("".join("test " + name + " ... ok\n" for name in sorted(independent.TESTS)) +
                    "test result: ok. 14 passed; 0 failed; 0 ignored; 0 measured; 15 filtered out;\n").encode()
        self.assertTrue(independent.verify(evidence, scope)["completed"])
        for name in independent.TESTS:
            with self.subTest(missing=name), self.assertRaises(ValueError):
                independent.verify(evidence.replace(("test " + name + " ... ok\n").encode(), b""), scope)
        for marker in independent.MARKERS:
            for changed in [scope.replace(marker.encode(), b""),
                            scope.replace(marker.encode(), marker.replace("true", "false", 1).encode()),
                            scope + marker.encode() + b"\n"]:
                with self.subTest(marker=marker), self.assertRaises(ValueError):
                    independent.verify(evidence, changed)
        for changed in [evidence.replace(b"0 ignored", b"1 ignored"),
                        evidence.replace(b"15 filtered out", b"14 filtered out"),
                        evidence + b"test another_case ... FAILED\n"]:
            with self.assertRaises(ValueError):
                independent.verify(changed, scope)
        # Combining streams would hide an absent scope stream or allow result
        # rows in diagnostic output to masquerade as libtest completion.
        for stdout, stderr in [(evidence + scope, b""), (b"", evidence + scope),
                               (scope, evidence)]:
            with self.subTest(stdout=stdout, stderr=stderr), self.assertRaises(ValueError):
                independent.verify(stdout, stderr)
