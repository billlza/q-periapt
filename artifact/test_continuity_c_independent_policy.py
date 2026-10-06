"""Reject incomplete, substituted or success-shaped independent lifecycle evidence."""
import unittest
import continuity_c_independent_policy as independent

class IndependentExecutionTests(unittest.TestCase):
    def test_exact_runtime_set_and_scope(self):
        evidence = ("\n".join(independent.MARKERS) + "\n" +
                    "".join("test " + name + " ... ok\n" for name in sorted(independent.TESTS)) +
                    "test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 13 filtered out;\n").encode()
        self.assertTrue(independent.verify(evidence)["completed"])
        for name in independent.TESTS:
            with self.subTest(missing=name), self.assertRaises(ValueError):
                independent.verify(evidence.replace(("test " + name + " ... ok\n").encode(), b""))
        for marker in independent.MARKERS:
            for changed in [evidence.replace(marker.encode(), b""),
                            evidence.replace(marker.encode(), marker.replace("true", "false", 1).encode()),
                            evidence + marker.encode() + b"\n"]:
                with self.subTest(marker=marker), self.assertRaises(ValueError):
                    independent.verify(changed)
        for changed in [evidence.replace(b"0 ignored", b"1 ignored"),
                        evidence.replace(b"13 filtered out", b"14 filtered out"),
                        evidence + b"test another_case ... FAILED\n"]:
            with self.assertRaises(ValueError):
                independent.verify(changed)
