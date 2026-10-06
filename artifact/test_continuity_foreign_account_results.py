"""Reject missing foreign work or substituted carrier/outcome scope."""
import unittest
import hashlib
import tempfile
from pathlib import Path

import continuity_foreign_account_results as results


class ForeignAccountResultsTests(unittest.TestCase):
    @staticmethod
    def scope(language):
        rows = results.markers(language) + results.peer_markers(language)
        rows += results.member_markers(language) * len(results.CASES)
        rows += [results.peer_native_marker(row) for row in results.MARKERS]
        rows += [f"FOREIGN_PEER_ROSTER_CALL language={language} label={label}"
                 for label, count in results.CALL_LABEL_COUNTS.items() for _ in range(count)]
        rows += [f"FOREIGN_PEER_ROSTER_RAW_CONTROL language={language} label={label}"
                 for label, count in results.RAW_LABEL_COUNTS.items() for _ in range(count)]
        rows += [f"FOREIGN_PEER_ROSTER_KILLED language={language} signal=9 actual_processed_barrier=true"] * 2
        return rows

    def test_collector_selects_foreign_results_and_binds_both_executables(self):
        for language, variant in (("Swift", ""), ("Kotlin", "-g1")):
            with tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                binary, primary, foreign = (root / name for name in ("harness", "c-client", "foreign-client"))
                for path in (binary, primary, foreign):
                    path.write_bytes(path.name.encode())
                def identity(path):
                    return dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(), bytes=path.stat().st_size)
                trace = identity(binary)
                native = {"enrollment": {"binary": trace}, "independent_policy_roster": {"binary": trace},
                          "binaries": {"C_client": identity(primary)}}
                runtime = dict(QPERIAPT_C_OWNER_CLIENT=str(foreign), QPERIAPT_INSTALLED_CLIENT_LANGUAGE=language,
                               QPERIAPT_PUBLIC_SERVICE_EVIDENCE="must-not-be-shared")
                mutate = False
                def run(argv, label, *, runtime):
                    self.assertEqual(argv, [str(binary), "--exact", *sorted(results.TESTS), "--nocapture"])
                    self.assertEqual(runtime["QPERIAPT_C_OWNER_CLIENT"], str(primary))
                    self.assertEqual(runtime["QPERIAPT_ACCOUNT_RESULT_CLIENT"], str(foreign))
                    self.assertEqual(runtime["QPERIAPT_ACCOUNT_RESULT_LANGUAGE"], language)
                    self.assertEqual(runtime["QPERIAPT_PEER_ROSTER_LIFECYCLE_CLIENT"], str(foreign))
                    self.assertEqual(runtime["QPERIAPT_PEER_ROSTER_LIFECYCLE_LANGUAGE"], language)
                    self.assertEqual(runtime["QPERIAPT_INSTALLED_CLIENT_LANGUAGE"], "C")
                    self.assertNotIn("QPERIAPT_PUBLIC_SERVICE_EVIDENCE", runtime)
                    scope = self.scope(language)
                    (root / (language.lower() + "-" + label + ".stderr")).write_text("\n".join(scope) + "\n")
                    if mutate:
                        foreign.write_bytes(b"substituted")
                    return ("".join("test " + name + " ... ok\n" for name in sorted(results.TESTS)) +
                            "test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 25 filtered out;\n").encode()
                checked = results.qualify(root, "debug", runtime, native, binary, run, language=language, variant=variant)
                self.assertEqual(checked["execution"]["cases"], 9)
                mutate = True
                with self.assertRaisesRegex(ValueError, "executable changed"):
                    results.qualify(root, "debug", runtime, native, binary, run, language=language, variant=variant)

    def test_exact_cases_are_required_for_each_foreign_language(self):
        stdout = ("".join("test " + name + " ... ok\n" for name in sorted(results.TESTS)) +
                  "test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 25 filtered out;\n").encode()
        for language in ("Swift", "Kotlin"):
            markers = [row for row in self.scope(language) if row.startswith(("FOREIGN_", "C_REQUIRED_PEER_REVOCATION", "C_PEER_ROSTER_INTERRUPTION", "C_PEER_ROSTER_TLS_INTERRUPTION"))]
            stderr = ("\n".join(markers) + "\n").encode()
            self.assertEqual(results.verify_execution(stdout, stderr, language=language)["cases"], 9)
            for marker in markers:
                for changed in (stderr.replace((marker + "\n").encode(), b""),
                                stderr + marker.encode() + b"\n",
                                stderr.replace(marker.encode(), (marker.replace("true", "false", 1) if "true" in marker else marker.replace("language=", "language=wrong-")).encode())):
                    with self.subTest(language=language, marker=marker), self.assertRaises(ValueError):
                        results.verify_execution(stdout, changed, language=language)
            for changed in (stdout.replace(b"0 ignored", b"1 ignored"),
                            stdout.replace(b"25 filtered out", b"26 filtered out"),
                            stdout.replace(next(iter(results.TESTS)).encode(), b"another_case")):
                with self.assertRaises(ValueError):
                    results.verify_execution(changed, stderr, language=language)
            for other in ("C", "Swift" if language == "Kotlin" else "Kotlin"):
                with self.assertRaises(ValueError):
                    results.verify_execution(stdout, stderr, language=other)
            with self.assertRaises(ValueError):
                results.verify_execution(stdout + stderr, b"", language=language)


if __name__ == "__main__":
    unittest.main()
