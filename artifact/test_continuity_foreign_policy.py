"""Collector/provenance tests with synthetic logs; real executions are separate."""
import hashlib
from pathlib import Path
import tempfile
import unittest

import continuity_foreign_policy as policy


class ForeignPolicyTests(unittest.TestCase):
    @staticmethod
    def logs(language):
        stdout = ("".join("test " + name + " ... ok\n" for name in sorted(policy.TESTS)) +
                  "test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 24 filtered out;\n").encode()
        rows = policy.markers(language)
        rows += [f"FOREIGN_POLICY_CALL language={language} mode={mode} label=synthetic-{index}"
                 for mode, count in policy.CALL_COUNTS.items() for index in range(count)]
        rows += [f"FOREIGN_POLICY_TRANSPORT language={language} label={label}" for label in sorted(policy.TRANSPORT_LABELS)]
        rows += [row for row in policy.MARKERS if row.split(" ", 1)[0] in policy.NATIVE_PREFIXES]
        return stdout, ("\n".join(rows) + "\n").encode()

    def test_every_case_and_actual_language_dispatch_is_required(self):
        for language in ("Swift", "Kotlin"):
            stdout, stderr = self.logs(language)
            checked = policy.verify_execution(stdout, stderr, language=language)
            self.assertEqual((checked["cases"], checked["foreign_policy_calls"], checked["foreign_transport_calls"]), (10, 117, 7))
            for row in stderr.splitlines():
                with self.subTest(language=language, row=row):
                    for changed in (stderr.replace(row + b"\n", b"", 1), stderr + row + b"\n"):
                        with self.assertRaises(ValueError):
                            policy.verify_execution(stdout, changed, language=language)
            for changed in (stderr.replace(b"language=" + language.encode(), b"language=C", 1),
                            stderr.replace(b"mode=witness-commit ", b"mode=witness-wrong-kind ", 1),
                            stderr.replace(b"case=tls-applied ", b"case=tls-lost-commit ", 1),
                            stderr.replace(b"shared_native_engine=true", b"shared_native_engine=false", 1)):
                with self.assertRaises(ValueError):
                    policy.verify_execution(stdout, changed, language=language)
            for changed in (stdout.replace(b"0 failed", b"1 failed"), stdout.replace(b"0 ignored", b"1 ignored"),
                            stdout.replace(b"24 filtered out", b"23 filtered out"),
                            stdout.replace(b"24 filtered out", b"25 filtered out"), stdout + stdout):
                with self.assertRaises(ValueError):
                    policy.verify_execution(changed, stderr, language=language)
            with self.assertRaises(ValueError):
                policy.verify_execution(stdout + stderr, b"", language=language)

    def test_collector_pins_registration_foreign_client_and_native_harness(self):
        for language, variant in (("Swift", ""), ("Kotlin", "-serial"), ("Kotlin", "-g1")):
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
                               QPERIAPT_PUBLIC_SERVICE_EVIDENCE="not-shared")
                mutate = False
                def run(argv, label, *, runtime):
                    self.assertEqual(argv, [str(binary), "--exact", *sorted(policy.TESTS), "--test-threads=2", "--nocapture"])
                    self.assertEqual(runtime["QPERIAPT_C_OWNER_CLIENT"], str(primary))
                    self.assertEqual(runtime["QPERIAPT_POLICY_LIFECYCLE_CLIENT"], str(foreign))
                    self.assertEqual(runtime["QPERIAPT_POLICY_LIFECYCLE_LANGUAGE"], language)
                    self.assertEqual(runtime["QPERIAPT_INSTALLED_CLIENT_LANGUAGE"], "C")
                    self.assertNotIn("QPERIAPT_PUBLIC_SERVICE_EVIDENCE", runtime)
                    stdout, stderr = self.logs(language)
                    (root / (language.lower() + "-" + label + ".stderr")).write_bytes(stderr)
                    if mutate:
                        foreign.write_bytes(b"changed")
                    return stdout
                checked = policy.qualify(root, "debug", runtime, native, binary, run, language=language, variant=variant)
                self.assertEqual(checked["execution"]["cases"], 10)
                mutate = True
                with self.assertRaisesRegex(ValueError, "executable changed"):
                    policy.qualify(root, "debug", runtime, native, binary, run, language=language, variant=variant)


if __name__ == "__main__":
    unittest.main()
