"""Synthetic collector/provenance tests; real language workloads are separate."""
import hashlib
from pathlib import Path
import tempfile
import unittest
import continuity_foreign_roster as roster

class ForeignRosterTests(unittest.TestCase):
    @staticmethod
    def logs(language):
        stdout = ("".join("test " + name + " ... ok\n" for name in sorted(roster.TESTS)) +
                  "test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 27 filtered out;\n").encode()
        rows = [f"FOREIGN_ROSTER_CALL language={language} mode={mode} label=synthetic-{index}"
                for mode, count in roster.CALL_COUNTS.items() for index in range(count)]
        rows += [row for row in roster.MARKERS if row.split(" ", 1)[0] in roster.NATIVE_PREFIXES]
        return stdout, ("\n".join(rows) + "\n").encode()

    def test_complete_dispatch_and_original_native_scenarios_are_required(self):
        for language in ("Swift", "Kotlin"):
            stdout, stderr = self.logs(language)
            checked = roster.verify_execution(stdout, stderr, language=language)
            self.assertEqual((checked["cases"], checked["foreign_roster_calls"]), (12, 141))
            for row in stderr.splitlines():
                with self.subTest(language=language, row=row):
                    for changed in (stderr.replace(row + b"\n", b"", 1), stderr + row + b"\n"):
                        with self.assertRaises(ValueError): roster.verify_execution(stdout, changed, language=language)
            for changed in (stderr.replace(b"language=" + language.encode(), b"language=C", 1),
                            stderr.replace(b"mode=commit ", b"mode=wrong-kind ", 1),
                            stderr.replace(b"no_current_runtime=true", b"no_current_runtime=false", 1)):
                with self.assertRaises(ValueError): roster.verify_execution(stdout, changed, language=language)
            for changed in (stdout.replace(b"0 failed", b"1 failed"), stdout.replace(b"0 ignored", b"1 ignored"),
                            stdout.replace(b"27 filtered out", b"26 filtered out"),
                            stdout.replace(b"27 filtered out", b"28 filtered out"), stdout + stdout):
                with self.assertRaises(ValueError): roster.verify_execution(changed, stderr, language=language)
            with self.assertRaises(ValueError): roster.verify_execution(stdout + stderr, b"", language=language)

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
                    self.assertEqual(argv, [str(binary), "--exact", *sorted(roster.TESTS), "--test-threads=2", "--nocapture"])
                    self.assertEqual(runtime["QPERIAPT_C_OWNER_CLIENT"], str(primary))
                    self.assertEqual(runtime["QPERIAPT_ROSTER_LIFECYCLE_CLIENT"], str(foreign))
                    self.assertEqual(runtime["QPERIAPT_ROSTER_LIFECYCLE_LANGUAGE"], language)
                    self.assertEqual(runtime["QPERIAPT_INSTALLED_CLIENT_LANGUAGE"], "C")
                    self.assertNotIn("QPERIAPT_PUBLIC_SERVICE_EVIDENCE", runtime)
                    stdout, stderr = self.logs(language)
                    (root / (language.lower() + "-" + label + ".stderr")).write_bytes(stderr)
                    if mutate:
                        foreign.write_bytes(b"changed")
                    return stdout
                checked = roster.qualify(root, "debug", runtime, native, binary, run, language=language, variant=variant)
                self.assertEqual(checked["execution"]["cases"], 12)
                mutate = True
                with self.assertRaisesRegex(ValueError, "executable changed"):
                    roster.qualify(root, "debug", runtime, native, binary, run, language=language, variant=variant)


if __name__ == "__main__":
    unittest.main()
