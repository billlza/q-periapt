"""Synthetic collector controls, separate from actual C/Swift/Kotlin TLS runs."""
import hashlib
from pathlib import Path
import tempfile
import unittest
import continuity_peer_tls_preprocessing as peer
from continuity_foreign_account_results import member_markers, traffic_markers, connection_markers, registration_markers

class PeerTlsPreprocessingTests(unittest.TestCase):
    @staticmethod
    def logs(language):
        stdout = ("test " + peer.TEST + " ... ok\n" +
                  "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 27 filtered out;\n").encode()
        rows = list(peer.MARKERS)
        if language != "C":
            rows += peer.foreign_markers(language)
            rows += member_markers(language) + traffic_markers(language) + connection_markers(language) + registration_markers(language)
            rows += [f"FOREIGN_{component}_CALL language={language} mode={mode} label=synthetic"
                     for component, modes in peer.TRANSITION_COUNTS.items() for mode, count in modes.items() for _ in range(count)]
            rows += [f"{prefix} language={language} label={label}"
                     for prefix in ("FOREIGN_PEER_ROSTER_CALL", "FOREIGN_PEER_ROSTER_RAW_CONTROL") for label in sorted(peer.LABELS)]
        return stdout, ("\n".join(rows) + "\n").encode()

    def test_requires_unprocessed_frame_original_target_and_actual_selected_caller(self):
        for language in ("C", "Swift", "Kotlin"):
            stdout, stderr = self.logs(language)
            self.assertTrue(peer.verify(stdout, stderr, language=language)["completed"])
            for row in stderr.splitlines():
                for changed in (stderr.replace(row + b"\n", b"", 1), stderr + row + b"\n"):
                    with self.assertRaises(ValueError): peer.verify(stdout, changed, language=language)
            for changed in (stderr.replace(b"no_store_handle=true", b"no_store_handle=false"),
                            stderr.replace(b"endpoint=OpenSSL", b"endpoint=native")):
                with self.assertRaises(ValueError): peer.verify(stdout, changed, language=language)
            for changed in (stdout.replace(b"27 filtered", b"26 filtered"), stdout + stdout,
                            stdout.replace(b"0 ignored", b"1 ignored")):
                with self.assertRaises(ValueError): peer.verify(changed, stderr, language=language)
            with self.assertRaises(ValueError): peer.verify(stdout + stderr, b"", language=language)

    def test_binds_openssl_dependency_and_every_participating_executable(self):
        for language, variant in (("C", ""), ("Swift", ""), ("Kotlin", "-g1"), ("Kotlin", "-serial")):
            with tempfile.TemporaryDirectory() as folder:
                root = Path(folder); binary, primary, endpoint, foreign = (root / name for name in ("harness", "c", "openssl", "foreign"))
                for p in (binary, primary, endpoint, foreign): p.write_bytes(p.name.encode())
                def identity(p): return dict(path=str(p), sha256=hashlib.sha256(p.read_bytes()).hexdigest(), bytes=p.stat().st_size)
                openssl = identity(endpoint) | dict(version="synthetic-only", dependency_files={str(endpoint): identity(endpoint)["sha256"]})
                source = dict(enrollment=identity(binary), C_client=identity(primary), openssl=openssl)
                runtime = dict(QPERIAPT_C_OWNER_CLIENT=str(primary if language == "C" else foreign), QPERIAPT_INSTALLED_CLIENT_LANGUAGE=language,
                               QPERIAPT_PUBLIC_SERVICE_EVIDENCE="must-not-be-shared")
                mutate = False
                def run(argv, label, *, runtime):
                    self.assertEqual(argv, [str(binary), "--exact", peer.TEST, "--nocapture"])
                    self.assertEqual(runtime["QPERIAPT_C_OWNER_CLIENT"], str(primary))
                    self.assertEqual(runtime["QPERIAPT_WITNESS_OPENSSL_PEER"], str(endpoint))
                    self.assertEqual(runtime["QPERIAPT_INSTALLED_CLIENT_LANGUAGE"], "C")
                    self.assertNotIn("QPERIAPT_PUBLIC_SERVICE_EVIDENCE", runtime)
                    if language != "C":
                        self.assertEqual(runtime["QPERIAPT_PEER_ROSTER_LIFECYCLE_CLIENT"], str(foreign))
                        self.assertEqual(runtime["QPERIAPT_ACCOUNT_RESULT_CLIENT"], str(foreign))
                        for component in ("ENROLLMENT", *peer.TRANSITION_COUNTS):
                            self.assertEqual(runtime[f"QPERIAPT_{component}_LIFECYCLE_CLIENT"], str(foreign))
                            self.assertEqual(runtime[f"QPERIAPT_{component}_LIFECYCLE_LANGUAGE"], language)
                    stdout, stderr = self.logs(language)
                    (root / (language.lower() + "-" + label + ".stderr")).write_bytes(stderr)
                    if mutate: endpoint.write_bytes(b"changed")
                    return stdout
                self.assertTrue(peer.qualify(root, "debug", runtime, binary, source, run, language=language, variant=variant)["execution"]["completed"])
                mutate = True
                with self.assertRaisesRegex(ValueError, "executable changed"):
                    peer.qualify(root, "debug", runtime, binary, source, run, language=language, variant=variant)

if __name__ == "__main__": unittest.main()
