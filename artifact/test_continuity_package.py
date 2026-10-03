"""Reject source substitution and success-shaped incomplete package execution."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

import continuity_package as package
import rust_sdk_profile as sdk
from test_rust_sdk_profile import archive


def metadata(root):
    rows = [{"id": name, "name": name, "version": sdk.VERSION, "source": None,
             "manifest_path": str(root / "packages" / f"{name}-{sdk.VERSION}" / "Cargo.toml")}
            for name in sdk.CONSUMER_CRATES]
    rows.extend([
        {"id": package.CONSUMER, "name": package.CONSUMER, "source": None,
         "manifest_path": str(root / "Cargo.toml")},
        {"id": package.NAME, "name": package.NAME, "version": package.VERSION, "source": None,
         "publish": [], "manifest_path": str(root / "packages" / f"{package.NAME}-{package.VERSION}" / "Cargo.toml")},
    ])
    return {"packages": rows, "resolve": {"nodes": [{"id": package.NAME,
            "features": ["connection-tls", "control-tls"]}]}}


def evidence(root):
    report = {"session": "11" * 32, "forward_message": "22" * 32, "reverse_message": "33" * 32,
              "network_rekeys": 1, "independent_readbacks": 3, "exclusive_leases_checked": 8,
              "unknown_delivery_reconciled": True, "durable_sdk_revocation": True,
              "cleanup_after_revocation": True, "cleanup_exclusive_leases_checked": 3}
    for role, field, payload in (
        ("responder", "forward_message", b"persisted before process exit"),
        ("initiator", "reverse_message", b"reverse after original installation restart"),
    ):
        (root / role).mkdir()
        (root / role / ("application-" + report[field])).write_bytes(
            bytes.fromhex(report["session"] + report[field]) + payload)
    for leaf in ("closure-id", "cleanup-complete", "cleanup-verified"):
        (root / "responder" / leaf).write_bytes(b"x" * 32)
    (root / "public-result.json").write_text(json.dumps(report))
    restored = root / "reopen"
    (restored / "initiator").mkdir(parents=True)
    (restored / "responder").mkdir()
    reopened = {"session": "44" * 32, "message": "55" * 32, "context": "66" * 32,
                "test_protocol_time": 170, "application_readbacks": 2,
                **{k: True for k in ("original_context", "exact_outbox", "unknown_commit_reconciled",
                   "fresh_bootstrap_refused", "independent_processes", "injected_protocol_clock")}}
    (restored / "public-reopen-result.json").write_text(json.dumps(reopened))
    for role in ("initiator", "responder"):
        (restored / role / "reopen-test-time").write_bytes((170).to_bytes(8, "big"))
    for leaf in ("original-outbox", "restored-outbox"):
        (restored / leaf).write_bytes(b"original ciphertext")
    (restored / "responder" / ("application-" + reopened["message"])).write_bytes(
        bytes.fromhex(reopened["session"] + reopened["message"])
        + b"original application commit before advertisement expiry")
    return report


STDOUT = ("\n".join(f"test {name} ... ok" for name in sorted(package.TESTS)) +
          "\ntest result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;\n").encode()


class ContinuityPackageTests(unittest.TestCase):
    def test_every_account_witness_reader_is_bound_to_package_source(self):
        import continuity_c_account_witness as signed
        import continuity_c_account_tls as tls
        import continuity_c_account_tls_loss as loss
        import continuity_c_account_delivery as delivery
        sources = package.source_inputs()['files']
        for module in (signed, tls, loss, delivery):
            path = Path(module.__file__).resolve()
            relative = path.relative_to(package.ROOT).as_posix()
            with self.subTest(reader=relative):
                self.assertIn(relative, sources)
                self.assertEqual(sources[relative], sdk.snapshot(path).sha256)

    def test_candidate_archive_version_does_not_relax_sdk_default(self):
        data = archive(name=package.NAME)
        with self.assertRaisesRegex(ValueError, "root differs"):
            sdk.archive_files(data, package.NAME, version=package.VERSION)
        self.assertEqual(len(sdk.archive_files(data, package.NAME)), 4)

    def test_installed_graph_requires_archive_origins_and_both_transports(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            good = metadata(root)
            lock = b"version = 4\npackage = []\n"
            self.assertEqual(package.verify_resolution(good, root, lock, lock)["candidate_crates"], 1)
            for field, value in (("manifest_path", str(root / "checkout/Cargo.toml")),
                                 ("version", "0.2.0"), ("source", "registry+injected"), ("publish", None)):
                changed = copy.deepcopy(good)
                changed["packages"][-1][field] = value
                with self.subTest(field=field), self.assertRaises(ValueError):
                    package.verify_resolution(changed, root, lock, lock)
            changed = copy.deepcopy(good)
            changed["resolve"]["nodes"][0]["features"] = ["connection-tls"]
            with self.assertRaisesRegex(ValueError, "omitted a transport"):
                package.verify_resolution(changed, root, lock, lock)
            changed = copy.deepcopy(good)
            changed["packages"].append({"name": "substituted-external", "source": None})
            with self.assertRaisesRegex(ValueError, "non-registry external"):
                package.verify_resolution(changed, root, lock, lock)

    def test_no_tests_skipped_tests_and_zero_rekeys_cannot_be_success(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            report = evidence(root)
            self.assertEqual(len(package.verify_execution(STDOUT, root, root / "reopen")["application_readbacks"]), 2)
            for stdout in (b"", STDOUT.replace(b"0 ignored", b"1 ignored"),
                           STDOUT.replace(b"0 filtered out", b"1 filtered out")):
                with self.subTest(stdout=stdout), self.assertRaisesRegex(ValueError, "all three complete"):
                    package.verify_execution(stdout, root, root / "reopen")
            for field, value in (("network_rekeys", 0), ("network_rekeys", True),
                                 ("cleanup_after_revocation", False), ("unknown_delivery_reconciled", 1)):
                changed = dict(report, **{field: value})
                (root / "public-result.json").write_text(json.dumps(changed))
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    package.verify_execution(STDOUT, root, root / "reopen")

    def test_receipt_cannot_replace_independent_application_and_cleanup_readback(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            report = evidence(root)
            received = root / "responder" / ("application-" + report["forward_message"])
            original = received.read_bytes()
            received.write_bytes(original[:-1] + b"!")
            with self.assertRaisesRegex(ValueError, "readback differs"):
                package.verify_execution(STDOUT, root, root / "reopen")
            received.write_bytes(original)
            (root / "responder/cleanup-verified").write_bytes(b"y" * 32)
            with self.assertRaisesRegex(ValueError, "original report identity"):
                package.verify_execution(STDOUT, root, root / "reopen")

    def test_installed_source_cannot_change_or_gain_extra_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Cargo.toml").write_bytes(b"original")
            package.verify_candidate_files(root, {"Cargo.toml": b"original"})
            (root / "Cargo.toml").write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "source changed"):
                package.verify_candidate_files(root, {"Cargo.toml": b"original"})
            (root / "Cargo.toml").write_bytes(b"original")
            (root / "injected.rs").write_bytes(b"extra")
            with self.assertRaisesRegex(ValueError, "source changed"):
                package.verify_candidate_files(root, {"Cargo.toml": b"original"})

    def test_executable_must_be_built_from_the_shipped_consumer(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            consumer = root / "consumer"
            build = root / "build/release"
            (build / "deps").mkdir(parents=True)
            binary = build / "deps/owned_connection-test"
            binary.write_bytes(b"test binary")
            source = consumer / "packages" / f"{package.NAME}-{package.VERSION}" / "tests/owned_connection.rs"
            message = {"reason": "compiler-artifact", "executable": str(binary),
                       "target": {"name": "owned_connection", "kind": ["test"], "src_path": str(source)}}
            encoded = lambda value: json.dumps(value).encode() + b"\n"
            self.assertEqual(package.built_test_binary(encoded(message), consumer, build), binary)
            for invalid in (b"", encoded(message) * 2,
                            encoded(dict(message, target=dict(message["target"], src_path=str(root / "checkout.rs"))))):
                with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                    package.built_test_binary(invalid, consumer, build)


if __name__ == "__main__":
    unittest.main(warnings="error")


class SessionReopenEvidenceTests(unittest.TestCase):
    def test_restoration_receipt_does_not_replace_actual_ciphertext_and_application_readback(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            evidence(root)
            restored = root / "reopen"
            for relative in ("restored-outbox", "responder/application-" + "55" * 32,
                             "initiator/reopen-test-time"):
                path = restored / relative
                original = path.read_bytes()
                path.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
                with self.subTest(relative=relative), self.assertRaises(ValueError):
                    package.verify_execution(STDOUT, root, restored)
                path.write_bytes(original)
            report_path = restored / "public-reopen-result.json"
            original = json.loads(report_path.read_text())
            for field, value in (("fresh_bootstrap_refused", False), ("exact_outbox", 1),
                                 ("application_readbacks", True)):
                report_path.write_text(json.dumps(dict(original, **{field: value})))
                with self.subTest(field=field), self.assertRaises(ValueError):
                    package.verify_execution(STDOUT, root, restored)
            report_path.write_text(json.dumps(original))
            self.assertTrue(package.verify_execution(STDOUT, root, restored)["session_reopen"]["exact_outbox"])


if __name__ == "__main__":
    unittest.main()
