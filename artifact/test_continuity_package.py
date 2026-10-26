"""Reject source substitution and success-shaped incomplete package execution."""
import copy
import contextlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from bounded_process import capture_output
import continuity_package as package
import rust_sdk_profile as sdk
from test_rust_sdk_profile import archive
from test_continuity_roster_renewal import fixture as roster_evidence
from test_continuity_enrollment import fixture as enrollment_evidence, wire as synthetic_wire
from test_continuity_device_replacement import fixture as replacement_evidence
from test_continuity_device_retirement import fixture as retirement_evidence
from continuity_enrollment import REGISTRATION_FILES
from continuity_c_witness import commit


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
              "network_rekeys": 1, "independent_readbacks": 3, "exclusive_leases_checked": 10,
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
                   "fresh_bootstrap_refused", "independent_processes", "injected_protocol_clock", "enrollment_roster_refresh")}}
    (restored / "public-reopen-result.json").write_text(json.dumps(reopened))
    for role in ("initiator", "responder"):
        (restored / role / "reopen-test-time").write_bytes((170).to_bytes(8, "big"))
    for leaf in ("original-outbox", "restored-outbox"):
        (restored / leaf).write_bytes(b"original ciphertext")
    (restored / "responder" / ("application-" + reopened["message"])).write_bytes(
        bytes.fromhex(reopened["session"] + reopened["message"])
        + b"original application commit before advertisement expiry")
    roster_evidence(root / "roster")
    replacement_evidence(root / "replacement")
    retirement_evidence(root / "retirement")
    enrollment_evidence(root / "enrollment-public")
    for role in ("initiator", "responder"):
        folder = root / "enrollment-public" / role
        for leaf, field in (("session", "session"), ("forward-message", "forward_message"), ("reverse-message", "reverse_message")):
            (folder / leaf).write_bytes(bytes.fromhex(report[field]))
        for leaf, receiving, field in (("forward-effect", "responder", "forward_message"), ("reverse-effect", "initiator", "reverse_message")):
            (folder / leaf).write_bytes((root / receiving / ("application-" + report[field])).read_bytes())
    for role in ("initiator", "responder"):
        folder = restored / role
        source = root / "enrollment-public" / role
        for name in REGISTRATION_FILES:
            (folder / name).write_bytes((source / name).read_bytes())
        # Reader-only synthetic signatures. Real exported traces use native signing.
        original_wire = (folder / "local-roster").read_bytes()
        size = int.from_bytes(original_wire[:4], "big")
        original = bytearray(original_wire[4:4 + size])
        original[56:64] = (170).to_bytes(8, "big")
        (folder / "local-roster").write_bytes(synthetic_wire(original))
        (folder / "local-roster-digest").write_bytes(commit(b"Q-PERIAPT-CONTINUITY-ROSTER-CANDIDATE/v1", original))
        target = bytearray(original)
        target[40:48] = (2).to_bytes(8, "big")
        target[56:64] = (300).to_bytes(8, "big")
        digest = commit(b"Q-PERIAPT-CONTINUITY-ROSTER-CANDIDATE/v1", target)
        (folder / "renewal-roster-2").write_bytes(synthetic_wire(target))
        (folder / "renewal-digest-2").write_bytes(digest)
        (folder / "refreshed-roster-checkpoint").write_bytes((2).to_bytes(8, "big") + digest)
        (folder / "refreshed-journal").write_bytes((folder / "accepted-journal").read_bytes())
        (folder / "session").write_bytes(bytes.fromhex(reopened["session"]))
    return report


STDOUT = ("\n".join(f"test {name} ... ok" for name in sorted(package.TESTS)) +
          "\ntest result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;\n").encode()


class ContinuityPackageTests(unittest.TestCase):
    def test_interleaved_rlib_cdylib_sources_cannot_replace_fresh_consumer_dependencies(self):
        # Cargo can leave a dependency fingerprint fresh after another source
        # root replaces its unhashed rlib. Exercise real compilation and linking.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            producer, rust, native = package.build_directories(root)
            self.assertEqual(native, root / "build", "native readers retain this path")
            for name, value in (("a", 1), ("b", 2), ("c", 3)):
                source = root / name
                (source / "src").mkdir(parents=True)
                (source / "Cargo.toml").write_text(
                    '[package]\nname="artifact-isolation-probe"\nversion="0.0.0"\n'
                    'edition="2021"\n[lib]\ncrate-type=["rlib","cdylib"]\n[workspace]\n')
                (source / "src/lib.rs").write_text(f'pub fn value() -> u32 {{ {value} }}\n')
            for name, dependency in (("rust-client", "a"), ("native-client", "c")):
                source = root / name
                (source / "src").mkdir(parents=True)
                (source / "Cargo.toml").write_text(
                    f'[package]\nname="{name}"\nversion="0.0.0"\nedition="2021"\n'
                    f'[dependencies]\nartifact-isolation-probe={{path="../{dependency}"}}\n'
                    '[profile.dev.package."*"]\nopt-level=3\n[workspace]\n')
                (source / "src/main.rs").write_text(
                    'fn main() { println!("{}", artifact_isolation_probe::value()); }\n')
            environment = {k: v for k, v in os.environ.items()
                           if not k.startswith(("CARGO_", "RUST")) or k == "RUSTUP_HOME"}
            environment.update(CARGO_HOME=str(root / "cargo-home"), CARGO_NET_OFFLINE="true",
                               CARGO_INCREMENTAL="0", RUSTFLAGS="-D warnings")

            def run(argv, target):
                with contextlib.chdir(root):
                    result = capture_output(argv, timeout_seconds=120,
                        maximum_stdout_bytes=512 * 1024, maximum_stderr_bytes=512 * 1024,
                        environment=dict(environment, CARGO_TARGET_DIR=str(target)))
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                return result.stdout.decode().strip()

            def consumer(name, target, revision):
                run(["rustup", "run", "1.98.1", "cargo", "rustc", "--offline", "--manifest-path",
                     str(root / name / "Cargo.toml"), "--", "-C", f"metadata=revision{revision}"], target)
                suffix = ".exe" if os.name == "nt" else ""
                return run([str(target / "debug" / (name + suffix))], target)

            self.assertEqual(consumer("rust-client", rust, 1), "1")
            self.assertEqual(consumer("native-client", native, 1), "3")
            run(["rustup", "run", "1.98.1", "cargo", "build", "--offline", "--manifest-path",
                 str(root / "b/Cargo.toml")], producer)
            self.assertEqual(consumer("rust-client", rust, 2), "1")
            self.assertEqual(consumer("native-client", native, 2), "3")
            for directory in (producer, rust):
                reclaimed = package.retire_completed_build(root, directory)
                self.assertTrue(reclaimed["completed"])
                self.assertGreater(reclaimed["files"], 0)
                self.assertGreater(reclaimed["unique_inode_allocated_bytes"], 0)
                self.assertFalse(directory.exists())
            # Actual C-side compilation/linking still consumes its own rlib.
            self.assertEqual(consumer("native-client", native, 3), "3")

    def test_build_retirement_preserves_sources_archive_and_native_outputs(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            producer, rust, native = package.build_directories(root)
            for directory in (producer, rust, native, root / "source", root / "consumer"):
                directory.mkdir()
                (directory / "retained").write_bytes(b"original")
            archive = root / "verified.crate"
            archive.write_bytes(b"verified archive")
            for directory in (producer, rust):
                receipt = package.retire_completed_build(root, directory)
                self.assertEqual(receipt["files"], 1)
                self.assertEqual(receipt["logical_bytes"], len(b"original"))
                self.assertIsInstance(receipt["filesystem_free_after"], int)
            for directory in (native, root / "source", root / "consumer"):
                self.assertEqual((directory / "retained").read_bytes(), b"original")
            self.assertEqual(archive.read_bytes(), b"verified archive")

    def test_build_retirement_refuses_active_unknown_external_and_linked_roots(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            outside = root / "private"
            outside.mkdir()
            external = root / "rust-build"
            external.mkdir()
            (external / "retained").write_bytes(b"external")
            (outside / "package-build").symlink_to(external, target_is_directory=True)
            (outside / "build").mkdir()
            (outside / "other").mkdir()
            for directory in (outside / "build", outside / "other", external,
                              outside / "package-build", outside / "missing", outside):
                with self.subTest(directory=directory), self.assertRaises(ValueError):
                    package.retire_completed_build(outside, directory)
            self.assertEqual((external / "retained").read_bytes(), b"external")
            self.assertTrue((outside / "build").is_dir())

    def test_build_retirement_unlinks_nested_symlink_without_touching_its_target(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            build = root / "package-build"
            build.mkdir()
            kept = root / "kept"
            kept.mkdir()
            (kept / "original").write_bytes(b"keep")
            (build / "linked").symlink_to(kept, target_is_directory=True)
            package.retire_completed_build(root, build)
            self.assertEqual((kept / "original").read_bytes(), b"keep")

    def test_build_retirement_propagates_io_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            build = root / "rust-build"
            build.mkdir()
            (build / "original").write_bytes(b"original")
            with patch.object(package.shutil, "rmtree", side_effect=OSError("removal failed")):
                with self.assertRaisesRegex(OSError, "removal failed"):
                    package.retire_completed_build(root, build)
            self.assertEqual((build / "original").read_bytes(), b"original")

    def test_build_retirement_counts_hardlinked_files_without_claiming_reclaimed_space(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            kept = root / "kept"
            kept.write_bytes(b"original")
            build = root / "rust-build"
            build.mkdir()
            for name in ("one", "two"):
                os.link(kept, build / name)
            allocated = kept.stat().st_blocks * 512
            receipt = package.retire_completed_build(root, build)
            self.assertEqual(receipt["files"], 2)
            self.assertEqual(receipt["logical_bytes"], len(b"original") * 2)
            self.assertEqual(receipt["unique_inode_allocated_bytes"], allocated)
            self.assertEqual(kept.read_bytes(), b"original")

    def test_package_compiler_uses_declared_producer_target_without_mutating_consumers(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            candidate = root / "research/candidate"
            candidate.mkdir(parents=True)
            (candidate / "Cargo.toml").write_bytes(b"candidate manifest")
            output = root / "output"
            output.mkdir()
            build = root / "producer-build"
            environment = {"CARGO_TARGET_DIR": str(root / "native-build"), "CARGO_NET_OFFLINE": "true"}
            original = dict(environment)
            observed = []

            def run(argv, label, *, env=None):
                if label == "candidate-sources":
                    return b"research/candidate/Cargo.toml\n"
                env = environment if env is None else env
                observed.append((label, dict(env)))
                if label == "package-list":
                    return b"Cargo.toml\n"
                if label == "package":
                    destination = Path(env["CARGO_TARGET_DIR"]) / "package"
                    destination.mkdir(parents=True)
                    (destination / f"{package.NAME}-{package.VERSION}.crate").write_bytes(b"archive")
                    for suffix in ("stdout", "stderr"):
                        (output / f"package.{suffix}").write_text("")
                return b""

            with patch.object(package, "ROOT", root), patch.object(package, "CANDIDATE", candidate), \
                    patch.object(sdk, "CONSUMER_CRATES", ()), \
                    patch.object(package, "validate_candidate", return_value={"Cargo.toml": b"manifest"}), \
                    patch.object(sdk, "validate_cargo_package_completion"):
                package.package_candidate(["cargo"], root / "source", build, root,
                                          {"crates": {}}, {}, output, run, environment)
            self.assertEqual(environment, original)
            self.assertEqual([label for label, _ in observed], ["fetch", "package-list", "package"])
            self.assertTrue(all(env["CARGO_TARGET_DIR"] == str(build) for _, env in observed))
            self.assertEqual([env["CARGO_NET_OFFLINE"] for _, env in observed], ["false", "true", "true"])

    def test_failed_child_diagnostics_are_bound_to_package_source(self):
        sources = package.source_inputs()['files']
        for relative in ('artifact/continuity_process_failure.py', 'artifact/continuity_process_crash.py',
                         'artifact/test_continuity_process_failure.py', 'artifact/test_continuity_process_crash.py',
                         'bindings/c/ContinuityPackageConsumer/tests/common/process_diagnostics.rs',
                         'bindings/c/ContinuityPackageConsumer/tests/process_diagnostics.rs'):
            with self.subTest(relative=relative):
                self.assertEqual(sources[relative], sdk.snapshot(package.ROOT / relative).sha256)

    def test_final_archive_check_uses_original_record_and_refuses_substitution(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            name = f"{package.NAME}-{package.VERSION}.crate"
            path = root / name
            path.write_bytes(b"original produced archive")
            original = sdk.snapshot(path)
            record = {"file": name, "sha256": original.sha256, "bytes": original.size}
            package.verify_candidate_archive(root, record)
            with self.assertRaisesRegex(ValueError, "filename changed"):
                package.verify_candidate_archive(root, dict(record, file="../another.crate"))
            with self.assertRaisesRegex(ValueError, "archive changed"):
                package.verify_candidate_archive(root, dict(record, bytes=original.size + 1))
            path.write_bytes(b"substitute bytes of same!".ljust(original.size, b"!"))
            self.assertEqual(path.stat().st_size, original.size)
            with self.assertRaisesRegex(ValueError, "archive changed"):
                package.verify_candidate_archive(root, record)
            path.unlink()
            with self.assertRaises(ValueError):
                package.verify_candidate_archive(root, record)

    def test_android_roster_readers_are_bound_to_package_source(self):
        import continuity_android_contract as contract
        import continuity_android_roster as roster
        import continuity_android_roster_witness as witnessed
        import continuity_android_policy_roster as policy_roster
        import continuity_android_roster_qualification as qualification
        import continuity_android_retirement as retirement
        import continuity_android_root as root_qualification
        sources = package.source_inputs()['files']
        for module in (contract, roster, witnessed, policy_roster, qualification, retirement, root_qualification):
            path = Path(module.__file__).resolve()
            relative = path.relative_to(package.ROOT).as_posix()
            with self.subTest(reader=relative):
                self.assertIn(relative, sources)
                self.assertEqual(sources[relative], sdk.snapshot(path).sha256)

    def test_installed_execution_requires_device_replacement_readback(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            evidence(root)
            (root / "replacement/result.json").unlink()
            with self.assertRaisesRegex(ValueError, "replacement public inventory"):
                package.verify_execution(STDOUT, root, root / "reopen", root / "roster", root / "replacement", root / "retirement")

    def test_installed_execution_requires_retirement_readback(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            evidence(root)
            (root / "retirement/retirement-ack").unlink()
            with self.assertRaisesRegex(ValueError, "retirement public inventory"):
                package.verify_execution(STDOUT, root, root / "reopen", root / "roster", root / "replacement", root / "retirement")

    def test_every_account_witness_reader_is_bound_to_package_source(self):
        import continuity_c_account_witness as signed
        import continuity_c_account_tls as tls
        import continuity_c_account_tls_loss as loss
        import continuity_c_account_delivery as delivery
        import continuity_c_setup as setup
        import continuity_roster_renewal as renewal
        import continuity_enrollment as enrollment
        import continuity_c_enrollment as c_enrollment
        import continuity_witnessed_renewal as witnessed_renewal
        import continuity_witnessed_policy_expiry as policy_expiry
        import continuity_witnessed_cancellation as cancellation
        import continuity_witnessed_commit_error as commit_error
        import continuity_foreign_account_results as foreign_account
        import continuity_foreign_policy as foreign_policy
        import continuity_foreign_roster as foreign_roster
        import continuity_peer_tls_preprocessing as peer_preprocessing
        import continuity_device_replacement as replacement
        import continuity_device_retirement as retirement
        import continuity_first_configuration as configuration
        import continuity_configuration_policy as configuration_policy
        import continuity_configuration_credential as configuration_credential
        import continuity_peer_configuration as peers
        sources = package.source_inputs()['files']
        for module in (signed, tls, loss, delivery, setup, renewal, enrollment, c_enrollment, witnessed_renewal, policy_expiry, cancellation, commit_error,
                       foreign_account, foreign_policy, foreign_roster, peer_preprocessing, replacement, retirement, configuration, configuration_policy, configuration_credential, peers):
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
            self.assertEqual(len(package.verify_execution(STDOUT, root, root / "reopen", root / "roster", root / "replacement", root / "retirement")["application_readbacks"]), 2)
            for stdout in (b"", STDOUT.replace(b"0 ignored", b"1 ignored"),
                           STDOUT.replace(b"0 filtered out", b"1 filtered out")):
                with self.subTest(stdout=stdout), self.assertRaisesRegex(ValueError, "all three complete"):
                    package.verify_execution(stdout, root, root / "reopen", root / "roster", root / "replacement", root / "retirement")
            for field, value in (("network_rekeys", 0), ("network_rekeys", True),
                                 ("cleanup_after_revocation", False), ("unknown_delivery_reconciled", 1)):
                changed = dict(report, **{field: value})
                (root / "public-result.json").write_text(json.dumps(changed))
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    package.verify_execution(STDOUT, root, root / "reopen", root / "roster", root / "replacement", root / "retirement")

    def test_receipt_cannot_replace_independent_application_and_cleanup_readback(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            report = evidence(root)
            received = root / "responder" / ("application-" + report["forward_message"])
            original = received.read_bytes()
            received.write_bytes(original[:-1] + b"!")
            with self.assertRaisesRegex(ValueError, "readback differs"):
                package.verify_execution(STDOUT, root, root / "reopen", root / "roster", root / "replacement", root / "retirement")
            received.write_bytes(original)
            (root / "responder/cleanup-verified").write_bytes(b"y" * 32)
            with self.assertRaisesRegex(ValueError, "original report identity"):
                package.verify_execution(STDOUT, root, root / "reopen", root / "roster", root / "replacement", root / "retirement")

    def test_old_success_log_cannot_omit_roster_recovery_stage(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            evidence(root)
            (root / "roster/public-roster-result.json").unlink()
            with self.assertRaises(ValueError):
                package.verify_execution(STDOUT, root, root / "reopen", root / "roster", root / "replacement", root / "retirement")

    def test_connection_log_requires_original_enrollment_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            evidence(root)
            path = root / "enrollment-public/initiator/reopened-request"
            path.unlink()
            with self.assertRaisesRegex(ValueError, "public file inventory"):
                package.verify_execution(STDOUT, root, root / "reopen", root / "roster", root / "replacement", root / "retirement")

    def test_other_self_consistent_enrollment_connection_is_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            evidence(root)
            for role in ("initiator", "responder"):
                folder = root / "enrollment-public" / role
                (folder / "session").write_bytes(b"z" * 32)
                for name in ("forward-effect", "reverse-effect"):
                    original = (folder / name).read_bytes()
                    (folder / name).write_bytes(b"z" * 32 + original[32:])
            with self.assertRaisesRegex(ValueError, "another connection"):
                package.verify_execution(STDOUT, root, root / "reopen", root / "roster", root / "replacement", root / "retirement")

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



class SessionReopenEvidenceTests(unittest.TestCase):
    def test_restoration_requires_original_enrollment_and_current_roster_readbacks(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            evidence(root)
            for name in ("request", "reopened-request", "renewal-roster-2", "renewal-digest-2",
                         "refreshed-roster-checkpoint", "refreshed-journal", "session"):
                path = root / "reopen/initiator" / name
                original = path.read_bytes()
                path.write_bytes(bytes([original[0] ^ 1]) + original[1:])
                with self.subTest(name=name), self.assertRaises(ValueError):
                    package.verify_execution(STDOUT, root, root / "reopen", root / "roster", root / "replacement", root / "retirement")
                path.write_bytes(original)
            report_path = root / "reopen/public-reopen-result.json"
            report = json.loads(report_path.read_text())
            del report["enrollment_roster_refresh"]
            report_path.write_text(json.dumps(report))
            with self.assertRaisesRegex(ValueError, "enrollment_roster_refresh"):
                package.verify_execution(STDOUT, root, root / "reopen", root / "roster", root / "replacement", root / "retirement")

    def test_enrolled_restoration_exports_only_the_verified_public_closure(self):
        from continuity_enrollment import export_reopen, verify_reopen
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            evidence(root)
            destination = root / "enrollment-restored"
            exported = export_reopen(root / "reopen", destination, 170, "44" * 32)
            self.assertEqual(len(exported["public_readbacks"]), 44)
            self.assertEqual(verify_reopen(destination, 170, "44" * 32, public_only=True), exported)
            (destination / "initiator/wrap.key").write_bytes(b"not public")
            with self.assertRaisesRegex(ValueError, "public file inventory"):
                verify_reopen(destination, 170, "44" * 32, public_only=True)

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
                    package.verify_execution(STDOUT, root, restored, root / "roster", root / "replacement", root / "retirement")
                path.write_bytes(original)
            report_path = restored / "public-reopen-result.json"
            original = json.loads(report_path.read_text())
            for field, value in (("fresh_bootstrap_refused", False), ("exact_outbox", 1),
                                 ("application_readbacks", True)):
                report_path.write_text(json.dumps(dict(original, **{field: value})))
                with self.subTest(field=field), self.assertRaises(ValueError):
                    package.verify_execution(STDOUT, root, restored, root / "roster", root / "replacement", root / "retirement")
            report_path.write_text(json.dumps(original))
            self.assertTrue(package.verify_execution(STDOUT, root, restored, root / "roster", root / "replacement", root / "retirement")["session_reopen"]["exact_outbox"])


if __name__ == "__main__":
    unittest.main(warnings="error")
