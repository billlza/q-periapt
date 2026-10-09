"""Incomplete foreign execution and build-tree loading must not qualify packages."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

import continuity_c_consumer as consumer


class AdmissionTests(unittest.TestCase):
    def test_all_deadline_and_drain_tests_must_actually_execute(self):
        names = [
            "configuration::tests::configuration_cancel_before_finish_has_no_filesystem_effect",
            "configuration::tests::configuration_headers_reject_short_structures_before_payload_reads",
            "configuration::tests::configuration_historical_snapshot_does_not_authorize_credential_acceptance",
            "configuration::tests::configuration_owned_store_reaches_real_enrollment_activation_and_reopen",
            "configuration::tests::configured_witness_snapshots_trust_without_files_and_checks_tls_identity",
            "configuration::tests::failed_continuation_handoff_releases_both_original_leases",
            "first_install::tests::configuration_changed_file_is_not_repaired_by_reconciliation",
            "first_install::tests::configuration_disabled_signed_profile_never_grants_bootstrap_permission",
            "first_install::tests::configuration_full_sdk_policy_bound_survives_operational_loader",
            "first_install::tests::configuration_inputs_are_bounded_and_snapshot_caller_buffers",
            "first_install::tests::configuration_invalid_recovery_proof_leaves_no_staging_directory",
            "first_install::tests::configuration_invalid_signature_or_tls_key_publishes_nothing",
            "first_install::tests::configuration_preparation_does_not_authorize_expired_or_future_policy",
            "first_install::tests::configuration_publishes_exact_inputs_and_owned_sdk_without_signing_identity",
            "first_install::tests::configuration_reconciliation_matches_enrollment_inside_database_not_only_sidecar",
            "first_install::tests::configuration_reconciliation_never_recreates_missing_database_or_changes_files",
            "first_install::tests::configuration_reconciliation_never_regenerates_a_missing_wrapping_key",
            "first_install::tests::configuration_reconciliation_preserves_genuine_advanced_policy",
            "first_install::tests::configuration_reconciliation_rejects_changed_root_with_identical_policy_floor",
            "first_install::tests::configuration_reconciliation_requires_exact_original_enrollment_proof",
            "first_install::tests::configuration_recoverable_first_use_requires_independent_trust_on_reopen",
            "first_install::tests::configuration_recoverable_reconciliation_does_not_enroll_a_fixed_store",
            "first_install::tests::configuration_rejects_substituted_pins_key_and_sdk_binding_before_publication",
            "invocation::tests::enclosing_deadline_is_shared_without_refresh_and_cannot_be_reentered",
            "invocation::tests::expired_admission_and_independent_owners_do_not_change_active_scope",
            "invocation::tests::sequential_calls_keep_their_own_cancellation_without_retaining_idle_authority",
            "native_fixture::owned_services_connect_restart_rekey_and_reconcile_unknown_delivery",
            "native_fixture::reopen::public_session_reopen_after_expiry_reconciles_unknown_commit_over_real_tls",
            "native_fixture::service_peer_process",
            "opening::tests::prepared_open_is_cancelable_single_use_and_capacity_bounded",
            "publication::tests::publication_absence_retirement_and_reserved_fields_cannot_fabricate_completion",
            "publication::tests::publication_invalid_plan_and_short_output_fail_before_owner_lookup",
            "publication::tests::publication_layouts_and_short_version_prefix_are_checked_before_the_body",
            "recovery::invocation_tests::expired_constructor_publication_returns_its_slot_without_a_handle",
            "recovery::invocation_tests::late_native_errors_survive_and_success_requires_original_state_reconciliation",
            "retirement::tests::retirement_output_layout_has_no_implicit_padding",
            "tests::full_call_budget_preserves_drain_and_returns_capacity_after_failure",
            "witness::tests::retained_tcp_endpoint_observes_each_invocations_cancellation",
            "witness::tests::retained_tls_endpoint_observes_each_invocations_cancellation",
        ]
        rows = [f"test {name} ... ok\n".encode() for name in names]
        summary = b"test result: ok. 39 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;\n"
        complete = b"".join(rows) + summary
        consumer.verify_admission(complete)
        for invalid in (summary, b"".join(rows[:-1]) + summary,
                        b"".join(rows[:-1] + [rows[0]]) + summary,
                        complete.replace(b"0 ignored", b"1 ignored"),
                        complete.replace(b"0 filtered out", b"1 filtered out")):
            with self.subTest(output=invalid), self.assertRaises(ValueError):
                consumer.verify_admission(invalid)
import continuity_package as package
from test_continuity_package import metadata


STDOUT = (f"test {consumer.TEST} ... ok\n"
          "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out;\n").encode()


def evidence(root):
    report = {"schema_version": 1, "completed": True, "scope": consumer.SCOPE,
              "session": "11" * 32, "first_message": "00" * 16 + "22" * 16,
              "post_rekey_message": "0000000000000001" + "00" * 8 + "33" * 16,
              "network_rekeys": 1, "independent_readbacks": 3, "release_claim_eligible": False,
              "unknown_delivery_reconciled": True, "pre_cancel_absent": True,
              "concurrent_close_busy": True, "cancelled_commit_reopened": True,
              "durable_sdk_revocation": True}
    (root / "initiator").mkdir()
    (root / "responder").mkdir()
    for name in ("first_message", "post_rekey_message"):
        (root / "responder" / ("application-" + report[name])).write_bytes(
            bytes.fromhex(report["session"] + report[name]) + b"persisted before process exit")
    outputs = {"self-check": "self-check-passed\n", "wrong-role": "rejected:211\n",
               "uncertain-send": "delivery-unknown-committed\n", "committed-status": "2\n",
               "exact-resend": "consumed\n", "rekey": "rekey-1-confirmed\n",
               "pre-cancel": "cancelled-absent\n", "concurrent-cancel": "cancelled-committed-reopened\n",
               "resume-cancelled": "consumed\n", "final-status": "3\n", "revoked-open": "rejected:603\n",
               "connect": report["session"] + "\n", "next": report["first_message"] + "\n",
               "next-after-rekey": report["post_rekey_message"] + "\n"}
    for name, output in outputs.items():
        (root / "initiator" / f"c-{name}.stdout").write_text(output)
        (root / "initiator" / f"c-{name}.stderr").write_bytes(b"")
    (root / "c-public-result.json").write_text(json.dumps(report))
    return report


class ContinuityCConsumerTests(unittest.TestCase):
    def test_foreign_client_scope_requires_the_explicit_language(self):
        for language in ("Swift", "Kotlin"):
            with self.subTest(language=language), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                report = evidence(root)
                report["scope"] = consumer.SCOPE.replace("C client", language + " client")
                (root / "c-public-result.json").write_text(json.dumps(report))
                with self.assertRaisesRegex(ValueError, "scope"):
                    consumer.verify_execution(STDOUT, root)
                observed = consumer.verify_execution(STDOUT, root, language=language)
                self.assertEqual(observed["scope"], report["scope"])
                with self.assertRaisesRegex(ValueError, "language"):
                    consumer.verify_execution(STDOUT, root, language="unverified")
                other = "Kotlin" if language == "Swift" else "Swift"
                with self.assertRaisesRegex(ValueError, "scope"):
                    consumer.verify_execution(STDOUT, root, language=other)

    def test_binary_copy_uses_its_explicit_bound_without_relaxing_source_inputs(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            binary = root / "library.so"
            with binary.open("xb") as stream:
                stream.seek(consumer.sdk.MAX_ARCHIVE)
                stream.write(b"x")
            # The actual Linux producer failed here before any C execution.
            with self.assertRaisesRegex(ValueError, "exceeds"):
                consumer.sdk.copy(binary, root / "source-copy")
            self.assertFalse((root / "source-copy").exists())
            target = root / "installed/library.so"
            consumer.sdk.copy(binary, target, maximum=consumer.MAX_BINARY)
            self.assertEqual(consumer.sdk.snapshot(binary, maximum=consumer.MAX_BINARY).sha256,
                             consumer.sdk.snapshot(target, maximum=consumer.MAX_BINARY).sha256)
            with self.assertRaises(FileExistsError):
                consumer.sdk.copy(binary, target, maximum=consumer.MAX_BINARY)
            with self.assertRaisesRegex(ValueError, "exceeds"):
                consumer.sdk.copy(binary, root / "too-small", maximum=binary.stat().st_size - 1)
            self.assertFalse((root / "too-small").exists())

    def server_evidence(self, root):
        messages = [(0).to_bytes(8, "big").hex() + n.to_bytes(8, "big").hex() + f"{n+2:02x}" * 16 for n in range(4)]
        messages.append("0000000000000001" + "00" * 8 + "55" * 16)
        report = {"schema_version": 1, "scope": consumer.SERVER_SCOPE, "session": "11" * 32,
                  "messages": messages, "network_rekeys": 1, "application_records": 5,
                  "release_claim_eligible": False, "listener_tls_deadline_ms": 20_010}
        for name in ("completed", "callback_failure_preserved", "unknown_commit_reconciled",
                     "crash_after_application_reconciled", "duplicate_skips_callback",
                     "reentrant_close_busy", "cancelled_listener_released",
                     "acknowledged_send_refused", "native_recovery_consumption"):
            report[name] = True
        (root / "responder").mkdir()
        (root / "initiator").mkdir()
        for message in messages:
            (root / "responder" / ("application-" + message)).write_bytes(
                bytes.fromhex(report["session"] + message) + b"persisted before process exit")
        def event(message, duplicate, calls, created):
            return f"served:{1 if message == '0' * 64 else 2}:{duplicate}:{calls}:{created}\n{report['session']}\n{message}\n"
        outputs = {"deadline": "server-deadline\n", "bootstrap": event("0" * 64, 0, 0, 0), "cancel": "server-cancelled\n",
                   "fail-before": "application-failed:1:0\n", "retry-0": event(messages[0], 0, 1, 1),
                   "duplicate-prepare": "application-failed:1:1\n",
                   "duplicate": event(messages[3], 1, 0, 0), "uncertain": "application-failed:1:1\n",
                   "retry-1": event(messages[1], 0, 1, 0), "crash-after": "",
                   "retry-2": event(messages[2], 0, 1, 0), "rekey": "server-rekey-1\n",
                   "after-rekey": event(messages[4], 0, 1, 1)}
        for name, output in outputs.items():
            (root / "responder" / f"c-server-{name}.stdout").write_text("listening:43210\n" + output)
            (root / "responder" / f"c-server-{name}.stderr").write_bytes(b"")
        (root / "c-server-public-result.json").write_text(json.dumps(report))
        return report

    def test_server_requires_all_callback_outcomes_and_exact_readback(self):
        stdout = STDOUT.replace(consumer.TEST.encode(), consumer.SERVER_TEST.encode())
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            report = self.server_evidence(root)
            observed = consumer.verify_server_execution(stdout, root)
            self.assertEqual(len(observed["command_logs"]), 26)
            self.assertEqual(len(observed["application_readbacks"]), 5)
            path = root / "responder" / ("application-" + report["messages"][1])
            data = path.read_bytes()
            path.write_bytes(data[:-1])
            with self.assertRaisesRegex(ValueError, "readback"):
                consumer.verify_server_execution(stdout, root)
            path.write_bytes(data)
            (root / "responder/c-server-uncertain.stdout").write_text("listening:43210\nconsumed\n")
            with self.assertRaisesRegex(ValueError, "command outcome"):
                consumer.verify_server_execution(stdout, root)

    def test_foreign_server_requires_explicit_scope_and_preserves_unknown_outcomes(self):
        stdout = STDOUT.replace(consumer.TEST.encode(), consumer.SERVER_TEST.encode())
        for language in ("Swift", "Kotlin"):
            with self.subTest(language=language), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                report = self.server_evidence(root)
                report["scope"] = consumer.SERVER_SCOPE.replace("C server", language + " server")
                (root / "c-server-public-result.json").write_text(json.dumps(report))
                with self.assertRaisesRegex(ValueError, "scope"):
                    consumer.verify_server_execution(stdout, root)
                observed = consumer.verify_server_execution(stdout, root, language=language)
                self.assertTrue(observed["unknown_commit_reconciled"])
                with self.assertRaisesRegex(ValueError, "language"):
                    consumer.verify_server_execution(stdout, root, language="unverified")
                other = "Kotlin" if language == "Swift" else "Swift"
                with self.assertRaisesRegex(ValueError, "scope"):
                    consumer.verify_server_execution(stdout, root, language=other)
                (root / "responder/c-server-uncertain.stdout").write_text("listening:43210\nconsumed\n")
                with self.assertRaisesRegex(ValueError, "command outcome"):
                    consumer.verify_server_execution(stdout, root, language=language)

    def test_server_rejects_omitted_tests_claims_and_epoch_substitution(self):
        stdout = STDOUT.replace(consumer.TEST.encode(), consumer.SERVER_TEST.encode())
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            report = self.server_evidence(root)
            for output in (b"", STDOUT, stdout + stdout, stdout.replace(b"0 ignored", b"1 ignored")):
                with self.subTest(output=output), self.assertRaises(ValueError):
                    consumer.verify_server_execution(output, root)
            for name, value in (("application_records", True), ("completed", 1),
                                ("listener_tls_deadline_ms", True), ("listener_tls_deadline_ms", 17_999),
                                ("listener_tls_deadline_ms", 23_000),
                                ("unknown_commit_reconciled", False), ("duplicate_skips_callback", False),
                                ("reentrant_close_busy", False), ("cancelled_listener_released", False),
                                ("release_claim_eligible", True), ("messages", report["messages"][:4]),
                                ("messages", report["messages"][:4] + ["00" * 16 + "55" * 16])):
                (root / "c-server-public-result.json").write_text(json.dumps(dict(report, **{name: value})))
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    consumer.verify_server_execution(stdout, root)

    def test_exact_trace_requires_independent_data_and_each_command(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            report = evidence(root)
            result = consumer.verify_execution(STDOUT, root)
            self.assertEqual(len(result["application_readbacks"]), 2)
            self.assertEqual(len(result["command_logs"]), 28)
            path = root / "responder" / ("application-" + report["post_rekey_message"])
            original = path.read_bytes()
            path.write_bytes(original[:-1] + b"!")
            with self.assertRaisesRegex(ValueError, "application readback"):
                consumer.verify_execution(STDOUT, root)
            path.write_bytes(original)
            (root / "initiator/c-concurrent-cancel.stdout").write_text("cancelled-absent\n")
            with self.assertRaisesRegex(ValueError, "command output"):
                consumer.verify_execution(STDOUT, root)

    def test_no_test_partial_flags_and_changed_epoch_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            report = evidence(root)
            for stdout in (b"", STDOUT.replace(b"0 ignored", b"1 ignored"),
                           STDOUT.replace(b"8 filtered out", b"5 filtered out"), STDOUT + STDOUT):
                with self.subTest(stdout=stdout), self.assertRaisesRegex(ValueError, "completely"):
                    consumer.verify_execution(stdout, root)
            for field, value in (("network_rekeys", 0), ("network_rekeys", True),
                                 ("independent_readbacks", True), ("completed", 1),
                                 ("concurrent_close_busy", False), ("release_claim_eligible", True),
                                 ("scope", "all platforms"), ("session", "0" * 64),
                                 ("post_rekey_message", "00" * 16 + "44" * 16)):
                changed = dict(report, **{field: value})
                (root / "c-public-result.json").write_text(json.dumps(changed))
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    consumer.verify_execution(STDOUT, root)

    def test_build_tree_library_and_loader_overrides_do_not_qualify_installation(self):
        name = "libq_periapt_continuity_c_consumer.dylib"
        deps = f"client:\n\t@rpath/{name} (compatibility version 0.0.0)\n\t/usr/lib/libSystem.B.dylib (x)\n"
        loader = "cmd LC_RPATH\ncmdsize 40\npath @loader_path (offset 12)\n"
        consumer.verify_linkage(deps, loader, name, darwin=True)
        for bad in (deps.replace("@rpath/", "/private/build/deps/"), deps.replace(name, "other.dylib")):
            with self.subTest(dependencies=bad), self.assertRaises(ValueError):
                consumer.verify_linkage(bad, loader, name, darwin=True)
        for bad in ("", loader.replace("@loader_path", "/private/build"), loader + loader):
            with self.subTest(loader=bad), self.assertRaises(ValueError):
                consumer.verify_linkage(deps, bad, name, darwin=True)
        name = "libq_periapt_continuity_c_consumer.so"
        deps = f"(NEEDED) Shared library: [{name}]\n(NEEDED) Shared library: [libc.so.6]\n(RUNPATH) Library runpath: [$ORIGIN]\n"
        consumer.verify_linkage(deps, deps, name, darwin=False)
        for bad in (deps.replace(name, "/tmp/build/" + name), deps.replace("$ORIGIN", "/tmp/build")):
            with self.subTest(elf=bad), self.assertRaises(ValueError):
                consumer.verify_linkage(bad, bad, name, darwin=False)

    def test_c_consumer_keeps_the_same_closed_archive_graph(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            graph = metadata(root)
            row = next(row for row in graph["packages"] if row["name"] == package.CONSUMER)
            row["id"] = row["name"] = consumer.NAME
            lock = b"version = 4\npackage = []\n"
            with self.assertRaisesRegex(ValueError, "feature"):
                package.verify_resolution(graph, root, lock, lock, consumer_name=consumer.NAME,
                                          required_features=consumer.FEATURES)
            graph["resolve"]["nodes"][0]["features"].append("anchor-tls")
            self.assertEqual(package.verify_resolution(graph, root, lock, lock,
                             consumer_name=consumer.NAME, required_features=consumer.FEATURES)["candidate_crates"], 1)
            bad = copy.deepcopy(graph)
            bad["packages"][-1]["manifest_path"] = str(root / "checkout/Cargo.toml")
            with self.assertRaisesRegex(ValueError, "resolved checkout"):
                package.verify_resolution(bad, root, lock, lock, consumer_name=consumer.NAME)
            with self.assertRaisesRegex(ValueError, "mixed product graph"):
                package.verify_resolution(graph, root, lock, lock)

    def test_trace_binary_requires_its_exact_source_and_profile(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            build = root / "build/debug"
            (build / "deps").mkdir(parents=True)
            encoded = lambda value: json.dumps(value).encode() + b"\n"
            for name in ("c_owner", "sync_fault", "witness", "account_cleanup", "account_witness", "retirement", "first_configuration"):
                binary = build / ("deps/" + name + "-test")
                binary.write_bytes(b"test")
                outside = build / binary.name
                outside.write_bytes(b"wrong profile")
                item = {"reason": "compiler-artifact", "executable": str(binary), "filenames": [str(binary)],
                        "target": {"name": name, "kind": ["test"], "src_path": str(root / ("tests/" + name + ".rs"))}}
                with self.subTest(target=name):
                    self.assertEqual(consumer.built_artifact(encoded(item), root, build,
                        library=False, test_name=name), binary)
                for bad in (b"", encoded(item) * 2,
                            encoded(dict(item, target=dict(item["target"], src_path=str(root / "substitute.rs")))),
                            encoded(dict(item, executable=str(outside)))):
                    with self.subTest(target=name, message=bad), self.assertRaises(ValueError):
                        consumer.built_artifact(bad, root, build, library=False, test_name=name)
            with self.assertRaisesRegex(ValueError, "unknown installed C test target"):
                consumer.built_artifact(encoded(item), root, build, library=False, test_name="unqualified")




class RestorationTests(unittest.TestCase):
    def test_expired_advertisement_restore_requires_actual_outputs_and_current_foreign_clock(self):
        stdout = (f"test {consumer.RESTORE_TEST} ... ok\n"
                  "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out;\n").encode()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for role in ("initiator", "responder"):
                (root / role).mkdir()
                (root / role / "session").write_bytes(bytes.fromhex("11" * 32))
                (root / role / "reopen-test-time").write_bytes((160).to_bytes(8, "big"))
            report = {"language": "C", "session": "11" * 32, "message": "22" * 32,
                      "advertisement_until": 160, "current_time": 170, "independent_readbacks": 2,
                      **{k: True for k in ("fresh_refused", "wrong_session_refused", "pre_cancel_absent",
                         "unknown_commit_reconciled", "actual_foreign_clock")}}
            report_path = root / "c-restore-public-result.json"
            report_path.write_text(json.dumps(report))
            effect = root / "responder" / ("application-" + report["message"])
            effect.write_bytes(bytes.fromhex(report["session"] + report["message"]) + b"persisted before process exit")
            expected = {"restore-fresh-refused": "rejected:104\n", "restore-wrong-session": "rejected:201\n",
                        "restore-next": report["message"] + "\n", "restore-cancelled": "cancelled-absent\n",
                        "restore-same-slot": report["message"] + "\n", "restore-unknown": "delivery-unknown-committed\n",
                        "restore-committed": "2\n", "restore-exact-resend": "consumed\n", "restore-acknowledged": "3\n"}
            for name, content in expected.items():
                (root / "initiator" / f"c-{name}.stdout").write_text(content)
                (root / "initiator" / f"c-{name}.stderr").write_bytes(b"")
            checked = consumer.verify_restore_execution(stdout, root)
            self.assertEqual(len(checked["public_readbacks"]), 6)
            self.assertEqual(len(checked["command_logs"]), 18)
            for field, value in (("current_time", 160), ("actual_foreign_clock", False),
                                 ("wrong_session_refused", 1), ("independent_readbacks", True), ("language", "Swift")):
                report_path.write_text(json.dumps(dict(report, **{field: value})))
                with self.subTest(field=field), self.assertRaises(ValueError):
                    consumer.verify_restore_execution(stdout, root)
            report_path.write_text(json.dumps(report))
            for leaf in (effect, root / "initiator/c-restore-acknowledged.stdout", root / "responder/reopen-test-time"):
                original = leaf.read_bytes();leaf.write_bytes(original[:-1] + b"!")
                with self.subTest(file=leaf.name), self.assertRaises(ValueError):
                    consumer.verify_restore_execution(stdout, root)
                leaf.write_bytes(original)
            for invalid in (b"", stdout + stdout, stdout.replace(b"8 filtered out", b"5 filtered out")):
                with self.subTest(stdout=invalid), self.assertRaises(ValueError):
                    consumer.verify_restore_execution(invalid, root)
            for language in ("Swift", "Kotlin"):
                report_path.write_text(json.dumps(dict(report, language=language)))
                self.assertEqual(consumer.verify_restore_execution(stdout, root, language=language)["language"], language)

if __name__ == "__main__":
    unittest.main(warnings="error")
