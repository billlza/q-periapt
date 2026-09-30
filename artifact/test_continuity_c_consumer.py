"""Incomplete foreign execution and build-tree loading must not qualify packages."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

import continuity_c_consumer as consumer
import continuity_package as package
from test_continuity_package import metadata


STDOUT = (f"test {consumer.TEST} ... ok\n"
          "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 4 filtered out;\n").encode()


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
                  "release_claim_eligible": False}
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
        outputs = {"bootstrap": event("0" * 64, 0, 0, 0), "cancel": "server-cancelled\n",
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
            self.assertEqual(len(observed["command_logs"]), 24)
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

    def test_server_rejects_omitted_tests_claims_and_epoch_substitution(self):
        stdout = STDOUT.replace(consumer.TEST.encode(), consumer.SERVER_TEST.encode())
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            report = self.server_evidence(root)
            for output in (b"", STDOUT, stdout + stdout, stdout.replace(b"0 ignored", b"1 ignored")):
                with self.subTest(output=output), self.assertRaises(ValueError):
                    consumer.verify_server_execution(output, root)
            for name, value in (("application_records", True), ("completed", 1),
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
                           STDOUT.replace(b"4 filtered out", b"5 filtered out"), STDOUT + STDOUT):
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
            self.assertEqual(package.verify_resolution(graph, root, lock, lock,
                             consumer_name=consumer.NAME)["candidate_crates"], 1)
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
            binary = build / "deps/c_owner-test"
            binary.write_bytes(b"test")
            item = {"reason": "compiler-artifact", "executable": str(binary), "filenames": [str(binary)],
                    "target": {"name": "c_owner", "kind": ["test"], "src_path": str(root / "tests/c_owner.rs")}}
            encoded = lambda value: json.dumps(value).encode() + b"\n"
            self.assertEqual(consumer.built_artifact(encoded(item), root, build, library=False), binary)
            for bad in (b"", encoded(item) * 2,
                        encoded(dict(item, target=dict(item["target"], src_path=str(root / "substitute.rs"))))):
                with self.subTest(message=bad), self.assertRaises(ValueError):
                    consumer.built_artifact(bad, root, build, library=False)


if __name__ == "__main__":
    unittest.main(warnings="error")
