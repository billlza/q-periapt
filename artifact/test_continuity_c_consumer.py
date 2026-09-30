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
          "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out;\n").encode()


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
                           STDOUT.replace(b"2 filtered out", b"3 filtered out"), STDOUT + STDOUT):
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
