"""Exact operation admission before remote-consumer execution or log creation."""

from __future__ import annotations

import pathlib
import unittest
from unittest import mock

import apple_stable_publication as publication


class RemoteConsumerOperationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.run = pathlib.Path("/repository/target/qperiapt-swift-remote-consumer-runs/transaction.123456")
        verifier = self.run / "verifier-inputs"
        target = verifier / "target"
        assets = self.run / "release-assets"
        archive = str(assets / "CQPeriapt.xcframework.zip")
        extracted = str(target / "extracted")
        framework = str(target / "extracted/CQPeriapt.xcframework")
        consumer = str(target / "consumer")
        self.commands = {
            "ditto-extract.log": ("/usr/bin/ditto", "-x", "-k", archive, extracted),
            "swift-url-binary-consumer.log": ("/usr/bin/swift", "test", "--package-path", consumer),
            "swiftpm-checksum.log": (
                "/bin/sh", "-c",
                '\numask 077\nset -C\n/usr/bin/swift package compute-checksum "$2" >"$1"\n',
                "swiftpm-checksum", str(self.run / "swiftpm-checksum.txt"), archive,
            ),
            "consumer-check.log": (
                "/usr/bin/env", "QPERIAPT_INTERNAL_REQUIRE_DUAL_MACOS_RUNTIME=0",
                "/bin/sh", str(verifier / "artifact/swift-xcframework-consumer-check.sh"),
                consumer, str(target / "apple-consumer-evidence"), framework,
            ),
        }
        for phase in ("post-extract", "pre-receipt"):
            self.commands[f"codesign-{phase}.log"] = (
                "/usr/bin/codesign", "--verify", "--strict", "--verbose=4", framework,
            )
        for phase in ("pre-url", "post-extract", "post-consumer"):
            self.commands[f"release-assets-{phase}.log"] = (
                "/bin/sh", str(verifier / "artifact/python-run.sh"),
                str(verifier / "artifact/apple_stable_publication.py"),
                "verify-release-assets", str(verifier / "artifact/results.json"), str(assets),
                "1" * 40, "2" * 64, "3" * 64, "4" * 64, "5" * 64, "6" * 64,
            )

    def test_all_nine_producer_operations_are_accepted(self) -> None:
        self.assertEqual(set(publication.REMOTE_CONSUMER_GATE_LOG_NAMES), set(self.commands))
        for name, command in self.commands.items():
            with self.subTest(operation=name):
                self.assertEqual(command, publication._remote_consumer_gate_command(self.run, name, command))

    def test_only_declared_operation_names_are_admitted(self) -> None:
        for name in self.commands:
            requested = name.encode().decode()
            selected = publication._declared_remote_gate_log_name(requested)
            self.assertEqual(name, selected)
        for name in ("../ditto-extract.log", "ditto-extract.log/extra", "ditto-extract.log\n", "unknown.log", ""):
            with self.subTest(name=name), self.assertRaises(publication.AppleStablePublicationError):
                publication._declared_remote_gate_log_name(name)

    def test_every_operation_rejects_extra_arguments_and_replaced_executable(self) -> None:
        for name, command in self.commands.items():
            for changed in ((*command, "--extra"), ("/bin/echo", *command[1:]), command[1:]):
                with self.subTest(operation=name, command=changed), self.assertRaises(publication.AppleStablePublicationError):
                    publication._remote_consumer_gate_command(self.run, name, changed)

    def test_each_fixed_option_script_and_path_is_exact(self) -> None:
        for name, command in self.commands.items():
            fixed_count = 6 if name.startswith("release-assets-") else len(command)
            for index in range(1, fixed_count):
                changed = list(command)
                changed[index] += "-other"
                with self.subTest(operation=name, index=index), self.assertRaises(publication.AppleStablePublicationError):
                    publication._remote_consumer_gate_command(self.run, name, changed)

    def test_valid_directory_prefix_does_not_admit_a_different_object(self) -> None:
        command = self.commands["swift-url-binary-consumer.log"]
        for path in (command[-1] + "-other", command[-1] + "/../consumer", str(self.run / "consumer")):
            with self.subTest(path=path), self.assertRaises(publication.AppleStablePublicationError):
                publication._remote_consumer_gate_command(self.run, "swift-url-binary-consumer.log", (*command[:-1], path))

    def test_release_pins_are_data_with_exact_hex_shapes(self) -> None:
        name = "release-assets-pre-url.log"
        command = self.commands[name]
        for index in range(6, 12):
            for invalid in ("", "a" * 39, "A" * len(command[index]), command[index] + "\n", "--help"):
                changed = list(command)
                changed[index] = invalid
                with self.subTest(index=index, value=invalid), self.assertRaises(publication.AppleStablePublicationError):
                    publication._remote_consumer_gate_command(self.run, name, changed)

    def test_malformed_or_cross_operation_request_is_rejected(self) -> None:
        for arguments in ("/bin/sh", b"/bin/sh", (), (None,), ("",)):
            with self.subTest(arguments=arguments), self.assertRaises(publication.AppleStablePublicationError):
                publication._remote_consumer_gate_command(self.run, "ditto-extract.log", arguments)
        with self.assertRaises(publication.AppleStablePublicationError):
            publication._remote_consumer_gate_command(self.run, "ditto-extract.log", self.commands["consumer-check.log"])

    def test_command_refusal_precedes_child_and_evidence_io(self) -> None:
        runtime_root = pathlib.Path("/repository")
        with (
            mock.patch.object(publication, "normalize_safe_root", return_value=self.run.parent),
            mock.patch.object(publication, "open_private_direct_child_handle") as open_run,
            mock.patch.object(publication, "capture_stdout") as capture,
            self.assertRaises(publication.AppleStablePublicationError),
        ):
            publication.capture_remote_consumer_gate_log(
                runtime_repository_root=runtime_root, run_directory_name=self.run.name,
                log_name="ditto-extract.log", timeout_seconds=1, maximum_bytes=1024,
                argv=("/bin/sh", "-c", "unexpected command"),
            )
        open_run.assert_not_called()
        capture.assert_not_called()


if __name__ == "__main__":
    unittest.main()
