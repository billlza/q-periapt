from __future__ import annotations

import contextlib
import io
import os
import pathlib
import re
import tempfile
import unittest
from unittest import mock

import formal_toolchain_contract as contract
from bounded_process import BoundedProcessError, BoundedResult


ROOT = pathlib.Path(__file__).resolve().parents[1]


class FormalToolchainContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.bin = pathlib.Path(self.temporary.name).resolve() / "bin"
        self.bin.mkdir()
        for name in ("easycrypt", "tamarin-prover", "maude", "proverif"):
            executable = self.bin / name
            executable.write_bytes(b"formal tool fixture\n")
            executable.chmod(0o755)
        self.path_environment = os.pathsep.join((str(self.bin), "/usr/bin", "/bin"))
        self.calls: list[tuple[tuple[str, ...], dict[str, object]]] = []

    @staticmethod
    def _output(name: str) -> bytes:
        outputs = {
            "easycrypt": (
                f"{contract.EXPECTED_EASYCRYPT_CONFIG_LINE}\n"
                "load-path:\n  <system>@/fixed/easycrypt/theories\n"
            ),
            "tamarin-prover": (
                "tamarin-prover 1.12.0, (C) Test Authors\n"
                "\nGenerated from:\n"
                f"Tamarin version {contract.EXPECTED_TAMARIN_VERSION}\n"
                f"Maude version {contract.EXPECTED_MAUDE_VERSION}\n"
            ),
            "maude": f"{contract.EXPECTED_MAUDE_VERSION}\n",
            "proverif": (
                f"Proverif {contract.EXPECTED_PROVERIF_VERSION}. "
                "Cryptographic protocol verifier, by Test Authors\n"
                "  -test  display more information\n"
            ),
        }
        return outputs[name].encode("utf-8")

    def runner(self, argv: tuple[str, ...], **kwargs: object) -> BoundedResult:
        self.calls.append((tuple(argv), dict(kwargs)))
        name = pathlib.Path(argv[0]).name
        output = self._output(name)
        if name == "easycrypt":
            stdout, stderr = b"", output
        elif name == "tamarin-prover":
            stdout = output
            stderr = (
                "maude tool: 'maude'\n"
                f" checking version: {contract.EXPECTED_MAUDE_VERSION}. OK.\n"
                " checking installation: OK.\n"
            ).encode("utf-8")
        else:
            stdout, stderr = output, b""
        return BoundedResult(
            returncode=0,
            stdout=stdout,
            stderr=stderr,
        )

    def test_fixed_versions_match_the_pinned_easycrypt_source(self) -> None:
        self.assertEqual(
            "50ae51d106dfb6611235f4a8bb7f46275d34a38d",
            contract.EXPECTED_EASYCRYPT_SOURCE_COMMIT,
        )
        self.assertEqual(
            "git-hash: r2026.06-6-g50ae51d",
            contract.EXPECTED_EASYCRYPT_CONFIG_LINE,
        )
        self.assertEqual("1.12.0", contract.EXPECTED_TAMARIN_VERSION)
        self.assertEqual("3.5.1", contract.EXPECTED_MAUDE_VERSION)
        self.assertEqual("2.05", contract.EXPECTED_PROVERIF_VERSION)
        dockerfile = (ROOT / "formal" / "Dockerfile").read_text(encoding="utf-8")
        match = re.search(r"(?m)^ARG EC_COMMIT=([0-9a-f]{40})$", dockerfile)
        self.assertIsNotNone(match)
        self.assertEqual(
            contract.EXPECTED_EASYCRYPT_SOURCE_COMMIT,
            match.group(1) if match is not None else None,
        )

    def test_all_exact_identities_pass_through_bounded_commands(self) -> None:
        verified = contract.verify_installed(
            "all",
            path_environment=self.path_environment,
            runner=self.runner,
        )
        self.assertEqual(
            ("easycrypt", "tamarin", "maude", "proverif"),
            verified,
        )
        self.assertEqual(
            [
                ("easycrypt", "config"),
                ("tamarin-prover", "--version"),
                ("maude", "--version"),
                ("proverif", "-help"),
            ],
            [argv for argv, _kwargs in self.calls],
        )
        for argv, kwargs in self.calls:
            with self.subTest(tool=argv[0]):
                self.assertEqual(
                    contract.COMMAND_TIMEOUT_SECONDS,
                    kwargs["timeout_seconds"],
                )
                self.assertEqual(
                    contract.MAXIMUM_STDOUT_BYTES,
                    kwargs["maximum_stdout_bytes"],
                )
                self.assertEqual(
                    contract.MAXIMUM_STDERR_BYTES,
                    kwargs["maximum_stderr_bytes"],
                )
                environment = kwargs["environment"]
                self.assertIsInstance(environment, dict)
                self.assertEqual(
                    {"LANG", "LC_ALL", "PATH"},
                    set(environment),
                )
                self.assertEqual("C", environment["LANG"])
                self.assertEqual("C", environment["LC_ALL"])

    def test_partial_selections_execute_only_available_tool_groups(self) -> None:
        expectations = {
            "easycrypt": (["easycrypt"], ("easycrypt",)),
            "tamarin": (["tamarin-prover", "maude"], ("tamarin", "maude")),
            "proverif": (["proverif"], ("proverif",)),
        }
        for selection, (expected_commands, expected_marker) in expectations.items():
            self.calls.clear()
            with self.subTest(selection=selection):
                marker = contract.verify_installed(
                    selection,
                    path_environment=self.path_environment,
                    runner=self.runner,
                )
                self.assertEqual(expected_marker, marker)
                self.assertEqual(
                    expected_commands,
                    [pathlib.Path(call[0][0]).name for call in self.calls],
                )

    def test_tamarin_and_maude_use_the_same_unchanged_path(self) -> None:
        selected_path = os.pathsep.join(("/usr/bin", str(self.bin)))
        contract.verify_installed(
            "tamarin",
            path_environment=selected_path,
            runner=self.runner,
        )
        self.assertEqual(
            ["tamarin-prover", "maude"],
            [argv[0] for argv, _kwargs in self.calls],
        )
        for _argv, kwargs in self.calls:
            self.assertEqual(selected_path, kwargs["environment"]["PATH"])

    def test_parsers_reject_missing_duplicate_and_wrong_identities(self) -> None:
        parser_cases = (
            (
                contract.parse_easycrypt_config,
                "git-hash: wrong\n",
                "EasyCrypt",
            ),
            (
                contract.parse_easycrypt_config,
                f"{contract.EXPECTED_EASYCRYPT_CONFIG_LINE}\n"
                f"{contract.EXPECTED_EASYCRYPT_CONFIG_LINE}\n",
                "EasyCrypt",
            ),
            (
                contract.parse_tamarin_version,
                "Tamarin version 1.10.0\nMaude version 3.5.1\n",
                "Tamarin",
            ),
            (
                contract.parse_tamarin_version,
                "Tamarin version 1.12.0\nMaude version 2.7.1\n",
                "Maude",
            ),
            (
                contract.parse_tamarin_version,
                "Tamarin version 1.12.0\n"
                "Tamarin version 1.12.0\n"
                "Maude version 3.5.1\n",
                "Tamarin",
            ),
            (
                contract.parse_tamarin_diagnostics,
                "maude tool: 'maude'\n"
                " checking version: 2.7.1. OK.\n"
                " checking installation: OK.\n",
                "Maude health",
            ),
            (contract.parse_maude_version, "3.5.1\n\n", "Maude"),
            (contract.parse_maude_version, "3.5.1\n3.5.1\n", "Maude"),
            (
                contract.parse_proverif_help,
                "Proverif 2.05.1. Cryptographic protocol verifier, by Authors\n",
                "ProVerif",
            ),
            (
                contract.parse_proverif_help,
                "Proverif 2.05. Cryptographic protocol verifier, by Authors\n"
                "Proverif 2.05. Cryptographic protocol verifier, by Authors\n",
                "one expected version",
            ),
            (
                contract.parse_proverif_help,
                "banner\nProverif 2.05. Cryptographic protocol verifier, by Authors\n",
                "begin",
            ),
            (
                contract.parse_easycrypt_config,
                f"{contract.EXPECTED_EASYCRYPT_CONFIG_LINE}\n"
                "warning: fixture diagnostic\n",
                "warning diagnostic",
            ),
        )
        for parser, output, message in parser_cases:
            with (
                self.subTest(parser=parser.__name__, output=output),
                self.assertRaisesRegex(
                    contract.FormalToolchainContractError,
                    message,
                ),
            ):
                parser(output)

    def test_runner_failures_and_malformed_outputs_fail_closed(self) -> None:
        failures = (
            (
                mock.Mock(
                    side_effect=BoundedProcessError("timeout", "fixture timeout")
                ),
                "bounded process timeout",
            ),
            (mock.Mock(return_value=BoundedResult(9, b"", b"")), "status 9"),
            (
                mock.Mock(return_value=BoundedResult(0, b"\xff", b"")),
                "not UTF-8",
            ),
            (
                mock.Mock(return_value=BoundedResult(0, b"wrong stream\n", b"")),
                "unexpected output",
            ),
            (
                mock.Mock(return_value=BoundedResult(0, b"ok\x00\n", b"")),
                "NUL byte",
            ),
            (mock.Mock(return_value=object()), "malformed"),
        )
        for runner, message in failures:
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(
                    contract.FormalToolchainContractError,
                    message,
                ),
            ):
                contract.verify_installed(
                    "easycrypt",
                    path_environment=self.path_environment,
                    runner=runner,
                )

        def missing_maude(
            argv: tuple[str, ...], **kwargs: object
        ) -> BoundedResult:
            if argv[0] == "maude":
                raise BoundedProcessError("start", "fixture Maude is unavailable")
            return self.runner(argv, **kwargs)

        with self.assertRaisesRegex(
            contract.FormalToolchainContractError,
            "Maude identity bounded process start",
        ):
            contract.verify_installed(
                "tamarin",
                path_environment=self.path_environment,
                runner=missing_maude,
            )

    def test_path_and_executable_selection_fail_closed(self) -> None:
        for selected_path, message in (
            ("", "PATH"),
            (f"relative{os.pathsep}{self.bin}", "absolute"),
            (f"{self.bin}{os.pathsep}", "absolute"),
            (f"{os.pathsep}{self.bin}", "absolute"),
            (f"{self.bin}\x00", "PATH"),
        ):
            with (
                self.subTest(selected_path=selected_path),
                self.assertRaisesRegex(
                    contract.FormalToolchainContractError,
                    message,
                ),
            ):
                contract.verify_installed(
                    "easycrypt",
                    path_environment=selected_path,
                    runner=self.runner,
                )

        with (
            mock.patch.dict(os.environ, {}, clear=True),
            self.assertRaisesRegex(
                contract.FormalToolchainContractError,
                "PATH",
            ),
        ):
            contract.verify_installed("easycrypt", runner=self.runner)

        missing_bin = pathlib.Path(self.temporary.name).resolve() / "missing-bin"
        missing_bin.mkdir()
        with self.assertRaisesRegex(
            contract.FormalToolchainContractError,
            "bounded process start",
        ):
            contract.verify_installed(
                "easycrypt",
                path_environment=str(missing_bin),
            )

        runner = mock.Mock()
        with self.assertRaisesRegex(
            contract.FormalToolchainContractError,
            "fixed contract command",
        ):
            contract._run_identity_command(
                "../easycrypt",
                ("config",),
                label="fixture",
                path_environment=self.path_environment,
                runner=runner,
            )
        runner.assert_not_called()

        with self.assertRaisesRegex(
            contract.FormalToolchainContractError,
            "fixed contract command",
        ):
            contract._run_identity_command(
                "easycrypt",
                ("config", "--injected"),
                label="fixture",
                path_environment=self.path_environment,
                runner=runner,
            )
        runner.assert_not_called()

    def test_cli_markers_and_errors_are_exact(self) -> None:
        stdout = io.StringIO()
        with (
            mock.patch.object(
                contract,
                "verify_installed",
                return_value=("tamarin", "maude"),
            ) as verify,
            contextlib.redirect_stdout(stdout),
        ):
            self.assertEqual(
                0,
                contract.main(["verify-installed", "--tool", "tamarin"]),
            )
        verify.assert_called_once_with("tamarin")
        self.assertEqual(
            "FORMAL_TOOLCHAIN_CONTRACT_PASS tools=tamarin,maude\n",
            stdout.getvalue(),
        )

        stderr = io.StringIO()
        with (
            mock.patch.object(
                contract,
                "verify_installed",
                side_effect=contract.FormalToolchainContractError("wrong version"),
            ),
            contextlib.redirect_stderr(stderr),
        ):
            self.assertEqual(
                1,
                contract.main(["verify-installed", "--tool", "all"]),
            )
        self.assertEqual(
            "error: formal toolchain contract: wrong version\n",
            stderr.getvalue(),
        )


if __name__ == "__main__":
    unittest.main()
