from __future__ import annotations

import contextlib
import hashlib
import os
import pathlib
import stat
import tempfile
import unittest
from types import MappingProxyType
from unittest import mock

import proof_to_byte_inputs as inputs
from evidence_io import EvidenceIOError


ROOT = pathlib.Path(__file__).resolve().parents[1]


class ProofToByteInputsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name).resolve()

    @contextlib.contextmanager
    def input_map(self, mapping: dict[str, str]):
        with mock.patch.object(
            inputs,
            "PROOF_TO_BYTE_INPUT_PATHS",
            MappingProxyType(mapping),
        ):
            yield

    def write(self, relative: str, data: bytes) -> pathlib.Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def test_live_map_is_exact_unique_and_self_covering(self) -> None:
        mapping = inputs.PROOF_TO_BYTE_INPUT_PATHS
        self.assertEqual(247, len(mapping))
        self.assertEqual(len(mapping), len(set(mapping.values())))
        self.assertEqual(
            "artifact/test_proof_to_byte_inputs.py",
            mapping["proof_to_byte_inputs_tests_sha256"],
        )
        self.assertEqual(
            "artifact/test_source_results_assembler.py",
            mapping["source_results_assembler_tests_sha256"],
        )
        self.assertEqual(
            "artifact/formal_toolchain_contract.py",
            mapping["formal_toolchain_contract_sha256"],
        )
        self.assertEqual(
            "artifact/test_formal_toolchain_contract.py",
            mapping["formal_toolchain_contract_tests_sha256"],
        )
        self.assertEqual(
            "formal/Dockerfile",
            mapping["formal_easycrypt_dockerfile_sha256"],
        )
        self.assertEqual(
            "formal/proverif/Makefile",
            mapping["proverif_makefile_sha256"],
        )
        self.assertEqual(
            "artifact/rust_package_handoff.py",
            mapping["rust_package_handoff_sha256"],
        )
        self.assertEqual(
            "artifact/test_rust_package_handoff.py",
            mapping["rust_package_handoff_tests_sha256"],
        )
        for key, relative in mapping.items():
            with self.subTest(key=key):
                self.assertTrue(key.endswith("_sha256"))
                self.assertEqual(
                    pathlib.PurePosixPath(relative).as_posix(),
                    relative,
                )
                self.assertFalse(pathlib.PurePosixPath(relative).is_absolute())
                self.assertNotIn("..", pathlib.PurePosixPath(relative).parts)
                self.assertTrue((ROOT / relative).is_file(), relative)

        self.assertEqual(
            {
                "formal/Dockerfile",
                "formal/easycrypt/BindingViaCR.ec",
                "formal/easycrypt/MigrationBindingV2.ec",
                "formal/easycrypt/Makefile",
                "formal/easycrypt/negative-controls.sh",
                "formal/easycrypt/continuity/LifecycleContextV1.ec",
                "formal/easycrypt/continuity/PrekeySelectionV1.ec",
                "formal/easycrypt/continuity/Makefile",
                "formal/proverif/Makefile",
                "formal/proverif/handshake.pv",
                "formal/tamarin/Makefile",
                "formal/tamarin/handshake.spthy",
                "formal/tamarin/migration_v2.spthy",
                "formal/tamarin/migration_v2_agreement.spthy",
                "formal/tamarin/migration_v2_liveness.spthy",
                "formal/tamarin/migration_v2_negative_controls.spthy",
                "formal/tamarin/migration_v2_no_witness.spthy",
                "formal/tamarin/migration_v2_rollback.spthy",
            },
            {
                relative
                for relative in mapping.values()
                if relative.startswith("formal/")
            },
        )

    def test_capture_and_verify_use_the_exact_stable_bytes(self) -> None:
        first = self.write("proof/first.bin", b"first\x00bytes")
        second = self.write("proof/second.bin", b"second bytes\n")
        mapping = {
            "first_sha256": "proof/first.bin",
            "second_sha256": "proof/second.bin",
        }
        expected = {
            "first_sha256": hashlib.sha256(first.read_bytes()).hexdigest(),
            "second_sha256": hashlib.sha256(second.read_bytes()).hexdigest(),
        }
        with self.input_map(mapping):
            self.assertEqual(
                expected,
                inputs.capture_proof_input_digests(self.root),
            )
            self.assertEqual(
                expected,
                inputs.verify_proof_input_digests(self.root, expected),
            )

    def test_expected_map_must_have_exact_keys_and_digests(self) -> None:
        self.write("proof.bin", b"proof")
        mapping = {"proof_sha256": "proof.bin"}
        with self.input_map(mapping):
            for expected, message in (
                ({}, "key-set mismatch"),
                (
                    {"proof_sha256": "a" * 64, "extra_sha256": "b" * 64},
                    "key-set mismatch",
                ),
                ({"proof_sha256": "not-a-digest"}, "digest is malformed"),
                ({1: "a" * 64}, "string keys"),
            ):
                with self.subTest(expected=expected), self.assertRaisesRegex(
                    inputs.ProofToByteInputsError,
                    message,
                ):
                    inputs.verify_proof_input_digests(self.root, expected)

            with self.assertRaisesRegex(
                inputs.ProofToByteInputsError,
                "hash mismatch for proof.bin",
            ):
                inputs.verify_proof_input_digests(
                    self.root,
                    {"proof_sha256": "a" * 64},
                )

    def test_noncanonical_and_duplicate_paths_fail_before_success(self) -> None:
        self.write("proof.bin", b"proof")
        cases = (
            ({"proof_sha256": "../proof.bin"}, "not canonical"),
            ({"proof_sha256": "/proof.bin"}, "not canonical"),
            (
                {
                    "first_sha256": "proof.bin",
                    "second_sha256": "proof.bin",
                },
                "duplicated",
            ),
            ({"proof": "proof.bin"}, "key is not canonical"),
        )
        for mapping, message in cases:
            with self.subTest(mapping=mapping), self.input_map(mapping):
                with self.assertRaisesRegex(
                    inputs.ProofToByteInputsError,
                    message,
                ):
                    inputs.capture_proof_input_digests(self.root)

    def test_symlink_directory_fifo_and_hardlink_inputs_are_rejected(self) -> None:
        regular = self.write("regular.bin", b"proof")
        symlink = self.root / "symlink.bin"
        symlink.symlink_to(regular)
        directory = self.root / "directory"
        directory.mkdir()
        hardlink = self.root / "hardlink.bin"
        os.link(regular, hardlink)
        cases = ("symlink.bin", "directory", "regular.bin", "hardlink.bin")
        if os.name == "posix":
            fifo = self.root / "proof.fifo"
            os.mkfifo(fifo)
            cases += ("proof.fifo",)
        for relative in cases:
            with self.subTest(relative=relative), self.input_map(
                {"proof_sha256": relative}
            ):
                with self.assertRaises(inputs.ProofToByteInputsError):
                    inputs.capture_proof_input_digests(self.root)

    def test_non_owner_metadata_is_rejected_on_posix(self) -> None:
        if os.name != "posix":
            self.assertNotEqual(os.name, "posix")
            return
        path = self.write("proof.bin", b"proof")
        metadata = path.stat()
        self.assertTrue(stat.S_ISREG(metadata.st_mode))
        with mock.patch.object(inputs.os, "geteuid", return_value=metadata.st_uid + 1):
            with self.assertRaisesRegex(EvidenceIOError, "metadata is unsafe"):
                inputs._validate_input_metadata(
                    metadata,
                    relative="proof.bin",
                )

    def test_group_or_world_writable_input_is_rejected(self) -> None:
        if os.name != "posix":
            self.assertNotEqual(os.name, "posix")
            return
        path = self.write("proof.bin", b"proof")
        path.chmod(0o664)
        self.addCleanup(path.chmod, 0o600)
        with self.input_map({"proof_sha256": "proof.bin"}):
            with self.assertRaisesRegex(
                inputs.ProofToByteInputsError,
                "metadata is unsafe",
            ):
                inputs.capture_proof_input_digests(self.root)

    def test_windows_mode_bits_are_not_treated_as_posix_permissions(self) -> None:
        metadata = mock.Mock(
            st_mode=stat.S_IFREG | 0o666,
            st_nlink=1,
            st_uid=0,
        )
        with mock.patch.object(inputs.os, "name", "nt"):
            inputs._validate_input_metadata(
                metadata,
                relative="proof.bin",
            )

    def test_per_file_and_aggregate_byte_limits_fail_closed(self) -> None:
        self.write("first.bin", b"123")
        self.write("second.bin", b"456")
        mapping = {
            "first_sha256": "first.bin",
            "second_sha256": "second.bin",
        }
        with self.input_map(mapping), mock.patch.object(
            inputs,
            "MAX_PROOF_INPUT_BYTES",
            2,
        ):
            with self.assertRaisesRegex(
                inputs.ProofToByteInputsError,
                "exceeds 2 bytes",
            ):
                inputs.capture_proof_input_digests(self.root)
        with self.input_map(mapping), mock.patch.object(
            inputs,
            "MAX_PROOF_INPUT_TOTAL_BYTES",
            5,
        ):
            with self.assertRaisesRegex(
                inputs.ProofToByteInputsError,
                "aggregate byte limit",
            ):
                inputs.capture_proof_input_digests(self.root)

    def test_change_between_complete_captures_is_rejected(self) -> None:
        with mock.patch.object(
            inputs,
            "_capture_once",
            side_effect=[
                ({"proof_sha256": "a" * 64}, 1),
                ({"proof_sha256": "b" * 64}, 1),
            ],
        ):
            with self.assertRaisesRegex(
                inputs.ProofToByteInputsError,
                "changed while they were captured: proof_sha256",
            ):
                inputs.capture_proof_input_digests(self.root)

    def test_read_failure_is_typed_and_does_not_leak_descriptors(self) -> None:
        self.write("proof.bin", b"proof")
        mapping = {"proof_sha256": "proof.bin"}
        descriptor_count = None
        if os.name == "posix" and pathlib.Path("/dev/fd").is_dir():
            descriptor_count = len(list(pathlib.Path("/dev/fd").iterdir()))
        with self.input_map(mapping), mock.patch.object(
            inputs,
            "read_regular_snapshot",
            side_effect=EvidenceIOError("injected read failure"),
        ):
            with self.assertRaisesRegex(
                inputs.ProofToByteInputsError,
                "injected read failure",
            ):
                inputs.capture_proof_input_digests(self.root)
        if descriptor_count is not None:
            self.assertEqual(
                descriptor_count,
                len(list(pathlib.Path("/dev/fd").iterdir())),
            )

    def test_repository_root_must_not_resolve_through_a_symlink(self) -> None:
        self.write("proof.bin", b"proof")
        linked = self.root.parent / f"{self.root.name}-link"
        linked.symlink_to(self.root, target_is_directory=True)
        self.addCleanup(linked.unlink)
        with self.input_map({"proof_sha256": "proof.bin"}):
            with self.assertRaisesRegex(
                inputs.ProofToByteInputsError,
                "canonical owned directory",
            ):
                inputs.capture_proof_input_digests(linked)


if __name__ == "__main__":
    unittest.main()
