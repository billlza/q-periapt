from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import pathlib
import stat
import tempfile
import unittest
from unittest import mock

import platform_candidate_attestation as candidate_attestation
from platform_candidate_attestation import (
    CANDIDATE_SNAPSHOT_NAME,
    PROJECTION_NAME,
    CandidateAttestationError,
    load_candidate_snapshot,
    snapshot_candidate,
    write_candidate_snapshot,
)
from platform_distribution_contract import (
    CANDIDATE_SUMS,
    PLATFORM_CANDIDATE_ASSETS,
    PLATFORM_CANDIDATE_ATTESTATION_SUBJECTS,
    RELEASE_TAG,
)


class PlatformCandidateAttestationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name).resolve()
        self.candidate_root = self.root / "abi2-platform-candidate-inputs"
        self.verification_root = self.root / "abi2-platform-candidate-verification"
        self.raw_root = self.verification_root / "raw"
        self.projection_root = self.root / "abi2-platform-candidate-projections"
        for path in (self.candidate_root, self.raw_root, self.projection_root):
            path.mkdir(parents=True, mode=0o700)
            os.chmod(path, 0o700)
        os.chmod(self.verification_root, 0o700)
        for attribute, value in (
            ("CANDIDATE_INPUT_ROOT", self.candidate_root),
            ("CANDIDATE_VERIFICATION_ROOT", self.verification_root),
            ("CANDIDATE_RAW_ROOT", self.raw_root),
            ("CANDIDATE_PROJECTION_ROOT", self.projection_root),
        ):
            patcher = mock.patch.object(candidate_attestation, attribute, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def _candidate(self, name: str) -> pathlib.Path:
        candidate = self.candidate_root / name
        candidate.mkdir()
        checksums: list[tuple[str, str]] = []
        for asset in PLATFORM_CANDIDATE_ASSETS:
            data = f"exact fixture bytes for {asset}\n".encode("ascii")
            (candidate / asset).write_bytes(data)
            checksums.append((asset, hashlib.sha256(data).hexdigest()))
        (candidate / CANDIDATE_SUMS).write_text(
            "".join(
                f"{digest}  {asset}\n" for asset, digest in sorted(checksums)
            ),
            encoding="ascii",
        )
        return candidate

    def _private_output_paths(self, name: str) -> tuple[pathlib.Path, pathlib.Path]:
        raw_parent = self.raw_root / name
        projection_parent = self.projection_root / name
        raw_parent.mkdir(mode=0o700)
        projection_parent.mkdir(mode=0o700)
        os.chmod(raw_parent, 0o700)
        os.chmod(projection_parent, 0o700)
        return (
            raw_parent / CANDIDATE_SNAPSHOT_NAME,
            projection_parent / PROJECTION_NAME,
        )

    def test_current_contract_is_the_exact_six_subject_tuple(self) -> None:
        self.assertEqual(5, len(PLATFORM_CANDIDATE_ASSETS))
        self.assertEqual(
            (*PLATFORM_CANDIDATE_ASSETS, CANDIDATE_SUMS),
            PLATFORM_CANDIDATE_ATTESTATION_SUBJECTS,
        )
        self.assertEqual(6, len(set(PLATFORM_CANDIDATE_ATTESTATION_SUBJECTS)))

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = candidate_attestation._main(["subject-names"])
        self.assertEqual(0, status)
        self.assertEqual(
            list(PLATFORM_CANDIDATE_ATTESTATION_SUBJECTS),
            output.getvalue().splitlines(),
        )

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = candidate_attestation._main(["release-tag"])
        self.assertEqual(0, status)
        self.assertEqual(f"{RELEASE_TAG}\n", output.getvalue())

    def test_snapshot_uses_contract_order_and_exact_bytes(self) -> None:
        candidate = self._candidate("valid-candidate")

        snapshot = snapshot_candidate(candidate)

        self.assertEqual(
            list(PLATFORM_CANDIDATE_ATTESTATION_SUBJECTS),
            [item.name for item in snapshot.files],
        )
        for item in snapshot.files:
            payload = (candidate / item.name).read_bytes()
            self.assertEqual(len(payload), item.size)
            self.assertEqual(hashlib.sha256(payload).hexdigest(), item.sha256)
        self.assertEqual(snapshot.subjects(), [item.subject() for item in snapshot.files])

    def test_snapshot_rejects_tamper_extra_symlink_and_noncanonical_sums(self) -> None:
        def tamper(candidate: pathlib.Path) -> None:
            (candidate / PLATFORM_CANDIDATE_ASSETS[0]).write_bytes(b"tampered\n")

        def extra(candidate: pathlib.Path) -> None:
            (candidate / "unexpected.bin").write_bytes(b"unexpected\n")

        def symlink(candidate: pathlib.Path) -> None:
            (candidate / "unsafe-link").symlink_to(
                candidate / PLATFORM_CANDIDATE_ASSETS[0]
            )

        def reorder(candidate: pathlib.Path) -> None:
            sums = candidate / CANDIDATE_SUMS
            lines = sums.read_text(encoding="ascii").splitlines(keepends=True)
            sums.write_text("".join(reversed(lines)), encoding="ascii")

        for name, mutation in (
            ("tamper", tamper),
            ("extra", extra),
            ("symlink", symlink),
            ("reorder", reorder),
        ):
            with self.subTest(name=name):
                candidate = self._candidate(f"candidate-{name}")
                mutation(candidate)
                with self.assertRaises(CandidateAttestationError):
                    snapshot_candidate(candidate)

    def test_snapshot_file_is_private_strict_and_exclusive(self) -> None:
        candidate = self._candidate("private-snapshot-candidate")
        snapshot_path, projection_path = self._private_output_paths("private-output")

        write_candidate_snapshot(candidate, snapshot_path, projection_path)

        metadata = snapshot_path.stat()
        self.assertEqual(0o600, stat.S_IMODE(metadata.st_mode))
        self.assertEqual(1, metadata.st_nlink)
        self.assertEqual(
            snapshot_candidate(candidate).document(),
            load_candidate_snapshot(snapshot_path).document(),
        )
        with self.assertRaises(CandidateAttestationError):
            write_candidate_snapshot(candidate, snapshot_path, projection_path)

    def test_shared_atomic_snapshot_and_projection_writers_recover_without_partials(
        self,
    ) -> None:
        candidate = self._candidate("atomic-writer-candidate")
        snapshot_path, projection_path = self._private_output_paths(
            "atomic-snapshot-output"
        )
        injected = candidate_attestation.PublicationReceiptIOError(
            "injected shared atomic failure"
        )

        with mock.patch.object(
            candidate_attestation,
            "write_private_json_noreplace_at",
            side_effect=injected,
        ):
            with self.assertRaisesRegex(
                CandidateAttestationError,
                "injected shared atomic failure",
            ):
                write_candidate_snapshot(candidate, snapshot_path, projection_path)
        self.assertFalse(snapshot_path.exists())
        self.assertEqual(
            [],
            list(snapshot_path.parent.glob(f".{CANDIDATE_SNAPSHOT_NAME}.pending-*")),
        )

        write_candidate_snapshot(candidate, snapshot_path, projection_path)
        self.assertEqual(
            snapshot_candidate(candidate).document(),
            load_candidate_snapshot(snapshot_path).document(),
        )

        _, projection_path = self._private_output_paths("atomic-projection-output")
        projection = {"kind": "fixture", "schema_version": 1}
        with mock.patch.object(
            candidate_attestation,
            "write_private_json_noreplace_at",
            side_effect=injected,
        ):
            with self.assertRaisesRegex(
                CandidateAttestationError,
                "injected shared atomic failure",
            ):
                candidate_attestation._write_private_json(
                    projection_path,
                    PROJECTION_NAME,
                    projection,
                    "candidate projection",
                )
        self.assertFalse(projection_path.exists())
        self.assertEqual(
            [],
            list(projection_path.parent.glob(f".{PROJECTION_NAME}.pending-*")),
        )

        digest = candidate_attestation._write_private_json(
            projection_path,
            PROJECTION_NAME,
            projection,
            "candidate projection",
        )
        payload = projection_path.read_bytes()
        self.assertEqual(projection, json.loads(payload))
        self.assertEqual(hashlib.sha256(payload).hexdigest(), digest)

    def test_projection_target_must_be_absolute_private_exact_and_absent(self) -> None:
        candidate = self._candidate("projection-policy-candidate")

        broad_parent = self.root / "broad-parent"
        broad_parent.mkdir(mode=0o755)
        os.chmod(broad_parent, 0o755)
        with self.assertRaises(CandidateAttestationError):
            write_candidate_snapshot(
                candidate,
                broad_parent / CANDIDATE_SNAPSHOT_NAME,
                broad_parent / PROJECTION_NAME,
            )

        snapshot_path, projection_path = self._private_output_paths("exact-output")
        projection_path.write_bytes(b"must not be overwritten\n")
        os.chmod(projection_path, 0o600)
        with self.assertRaises(CandidateAttestationError):
            write_candidate_snapshot(candidate, snapshot_path, projection_path)
        self.assertEqual(b"must not be overwritten\n", projection_path.read_bytes())
        self.assertFalse(snapshot_path.exists())

        relative_parent = pathlib.Path("relative-output")
        with self.assertRaises(CandidateAttestationError):
            write_candidate_snapshot(
                candidate,
                relative_parent / CANDIDATE_SNAPSHOT_NAME,
                relative_parent / PROJECTION_NAME,
            )

        wrong_snapshot, _ = self._private_output_paths("wrong-leaf-output")
        with self.assertRaises(CandidateAttestationError):
            write_candidate_snapshot(
                candidate,
                wrong_snapshot,
                wrong_snapshot.parent / "projection.json",
            )

    def test_projection_parent_must_be_disjoint_from_candidate_tree(self) -> None:
        candidate = self._candidate("disjoint-candidate")
        os.chmod(candidate, 0o700)
        snapshot_path, _ = self._private_output_paths("disjoint-snapshot")
        projection_in_root = candidate / PROJECTION_NAME

        with mock.patch.object(
            candidate_attestation,
            "CANDIDATE_PROJECTION_ROOT",
            self.candidate_root,
        ):
            with self.assertRaisesRegex(
                CandidateAttestationError,
                "projection parent is inside the candidate directory",
            ):
                write_candidate_snapshot(
                    candidate,
                    snapshot_path,
                    projection_in_root,
                )
            self.assertFalse(snapshot_path.exists())
            self.assertFalse(projection_in_root.exists())

            with self.assertRaisesRegex(
                CandidateAttestationError,
                "projection parent is inside the candidate directory",
            ):
                candidate_attestation.verify_candidate_attestations(
                    candidate,
                    "a" * 40,
                    projection_in_root,
                    self.raw_root / "unread-raw-attestations",
                    self.raw_root / "unread-candidate-snapshot.json",
                )
            self.assertFalse(projection_in_root.exists())

        descendant = candidate / "private-projection-output"
        descendant.mkdir(mode=0o700)
        os.chmod(descendant, 0o700)
        projection_in_descendant = descendant / PROJECTION_NAME
        with self.assertRaises(CandidateAttestationError):
            write_candidate_snapshot(candidate, snapshot_path, projection_in_descendant)
        self.assertFalse(snapshot_path.exists())
        self.assertFalse(projection_in_descendant.exists())

    def test_fixed_roots_reject_prefix_traversal_tmp_and_symlink_escape(self) -> None:
        candidate = self._candidate("safe-candidate")
        _snapshot_path, projection = self._private_output_paths("safe-output")
        outside = self.root / "outside"
        outside.mkdir(mode=0o700)

        evil_prefix = self.root / "abi2-platform-candidate-inputs-evil"
        evil_prefix.mkdir()
        tmp_candidate = pathlib.Path("/tmp/qperiapt-unsafe-candidate")
        traversal_candidate = self.candidate_root / "child" / ".." / ".." / "outside"
        symlink_candidate = self.candidate_root / "candidate-link"
        symlink_candidate.symlink_to(outside, target_is_directory=True)

        for unsafe in (
            tmp_candidate,
            evil_prefix,
            traversal_candidate,
            symlink_candidate,
        ):
            with self.subTest(candidate=unsafe):
                with self.assertRaises(CandidateAttestationError):
                    candidate_attestation.preflight_candidate_paths(
                        unsafe,
                        projection,
                    )
                self.assertFalse(projection.exists())

        symlink_parent = self.projection_root / "projection-link"
        symlink_parent.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(CandidateAttestationError):
            candidate_attestation.preflight_candidate_paths(
                candidate,
                symlink_parent / PROJECTION_NAME,
            )
        self.assertFalse((outside / PROJECTION_NAME).exists())

        os.chmod(self.candidate_root, 0o755)
        try:
            with self.assertRaisesRegex(
                CandidateAttestationError,
                "safe root is not an owned non-symlink directory",
            ):
                candidate_attestation.preflight_candidate_paths(
                    candidate,
                    projection,
                )
        finally:
            os.chmod(self.candidate_root, 0o700)

    def test_private_snapshot_rejects_mode_and_hardlink_changes(self) -> None:
        candidate = self._candidate("metadata-candidate")
        snapshot_path, projection_path = self._private_output_paths("metadata-output")
        write_candidate_snapshot(candidate, snapshot_path, projection_path)

        os.chmod(snapshot_path, 0o644)
        with self.assertRaises(CandidateAttestationError):
            load_candidate_snapshot(snapshot_path)

        os.chmod(snapshot_path, 0o600)
        os.link(snapshot_path, snapshot_path.parent / "snapshot-hardlink.json")
        with self.assertRaises(CandidateAttestationError):
            load_candidate_snapshot(snapshot_path)


if __name__ == "__main__":
    unittest.main()
