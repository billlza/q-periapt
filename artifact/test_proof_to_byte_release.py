#!/usr/bin/env python3

from __future__ import annotations

import contextlib
import copy
import dataclasses
import errno
import fcntl
import hashlib
import importlib._bootstrap_external
import importlib.util
import json
import os
import pathlib
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
import unittest
from collections.abc import Iterator
from unittest import mock

import apple_publication_contract
import proof_to_byte_finalizer
import proof_to_byte_inputs
import release_publication_contract
from camera_ready_proof import EXPECTED_TOOLS
from git_provenance import WorktreeInspection, git_commit
from test_apple_publication_contract import alpha2_receipt

ROOT = pathlib.Path(__file__).resolve().parents[1]
PROOF_SCRIPT = ROOT / "artifact" / "proof-to-byte.sh"
CAMERA_READY_SCRIPT = ROOT / "camera-ready-bare-metal.sh"
CAMERA_SANDBOX_SCRIPT = ROOT / "artifact" / "camera-ready-sandbox.sh"
ARTIFACT_GUIDE = ROOT / "ARTIFACT.md"
PAPER_SOURCE = ROOT / "paper" / "q-periapt.tex"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
CODEQL_WORKFLOW = ROOT / ".github" / "workflows" / "codeql.yml"
DEPENDABOT_CONFIG = ROOT / ".github" / "dependabot.yml"
SECURITY_POLICY = ROOT / "SECURITY.md"
ABI2_PLATFORM_CANDIDATE_WORKFLOW = (
    ROOT / ".github" / "workflows" / "abi2-platform-candidate.yml"
)
WINDOWS_C_SMOKE_SCRIPT = ROOT / "bindings" / "c" / "build-and-run.bat"
RUST_TOOLCHAIN_FILE = ROOT / "rust-toolchain.toml"
CANONICAL_RUST_TOOLCHAIN = "1.96.1"
CANONICAL_RUSTC_VERSION = "rustc 1.96.1 (31fca3adb 2026-06-26)"
CANONICAL_CARGO_VERSION = "cargo 1.96.1 (356927216 2026-06-26)"
WINDOWS_RELEASE_RUST_TOOLCHAIN = "1.97.0"
WINDOWS_RELEASE_RUSTC_VERSION = "rustc 1.97.0 (2d8144b78 2026-07-07)"
WINDOWS_RELEASE_CARGO_VERSION = "cargo 1.97.0 (c980f4866 2026-06-30)"
PINNED_CANONICAL_RUST_ACTION = (
    "dtolnay/rust-toolchain@2c7215f132e9ebf062739d9130488b56d53c060c"
)
RUST_PACKAGE_CONTRACT_SCRIPT = ROOT / "artifact" / "rust-publish-contract.sh"
RUST_PUBLISH_CONTRACT = ROOT / "artifact" / "rust_publish_contract.py"
RUST_PUBLISH_CONTRACT_TESTS = ROOT / "artifact" / "test_rust_publish_contract.py"
FINALIZER_SCRIPT = ROOT / "artifact" / "proof_to_byte_finalizer.py"
XCODE27_GATE = ROOT / "artifact" / "apple-device-xcode27-gate.sh"
TEST_COMMIT = "a" * 40
TEST_SOURCE_SHA256 = "b" * 64
TEST_MANIFEST_SHA256 = "c" * 64
PINNED_CHECKOUT_ACTION = (
    "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0"
)
PINNED_DOWNLOAD_ARTIFACT_ACTION = (
    "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1"
)
PINNED_UPLOAD_ARTIFACT_ACTION = (
    "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1"
)
PINNED_CODEQL_ACTION = (
    "github/codeql-action/{action}@5595ccaf912efad79be6eef63a5619ff05969be3 "
    "# v4.37.6"
)
EXPECTED_CHECKOUT_STEP = (
    f"      - uses: {PINNED_CHECKOUT_ACTION}\n"
    "        env:\n"
    '          GIT_CONFIG_COUNT: "1"\n'
    "          GIT_CONFIG_KEY_0: init.defaultBranch\n"
    "          GIT_CONFIG_VALUE_0: main\n"
    "        with:\n"
    "          persist-credentials: false\n"
    "          fetch-depth: 0\n"
)
EXPECTED_CHECKOUT_GIT_ENV = (
    "        env:\n"
    '          GIT_CONFIG_COUNT: "1"\n'
    "          GIT_CONFIG_KEY_0: init.defaultBranch\n"
    "          GIT_CONFIG_VALUE_0: main\n"
)
EXPECTED_CHECKOUT_PROVENANCE_STEP = (
    "      - name: Verify checkout provenance\n"
    "        env:\n"
    "          EXPECTED_COMMIT: ${{ github.sha }}\n"
    "        run: |\n"
    "          actual_commit=$(git rev-parse --verify 'HEAD^{commit}')\n"
    '          if [ "$actual_commit" != "$EXPECTED_COMMIT" ]; then\n'
    '            echo "checked-out HEAD $actual_commit does not match GitHub commit $EXPECTED_COMMIT" >&2\n'
    "            exit 1\n"
    "          fi\n"
)
EXPECTED_PROOF_TO_BYTE_STEP = (
    "      - name: Exact source-transition or installed proof-to-byte gate\n"
    "        env:\n"
    "          QPERIAPT_EXPECTED_GIT_COMMIT: ${{ github.sha }}\n"
    "        run: |\n"
    "          results_sha256=$(/usr/bin/sha256sum artifact/results.json | /usr/bin/cut -d' ' -f1)\n"
    "          source_gate=$(/bin/sh artifact/python-run.sh artifact/source_results_assembler.py \\\n"
    "            ci-source-gate \\\n"
    "            \"$results_sha256\" \"$QPERIAPT_EXPECTED_GIT_COMMIT\")\n"
    "          initial_gate=\"SOURCE_TRANSITION_READINESS_PASS mode=initial commit=$QPERIAPT_EXPECTED_GIT_COMMIT results_sha256=$results_sha256 proof_inputs=234 declared_delta=44\"\n"
    "          installed_gate=\"SOURCE_CI_GATE_MODE mode=installed commit=$QPERIAPT_EXPECTED_GIT_COMMIT results_sha256=$results_sha256 proof_inputs=234\"\n"
    "          if [ \"$source_gate\" = \"$initial_gate\" ]; then\n"
    "            printf '%s\\n' \"$source_gate\"\n"
    "          elif [ \"$source_gate\" = \"$installed_gate\" ]; then\n"
    "            printf '%s\\n' \"$source_gate\"\n"
    "            QPERIAPT_SKIP_SMOKE=1 /bin/sh artifact/proof-to-byte.sh\n"
    "          else\n"
    "            printf 'unexpected source CI gate result\\n' >&2\n"
    "            exit 2\n"
    "          fi\n"
)
YAML_ALIAS = re.compile(r"(?m)(?:^|[ \t:\-\[,{}])\*[^\s\[\]{},]+")


_RELEASE_TEST_DIRECTORY_OPEN_FLAGS = (
    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
)


@dataclasses.dataclass(slots=True)
class _ReleaseTestParentDirectory:
    path: pathlib.Path
    owned: bool
    identity: tuple[int, int] | None = None
    directory_fd: int | None = None


@dataclasses.dataclass(slots=True)
class _ReleaseTestChildDirectory:
    parent: _ReleaseTestParentDirectory
    name: str
    identity: tuple[int, int] | None = None
    directory_fd: int | None = None

    @property
    def path(self) -> pathlib.Path:
        return self.parent.path / self.name


def _release_test_directory_identity_from_state(
    state: os.stat_result, path: pathlib.Path
) -> tuple[int, int]:
    if not stat.S_ISDIR(state.st_mode):
        raise AssertionError(f"release test path must be a real directory: {path}")
    return state.st_dev, state.st_ino


def _release_test_directory_identity(path: pathlib.Path) -> tuple[int, int]:
    return _release_test_directory_identity_from_state(path.lstat(), path)


def _release_test_directory_identity_at(
    parent: _ReleaseTestParentDirectory, name: str
) -> tuple[int, int]:
    if parent.directory_fd is None:
        raise AssertionError(
            f"release test parent has no anchored descriptor: {parent.path}"
        )
    state = os.stat(name, dir_fd=parent.directory_fd, follow_symlinks=False)
    return _release_test_directory_identity_from_state(state, parent.path / name)


def _clear_release_test_directory_contents(
    directory_fd: int, display_path: pathlib.Path
) -> list[BaseException]:
    cleanup_errors: list[BaseException] = []
    try:
        with os.scandir(directory_fd) as entries:
            entry_names = [entry.name for entry in entries]
    except OSError as exc:
        exc.add_note(f"while listing test-owned release directory: {display_path}")
        return [exc]

    for entry_name in entry_names:
        entry_path = display_path / entry_name
        try:
            entry_fd = os.open(
                entry_name,
                _RELEASE_TEST_DIRECTORY_OPEN_FLAGS,
                dir_fd=directory_fd,
            )
        except OSError as exc:
            if exc.errno not in {errno.ELOOP, errno.ENOTDIR}:
                exc.add_note(f"while opening test-owned release entry: {entry_path}")
                cleanup_errors.append(exc)
                continue
            try:
                os.unlink(entry_name, dir_fd=directory_fd)
            except OSError as unlink_error:
                unlink_error.add_note(
                    f"while unlinking test-owned release entry: {entry_path}"
                )
                cleanup_errors.append(unlink_error)
            continue

        try:
            entry_identity = _release_test_directory_identity_from_state(
                os.fstat(entry_fd), entry_path
            )
            cleanup_errors.extend(
                _clear_release_test_directory_contents(entry_fd, entry_path)
            )
            try:
                actual_state = os.stat(
                    entry_name, dir_fd=directory_fd, follow_symlinks=False
                )
                actual_identity = _release_test_directory_identity_from_state(
                    actual_state, entry_path
                )
            except FileNotFoundError:
                cleanup_errors.append(
                    AssertionError(
                        "test-owned release directory disappeared before removal: "
                        f"{entry_path}"
                    )
                )
                continue
            except AssertionError as exc:
                cleanup_error = AssertionError(
                    "test-owned release directory was replaced before removal: "
                    f"{entry_path}"
                )
                cleanup_error.__cause__ = exc
                cleanup_errors.append(cleanup_error)
                continue
            except OSError as exc:
                cleanup_errors.append(exc)
                continue
            if actual_identity != entry_identity:
                cleanup_errors.append(
                    AssertionError(
                        "test-owned release directory was replaced before removal: "
                        f"{entry_path}"
                    )
                )
                continue
            try:
                os.rmdir(entry_name, dir_fd=directory_fd)
            except OSError as exc:
                exc.add_note(
                    f"while removing test-owned release directory: {entry_path}"
                )
                cleanup_errors.append(exc)
        finally:
            try:
                os.close(entry_fd)
            except BaseException as exc:
                exc.add_note(
                    f"while closing test-owned release directory: {entry_path}"
                )
                cleanup_errors.append(exc)
    return cleanup_errors


@contextlib.contextmanager
def _temporary_release_test_directories(
    parents: tuple[pathlib.Path, ...],
) -> Iterator[tuple[pathlib.Path, ...]]:
    """Create isolated children under release roots without assuming ignored dirs exist.

    Design invariants: every parent, child, and nested directory stays anchored by
    an ``O_DIRECTORY | O_NOFOLLOW`` descriptor until its cleanup completes, which
    prevents Linux inode-ABA reuse and path replacement from changing the deletion
    target. Child contents are removed only relative to an anchored descriptor;
    child roots use identity revalidation plus non-recursive ``rmdir``, and only
    parents created by this helper may be removed. ``TemporaryDirectory`` or a
    root-name ``rmtree`` would violate those replacement boundaries. Cleanup must
    always attempt child clearing, child close, owned-parent removal, and parent
    close in that order, preserving body and cleanup failures in an exception group.
    """

    # The lock is a stable, repo-scoped inode and leaves no worktree or /tmp lock
    # artifact. It serializes create/use/cleanup across concurrent test processes.
    with pathlib.Path(__file__).resolve().open("rb") as lock_handle:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        parent_directories: list[_ReleaseTestParentDirectory] = []
        child_directories: list[_ReleaseTestChildDirectory] = []

        def cleanup_child_directories() -> list[BaseException]:
            cleanup_errors: list[BaseException] = []
            for child in reversed(child_directories):
                if (
                    child.parent.directory_fd is None
                    or child.identity is None
                    or child.directory_fd is None
                ):
                    cleanup_errors.append(
                        AssertionError(
                            "test-owned release child could not be verified for cleanup: "
                            f"{child.path}"
                        )
                    )
                    continue
                try:
                    parent_state = os.fstat(child.parent.directory_fd)
                    child_state = os.fstat(child.directory_fd)
                except OSError as exc:
                    exc.add_note(
                        f"while verifying test-owned release child: {child.path}"
                    )
                    cleanup_errors.append(exc)
                    continue
                parent_identity = _release_test_directory_identity_from_state(
                    parent_state, child.parent.path
                )
                if parent_identity != child.parent.identity:
                    cleanup_errors.append(
                        AssertionError(
                            "release test parent descriptor identity changed: "
                            f"{child.parent.path}"
                        )
                    )
                    continue
                child_identity = _release_test_directory_identity_from_state(
                    child_state, child.path
                )
                if child_identity != child.identity:
                    cleanup_errors.append(
                        AssertionError(
                            "test-owned release child descriptor identity changed: "
                            f"{child.path}"
                        )
                    )
                    continue
                cleanup_errors.extend(
                    _clear_release_test_directory_contents(
                        child.directory_fd, child.path
                    )
                )
                try:
                    actual_identity = _release_test_directory_identity_at(
                        child.parent, child.name
                    )
                except FileNotFoundError:
                    cleanup_errors.append(
                        AssertionError(
                            "test-owned release child disappeared before cleanup: "
                            f"{child.path}"
                        )
                    )
                    continue
                except AssertionError as exc:
                    cleanup_error = AssertionError(
                        "test-owned release child was replaced before cleanup: "
                        f"{child.path}"
                    )
                    cleanup_error.__cause__ = exc
                    cleanup_errors.append(cleanup_error)
                    continue
                except OSError as exc:
                    cleanup_errors.append(exc)
                    continue
                if actual_identity != child.identity:
                    cleanup_errors.append(
                        AssertionError(
                            "test-owned release child was replaced before cleanup: "
                            f"{child.path}"
                        )
                    )
                    continue
                try:
                    os.rmdir(child.name, dir_fd=child.parent.directory_fd)
                except OSError as exc:
                    exc.add_note(
                        f"while removing test-owned release child: {child.path}"
                    )
                    cleanup_errors.append(exc)
            return cleanup_errors

        def close_child_descriptors() -> list[BaseException]:
            cleanup_errors: list[BaseException] = []
            for child in reversed(child_directories):
                if child.directory_fd is None:
                    continue
                try:
                    os.close(child.directory_fd)
                except BaseException as exc:
                    exc.add_note(
                        f"while closing test-owned release child descriptor: {child.path}"
                    )
                    cleanup_errors.append(exc)
            return cleanup_errors

        def cleanup_parent_directories() -> list[Exception]:
            cleanup_errors: list[Exception] = []
            for parent in reversed(parent_directories):
                if parent.directory_fd is None or parent.identity is None:
                    if parent.owned:
                        cleanup_errors.append(
                            AssertionError(
                                "test-owned release parent could not be verified for cleanup: "
                                f"{parent.path}"
                            )
                        )
                    continue
                try:
                    descriptor_state = os.fstat(parent.directory_fd)
                except OSError as exc:
                    exc.add_note(
                        f"while verifying release parent descriptor: {parent.path}"
                    )
                    cleanup_errors.append(exc)
                    continue
                descriptor_identity = _release_test_directory_identity_from_state(
                    descriptor_state, parent.path
                )
                if descriptor_identity != parent.identity:
                    cleanup_errors.append(
                        AssertionError(
                            f"release parent descriptor identity changed: {parent.path}"
                        )
                    )
                    continue
                try:
                    actual_identity = _release_test_directory_identity(parent.path)
                except FileNotFoundError:
                    qualifier = "test-owned " if parent.owned else ""
                    cleanup_errors.append(
                        AssertionError(
                            f"{qualifier}release parent disappeared before cleanup: "
                            f"{parent.path}"
                        )
                    )
                    continue
                except AssertionError as exc:
                    qualifier = "test-owned " if parent.owned else ""
                    cleanup_error = AssertionError(
                        f"{qualifier}release parent was replaced before cleanup: "
                        f"{parent.path}"
                    )
                    cleanup_error.__cause__ = exc
                    cleanup_errors.append(cleanup_error)
                    continue
                except OSError as exc:
                    cleanup_errors.append(exc)
                    continue
                if actual_identity != parent.identity:
                    qualifier = "test-owned " if parent.owned else ""
                    cleanup_errors.append(
                        AssertionError(
                            f"{qualifier}release parent was replaced before cleanup: "
                            f"{parent.path}"
                        )
                    )
                    continue
                if not parent.owned:
                    continue
                try:
                    parent.path.rmdir()
                except OSError as exc:
                    if exc.errno in {errno.ENOTEMPTY, errno.EEXIST}:
                        cleanup_error = AssertionError(
                            "test-owned release parent is not empty after cleanup: "
                            f"{parent.path}"
                        )
                        cleanup_error.__cause__ = exc
                        cleanup_errors.append(cleanup_error)
                    else:
                        cleanup_errors.append(exc)
            return cleanup_errors

        def close_parent_descriptors() -> list[BaseException]:
            cleanup_errors: list[BaseException] = []
            for parent in reversed(parent_directories):
                if parent.directory_fd is None:
                    continue
                try:
                    os.close(parent.directory_fd)
                except BaseException as exc:
                    exc.add_note(
                        f"while closing release parent descriptor: {parent.path}"
                    )
                    cleanup_errors.append(exc)
            return cleanup_errors

        def cleanup_release_directories() -> list[BaseException]:
            cleanup_errors: list[BaseException] = []
            cleanup_phases = (
                cleanup_child_directories,
                close_child_descriptors,
                cleanup_parent_directories,
                close_parent_descriptors,
            )
            for cleanup_phase in cleanup_phases:
                try:
                    cleanup_errors.extend(cleanup_phase())
                except BaseException as exc:
                    cleanup_errors.append(exc)
            return cleanup_errors

        try:
            for parent_path in parents:
                try:
                    parent_path.mkdir(mode=0o700)
                except FileExistsError:
                    parent_identity = _release_test_directory_identity(parent_path)
                    parent = _ReleaseTestParentDirectory(
                        path=parent_path,
                        owned=False,
                        identity=parent_identity,
                    )
                    parent_directories.append(parent)
                else:
                    parent = _ReleaseTestParentDirectory(path=parent_path, owned=True)
                    parent_directories.append(parent)
                    parent.identity = _release_test_directory_identity(parent_path)
                parent.directory_fd = os.open(
                    parent.path, _RELEASE_TEST_DIRECTORY_OPEN_FLAGS
                )
                descriptor_identity = _release_test_directory_identity_from_state(
                    os.fstat(parent.directory_fd), parent.path
                )
                if descriptor_identity != parent.identity:
                    raise AssertionError(
                        f"release parent changed while acquiring ownership: {parent.path}"
                    )

            for parent in parent_directories:
                if parent.directory_fd is None:
                    raise AssertionError(
                        f"release test parent has no anchored descriptor: {parent.path}"
                    )
                for _ in range(128):
                    child_name = f".qperiapt-release-test-{secrets.token_hex(16)}"
                    try:
                        os.mkdir(child_name, mode=0o700, dir_fd=parent.directory_fd)
                    except FileExistsError:
                        continue
                    break
                else:
                    raise FileExistsError(
                        errno.EEXIST,
                        "could not allocate a unique release test child directory",
                        str(parent.path),
                    )
                child = _ReleaseTestChildDirectory(parent=parent, name=child_name)
                child_directories.append(child)
                child.identity = _release_test_directory_identity_at(parent, child_name)
                child.directory_fd = os.open(
                    child_name,
                    _RELEASE_TEST_DIRECTORY_OPEN_FLAGS,
                    dir_fd=parent.directory_fd,
                )
                descriptor_identity = _release_test_directory_identity_from_state(
                    os.fstat(child.directory_fd), child.path
                )
                if descriptor_identity != child.identity:
                    raise AssertionError(
                        "release test child changed while acquiring ownership: "
                        f"{child.path}"
                    )

            yield tuple(child.path for child in child_directories)
        except BaseException as operation_error:
            cleanup_errors = cleanup_release_directories()
            if cleanup_errors:
                raise BaseExceptionGroup(
                    "release test fixture operation and cleanup both failed",
                    [operation_error, *cleanup_errors],
                ) from None
            raise
        else:
            cleanup_errors = cleanup_release_directories()
            if len(cleanup_errors) == 1:
                raise cleanup_errors[0]
            if cleanup_errors:
                raise BaseExceptionGroup(
                    "multiple release test fixture cleanups failed", cleanup_errors
                )


CONTINUITY_PROOF_INPUTS = {
    "continuity_context_spec_sha256": "docs/continuity/LIFECYCLE_CONTEXT_V1.md",
    "continuity_context_model_sha256": "models/q-periapt-continuity-model/src/context.rs",
    "continuity_context_tests_sha256": "models/q-periapt-continuity-model/tests/context.rs",
    "continuity_context_vectors_sha256": "models/q-periapt-continuity-model/vectors/lifecycle-context-v1.json",
    "continuity_context_vector_emitter_sha256": "models/q-periapt-continuity-model/examples/continuity_context_vectors.rs",
    "continuity_context_verifier_sha256": "artifact/continuity_context.py",
    "continuity_context_verifier_tests_sha256": "artifact/test_continuity_context.py",
    "continuity_prekey_spec_sha256": "docs/continuity/PREKEY_SELECTION_V1.md",
    "continuity_prekey_codec_sha256": "models/q-periapt-continuity-model/src/codec.rs",
    "continuity_prekey_commitments_sha256": "models/q-periapt-continuity-model/src/commitments.rs",
    "continuity_prekey_model_sha256": "models/q-periapt-continuity-model/src/prekey.rs",
    "continuity_prekey_tests_sha256": "models/q-periapt-continuity-model/tests/prekey_selection.rs",
    "continuity_prekey_vectors_sha256": "models/q-periapt-continuity-model/vectors/prekey-selection-v1.json",
    "continuity_prekey_vector_emitter_sha256": "models/q-periapt-continuity-model/examples/prekey_selection_vectors.rs",
    "continuity_prekey_verifier_sha256": "artifact/prekey_selection.py",
    "continuity_prekey_verifier_tests_sha256": "artifact/test_prekey_selection.py",
    "continuity_model_manifest_sha256": "models/q-periapt-continuity-model/Cargo.toml",
    "continuity_model_lib_sha256": "models/q-periapt-continuity-model/src/lib.rs",
    "continuity_model_types_sha256": "models/q-periapt-continuity-model/src/types.rs",
    "continuity_model_state_machine_sha256": "models/q-periapt-continuity-model/src/model.rs",
    "continuity_model_lifecycle_tests_sha256": "models/q-periapt-continuity-model/tests/lifecycle.rs",
    "continuity_model_isolation_tests_sha256": "artifact/test_continuity_model_isolation.py",
    "continuity_effect_lifecycle_spec_sha256": "docs/continuity/G1_EFFECT_LIFECYCLE.md",
    "continuity_easycrypt_model_sha256": "formal/easycrypt/continuity/LifecycleContextV1.ec",
    "continuity_prekey_easycrypt_model_sha256": "formal/easycrypt/continuity/PrekeySelectionV1.ec",
    "continuity_easycrypt_makefile_sha256": "formal/easycrypt/continuity/Makefile",
}

MIGRATION_V2_PROOF_INPUTS = {
    "easycrypt_migration_v2_sha256": "formal/easycrypt/MigrationBindingV2.ec",
    "easycrypt_makefile_sha256": "formal/easycrypt/Makefile",
    "easycrypt_negative_controls_sha256": "formal/easycrypt/negative-controls.sh",
    "tamarin_migration_state_v2_sha256": "formal/tamarin/migration_v2.spthy",
    "tamarin_migration_agreement_v2_sha256": "formal/tamarin/migration_v2_agreement.spthy",
    "tamarin_migration_liveness_v2_sha256": "formal/tamarin/migration_v2_liveness.spthy",
    "tamarin_migration_rollback_v2_sha256": "formal/tamarin/migration_v2_rollback.spthy",
    "tamarin_migration_no_witness_v2_sha256": "formal/tamarin/migration_v2_no_witness.spthy",
    "tamarin_migration_negative_controls_v2_sha256": "formal/tamarin/migration_v2_negative_controls.spthy",
    "tamarin_makefile_sha256": "formal/tamarin/Makefile",
    "migration_contract_v2_spec_sha256": "docs/migration/MIGRATION_CONTRACT_V2.md",
    "migration_model_manifest_sha256": "models/q-periapt-migration/Cargo.toml",
    "migration_model_readme_sha256": "models/q-periapt-migration/README.md",
    "migration_model_lib_sha256": "models/q-periapt-migration/src/lib.rs",
    "migration_model_codec_sha256": "models/q-periapt-migration/src/codec.rs",
    "migration_context_v2_model_sha256": "models/q-periapt-migration/src/context_v2.rs",
    "migration_state_model_sha256": "models/q-periapt-migration/src/state.rs",
    "migration_capability_model_sha256": "models/q-periapt-migration/src/capability.rs",
    "migration_transcript_model_sha256": "models/q-periapt-migration/src/transcript.rs",
    "migration_confirmation_model_sha256": "models/q-periapt-migration/src/confirmation.rs",
    "migration_contract_v2_tests_sha256": "models/q-periapt-migration/tests/contract_v2.rs",
    "migration_contract_v2_vectors_sha256": "models/q-periapt-migration/vectors/migration-contract-v2.json",
    "migration_contract_v2_verifier_sha256": "artifact/migration_contract_v2.py",
    "migration_contract_v2_verifier_tests_sha256": "artifact/test_migration_contract_v2.py",
    "migration_agent_manifest_sha256": "services/q-periapt-policy-agent/Cargo.toml",
    "migration_agent_readme_sha256": "services/q-periapt-policy-agent/README.md",
    "migration_agent_lib_sha256": "services/q-periapt-policy-agent/src/lib.rs",
    "migration_agent_main_sha256": "services/q-periapt-policy-agent/src/main.rs",
    "migration_agent_authentication_sha256": "services/q-periapt-policy-agent/src/authentication.rs",
    "migration_agent_authority_sha256": "services/q-periapt-policy-agent/src/authority.rs",
    "migration_agent_authority_store_sha256": "services/q-periapt-policy-agent/src/authority_store.rs",
    "migration_agent_codec_sha256": "services/q-periapt-policy-agent/src/codec.rs",
    "migration_agent_crypto_sha256": "services/q-periapt-policy-agent/src/crypto.rs",
    "migration_agent_filesystem_sha256": "services/q-periapt-policy-agent/src/filesystem.rs",
    "migration_agent_macos_acl_sha256": "services/q-periapt-policy-agent/src/macos_acl.rs",
    "migration_agent_service_sha256": "services/q-periapt-policy-agent/src/service.rs",
    "migration_agent_repository_sha256": "services/q-periapt-policy-agent/src/repository.rs",
    "migration_agent_witness_sha256": "services/q-periapt-policy-agent/src/witness.rs",
    "migration_agent_ipc_sha256": "services/q-periapt-policy-agent/src/ipc.rs",
    "migration_agent_tests_sha256": "services/q-periapt-policy-agent/src/tests.rs",
    "migration_agent_types_sha256": "services/q-periapt-policy-agent/src/types.rs",
}

HQC_CANDIDATE_PROOF_INPUTS = {
    "hqc_candidate_readme_sha256": "research/hqc-fips207-candidate/README.md",
    "hqc_candidate_manifest_sha256": "research/hqc-fips207-candidate/Cargo.toml",
    "hqc_candidate_lock_sha256": "research/hqc-fips207-candidate/Cargo.lock",
    "hqc_candidate_adapter_sha256": "research/hqc-fips207-candidate/src/lib.rs",
    "hqc_candidate_tests_sha256": "research/hqc-fips207-candidate/tests/adapter.rs",
    "hqc_candidate_verify_sha256": "research/hqc-fips207-candidate/scripts/verify.sh",
}

APPLE_DISTRIBUTION_PROOF_INPUTS = {
    "swift_xcframework_script_sha256": "artifact/swift-xcframework.sh",
    "swift_xcframework_release_script_sha256": "artifact/swift-xcframework-release.sh",
    "swift_xcframework_consumer_check_script_sha256": "artifact/swift-xcframework-consumer-check.sh",
    "swift_xcframework_remote_consumer_script_sha256": "artifact/swift-xcframework-remote-consumer.sh",
    "apple_distribution_verifier_sha256": "artifact/apple_distribution.py",
    "apple_distribution_tests_sha256": "artifact/test_apple_distribution.py",
    "apple_release_verification_sha256": "artifact/apple_release_verification.py",
    "apple_release_verification_tests_sha256": "artifact/test_apple_release_verification.py",
    "apple_publication_contract_sha256": "artifact/apple_publication_contract.py",
    "apple_publication_contract_tests_sha256": "artifact/test_apple_publication_contract.py",
    "apple_stable_publication_sha256": "artifact/apple_stable_publication.py",
    "apple_stable_publication_tests_sha256": "artifact/test_apple_stable_publication.py",
    "github_release_observation_sha256": "artifact/github_release_observation.py",
    "github_release_observation_tests_sha256": "artifact/test_github_release_observation.py",
    "publication_receipt_io_sha256": "artifact/publication_receipt_io.py",
    "publication_receipt_io_tests_sha256": "artifact/test_publication_receipt_io.py",
    "release_publication_contract_sha256": "artifact/release_publication_contract.py",
    "release_publication_contract_tests_sha256": "artifact/test_release_publication_contract.py",
    "release_receipt_finalizer_sha256": "artifact/release_receipt_finalizer.py",
    "release_receipt_finalizer_tests_sha256": "artifact/test_release_receipt_finalizer.py",
    "apple_publication_finalizer_tests_sha256": "artifact/test_apple_publication_finalizer.py",
    "release_publication_proof_manifest_tests_sha256": "artifact/test_release_publication_proof_manifest.py",
    "swift_binary_consumer_link_probe_sha256": "bindings/swift/BinaryConsumerFixture/Sources/QPeriaptLinkProbe/main.swift",
    "swift_binary_consumer_tests_sha256": "bindings/swift/BinaryConsumerFixture/Tests/QPeriaptHybridBinaryConsumerTests/QPeriaptHybridBinaryConsumerTests.swift",
}

APPLE_DEVICE_PROOF_INPUTS = {
    "apple_device_smoke_script_sha256": "artifact/apple-device-smoke.sh",
    "apple_device_matrix_script_sha256": "artifact/apple-device-matrix.sh",
    "apple_device_xcode27_gate_script_sha256": "artifact/apple-device-xcode27-gate.sh",
    "apple_device_proof_verifier_sha256": "artifact/apple_device_proof.py",
    "apple_device_proof_tests_sha256": "artifact/test_apple_device_proof.py",
    "apple_proof_contract_sha256": "artifact/apple_proof_contract.py",
    "apple_toolchain_verifier_sha256": "artifact/apple_toolchain.py",
    "apple_toolchain_tests_sha256": "artifact/test_apple_toolchain.py",
}

BOUNDED_PROCESS_PROOF_INPUTS = {
    "bounded_process_sha256": "artifact/bounded_process.py",
    "bounded_process_tests_sha256": "artifact/test_bounded_process.py",
    "process_identity_sha256": "artifact/process_identity.py",
    "android_emulator_control_sha256": "artifact/android_emulator_control.py",
    "android_runtime_state_sha256": "artifact/android_runtime_state.py",
    "android_runtime_state_tests_sha256": "artifact/test_android_runtime_state.py",
    "android_bounded_command_sha256": "artifact/android_bounded_command.py",
    "android_bounded_command_tests_sha256": "artifact/test_android_bounded_command.py",
}

ABI2_PLATFORM_RELEASE_PROOF_INPUTS = {
    "ci_workflow_sha256": ".github/workflows/ci.yml",
    "formal_easycrypt_dockerfile_sha256": "formal/Dockerfile",
    "formal_tool_asset_sha256": "artifact/formal_tool_asset.py",
    "formal_tool_asset_tests_sha256": "artifact/test_formal_tool_asset.py",
    "formal_toolchain_contract_sha256": "artifact/formal_toolchain_contract.py",
    "formal_toolchain_contract_tests_sha256": "artifact/test_formal_toolchain_contract.py",
    "proverif_makefile_sha256": "formal/proverif/Makefile",
    "codeql_workflow_sha256": ".github/workflows/codeql.yml",
    "codeql_rust_quality_gate_sha256": "artifact/codeql_rust_quality.py",
    "codeql_rust_checkout_gate_sha256": "artifact/codeql_rust_checkout.py",
    "codeql_rust_quality_tests_sha256": "artifact/test_codeql_rust_quality.py",
    "codeql_rust_quality_pack_sha256": "artifact/codeql-rust-quality/qlpack.yml",
    "codeql_rust_extracted_paths_query_sha256": "artifact/codeql-rust-quality/ExtractedPaths.ql",
    "codeql_rust_metrics_query_sha256": "artifact/codeql-rust-quality/Metrics.ql",
    "codeql_rust_unresolved_macros_query_sha256": "artifact/codeql-rust-quality/UnresolvedMacros.ql",
    "dependabot_config_sha256": ".github/dependabot.yml",
    "abi2_platform_candidate_workflow_sha256": ".github/workflows/abi2-platform-candidate.yml",
    "abi2_platform_candidate_verifier_script_sha256": "artifact/verify-platform-candidate.sh",
    "abi2_platform_candidate_verifier_tests_sha256": "artifact/test_platform_candidate_verifier.py",
    "platform_candidate_attestation_sha256": "artifact/platform_candidate_attestation.py",
    "platform_candidate_attestation_tests_sha256": "artifact/test_platform_candidate_attestation.py",
    "github_release_observation_sha256": "artifact/github_release_observation.py",
    "github_release_observation_tests_sha256": "artifact/test_github_release_observation.py",
    "publication_receipt_io_sha256": "artifact/publication_receipt_io.py",
    "publication_receipt_io_tests_sha256": "artifact/test_publication_receipt_io.py",
    "platform_stable_publication_sha256": "artifact/platform_stable_publication.py",
    "platform_stable_publication_tests_sha256": "artifact/test_platform_stable_publication.py",
    "release_receipt_finalizer_sha256": "artifact/release_receipt_finalizer.py",
    "release_receipt_finalizer_tests_sha256": "artifact/test_release_receipt_finalizer.py",
    "abi2_platform_release_notes_sha256": "artifact/abi2-platform-release-notes.md",
    "stable_release_notes_sha256": "artifact/stable-release-notes.md",
    "workflow_artifact_extractor_sha256": "artifact/workflow_artifact.py",
    "workflow_artifact_tests_sha256": "artifact/test_workflow_artifact.py",
    "android_aar_script_sha256": "artifact/android-aar.sh",
    "process_identity_sha256": "artifact/process_identity.py",
    "android_emulator_control_sha256": "artifact/android_emulator_control.py",
    "android_runtime_state_sha256": "artifact/android_runtime_state.py",
    "android_runtime_state_tests_sha256": "artifact/test_android_runtime_state.py",
    "android_bounded_command_sha256": "artifact/android_bounded_command.py",
    "android_bounded_command_tests_sha256": "artifact/test_android_bounded_command.py",
    "android_device_smoke_script_sha256": "artifact/android-device-smoke.sh",
    "android_device_proof_verifier_sha256": "artifact/android_device_proof.py",
    "android_device_proof_tests_sha256": "artifact/test_android_device_proof.py",
    "android_elf_verifier_sha256": "artifact/android_elf.py",
    "android_elf_tests_sha256": "artifact/test_android_elf.py",
    "c_package_script_sha256": "artifact/c-package.sh",
    "c_package_manifest_verifier_sha256": "artifact/c_package_manifest.py",
    "c_package_manifest_tests_sha256": "artifact/test_c_package_manifest.py",
    "deterministic_archive_sha256": "artifact/deterministic_archive.py",
    "deterministic_archive_tests_sha256": "artifact/test_deterministic_archive.py",
    "package_bom_sha256": "artifact/package_bom.py",
    "platform_distribution_verifier_sha256": "artifact/platform_distribution.py",
    "platform_distribution_contract_sha256": "artifact/platform_distribution_contract.py",
    "platform_distribution_tests_sha256": "artifact/test_platform_distribution.py",
    "platform_release_contract_sha256": "artifact/platform_release_contract.py",
    "platform_release_contract_tests_sha256": "artifact/test_platform_release_contract.py",
    "platform_stable_publication_contract_sha256": "artifact/platform_stable_publication_contract.py",
    "platform_stable_publication_contract_tests_sha256": "artifact/test_platform_stable_publication_contract.py",
    "platform_publication_contract_sha256": "artifact/platform_publication_contract.py",
    "platform_publication_contract_tests_sha256": "artifact/test_platform_publication_contract.py",
    "proof_to_byte_release_tests_sha256": "artifact/test_proof_to_byte_release.py",
    "release_binary_scan_sha256": "artifact/release_binary_scan.py",
    "release_binary_scan_tests_sha256": "artifact/test_release_binary_scan.py",
    "release_index_verifier_sha256": "artifact/release_index.py",
    "release_index_tests_sha256": "artifact/test_release_index.py",
    "local_release_consumer_smoke_script_sha256": "artifact/local-release-consumer-smoke.sh",
    "release_consumer_smoke_verifier_sha256": "artifact/release_consumer_smoke.py",
    "release_consumer_smoke_tests_sha256": "artifact/test_release_consumer_smoke.py",
    "security_policy_sha256": "SECURITY.md",
    "third_party_licenses_sha256": "artifact/third_party_licenses.py",
    "third_party_licenses_tests_sha256": "artifact/test_third_party_licenses.py",
    "windows_msvc_version_probe_sha256": "artifact/msvc-version-probe.c",
    "windows_package_script_sha256": "artifact/windows-package.ps1",
    "windows_package_verifier_sha256": "artifact/windows_package.py",
    "windows_package_tests_sha256": "artifact/test_windows_package.py",
    "windows_toolchain_tests_sha256": "artifact/windows-toolchain-tests.ps1",
}

CRATES_IO_PUBLICATION_PROOF_INPUTS = {
    "rust_package_handoff_sha256": "artifact/rust_package_handoff.py",
    "rust_package_handoff_tests_sha256": (
        "artifact/test_rust_package_handoff.py"
    ),
    "crates_io_publication_contract_sha256": (
        "artifact/crates_io_publication_contract.py"
    ),
    "crates_io_publication_contract_tests_sha256": (
        "artifact/test_crates_io_publication_contract.py"
    ),
    "crates_io_publication_sha256": "artifact/crates_io_publication.py",
    "crates_io_publication_tests_sha256": (
        "artifact/test_crates_io_publication.py"
    ),
}


def extract_workflow_job(workflow: str, job_name: str) -> str:
    job_match = re.search(
        rf"(?ms)^  {re.escape(job_name)}:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        workflow,
    )
    if job_match is None:
        raise ValueError(f"workflow has no {job_name!r} job")
    return job_match.group("body")


def extract_ci_check_job(workflow: str) -> str:
    return extract_workflow_job(workflow, "check")


def extract_named_workflow_step(job: str, step_name: str) -> str:
    step_match = re.search(
        rf"(?ms)^      - name: {re.escape(step_name)}\n"
        r"(?P<body>.*?)(?=^      - (?:name:|uses:|run:)|\Z)",
        job,
    )
    if step_match is None:
        raise ValueError(f"workflow job has no {step_name!r} step")
    return step_match.group(0)


def extract_action_steps(workflow: str, action: str) -> list[str]:
    return [
        match.group(0)
        for match in re.finditer(
            rf"(?ms)^      - uses: {re.escape(action)}[^\n]*\n"
            r".*?(?=^      - |^  [A-Za-z0-9_-]+:\n|\Z)",
            workflow,
        )
    ]


def repository_head() -> str:
    commit = git_commit(ROOT)
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise AssertionError(f"repository HEAD is not a 40-character commit: {commit}")
    return commit


def _git_fixture_command(root: pathlib.Path, *arguments: str) -> None:
    subprocess.run(
        ["/usr/bin/git", "-C", str(root), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _git_fixture_commit(root: pathlib.Path, message: str) -> None:
    _git_fixture_command(root, "add", "--all")
    _git_fixture_command(
        root,
        "-c",
        "user.name=Proof Test",
        "-c",
        "user.email=proof@example.invalid",
        "commit",
        "-qm",
        message,
    )


def _initialize_first_parent_results_fixture(
    root: pathlib.Path, parent_results: bytes | None
) -> None:
    subprocess.run(
        ["/usr/bin/git", "init", "-q", str(root)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if parent_results is not None:
        artifact = root / "artifact"
        artifact.mkdir()
        (artifact / "results.json").write_bytes(parent_results)
    (root / "fixture.txt").write_text("parent\n", encoding="utf-8")
    _git_fixture_commit(root, "Record parent results")
    (root / "fixture.txt").write_text("successor\n", encoding="utf-8")
    _git_fixture_commit(root, "Record successor")


def validate_ci_check_checkout(check_job: str) -> None:
    if check_job.lower().count("actions/checkout@") != 1:
        raise ValueError("CI check job must contain exactly one checkout action")
    if YAML_ALIAS.search(check_job) is not None:
        raise ValueError("CI check job must not use YAML aliases")

    lines = check_job.splitlines(keepends=True)
    checkout_starts = [
        index
        for index, line in enumerate(lines)
        if line.lower().startswith("      - uses: actions/checkout@")
    ]
    if len(checkout_starts) != 1:
        raise ValueError("CI check job must contain one explicit checkout step")

    def step_end(start: int) -> int:
        end = start + 1
        while end < len(lines):
            line = lines[end]
            if line.startswith("      - ") or (
                line.strip() and len(line) - len(line.lstrip(" ")) <= 6
            ):
                break
            end += 1
        return end

    start = checkout_starts[0]
    checkout_end = step_end(start)
    checkout_step = "".join(lines[start:checkout_end])
    if checkout_step != EXPECTED_CHECKOUT_STEP:
        raise ValueError(
            "CI check checkout must use the pinned action and exact hardened settings"
        )
    provenance_end = step_end(checkout_end)
    provenance_step = "".join(lines[checkout_end:provenance_end])
    if provenance_step != EXPECTED_CHECKOUT_PROVENANCE_STEP:
        raise ValueError(
            "CI check job must verify checkout provenance immediately after checkout"
        )

    proof_starts = [
        index
        for index, line in enumerate(lines)
        if line == "      - name: Exact source-transition or installed proof-to-byte gate\n"
    ]
    if len(proof_starts) != 1:
        raise ValueError("CI check job must contain one explicit proof-to-byte step")
    proof_start = proof_starts[0]
    proof_step = "".join(lines[proof_start : step_end(proof_start)])
    if proof_step != EXPECTED_PROOF_TO_BYTE_STEP:
        raise ValueError(
            "CI proof-to-byte step differs from the audited fail-closed form"
        )


def format_marker(**overrides: int) -> str:
    unknown = set(overrides) - set(proof_to_byte_finalizer.STATE_NAMES)
    if unknown:
        raise AssertionError(f"unknown finalizer state names: {sorted(unknown)}")
    states = {
        name: overrides.get(name, 0)
        for name in proof_to_byte_finalizer.STATE_NAMES
    }
    state = proof_to_byte_finalizer.AttestationState.from_values(
        [str(states[name]) for name in proof_to_byte_finalizer.STATE_NAMES]
    )
    return proof_to_byte_finalizer.format_attestation_marker(
        state,
        proof_to_byte_finalizer.SourceSnapshot(
            commit=TEST_COMMIT,
            source_sha256=TEST_SOURCE_SHA256,
            manifest_sha256=TEST_MANIFEST_SHA256,
            dirty=state.source_tree_dirty,
        ),
    )


class BoundVerifierWiringTests(unittest.TestCase):
    current_proof_inputs: dict[str, str]

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.current_proof_inputs = (
            proof_to_byte_inputs.capture_proof_input_digests(ROOT)
        )

    def assert_named_proof_input(self, key: str, relative: str) -> None:
        self.assertEqual(
            proof_to_byte_inputs.PROOF_TO_BYTE_INPUT_PATHS.get(key),
            relative,
        )
        self.assertEqual(
            self.current_proof_inputs.get(key),
            hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(),
        )

    def test_every_workflow_action_is_full_sha_pinned(self) -> None:
        action_ref = re.compile(
            r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+"
            r"(?:/[A-Za-z0-9_.-]+)*@([0-9a-f]{40})$"
        )
        workflows = sorted((ROOT / ".github" / "workflows").glob("*.y*ml"))
        self.assertTrue(workflows)
        action_count = 0
        for workflow in workflows:
            source = workflow.read_text(encoding="utf-8")
            references = re.findall(r"(?m)^\s*-?\s*uses:\s*([^\s#]+)", source)
            self.assertTrue(references, workflow.relative_to(ROOT))
            for reference in references:
                with self.subTest(
                    workflow=workflow.relative_to(ROOT), reference=reference
                ):
                    self.assertIsNotNone(action_ref.fullmatch(reference))
                action_count += 1
        self.assertGreater(action_count, 20)

    def test_tls_standard_baseline_and_private_groups_are_not_conflated(self) -> None:
        authorities = {
            "README.md": ROOT / "README.md",
            "competitive analysis": ROOT / "docs" / "COMPETITIVE_ANALYSIS.md",
            "paper draft": ROOT / "docs" / "PAPER_DRAFT.md",
            "rustls integration": ROOT / "crates" / "q-periapt-rustls" / "src" / "lib.rs",
            "TLS demo": ROOT / "crates" / "q-periapt-tls-demo" / "src" / "lib.rs",
            "paper": PAPER_SOURCE,
        }
        sources = {
            label: path.read_text(encoding="utf-8")
            for label, path in authorities.items()
        }
        for label, source in sources.items():
            with self.subTest(authority=label):
                self.assertIn("RFC 10024", source)

        combined = "\n".join(sources.values())
        for required in (
            "RFC 9954",
            "RFC 9846",
            "0x11EC",
            "0xFE01",
            "0xFE02",
            "private-use",
        ):
            self.assertIn(required, combined)
        for stale in (
            "draft-ietf-tls-ecdhe-mlkem",
            "draft-ietf-tls-hybrid-design",
            "RFC number unassigned",
            "RFC 8446",
            "\\cite{rfc8446}",
            "\\cite{tlshybrid}",
            "\\cite{tlsmlkem}",
        ):
            self.assertNotIn(stale, combined)

        rustls_source = sources["rustls integration"]
        self.assertIn("NamedGroup::Unknown(0xFE01)", rustls_source)
        self.assertIn("NamedGroup::Unknown(0xFE02)", rustls_source)
        handshake = (
            ROOT / "crates" / "q-periapt-rustls" / "tests" / "handshake.rs"
        ).read_text(encoding="utf-8")
        self.assertIn("rfc10024_x25519_mlkem768_direct_contract", handshake)
        self.assertIn("assert_eq!(u16::from(group.name()), 0x11EC)", handshake)
        self.assertIn("const CLIENT_SHARE_LEN: usize = 1_216", handshake)
        self.assertIn("const SERVER_SHARE_LEN: usize = 1_120", handshake)
        self.assertIn("const SHARED_SECRET_LEN: usize = 64", handshake)
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("- name: RFC 10024 standard baseline contract", workflow)
        self.assertIn(
            "cargo clippy -p q-periapt-rustls --all-targets "
            "--features bench-baseline --locked -- -D warnings",
            workflow,
        )
        self.assertIn(
            "cargo test -p q-periapt-rustls --features bench-baseline --locked",
            workflow,
        )

    def test_stable_runbook_names_the_current_binary_ct_protection_transition(self) -> None:
        notes = (ROOT / "artifact" / "stable-release-notes.md").read_text(
            encoding="utf-8"
        )
        for obsolete in (
            "constant-time (ubuntu-latest)",
            "constant-time (ubuntu-24.04-arm)",
        ):
            self.assertIn(f"`{obsolete}`", notes)
        for current in (
            "Binary CT [x86_64-portable]",
            "Binary CT [aarch64-native]",
        ):
            self.assertIn(f"`{current}`", notes)
        self.assertIn("strict branch protection", notes)
        self.assertIn("administrator enforcement", notes)
        self.assertIn("replace the obsolete required contexts", notes)

    def test_codeql_covers_all_detected_languages_with_real_builds(self) -> None:
        source = CODEQL_WORKFLOW.read_text(encoding="utf-8")
        self.assertNotIn("continue-on-error:", source)
        self.assertNotIn("id-token:", source)
        self.assertIn("security-events: write", source)
        matrix_entries = re.findall(
            r"(?m)^          - language: ([a-z-]+)\n"
            r"            build_mode: ([a-z]+)\n"
            r"            runner: ([a-z-]+)$",
            source,
        )
        self.assertEqual(
            matrix_entries,
            [
                ("actions", "none", "ubuntu-latest"),
                ("c-cpp", "none", "ubuntu-latest"),
                ("java-kotlin", "manual", "ubuntu-latest"),
                ("python", "none", "ubuntu-latest"),
                ("rust", "none", "ubuntu-latest"),
                ("swift", "manual", "macos-latest"),
            ],
        )
        self.assertIn(
            "gradle test --project-dir bindings/kotlin --no-daemon --warning-mode fail",
            source,
        )
        self.assertIn(
            "swift test --package-path bindings/swift -Xlinker "
            "-L${{ github.workspace }}/target/release",
            source,
        )
        # Kotlin builds the host library once; Swift builds both Apple
        # architectures and merges a universal static archive so the CodeQL
        # tracer links whichever slice its SwiftPM triple selects.
        self.assertEqual(
            len(
                re.findall(
                    r"(?m)cargo build --locked -p q-periapt-ffi --release$", source
                )
            ),
            1,
        )
        self.assertEqual(
            source.count(
                "cargo build --locked -p q-periapt-ffi --release "
                "--target aarch64-apple-darwin"
            ),
            1,
        )
        self.assertEqual(
            source.count(
                "cargo build --locked -p q-periapt-ffi --release "
                "--target x86_64-apple-darwin"
            ),
            1,
        )
        self.assertIn("lipo -create", source)
        self.assertIn("lipo -info target/release/libq_periapt_ffi_abi2.a", source)
        self.assertIn("queries: security-extended", source)
        self.assertIn("threat-models: [local]", source)

    def test_rust_codeql_analysis_has_a_fail_closed_database_quality_gate(self) -> None:
        source = CODEQL_WORKFLOW.read_text(encoding="utf-8")
        self.assertEqual(
            source.count(PINNED_CODEQL_ACTION.format(action="init")), 1
        )
        self.assertEqual(
            source.count(PINNED_CODEQL_ACTION.format(action="analyze")), 1
        )
        self.assertNotIn("github/codeql-action/init@7188fc", source)
        self.assertNotIn("github/codeql-action/analyze@7188fc", source)

        compatibility = extract_named_workflow_step(
            source, "Set up Rust CodeQL compatibility toolchain"
        )
        self.assertIn("        if: matrix.language == 'rust'\n", compatibility)
        self.assertIn(f"        uses: {PINNED_CANONICAL_RUST_ACTION}\n", compatibility)
        self.assertIn("          toolchain: 1.94.0\n", compatibility)
        self.assertIn("          components: rust-src\n", compatibility)

        compile_step = extract_named_workflow_step(
            source,
            "Compile all Rust targets with compatibility and canonical toolchains",
        )
        self.assertEqual(
            compile_step.count("          test ! -e target && test ! -L target\n"), 2
        )
        self.assertIn(
            'CARGO_TARGET_DIR="${RUNNER_TEMP}/qperiapt-rust-check-1.94.0"',
            compile_step,
        )
        self.assertIn(
            "cargo +1.94.0 check --workspace --all-targets --locked",
            compile_step,
        )
        self.assertIn(
            'CARGO_TARGET_DIR="${RUNNER_TEMP}/qperiapt-rust-check-1.96.1"',
            compile_step,
        )
        self.assertIn(
            "cargo +1.96.1 check --workspace --all-targets --locked",
            compile_step,
        )
        self.assertEqual(compile_step.count("          RUSTFLAGS='-D warnings' \\\n"), 2)

        sysroot_step = extract_named_workflow_step(
            source, "Bind Rust CodeQL to the compatible analysis sysroot"
        )
        self.assertIn("rustc 1.94.0 (4a4ef493e 2026-03-02)", sysroot_step)
        self.assertIn("CODEQL_EXTRACTOR_RUST_OPTION_SYSROOT=%s", sysroot_step)
        self.assertIn("CODEQL_EXTRACTOR_RUST_OPTION_SYSROOT_SRC=%s", sysroot_step)
        self.assertIn("RUSTUP_TOOLCHAIN=%s", sysroot_step)

        initialize = extract_named_workflow_step(source, "Initialize CodeQL")
        self.assertIn("        id: codeql_init\n", initialize)
        self.assertIn(
            "          db-location: ${{ runner.temp }}/qperiapt-codeql-database\n",
            initialize,
        )
        exact_bundle = extract_named_workflow_step(source, "Verify linked CodeQL bundle")
        self.assertIn(
            "          CODEQL_BINARY: "
            "${{ steps.codeql_init.outputs.codeql-path }}\n",
            exact_bundle,
        )
        self.assertIn(
            'run: test "$("$CODEQL_BINARY" version --format=terse)" = "2.26.2"',
            exact_bundle,
        )
        fixed_bundle = extract_named_workflow_step(
            source, "Bind Rust quality gate to the linked CodeQL bundle"
        )
        self.assertIn("        if: matrix.language == 'rust'\n", fixed_bundle)
        self.assertIn(
            "          CODEQL_BINARY: "
            "${{ steps.codeql_init.outputs.codeql-path }}\n",
            fixed_bundle,
        )
        self.assertIn(
            "          fixed_codeql=/opt/hostedtoolcache/CodeQL/2.26.2/x64/"
            "codeql/codeql\n",
            fixed_bundle,
        )
        self.assertIn(
            '          test "$CODEQL_BINARY" = "$fixed_codeql"\n', fixed_bundle
        )
        self.assertIn(
            "          stat --format='CODEQL_TOOLCACHE_STAT type=%F mode=%a "
            "uid=%u gid=%g nlink=%h' \\\n",
            fixed_bundle,
        )
        self.assertIn('            -- "$fixed_codeql"\n', fixed_bundle)
        self.assertNotIn("|| true", fixed_bundle)
        self.assertNotIn("continue-on-error:", fixed_bundle)
        self.assertEqual(initialize.count("          tools: linked\n"), 1)
        analyze = extract_named_workflow_step(source, "Analyze")
        self.assertIn("        id: codeql_analyze\n", analyze)
        self.assertIn(
            "          upload: "
            "${{ matrix.language == 'rust' && 'never' || 'always' }}\n",
            analyze,
        )
        self.assertIn(
            "          upload-database: "
            "${{ matrix.language == 'rust' && 'false' || 'true' }}\n",
            analyze,
        )
        reject_target = extract_named_workflow_step(
            source, "Reject repository-local Rust build output"
        )
        self.assertEqual(
            reject_target.count("test ! -e target && test ! -L target"), 1
        )
        checkout_before = extract_named_workflow_step(
            source, "Verify Rust CodeQL checkout before initialization"
        )
        checkout_after = extract_named_workflow_step(
            source, "Verify Rust CodeQL checkout after analysis"
        )
        for checkout in (checkout_before, checkout_after):
            self.assertIn("          CODEQL_EXPECTED_COMMIT: ${{ github.sha }}\n", checkout)
            self.assertIn(
                "        run: sh artifact/python-run.sh "
                "artifact/codeql_rust_checkout.py\n",
                checkout,
            )
        self.assertLess(source.index(checkout_before), source.index(initialize))
        self.assertLess(source.index(fixed_bundle), source.index(exact_bundle))
        self.assertLess(source.index(exact_bundle), source.index(analyze))
        self.assertGreater(source.index(checkout_after), source.index(analyze))

        quality = extract_named_workflow_step(
            source, "Verify Rust CodeQL database quality"
        )
        self.assertIn("        if: matrix.language == 'rust'\n", quality)
        self.assertIn("          CODEQL_EXPECTED_COMMIT: ${{ github.sha }}\n", quality)
        self.assertNotIn("CODEQL_BINARY", quality)
        self.assertNotIn("CODEQL_DATABASE_LOCATIONS", quality)
        self.assertNotIn("CODEQL_RUNNER_TEMP", quality)
        self.assertIn(
            "        run: sh artifact/python-run.sh "
            "artifact/codeql_rust_quality.py\n",
            quality,
        )
        self.assertNotIn("continue-on-error:", quality)
        self.assertNotIn("|| true", quality)
        upload = extract_named_workflow_step(
            source, "Upload quality-gated Rust CodeQL results"
        )
        self.assertIn("        if: matrix.language == 'rust'\n", upload)
        self.assertIn(
            f"        uses: {PINNED_CODEQL_ACTION.format(action='upload-sarif')}\n",
            upload,
        )
        self.assertIn(
            "          sarif_file: "
            "${{ steps.codeql_analyze.outputs.sarif-output }}\n",
            upload,
        )
        self.assertIn("          wait-for-processing: true\n", upload)
        self.assertGreater(source.index(upload), source.index(quality))
        self.assertLess(source.index(checkout_after), source.index(quality))

        quality_source = (ROOT / "artifact" / "codeql_rust_quality.py").read_text(
            encoding="utf-8"
        )
        self.assertEqual(
            quality_source.count("        require_clean_checkout(expected_commit)\n"),
            2,
        )
        self.assertEqual(
            quality_source.count("        require_repository_target_absent()\n"),
            2,
        )
        self.assertNotIn('os.environ.get("CODEQL_BINARY"', quality_source)
        self.assertNotIn(
            'os.environ.get("CODEQL_DATABASE_LOCATIONS"', quality_source
        )
        self.assertNotIn('os.environ.get("CODEQL_RUNNER_TEMP"', quality_source)
        self.assertIn(
            '"/opt/hostedtoolcache/CodeQL/2.26.2/x64/codeql/codeql"',
            quality_source,
        )
        self.assertIn(
            '"/home/runner/work/_temp/qperiapt-codeql-database/rust"',
            quality_source,
        )
        self.assertIn(
            'FIXED_RUNNER_TEMP = pathlib.Path("/home/runner/work/_temp")',
            quality_source,
        )

    def test_rust_codeql_compatibility_and_upload_boundary_is_documented(self) -> None:
        guide = ARTIFACT_GUIDE.read_text(encoding="utf-8")
        normalized = " ".join(guide.split())
        self.assertIn("## Rust CodeQL analysis boundary", guide)
        self.assertIn("not native Rust 1.96.1 CodeQL analysis", normalized)
        self.assertIn("under both Rust 1.94.0 and Rust 1.96.1 with", normalized)
        self.assertIn("90 tracked `.rs` files", normalized)
        self.assertIn(
            "reported as telemetry rather than required to be zero", normalized
        )
        self.assertIn("`wasm_bindgen`-generated `Abi` type mentions", normalized)
        self.assertIn("raw database upload disabled", normalized)
        self.assertIn("only an explicit SARIF upload after the quality", normalized)
        self.assertIn(
            "accepts no environment-selected executable, database, or temporary path",
            normalized,
        )
        self.assertIn("trusted-runner integrity checks", normalized)
        self.assertIn("not isolation from hostile code", normalized)
        self.assertIn("path-identity snapshots", normalized)
        self.assertIn("remain trusted inputs used by pathname", normalized)
        self.assertIn("inherited process environment and OS runtime are trusted", normalized)
        self.assertIn(
            "Each custom query receives a fixed four-thread, 14,000 MB evaluator "
            "budget while retaining its 300-second process deadline and bounded "
            "diagnostic output; a resource or deadline failure blocks publication.",
            normalized,
        )
        self.assertIn("public-repository Rust `ubuntu-latest` lane", normalized)
        self.assertIn(
            "runner-label, repository-visibility, or hosted-hardware change requires "
            "revalidating the fixed budget",
            normalized,
        )
        for boundary in (
            "foreign-owned",
            "group/other-writable",
            "multiply linked",
            "original inode",
            "alternate hard link",
            "separate account alone is insufficient",
        ):
            self.assertIn(boundary, normalized)

    def test_dependency_monitoring_and_private_reporting_policy_are_explicit(
        self,
    ) -> None:
        dependabot = DEPENDABOT_CONFIG.read_text(encoding="utf-8")
        configured = re.findall(
            r"(?m)^  - package-ecosystem: ([a-z-]+)\n"
            r"    directory: ([^\n]+)$",
            dependabot,
        )
        self.assertEqual(
            configured,
            [
                ("cargo", "/"),
                ("cargo", "/fuzz"),
                ("cargo", "/research/hqc-fips207-candidate"),
                ("gradle", "/bindings/kotlin"),
                ("swift", "/bindings/swift"),
                ("docker", "/formal"),
                ("github-actions", "/"),
            ],
        )
        self.assertNotIn("target-branch:", dependabot)
        self.assertNotIn("ignore:", dependabot)
        self.assertNotIn("groups:", dependabot)
        policy = SECURITY_POLICY.read_text(encoding="utf-8")
        normalized_policy = " ".join(policy.split())
        self.assertIn("Report a vulnerability", normalized_policy)
        self.assertIn(
            "unsigned and is excluded from the stable candidate",
            normalized_policy,
        )
        self.assertIn(
            "does not establish Windows publisher identity",
            normalized_policy,
        )

    def test_android_release_gate_binds_every_verifier_argument(self) -> None:
        source = PROOF_SCRIPT.read_text(encoding="utf-8")
        gate_start = source.index(
            'if [ "$REQUIRE_ANDROID_RUNTIME" = "1" ]; then\n\ttest -f "$ANDROID_PROOF"'
        )
        gate_end = source.index(
            '\nif [ "$REQUIRE_ANDROID_PHYSICAL_RUNTIME" = "1" ]; then',
            gate_start,
        )
        gate_lines = source[gate_start:gate_end].splitlines()

        commands: list[list[str]] = []
        command_spans: list[tuple[int, int]] = []
        command_prefix = "python3 artifact/android_device_proof.py verify \\"
        for index, line in enumerate(gate_lines):
            if line.strip() != command_prefix:
                continue
            fragments = [command_prefix.removesuffix(" \\")]
            cursor = index + 1
            while cursor < len(gate_lines):
                fragment = gate_lines[cursor].strip()
                continued = fragment.endswith("\\")
                fragments.append(fragment[:-1].rstrip() if continued else fragment)
                if not continued:
                    break
                cursor += 1
            else:
                self.fail("Android verifier command has no terminating argument")
            commands.append(shlex.split(" ".join(fragments)))
            command_spans.append((index, cursor))

        base = [
            "python3",
            "artifact/android_device_proof.py",
            "verify",
            "--root",
            "$ROOT",
            "--proof",
            "$ANDROID_PROOF",
            "--max-age-seconds",
            "$ANDROID_MAX_AGE_SECONDS",
        ]
        expected_kind = ["--expected-device-kind", "$EXPECTED_KIND"]
        release_contract = [
            "--expected-device-abi",
            "$EXPECTED_ANDROID_DEVICE_ABI",
            "--expected-page-size",
            "16384",
            "--expected-device-sdk",
            "35",
            "--require-release-mode",
            "--results-manifest",
            "$RESULTS_MANIFEST",
            "--expected-results-manifest-sha256",
            "$RESULTS_MANIFEST_SHA256",
        ]
        self.assertEqual(
            commands,
            [[*base, *expected_kind, *release_contract]],
        )
        self.assertNotIn("--allow-dirty-proof", "\n".join(gate_lines))

        scaffold_lines = gate_lines.copy()
        for start, end in reversed(command_spans):
            indentation = scaffold_lines[start][
                : len(scaffold_lines[start]) - len(scaffold_lines[start].lstrip())
            ]
            scaffold_lines[start : end + 1] = [f"{indentation}<ANDROID_VERIFY>"]
        verify_marker = scaffold_lines.index("\t<ANDROID_VERIFY>")
        pass_marker = scaffold_lines.index("\tANDROID_RUNTIME_PASSED=1")
        self.assertEqual(
            scaffold_lines[verify_marker:pass_marker],
            ["\t<ANDROID_VERIFY>"],
        )
        self.assertNotIn("ALLOW_DIRTY_ANDROID_RUNTIME_PROOF", "\n".join(gate_lines))

    def test_android_physical_gate_is_one_clean_manifest_bound_command(self) -> None:
        source = PROOF_SCRIPT.read_text(encoding="utf-8")
        gate_start = source.index(
            'if [ "$REQUIRE_ANDROID_PHYSICAL_RUNTIME" = "1" ]; then\n'
            '\ttest -f "$ANDROID_PHYSICAL_PROOF"'
        )
        gate_end = source.index(
            '\nif [ "$REQUIRE_LOCAL_RELEASE_CONSUMER" = "1" ]; then',
            gate_start,
        )
        gate_lines = source[gate_start:gate_end].splitlines()

        commands: list[list[str]] = []
        command_spans: list[tuple[int, int]] = []
        command_prefix = "python3 artifact/android_device_proof.py verify \\"
        for index, line in enumerate(gate_lines):
            if line.strip() != command_prefix:
                continue
            fragments = [command_prefix.removesuffix(" \\")]
            cursor = index + 1
            while cursor < len(gate_lines):
                fragment = gate_lines[cursor].strip()
                continued = fragment.endswith("\\")
                fragments.append(fragment[:-1].rstrip() if continued else fragment)
                if not continued:
                    break
                cursor += 1
            else:
                self.fail("physical Android verifier command has no terminating argument")
            commands.append(shlex.split(" ".join(fragments)))
            command_spans.append((index, cursor))

        self.assertEqual(
            commands,
            [
                [
                    "python3",
                    "artifact/android_device_proof.py",
                    "verify",
                    "--root",
                    "$ROOT",
                    "--proof",
                    "$ANDROID_PHYSICAL_PROOF",
                    "--max-age-seconds",
                    "$ANDROID_PHYSICAL_MAX_AGE_SECONDS",
                    "--expected-device-kind",
                    "physical",
                    "--results-binding",
                    "android_physical_runtime",
                    "--results-manifest",
                    "$RESULTS_MANIFEST",
                    "--expected-results-manifest-sha256",
                    "$RESULTS_MANIFEST_SHA256",
                ]
            ],
        )
        self.assertEqual(source.count("--results-binding android_physical_runtime"), 1)
        command = commands[0]
        for forbidden in (
            "--expected-device-abi",
            "--expected-page-size",
            "--expected-device-sdk",
            "--require-release-mode",
            "--allow-dirty-proof",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, command)

        scaffold_lines = gate_lines.copy()
        for start, end in reversed(command_spans):
            indentation = scaffold_lines[start][
                : len(scaffold_lines[start]) - len(scaffold_lines[start].lstrip())
            ]
            scaffold_lines[start : end + 1] = [f"{indentation}<PHYSICAL_VERIFY>"]
        verify_marker = scaffold_lines.index("\t<PHYSICAL_VERIFY>")
        pass_state = scaffold_lines.index("\tANDROID_PHYSICAL_RUNTIME_PASSED=1")
        self.assertEqual(
            scaffold_lines[verify_marker:pass_state],
            ["\t<PHYSICAL_VERIFY>"],
        )
        self.assertEqual(
            scaffold_lines[pass_state + 1],
            "\tprintf 'PROOF_TO_BYTE_ANDROID_PHYSICAL_RUNTIME_PASS\\n'",
        )

    def test_android_release_gate_and_finalizer_state_wiring_are_explicit(self) -> None:
        source = PROOF_SCRIPT.read_text(encoding="utf-8")
        self.assertIn(
            'REQUIRE_ANDROID_AAR=$(bool_flag QPERIAPT_REQUIRE_ANDROID_AAR ',
            source,
        )
        self.assertIn(
            "REQUIRE_ANDROID_PHYSICAL_RUNTIME=$(bool_flag "
            "QPERIAPT_REQUIRE_ANDROID_PHYSICAL_RUNTIME ",
            source,
        )
        self.assertIn(
            "REQUIRE_LOCAL_RELEASE_CONSUMER=$(bool_flag "
            "QPERIAPT_REQUIRE_LOCAL_RELEASE_CONSUMER ",
            source,
        )
        self.assertIn(
            'if [ "$REQUIRE_ANDROID_RUNTIME" = "1" ] || \\\n'
            '\t[ "$REQUIRE_ANDROID_PHYSICAL_RUNTIME" = "1" ] || \\\n'
            '\t[ "$REQUIRE_LOCAL_RELEASE_CONSUMER" = "1" ]; then',
            source,
        )
        self.assertIn(
            "python3 artifact/android_elf.py verify-results-bound-aar \\",
            source,
        )
        self.assertIn(
            "python3 artifact/release_consumer_smoke.py verify-bound \\",
            source,
        )
        self.assertIn(
            'if [ "$REQUIRE_LOCAL_RELEASE_CONSUMER" = "1" ] && '
            '[ "$REQUIRE_ANDROID_RUNTIME" != "1" ]; then',
            source,
        )
        aar_gate = source.index(
            "python3 artifact/android_elf.py verify-results-bound-aar \\"
        )
        canonical_gate = source.index(
            'if [ "$REQUIRE_ANDROID_RUNTIME" = "1" ]; then',
            aar_gate,
        )
        physical_gate = source.index(
            'if [ "$REQUIRE_ANDROID_PHYSICAL_RUNTIME" = "1" ]; then',
            canonical_gate,
        )
        consumer_gate = source.index(
            'if [ "$REQUIRE_LOCAL_RELEASE_CONSUMER" = "1" ]; then',
            physical_gate,
        )
        self.assertLess(aar_gate, canonical_gate)
        self.assertLess(canonical_gate, physical_gate)
        self.assertLess(physical_gate, consumer_gate)

        finalizer_call = source[source.index("python3 artifact/proof_to_byte_finalizer.py finalize \\") :]
        expected_state_arguments = [
            '"$HOST_SMOKE_PASSED"',
            '"$FORMAL_PASSED"',
            '"$APPLE_DEVICE_PASSED"',
            '"$APPLE_MATRIX_PASSED"',
            '"$ANDROID_AAR_PASSED"',
            '"$ANDROID_RUNTIME_PASSED"',
            '"$ANDROID_PHYSICAL_RUNTIME_PASSED"',
            '"$LOCAL_RELEASE_CONSUMER_PASSED"',
            '"$PERFORMANCE_PASSED"',
            '"$CAMERA_READY_BUNDLE_PASSED"',
            '"$REQUIRE_CAMERA_READY"',
            '"$DEPENDENCY_AUDIT_PASSED"',
            '"$ALLOW_DIRTY_APPLE_DEVICE_PROOF"',
            '"$ALLOW_DIRTY_PERFORMANCE_PROOF"',
            '"$RUST_PACKAGE_CONTRACT_PASSED"',
        ]
        positions = [finalizer_call.index(argument) for argument in expected_state_arguments]
        self.assertEqual(positions, sorted(positions))
        self.assertNotIn('"$ALLOW_DIRTY_ANDROID_RUNTIME_PROOF"', finalizer_call)

        self.assertEqual(
            proof_to_byte_finalizer.STATE_NAMES,
            (
                "host_smoke",
                "formal",
                "apple_device",
                "apple_matrix",
                "android_aar",
                "android_runtime",
                "android_physical_runtime",
                "local_release_consumer",
                "performance",
                "camera_ready",
                "camera_required",
                "dependency_audit",
                "source_tree_dirty",
                "allow_dirty_apple",
                "allow_dirty_performance",
                "rust_package_contract",
            ),
        )

    def test_rust_package_receipt_is_an_independent_manifest_bound_gate(self) -> None:
        source = PROOF_SCRIPT.read_text(encoding="utf-8")
        self.assertIn(
            'REQUIRE_RUST_PACKAGE_CONTRACT=$(bool_flag '
            'QPERIAPT_REQUIRE_RUST_PACKAGE_CONTRACT ',
            source,
        )
        gate_start = source.index(
            'if [ "$REQUIRE_RUST_PACKAGE_CONTRACT" = "1" ]; then'
        )
        gate_end = source.index(
            "sh artifact/python-run.sh artifact/migration_contract_v2.py verify",
            gate_start,
        )
        gate = source[gate_start:gate_end]
        for token in (
            "load_current_rust_package_contract_receipt(",
            "frozen_commit=sys.argv[4]",
            "frozen_source_sha256=sys.argv[5]",
            "PROOF_TO_BYTE_RUST_PACKAGE_CONTRACT_PASS upload=not-attempted",
        ):
            with self.subTest(token=token):
                self.assertIn(token, gate)
        pass_position = gate.index(
            "PROOF_TO_BYTE_RUST_PACKAGE_CONTRACT_PASS upload=not-attempted"
        )
        state_position = gate.index("RUST_PACKAGE_CONTRACT_PASSED=1")
        self.assertLess(pass_position, state_position)
        self.assertNotIn("DEPENDENCY_AUDIT_PASSED=1", gate)

        audit_gate = source[
            source.index(
                'if [ "$REQUIRE_DEPENDENCY_AUDIT" = "1" ]; then',
                gate_end,
            ):
            source.index('if [ "$SKIP_SMOKE" = "0" ]; then')
        ]
        self.assertIn("DEPENDENCY_AUDIT_PASSED=1", audit_gate)
        self.assertNotIn("RUST_PACKAGE_CONTRACT_PASSED=1", audit_gate)

    def test_release_candidate_requires_the_independent_rust_package_gate(self) -> None:
        without_package = format_marker(
            host_smoke=1,
            formal=1,
            apple_matrix=1,
            performance=1,
            dependency_audit=1,
        )
        self.assertIn("PROOF_TO_BYTE_RUN_FINISHED", without_package)
        self.assertIn("rust_package_contract=0", without_package)
        self.assertNotIn("PROOF_TO_BYTE_APPLE_LOCAL_CANDIDATE_PASS", without_package)

        with_package = format_marker(
            host_smoke=1,
            formal=1,
            apple_matrix=1,
            performance=1,
            dependency_audit=1,
            rust_package_contract=1,
        )
        self.assertIn("PROOF_TO_BYTE_APPLE_LOCAL_CANDIDATE_PASS", with_package)
        self.assertIn("rust_package_contract=1", with_package)

    def test_ci_android_16k_runtime_consumes_same_run_aar_fail_closed(self) -> None:
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")
        job = extract_workflow_job(workflow, "bindings-android-runtime-16k")

        self.assertIn("    needs: bindings-android-aar\n", job)
        self.assertIn("    runs-on: ubuntu-24.04\n", job)
        self.assertIn("    timeout-minutes: 45\n", job)
        download_steps = extract_action_steps(job, "actions/download-artifact")
        self.assertEqual(len(download_steps), 1)
        self.assertEqual(
            download_steps[0],
            f"      - uses: {PINNED_DOWNLOAD_ARTIFACT_ACTION}\n"
            "        with:\n"
            "          name: abi2-android-aar\n"
            "          path: target/workflow-artifact/raw\n"
            "          skip-decompress: true\n"
            "          digest-mismatch: error\n",
        )
        extractor = extract_named_workflow_step(
            job, "Strictly extract the same-run Android AAR artifact"
        )
        self.assertEqual(
            extractor,
            "      - name: Strictly extract the same-run Android AAR artifact\n"
            "        env:\n"
            "          QPERIAPT_PYTHON: "
            "${{ steps.proof_python.outputs.python-path }}\n"
            "        run: sh artifact/python-run.sh "
            "artifact/workflow_artifact.py android-aar\n",
        )
        self.assertNotIn("merge-multiple:", download_steps[0])
        self.assertNotIn("          run-id:", job)
        self.assertNotIn("          github-token:", job)
        self.assertIn("license_answers=$(printf 'y\\n%.0s' {1..64})", job)
        self.assertIn('sdkmanager --licenses <<< "$license_answers"', job)
        self.assertIn("unset license_answers", job)
        self.assertNotIn("yes | sdkmanager", job)
        self.assertNotIn("sdkmanager --licenses <<< \"$license_answers\" ||", job)

        image = '"system-images;android-35;google_apis_ps16k;x86_64"'
        self.assertGreaterEqual(job.count(image), 2)
        for required in (
            'QPERIAPT_ANDROID_ADB_PROFILE: linux-system',
            'QPERIAPT_ANDROID_RELEASE_MODE: "1"',
            'QPERIAPT_ANDROID_BOOT_AVD: "1"',
            'QPERIAPT_ANDROID_EXPECT_DEVICE_KIND: emulator',
            'QPERIAPT_ANDROID_EXPECT_ABI: x86_64',
            'QPERIAPT_ANDROID_EXPECT_PAGE_SIZE: "16384"',
            'QPERIAPT_ANDROID_EXPECT_SDK: "35"',
            'QPERIAPT_ANDROID_EXISTING_AAR="$aar"',
            'QPERIAPT_ANDROID_EXISTING_AAR_MANIFEST="$manifest"',
            'QPERIAPT_ANDROID_EXPECTED_AAR_SHA256="$aar_sha256"',
            'QPERIAPT_ANDROID_EXPECTED_AAR_MANIFEST_SHA256="$manifest_sha256"',
            "command -v setfacl",
            "command -v lsof",
            "QPERIAPT_PYTHON: ${{ steps.proof_python.outputs.python-path }}",
            'test ! -e "$HOME/.android/adbkey"',
            'test ! -e "$HOME/.emulator_console_auth_token"',
            "sh artifact/python-run.sh",
            "artifact/android_bounded_command.py avd-home-path",
            "runtime-avd-name --adb-profile linux-system --device-abi x86_64",
            'test "$avd_name" = QPeriapt_Release_16K_API_35_CI_V1',
            'test ! -e "$avd_home"',
            'mkdir "$avd_home"',
            'export ANDROID_AVD_HOME="$avd_home"',
            'test ! -e "$ANDROID_AVD_HOME/$avd_name.avd"',
            'test ! -L "$ANDROID_AVD_HOME/$avd_name.avd"',
            'test ! -e "$ANDROID_AVD_HOME/$avd_name.ini"',
            'test ! -L "$ANDROID_AVD_HOME/$avd_name.ini"',
            '--name "$avd_name"',
            "--device pixel_6 <<< 'no'",
            'test -d "$ANDROID_AVD_HOME/$avd_name.avd"',
            'test -f "$ANDROID_AVD_HOME/$avd_name.ini"',
            "verify-avd-home",
            '--avd-home "$ANDROID_AVD_HOME"',
            "--adb-profile linux-system",
            "--device-abi x86_64",
            "unset ANDROID_AVD_HOME avd_home avd_name",
            'sh artifact/android-device-smoke.sh',
        ):
            with self.subTest(required=required):
                self.assertIn(required, job)

        for forbidden in (
            "continue-on-error:",
            "ADB_SERVER_PORT",
            "ANDROID_ADB_SERVER_PORT",
            "localhost:5037",
            "127.0.0.1:5037",
            "adb start-server",
            "adb kill-server",
            "QPERIAPT_ADB=",
            "apt-get",
            "--force",
            'mkdir -p "$avd_home"',
            'chmod -R',
            '$HOME/.android/avd',
            "/home/runner",
            "ANDROID_USER_HOME",
            "GITHUB_ENV",
            "printf 'no\\n' | avdmanager",
            "PYTHONPATH=artifact python3",
            "QPERIAPT_ANDROID_AVD",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, job)

        derive_home = job.index(
            "artifact/android_bounded_command.py avd-home-path"
        )
        create_home = job.index('mkdir "$avd_home"', derive_home)
        export_home = job.index(
            'export ANDROID_AVD_HOME="$avd_home"', create_home
        )
        derive_name = job.index("runtime-avd-name", export_home)
        create_avd = job.index("avdmanager create avd", derive_name)
        verify_avd = job.index("verify-avd-home", create_avd)
        execute_smoke = job.index("sh artifact/android-device-smoke.sh", verify_avd)
        self.assertLess(derive_home, create_home)
        self.assertLess(create_home, export_home)
        self.assertLess(export_home, derive_name)
        self.assertLess(derive_name, create_avd)
        self.assertLess(create_avd, verify_avd)
        self.assertLess(verify_avd, execute_smoke)

        diagnostic_upload = extract_named_workflow_step(
            job, "Upload bounded Android package diagnostics after failure"
        )
        self.assertEqual(
            diagnostic_upload,
            "      - name: Upload bounded Android package diagnostics after failure\n"
            "        if: failure() && "
            "hashFiles('target/qperiapt-android-device-smoke-runs/*/proof/adb-package-state-observation.log') != ''\n"
            f"        uses: {PINNED_UPLOAD_ARTIFACT_ACTION}\n"
            "        with:\n"
            "          name: abi2-android-runtime-api35-16k-x86_64-failure-diagnostics\n"
            "          path: |\n"
            "            target/qperiapt-android-device-smoke-runs/*/proof/adb-package-state-observation.log\n"
            "          if-no-files-found: error\n",
        )
        self.assertNotIn("attempt-*.txt", diagnostic_upload)
        self.assertNotIn("attempt-*.err", diagnostic_upload)
        self.assertNotIn("adb-uninstall-cleanup.log", diagnostic_upload)
        self.assertNotIn("adb-package-query-", diagnostic_upload)

        proof_upload = extract_named_workflow_step(job, "Upload Android runtime proof")
        self.assertIn(
            f"        uses: {PINNED_UPLOAD_ARTIFACT_ACTION}\n", proof_upload
        )
        self.assertIn("name: abi2-android-runtime-api35-16k-x86_64\n", proof_upload)
        self.assertNotIn("if: failure()", proof_upload)
        self.assertIn("if-no-files-found: error\n", proof_upload)

        producer = (ROOT / "artifact" / "android-device-smoke.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            'ADB_PRIVATE_SERVER_SOCKET_SPEC="localfilesystem:'
            '$ADB_PRIVATE_SERVER_SOCKET_PATH"',
            producer,
        )
        self.assertIn('export ADB_SERVER_SOCKET="$ADB_PRIVATE_SERVER_SOCKET_SPEC"', producer)
        self.assertIn("assert_default_adb_server_absent", producer)

    def test_platform_candidate_download_uses_raw_strict_profile_without_merge(
        self,
    ) -> None:
        workflow = ABI2_PLATFORM_CANDIDATE_WORKFLOW.read_text(encoding="utf-8")
        job = extract_workflow_job(workflow, "attest")
        download_steps = extract_action_steps(job, "actions/download-artifact")
        self.assertEqual(len(download_steps), 1)
        self.assertEqual(
            download_steps[0],
            f"      - uses: {PINNED_DOWNLOAD_ARTIFACT_ACTION}\n"
            "        with:\n"
            "          pattern: abi2-candidate-*\n"
            "          path: target/workflow-artifact/raw\n"
            "          merge-multiple: false\n"
            "          skip-decompress: true\n"
            "          digest-mismatch: error\n",
        )
        extractor = extract_named_workflow_step(
            job, "Strictly extract the platform candidate artifacts"
        )
        self.assertEqual(
            extractor,
            "      - name: Strictly extract the platform candidate artifacts\n"
            "        env:\n"
            "          QPERIAPT_PYTHON: "
            "${{ steps.proof_python.outputs.python-path }}\n"
            "        run: sh artifact/python-run.sh "
            "artifact/workflow_artifact.py platform-candidate\n",
        )

    def test_every_android_sdk_license_input_is_finite_and_fail_closed(self) -> None:
        workflow_sources = {
            path.relative_to(ROOT).as_posix(): path.read_text(encoding="utf-8")
            for path in sorted((ROOT / ".github/workflows").glob("*.yml"))
        }
        combined = "\n".join(workflow_sources.values())
        self.assertEqual(combined.count("sdkmanager --licenses"), 3)
        self.assertEqual(
            combined.count("license_answers=$(printf 'y\\n%.0s' {1..64})"),
            3,
        )
        self.assertEqual(
            combined.count('sdkmanager --licenses <<< "$license_answers"'),
            3,
        )
        self.assertEqual(combined.count("unset license_answers"), 3)
        self.assertNotIn("yes | sdkmanager", combined)
        self.assertNotIn('sdkmanager --licenses <<< "$license_answers" ||', combined)

    def test_proof_to_byte_names_every_continuity_input(self) -> None:
        for key, relative in CONTINUITY_PROOF_INPUTS.items():
            with self.subTest(key=key):
                self.assert_named_proof_input(key, relative)

    def test_proof_to_byte_names_every_migration_v2_input(self) -> None:
        source = PROOF_SCRIPT.read_text(encoding="utf-8")
        for key, relative in MIGRATION_V2_PROOF_INPUTS.items():
            with self.subTest(key=key):
                self.assert_named_proof_input(key, relative)
        self.assertIn("artifact/migration_contract_v2.py verify", source)
        self.assertIn("formal_make -C formal/easycrypt EC=easycrypt check", source)
        self.assertIn(
            "formal_make -C formal/tamarin TAMARIN=tamarin-prover \\\n"
            "\t\tDERIVCHECK_TIMEOUT=60 prove",
            source,
        )

    def test_proof_to_byte_verifies_the_complete_formal_toolchain_first(self) -> None:
        source = PROOF_SCRIPT.read_text(encoding="utf-8")
        all_tools_call = (
            "sh artifact/python-run.sh artifact/formal_toolchain_contract.py "
            "\\\n\t\tverify-installed --tool all"
        )
        easycrypt_call = (
            "sh artifact/python-run.sh artifact/formal_toolchain_contract.py "
            "\\\n\t\tverify-installed --tool easycrypt"
        )
        expected_dispatch = (
            'if [ "$REQUIRE_FORMAL" = "1" ]; then\n'
            f"\t{all_tools_call}\n"
            'elif [ "$RUN_CONTINUITY_DIAGNOSTIC" = "1" ]; then\n'
            f"\t{easycrypt_call}\n"
            "fi\n"
        )
        self.assertEqual(source.count(expected_dispatch), 1)
        all_tool_checks = [
            match.start() for match in re.finditer(re.escape(all_tools_call), source)
        ]
        easycrypt_checks = [
            match.start() for match in re.finditer(re.escape(easycrypt_call), source)
        ]
        self.assertEqual(len(all_tool_checks), 2)
        self.assertEqual(len(easycrypt_checks), 2)
        self.assertEqual(source.count("\tneed maude\n"), 1)
        formal_make_definition = (
            "formal_make() {\n"
            "\tMAKEFLAGS='' GNUMAKEFLAGS='' MAKEFILES='' \\\n"
            '\t\tcommand make "$@"\n'
            "}\n"
        )
        self.assertEqual(source.count(formal_make_definition), 1)
        self.assertEqual(source.count("\tformal_make "), 4)
        for command in (
            'RESULTS_MANIFEST="$ROOT/artifact/results.json"',
            "PROOF_TO_BYTE_SOURCE_SNAPSHOT_PASS",
            "formal_make -C formal/easycrypt EC=easycrypt check",
            "EASYCRYPT=easycrypt sh formal/easycrypt/negative-controls.sh",
            "formal_make -C formal/tamarin TAMARIN=tamarin-prover \\\n"
            "\t\tDERIVCHECK_TIMEOUT=60 prove",
            "formal_make -C formal/proverif PROVERIF=proverif prove",
            "FORMAL_PASSED=1",
            "PROOF_TO_BYTE_FORMAL_MACHINECHECK_PASS",
        ):
            with self.subTest(command=command):
                self.assertLess(source.index(expected_dispatch), source.index(command))
        self.assertLess(
            all_tool_checks[1],
            source.index("formal_make -C formal/easycrypt EC=easycrypt check"),
        )
        self.assertLess(
            easycrypt_checks[1],
            source.index(
                "formal_make -C formal/easycrypt/continuity EC=easycrypt check"
            ),
        )
        for bypass in (" ||", "; true", "continue"):
            with self.subTest(bypass=bypass):
                self.assertNotIn(all_tools_call + bypass, source)
                self.assertNotIn(easycrypt_call + bypass, source)
        for ambient_override in (
            "make -C formal/easycrypt check",
            "make -C formal/tamarin prove",
            "make -C formal/proverif prove",
            "EC=$(command -v easycrypt)",
            "EASYCRYPT=$(command -v easycrypt)",
        ):
            with self.subTest(ambient_override=ambient_override):
                self.assertNotIn(ambient_override, source)

    def test_proof_to_byte_names_every_hqc_candidate_input(self) -> None:
        for key, relative in HQC_CANDIDATE_PROOF_INPUTS.items():
            with self.subTest(key=key):
                self.assert_named_proof_input(key, relative)

    def test_formal_make_environment_cannot_dry_run_or_override_tools(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qperiapt-formal-make-") as raw:
            temporary = pathlib.Path(raw)
            makefile = temporary / "Makefile"
            injected = temporary / "injected.mk"
            marker = temporary / "marker.txt"
            makefile.write_text(
                "check:\n"
                "\t@printf '%s\\n' '$(TOOL)' > '$(MARKER)'\n",
                encoding="utf-8",
            )
            injected.write_text("override TOOL := injected\n", encoding="utf-8")
            environment = os.environ.copy()
            environment.update(
                {
                    "MAKEFLAGS": "-n TOOL=flags",
                    "GNUMAKEFLAGS": "-n",
                    "MAKEFILES": os.fspath(injected),
                    "TOOL": "ambient",
                }
            )
            completed = subprocess.run(
                [
                    "/bin/sh",
                    "-c",
                    "MAKEFLAGS='' GNUMAKEFLAGS='' MAKEFILES='' "
                    'command make -f "$1" TOOL=trusted "MARKER=$2" check',
                    "formal-make-environment-test",
                    os.fspath(makefile),
                    os.fspath(marker),
                ],
                cwd=ROOT,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout, "")
            self.assertEqual(completed.stderr, "")
            self.assertEqual(marker.read_bytes(), b"trusted\n")

    def test_proof_to_byte_names_every_apple_distribution_input(self) -> None:
        for key, relative in APPLE_DISTRIBUTION_PROOF_INPUTS.items():
            with self.subTest(key=key):
                self.assert_named_proof_input(key, relative)

    def test_proof_to_byte_names_every_apple_device_input(self) -> None:
        for key, relative in APPLE_DEVICE_PROOF_INPUTS.items():
            with self.subTest(key=key):
                self.assert_named_proof_input(key, relative)

    def test_proof_to_byte_names_every_bounded_process_input(self) -> None:
        for key, relative in BOUNDED_PROCESS_PROOF_INPUTS.items():
            with self.subTest(key=key):
                self.assert_named_proof_input(key, relative)

    def test_proof_to_byte_names_every_abi2_platform_release_input(self) -> None:
        for key, relative in ABI2_PLATFORM_RELEASE_PROOF_INPUTS.items():
            with self.subTest(key=key):
                self.assert_named_proof_input(key, relative)

    def test_proof_to_byte_names_every_crates_io_publication_input(self) -> None:
        for key, relative in CRATES_IO_PUBLICATION_PROOF_INPUTS.items():
            with self.subTest(key=key):
                self.assert_named_proof_input(key, relative)

    def test_publish_contract_fences_research_and_mlkem_provider(self) -> None:
        source = RUST_PACKAGE_CONTRACT_SCRIPT.read_text(encoding="utf-8")
        for token in (
            "pqcrypto-hqc",
            "pqcrypto-internals",
            "pqcrypto-traits",
            "hqc-kem",
            "src/hqc.rs",
        ):
            with self.subTest(token=token):
                self.assertIn(token, source)
        self.assertIn("RUST_BACKENDS_NORMALIZED_MANIFEST_PASS", source)
        self.assertIn("RUST_BACKENDS_INSPECTION_PACKAGE_PASS", source)

        self.assertIn("cargo +1.96.1 package $ALLOW_DIRTY_ARG --locked", source)
        self.assertIn("--registry crates-io", source)
        self.assertEqual(source.count("run_cargo_captured"), 8)
        self.assertIn("validate_cargo_output", source)
        self.assertIn("validate_cargo_package_completion", source)
        self.assertIn("RUST_PACKAGE_VERIFICATION_PASS", source)
        self.assertIn("RUST_PACKAGE_CONTRACT_PASS", source)
        self.assertIn("create_owned_package_directory", source)
        self.assertIn("remove_owned_package_directory", source)
        self.assertIn("RUST_OWNED_PACKAGE_DIRECTORY_CLEANUP_PASS", source)
        self.assertNotIn("rm -rf", source)
        self.assertNotIn("--no-verify", source)
        self.assertNotIn("cargo publish", source)
        self.assertNotIn("--dry-run", source)
        self.assertNotIn("--quiet", source)
        self.assertNotIn("aborting upload due to dry run", source)
        self.assertIn(
            "create_owned_package_target qperiapt-package-inspection.", source
        )
        self.assertIn(
            "publishable q-periapt-backends exposes retired hqc feature", source
        )
        self.assertIn(
            'python3 "$ROOT/crates/q-periapt-mlkem-native-sys/scripts/verify-vendor.py"',
            source,
        )
        self.assertIn("mlkem_reference_dependencies", source)
        self.assertIn("=0.2.3", source)
        self.assertIn("RUST_MLKEM_PROVIDER_FENCE_PASS", source)
        self.assertIn("resolved_mlkem_providers", source)
        self.assertIn('"src/build_support.rs"', source)
        self.assertIn("from rust_publish_contract import", source)
        self.assertIn("validate_mlkem_native_build_surface", source)
        self.assert_named_proof_input(
            "rust_publish_contract_script_sha256",
            "artifact/rust-publish-contract.sh",
        )
        self.assert_named_proof_input(
            "rust_publish_contract_sha256",
            "artifact/rust_publish_contract.py",
        )
        self.assert_named_proof_input(
            "rust_publish_contract_tests_sha256",
            "artifact/test_rust_publish_contract.py",
        )

    def test_rust_package_claims_preserve_the_no_upload_boundary(self) -> None:
        claim_paths = (
            ROOT / "README.md",
            ROOT / "ARTIFACT.md",
            ROOT / "docs" / "EMBEDDING_READINESS.md",
            ROOT / "docs" / "ROADMAP.md",
            ROOT / "docs" / "ARCHITECTURE.md",
            ROOT / "docs" / "PAPER_DRAFT.md",
            ROOT / "paper" / "q-periapt.tex",
            ROOT / "artifact" / "claim-ledger.json",
        )
        required_boundaries = (
            "upload-API acceptance",
            "crate-name ownership",
            "publishing credentials",
            "server-side policy acceptance",
            "registry receipt",
        )
        forbidden_claims = (
            "**Status: release-ready",
            "release-ready research-alpha source line intended",
            "release-ready research-alpha source/crate",
            "release-ready `0.1.0` research-alpha source/crate",
            "release-ready as a research-alpha source/Rust-crate",
            "release-ready research\n   alpha",
            "release-ready **ABI 2 research-alpha source/crate contract**",
            "release-ready ABI 2 research alpha, not production",
        )
        for path in claim_paths:
            source = path.read_text(encoding="utf-8")
            normalized = " ".join(re.sub(r"(?m)^> ?", "", source).split())
            with self.subTest(path=path.relative_to(ROOT)):
                self.assertIn("pre-publication package-ready", normalized)
                for boundary in required_boundaries:
                    self.assertIn(boundary, normalized)
                for claim in forbidden_claims:
                    self.assertNotIn(" ".join(claim.split()), normalized)

    def test_continuity_diagnostic_is_scoped_fail_closed_and_non_release(self) -> None:
        source = PROOF_SCRIPT.read_text(encoding="utf-8")
        cargo = "cargo test -p q-periapt-continuity-model --locked"
        python_tests = "sh artifact/python-run.sh -m unittest -v"
        vectors = "sh artifact/python-run.sh artifact/continuity_context.py verify"
        prekey_vectors = "sh artifact/python-run.sh artifact/prekey_selection.py verify"
        formal = "formal_make -C formal/easycrypt/continuity EC=easycrypt check"
        marker = (
            "PROOF_TO_BYTE_CONTINUITY_MODEL_DIAGNOSTIC_PASS "
            "boundary=non_normative_not_release"
        )
        self.assertIn("QPERIAPT_RUN_CONTINUITY_DIAGNOSTIC", source)
        self.assertLess(source.index(cargo), source.index(python_tests))
        self.assertLess(source.index(python_tests), source.index(vectors))
        self.assertLess(source.index(vectors), source.index(prekey_vectors))
        self.assertLess(source.index(prekey_vectors), source.index(formal))
        self.assertLess(source.index(formal), source.index(marker))
        self.assertIn("artifact/test_prekey_selection.py", source)
        for command in (cargo, python_tests, vectors, prekey_vectors, formal):
            self.assertNotIn(command + " ||", source)
            self.assertNotIn(command + "; true", source)
        release_marker = FINALIZER_SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn("CONTINUITY", release_marker)
        self.assertNotIn("continuity", release_marker)
        self.assertNotIn("CONTINUITY_DIAGNOSTIC_PASSED", source)

    def test_publish_and_device_entrypoints_harden_before_first_python(self) -> None:
        source_line = '. "$ROOT/artifact/python-env.sh"'
        python_token = re.compile(r"(?<![A-Za-z0-9_])python3(?![A-Za-z0-9_])")
        entrypoints = []
        for path in sorted((ROOT / "artifact").glob("*.sh")):
            if path.name in {"python-env.sh", "python-run.sh"}:
                continue
            source = path.read_text(encoding="utf-8")
            if python_token.search(source):
                entrypoints.append(path)
        self.assertTrue(
            entrypoints, "no repository Python shell entrypoints discovered"
        )
        for path in entrypoints:
            relative = path.relative_to(ROOT).as_posix()
            with self.subTest(entrypoint=relative):
                if path.name == "swift-xcframework-remote-consumer.sh":
                    source = path.read_text(encoding="utf-8")
                    self.assertNotIn(source_line, source)
                    artifact_materialize = source.index(
                        "for relative in $ARTIFACT_INPUTS"
                    )
                    verifier_materialize = source.index(
                        "for relative in $VERIFIER_INPUTS"
                    )
                    self_check = source.index(
                        'cmp "$ROOT/artifact/swift-xcframework-remote-consumer.sh"'
                    )
                    snapshot_helper = source.index(
                        '. "$VERIFIER_SNAPSHOT/artifact/python-env.sh"'
                    )
                    snapshot_dispatch = source.index('python3 "$@"')
                    first_snapshot_call = source.index(
                        'snapshot_python - "$effective_url"'
                    )
                    self.assertLess(artifact_materialize, verifier_materialize)
                    self.assertLess(verifier_materialize, self_check)
                    self.assertLess(self_check, snapshot_helper)
                    self.assertLess(snapshot_helper, snapshot_dispatch)
                    self.assertLess(snapshot_dispatch, first_snapshot_call)
                    continue
                lines = path.read_text(encoding="utf-8").splitlines()
                executable_lines = [
                    (number, line)
                    for number, line in enumerate(lines, start=1)
                    if line.strip() and not line.lstrip().startswith("#")
                ]
                source_lines = [
                    number
                    for number, line in executable_lines
                    if line.strip() == source_line
                ]
                self.assertEqual(
                    len(source_lines),
                    1,
                    f"{relative} must source the hardened helper exactly once",
                )
                python_lines = [
                    number
                    for number, line in executable_lines
                    if python_token.search(line)
                ]
                self.assertTrue(
                    python_lines, f"{relative} has no Python invocation to protect"
                )
                self.assertLess(
                    source_lines[0],
                    python_lines[0],
                    f"{relative} invokes Python before sourcing the hardened helper",
                )

    def test_one_shot_runner_sources_helper_before_dispatch(self) -> None:
        source = (ROOT / "artifact" / "python-run.sh").read_text(encoding="utf-8")
        helper = source.index('. "$ROOT/artifact/python-env.sh"')
        dispatch = source.index('python3 "$@"')
        self.assertIn("set -eu", source)
        self.assertLess(helper, dispatch)

    def test_shell_has_no_post_verification_selected_proof_reopen(self) -> None:
        source = PROOF_SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn("manifest_selected_proof_binding", source)
        self.assertGreaterEqual(
            source.count('--results-manifest "$RESULTS_MANIFEST"'), 6
        )
        self.assertGreaterEqual(
            source.count(
                '--expected-results-manifest-sha256 "$RESULTS_MANIFEST_SHA256"'
            ),
            6,
        )
        finalizer = FINALIZER_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("PROOF_TO_BYTE_RESULTS_MANIFEST_STABLE_PASS", finalizer)

    def test_finalizer_is_a_named_proof_input(self) -> None:
        source = PROOF_SCRIPT.read_text(encoding="utf-8")
        self.assert_named_proof_input(
            "proof_to_byte_finalizer_sha256",
            "artifact/proof_to_byte_finalizer.py",
        )
        self.assertIn("from proof_to_byte_inputs import (", source)

    def test_finalizer_freezes_before_domains_and_rechecks_after_them(self) -> None:
        source = PROOF_SCRIPT.read_text(encoding="utf-8")
        preflight = source.index("# Normalize every active caller-controlled option")
        freeze = source.index("proof_to_byte_finalizer.py freeze")
        first_domain = source.index('test -f "$CAMERA_READY_TRANSCRIPT"')
        last_domain = source.index('test -f "$PERFORMANCE_PROOF"')
        finalize = source.index("proof_to_byte_finalizer.py finalize")
        self.assertLess(preflight, freeze)
        self.assertLess(freeze, first_domain)
        self.assertLess(last_domain, finalize)
        self.assertIn('--expected-git-commit "$EXPECTED_GIT_COMMIT"', source)
        self.assertIn('--expected-git-commit "$FROZEN_GIT_COMMIT"', source)
        self.assertIn('--expected-source-sha256 "$FROZEN_SOURCE_TREE_SHA256"', source)

    def test_xcode27_capture_does_not_self_promote_unselected_proof(self) -> None:
        source = XCODE27_GATE.read_text(encoding="utf-8")
        self.assertNotIn("artifact/proof-to-byte.sh", source)
        self.assertIn("APPLE_DEVICE_XCODE27_CAPTURE_PASS", source)
        self.assertIn("promotion=pending", source)

    def test_domain_verifiers_emit_manifest_bound_marker(self) -> None:
        apple = (ROOT / "artifact" / "apple_device_proof.py").read_text(
            encoding="utf-8"
        )
        performance = (ROOT / "artifact" / "performance_gate.py").read_text(
            encoding="utf-8"
        )
        android = (ROOT / "artifact" / "android_device_proof.py").read_text(
            encoding="utf-8"
        )
        marker = "PROOF_TO_BYTE_SELECTED_PROOF_MANIFEST_PASS"
        self.assertIn(marker, apple)
        self.assertIn(marker, performance)
        self.assertIn(marker, android)
        self.assertIn('binding="apple_device"', apple)
        self.assertIn('binding="apple_matrix"', apple)
        self.assertIn('binding="performance"', performance)
        self.assertIn("binding=args.results_binding", android)
        self.assertIn("choices=ANDROID_RUNTIME_BINDING_CHOICES", android)

    def test_release_policy_cannot_be_selected_by_evidence_or_environment(self) -> None:
        matrix_script = (ROOT / "artifact" / "apple-device-matrix.sh").read_text(
            encoding="utf-8"
        )
        apple = (ROOT / "artifact" / "apple_device_proof.py").read_text(
            encoding="utf-8"
        )
        performance = (ROOT / "artifact" / "performance_gate.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("QPERIAPT_REQUIRED_DEVICE_TYPES was removed", matrix_script)
        self.assertNotIn('add_argument("--required-device-types"', apple)
        self.assertNotIn('add_argument("--budget"', performance)
        self.assertIn(
            'PRODUCTION_BUDGET_RELATIVE = pathlib.PurePosixPath("artifact/performance-budgets.json")',
            performance,
        )

    def test_release_dirty_state_uses_hardened_git_provenance(self) -> None:
        finalizer = FINALIZER_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("from git_provenance import (", finalizer)
        self.assertIn("inspect_worktree", finalizer)
        self.assertNotIn("git status --porcelain", finalizer)
        for relative in (
            "artifact/apple-device-smoke.sh",
            "artifact/apple-device-matrix.sh",
            "artifact/android-device-smoke.sh",
        ):
            source = (ROOT / relative).read_text(encoding="utf-8")
            self.assertIn("from git_provenance import source_tree_dirty", source)
            self.assertNotIn("git status --porcelain", source)

    def test_release_entrypoint_does_not_execute_forged_timestamp_pyc(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            artifact = root / "artifact"
            artifact.mkdir()
            for name in (
                "proof-to-byte.sh",
                "proof_manifest.py",
                "evidence_io.py",
                "python-env.sh",
                "python_bootstrap.py",
            ):
                shutil.copy2(ROOT / "artifact" / name, artifact / name)
            (artifact / "results.json").write_text("{}\n", encoding="utf-8")

            trusted_source = artifact / "proof_manifest.py"
            source_stat = trusted_source.stat()
            sentinel = root / "malicious-pyc-executed"
            malicious_source = (
                "import hashlib\n"
                "import os\n"
                "import pathlib\n"
                "pathlib.Path(os.environ['QPERIAPT_TEST_PYC_SENTINEL']).write_text("
                "'executed', encoding='utf-8')\n"
                "class _File:\n"
                "    sha256 = '0' * 64\n"
                "class _Snapshot:\n"
                "    file = _File()\n"
                "def load_results_manifest_snapshot(*args, **kwargs):\n"
                "    return _Snapshot()\n"
            )
            malicious_code = compile(
                malicious_source,
                str(trusted_source),
                "exec",
            )
            # Compute the ordinary adjacent cache location explicitly.  This
            # test itself may be running through the hardened launcher, whose
            # private sys.pycache_prefix must not redirect the planted control.
            cache_path = (
                trusted_source.parent
                / "__pycache__"
                / f"{trusted_source.stem}.{sys.implementation.cache_tag}.pyc"
            )
            cache_path.parent.mkdir()
            cache_path.write_bytes(
                importlib._bootstrap_external._code_to_timestamp_pyc(
                    malicious_code,
                    int(source_stat.st_mtime),
                    source_stat.st_size,
                )
            )

            environment = os.environ.copy()
            environment["PYTHONPATH"] = str(artifact)
            environment["QPERIAPT_TEST_PYC_SENTINEL"] = str(sentinel)
            environment["GITHUB_SHA"] = TEST_COMMIT
            environment.pop("PYTHONPYCACHEPREFIX", None)
            control = subprocess.run(
                [sys.executable, "-c", "import proof_manifest"],
                cwd=root,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(control.returncode, 0, control.stderr)
            self.assertTrue(sentinel.is_file(), "forged pyc control did not execute")
            sentinel.unlink()

            environment["QPERIAPT_SKIP_SMOKE"] = "invalid"
            guarded = subprocess.run(
                ["sh", str(artifact / "proof-to-byte.sh")],
                cwd=root,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(guarded.returncode, 2, guarded.stderr)
            self.assertIn("QPERIAPT_SKIP_SMOKE must be 0 or 1", guarded.stderr)
            self.assertFalse(
                sentinel.exists(),
                "release entrypoint executed a forged ignored timestamp pyc",
            )

    def test_release_entrypoint_ignores_hostile_python_startup_environment(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            artifact = root / "artifact"
            artifact.mkdir()
            for name in (
                "proof-to-byte.sh",
                "proof_manifest.py",
                "evidence_io.py",
                "python-env.sh",
                "python_bootstrap.py",
            ):
                shutil.copy2(ROOT / "artifact" / name, artifact / name)
            (artifact / "results.json").write_text("{}\n", encoding="utf-8")

            user_base = root / "hostile-user-base"
            clean_python_environment = {
                name: value
                for name, value in os.environ.items()
                if not name.startswith("PYTHON")
            }
            clean_python_environment["PYTHONUSERBASE"] = str(user_base)
            site_query = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "import site; print(site.getusersitepackages())",
                ],
                cwd=root,
                env=clean_python_environment,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(site_query.returncode, 0, site_query.stderr)
            user_site = pathlib.Path(site_query.stdout.strip())
            self.assertTrue(user_site.is_absolute())
            self.assertTrue(user_site.is_relative_to(user_base))
            user_site.mkdir(parents=True)
            pth_sentinel = root / "hostile-pth-executed"
            (user_site / "hostile.pth").write_text(
                "import os, pathlib; pathlib.Path(os.environ["
                "'QPERIAPT_TEST_PTH_SENTINEL']).write_text('executed', encoding='utf-8')\n",
                encoding="utf-8",
            )

            python_path = root / "hostile-python-path"
            python_path.mkdir()
            path_sentinel = root / "hostile-pythonpath-executed"
            (python_path / "sitecustomize.py").write_text(
                "import os\n"
                "import pathlib\n"
                "pathlib.Path(os.environ['QPERIAPT_TEST_PATH_SENTINEL']).write_text("
                "'executed', encoding='utf-8')\n",
                encoding="utf-8",
            )
            bootstrap_sentinel = root / "hostile-bootstrap-executed"
            hostile_bootstrap = root / "hostile-bootstrap.py"
            hostile_bootstrap.write_text(
                "import os\n"
                "import pathlib\n"
                "pathlib.Path(os.environ['QPERIAPT_TEST_BOOTSTRAP_SENTINEL']).write_text("
                "'executed', encoding='utf-8')\n",
                encoding="utf-8",
            )

            control_environment = clean_python_environment.copy()
            control_environment["PYTHONUSERBASE"] = str(user_base)
            control_environment["QPERIAPT_TEST_PTH_SENTINEL"] = str(pth_sentinel)
            pth_control = subprocess.run(
                [sys.executable, "-c", "pass"],
                cwd=root,
                env=control_environment,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(pth_control.returncode, 0, pth_control.stderr)
            self.assertTrue(
                pth_sentinel.is_file(), "hostile .pth control did not execute"
            )
            pth_sentinel.unlink()

            control_environment = clean_python_environment.copy()
            control_environment.pop("PYTHONUSERBASE", None)
            control_environment["PYTHONPATH"] = str(python_path)
            control_environment["QPERIAPT_TEST_PATH_SENTINEL"] = str(path_sentinel)
            path_control = subprocess.run(
                [sys.executable, "-c", "pass"],
                cwd=root,
                env=control_environment,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(path_control.returncode, 0, path_control.stderr)
            self.assertTrue(
                path_sentinel.is_file(), "hostile PYTHONPATH control did not execute"
            )
            path_sentinel.unlink()

            hostile_python_home = root / "nonexistent-python-home"
            control_environment = clean_python_environment.copy()
            control_environment["PYTHONHOME"] = str(hostile_python_home)
            home_control = subprocess.run(
                [sys.executable, "-c", "pass"],
                cwd=root,
                env=control_environment,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(
                home_control.returncode,
                0,
                "hostile PYTHONHOME control unexpectedly had no effect",
            )

            guarded_environment = clean_python_environment.copy()
            guarded_environment.update(
                {
                    "PYTHONUSERBASE": str(user_base),
                    "PYTHONPATH": str(python_path),
                    "PYTHONHOME": str(hostile_python_home),
                    "QPERIAPT_TEST_PTH_SENTINEL": str(pth_sentinel),
                    "QPERIAPT_TEST_PATH_SENTINEL": str(path_sentinel),
                    "QPERIAPT_TEST_BOOTSTRAP_SENTINEL": str(bootstrap_sentinel),
                    "QPERIAPT_PYTHON_ENV_INITIALIZED": "1",
                    "QPERIAPT_PYTHON_BOOTSTRAP": str(hostile_bootstrap),
                    "QPERIAPT_SKIP_SMOKE": "invalid",
                    "GITHUB_SHA": TEST_COMMIT,
                }
            )
            guarded = subprocess.run(
                ["sh", str(artifact / "proof-to-byte.sh")],
                cwd=root,
                env=guarded_environment,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(guarded.returncode, 2, guarded.stderr)
            self.assertIn("QPERIAPT_SKIP_SMOKE must be 0 or 1", guarded.stderr)
            self.assertFalse(
                pth_sentinel.exists(), "release entrypoint executed hostile .pth"
            )
            self.assertFalse(
                path_sentinel.exists(), "release entrypoint executed hostile PYTHONPATH"
            )
            self.assertFalse(
                bootstrap_sentinel.exists(),
                "release entrypoint trusted a caller-selected Python bootstrap",
            )


class ProofToByteReleaseMarkerTests(unittest.TestCase):
    def test_embedding_android_final_mode_is_read_only_and_exits_before_producers(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            artifact = root / "artifact"
            artifact.mkdir()
            for name in (
                "embedding-readiness.sh",
                "python-env.sh",
                "python_bootstrap.py",
            ):
                shutil.copy2(ROOT / "artifact" / name, artifact / name)
            event_log = root / "bound-events.txt"
            (artifact / "proof-to-byte.sh").write_text(
                """#!/bin/sh
set -eu
printf 'proof-to-byte\\n' >> "$BOUND_EVENT_LOG"
test "${QPERIAPT_SKIP_SMOKE:-}" = 1
test "${QPERIAPT_REQUIRE_ANDROID_AAR:-}" = 1
test "${QPERIAPT_REQUIRE_ANDROID_RUNTIME:-}" = 1
test "${QPERIAPT_REQUIRE_ANDROID_PHYSICAL_RUNTIME:-}" = "${EXPECTED_PHYSICAL:-1}"
test "${QPERIAPT_REQUIRE_LOCAL_RELEASE_CONSUMER:-}" = "${EXPECTED_LOCAL_CONSUMER:-1}"
test -n "${QPERIAPT_ANDROID_DEVICE_PROOF:-}"
if [ "${EXPECTED_PHYSICAL:-1}" = 1 ]; then
    test -n "${QPERIAPT_ANDROID_PHYSICAL_DEVICE_PROOF:-}"
fi
exit "${BOUND_EXIT_CODE:-0}"
""",
                encoding="utf-8",
            )
            environment = {
                name: value
                for name, value in os.environ.items()
                if not name.startswith("QPERIAPT_")
            }
            environment.update(
                {
                    "BOUND_EVENT_LOG": str(event_log),
                    "QPERIAPT_PYTHON": str(pathlib.Path(sys.executable).resolve()),
                    "QPERIAPT_EMBED_REQUIRE_ANDROID_RUNTIME": "1",
                    "QPERIAPT_EMBED_REQUIRE_ANDROID_PHYSICAL_RUNTIME": "1",
                    "QPERIAPT_EMBED_REQUIRE_LOCAL_RELEASE_CONSUMER": "1",
                    "QPERIAPT_ANDROID_DEVICE_PROOF": "canonical-proof.json",
                    "QPERIAPT_ANDROID_PHYSICAL_DEVICE_PROOF": "physical-proof.json",
                }
            )

            completed = subprocess.run(
                ["/bin/sh", str(artifact / "embedding-readiness.sh")],
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(event_log.read_text(encoding="utf-8"), "proof-to-byte\n")
            self.assertIn(
                "EMBEDDING_ANDROID_BOUND_VERIFY_PASS canonical=1 physical=1 local_release_consumer=1",
                completed.stdout,
            )
            self.assertNotIn("EMBEDDING_READINESS_PASS", completed.stdout)
            self.assertFalse((root / "target").exists())

            event_log.unlink()
            canonical_environment = {
                **environment,
                "EXPECTED_PHYSICAL": "0",
                "EXPECTED_LOCAL_CONSUMER": "0",
                "QPERIAPT_EMBED_REQUIRE_ANDROID_PHYSICAL_RUNTIME": "0",
                "QPERIAPT_EMBED_REQUIRE_LOCAL_RELEASE_CONSUMER": "0",
            }
            canonical_environment.pop(
                "QPERIAPT_ANDROID_PHYSICAL_DEVICE_PROOF",
                None,
            )
            canonical = subprocess.run(
                ["/bin/sh", str(artifact / "embedding-readiness.sh")],
                cwd=root,
                env=canonical_environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(canonical.returncode, 0, canonical.stderr)
            self.assertIn(
                "EMBEDDING_ANDROID_BOUND_VERIFY_PASS canonical=1 physical=0 local_release_consumer=0",
                canonical.stdout,
            )
            self.assertEqual(event_log.read_text(encoding="utf-8"), "proof-to-byte\n")

            failed_environment = {**environment, "BOUND_EXIT_CODE": "7"}
            failed = subprocess.run(
                ["/bin/sh", str(artifact / "embedding-readiness.sh")],
                cwd=root,
                env=failed_environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(failed.returncode, 7, failed.stderr)
            self.assertNotIn(
                "EMBEDDING_ANDROID_BOUND_VERIFY_PASS",
                failed.stdout,
            )
            self.assertFalse((root / "target").exists())

    def test_embedding_gate_scopes_verified_wasm_compiler_to_wasm_child(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            artifact = root / "artifact"
            stub_bin = root / "bin"
            artifact.mkdir()
            stub_bin.mkdir()
            shutil.copy2(ROOT / "artifact/embedding-readiness.sh", artifact)
            shutil.copy2(ROOT / "artifact/python-env.sh", artifact)
            shutil.copy2(ROOT / "artifact/python_bootstrap.py", artifact)
            (artifact / "test_android_device_proof.py").write_text(
                """import unittest


class HarnessTest(unittest.TestCase):
    def test_harness(self) -> None:
        pass
""",
                encoding="utf-8",
            )

            def write_executable(name: str, source: str) -> pathlib.Path:
                path = stub_bin / name
                path.write_text(source, encoding="utf-8")
                path.chmod(0o755)
                return path

            generic_stub = "#!/bin/sh\nexit 0\n"
            for name in (
                "cargo",
                "cbindgen",
                "cmake",
                "cmp",
                "git",
                "gradle",
                "lipo",
                "node",
                "pkg-config",
                "rustup",
                "shasum",
                "uname",
                "xcodebuild",
                "zip",
            ):
                write_executable(name, generic_stub)

            compiler = write_executable(
                "clang",
                """#!/bin/sh
printf 'clang:%s\\n' "${1:-}" >> "$SCOPE_EVENT_LOG"
case "${1:-}" in
    --version) printf 'clang version 22.1.8\\n' ;;
    --print-targets)
        printf '    wasm32      - WebAssembly 32-bit\\n'
        if [ "${FAIL_TARGET_PROBE:-0}" = 1 ]; then
            exit 7
        fi
        ;;
    *) exit 2 ;;
esac
""",
            )
            write_executable(
                "java",
                """#!/bin/sh
if [ "${CC_wasm32_unknown_unknown+x}" = x ] || [ "${wasm_compiler_input+x}" = x ] || [ "${WASM_C_COMPILER+x}" = x ] || [ "${compiler+x}" = x ] || [ "${compiler_version+x}" = x ] || [ "${compiler_targets+x}" = x ] || [ "${java_version_output+x}" = x ]; then
    printf 'compiler selector or internal state leaked into Java preflight\\n' >&2
    exit 89
fi
printf 'openjdk version "22.0.2"\\n' >&2
if [ "${FAIL_JAVA_PROBE:-0}" = 1 ]; then
    exit 7
fi
""",
            )
            swift_marker = root / "swift-environment-checked"
            wasm_marker = root / "wasm-environment-checked"
            event_log = root / "scope-events.txt"
            write_executable(
                "swift",
                """#!/bin/sh
if [ "${CC_wasm32_unknown_unknown+x}" = x ]; then
    printf 'compiler override leaked into Swift binding tests\\n' >&2
    exit 90
fi
if [ "${wasm_compiler_input+x}" = x ] || [ "${WASM_C_COMPILER+x}" = x ] || [ "${compiler+x}" = x ] || [ "${compiler_version+x}" = x ] || [ "${compiler_targets+x}" = x ] || [ "${java_version_output+x}" = x ]; then
    printf 'internal compiler state leaked into Swift binding tests\\n' >&2
    exit 93
fi
printf 'swift-binding\\n' >> "$SCOPE_EVENT_LOG"
printf 'Executed 2 tests, with 0 failures\\n'
""",
            )
            write_executable(
                "wasm-pack",
                """#!/bin/sh
if [ "${CC_wasm32_unknown_unknown:-}" != "$EXPECTED_WASM_COMPILER" ]; then
    printf 'verified compiler was not scoped to wasm-pack\\n' >&2
    exit 91
fi
if [ "${wasm_compiler_input+x}" = x ] || [ "${WASM_C_COMPILER+x}" = x ] || [ "${compiler+x}" = x ] || [ "${compiler_version+x}" = x ] || [ "${compiler_targets+x}" = x ] || [ "${java_version_output+x}" = x ]; then
    printf 'internal compiler state leaked into wasm-pack\\n' >&2
    exit 94
fi
printf 'wasm-pack\\n' >> "$SCOPE_EVENT_LOG"
: > "$WASM_SCOPE_MARKER"
""",
            )
            write_executable(
                "sh",
                """#!/bin/sh
if [ "${1:-}" = -c ]; then
    exit 0
fi
if [ "${1:-}" = artifact/swift-xcframework.sh ]; then
    if [ "${CC_wasm32_unknown_unknown+x}" = x ]; then
        printf 'compiler override leaked into Swift XCFramework packaging\\n' >&2
        exit 92
    fi
    if [ "${wasm_compiler_input+x}" = x ] || [ "${WASM_C_COMPILER+x}" = x ] || [ "${compiler+x}" = x ] || [ "${compiler_version+x}" = x ] || [ "${compiler_targets+x}" = x ] || [ "${java_version_output+x}" = x ]; then
        printf 'internal compiler state leaked into Swift XCFramework packaging\\n' >&2
        exit 95
    fi
    printf 'swift-xcframework\\n' >> "$SCOPE_EVENT_LOG"
    : > "$SWIFT_SCOPE_MARKER"
fi
exit 0
""",
            )

            environment = {
                name: value
                for name, value in os.environ.items()
                if not name.startswith("QPERIAPT_")
            }
            environment.update(
                {
                    "CC_wasm32_unknown_unknown": str(compiler),
                    "WASM_C_COMPILER": "attacker-exported-internal-value",
                    "compiler": "attacker-exported-internal-value",
                    "compiler_version": "attacker-exported-internal-value",
                    "compiler_targets": "attacker-exported-internal-value",
                    "EXPECTED_WASM_COMPILER": str(compiler),
                    "HOME": str(root),
                    "PATH": f"{stub_bin}:/usr/bin:/bin:/usr/sbin:/sbin",
                    "QPERIAPT_PYTHON": str(pathlib.Path(sys.executable).resolve()),
                    "SCOPE_EVENT_LOG": str(event_log),
                    "SWIFT_SCOPE_MARKER": str(swift_marker),
                    "WASM_SCOPE_MARKER": str(wasm_marker),
                    "wasm_compiler_input": "attacker-exported-internal-value",
                    "java_version_output": "attacker-exported-internal-value",
                }
            )

            for failure_flag, expected_error in (
                ("FAIL_JAVA_PROBE", "Java could not report its version"),
                (
                    "FAIL_TARGET_PROBE",
                    "CC_wasm32_unknown_unknown could not report supported targets",
                ),
            ):
                with self.subTest(failure_flag=failure_flag):
                    failed_environment = {**environment, failure_flag: "1"}
                    failed = subprocess.run(
                        ["/bin/sh", str(artifact / "embedding-readiness.sh")],
                        cwd=root,
                        env=failed_environment,
                        capture_output=True,
                        text=True,
                        check=False,
                        timeout=30,
                    )
                    self.assertEqual(failed.returncode, 2, failed.stderr)
                    self.assertIn(expected_error, failed.stderr)
                    self.assertNotIn("EMBEDDING_READINESS_PASS", failed.stdout)
                    self.assertFalse(swift_marker.exists())
                    self.assertFalse(wasm_marker.exists())

            event_log.unlink(missing_ok=True)
            completed = subprocess.run(
                ["/bin/sh", str(artifact / "embedding-readiness.sh")],
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("EMBEDDING_READINESS_PASS", completed.stdout)
            self.assertTrue(swift_marker.is_file())
            self.assertTrue(wasm_marker.is_file())
            self.assertEqual(
                event_log.read_text(encoding="utf-8").splitlines(),
                [
                    "clang:--version",
                    "clang:--print-targets",
                    "swift-binding",
                    "swift-xcframework",
                    "clang:--version",
                    "clang:--print-targets",
                    "wasm-pack",
                ],
            )

    def test_every_boolean_flag_fails_before_provenance_and_markers(self) -> None:
        flags = (
            "QPERIAPT_SKIP_SMOKE",
            "QPERIAPT_REQUIRE_FORMAL",
            "QPERIAPT_RUN_CONTINUITY_DIAGNOSTIC",
            "QPERIAPT_REQUIRE_APPLE_DEVICE",
            "QPERIAPT_REQUIRE_APPLE_DEVICE_MATRIX",
            "QPERIAPT_REQUIRE_ANDROID_AAR",
            "QPERIAPT_REQUIRE_ANDROID_RUNTIME",
            "QPERIAPT_REQUIRE_ANDROID_PHYSICAL_RUNTIME",
            "QPERIAPT_REQUIRE_LOCAL_RELEASE_CONSUMER",
            "QPERIAPT_REQUIRE_PERFORMANCE",
            "QPERIAPT_REQUIRE_CAMERA_READY",
            "QPERIAPT_REQUIRE_DEPENDENCY_AUDIT",
            "QPERIAPT_ALLOW_DIRTY_APPLE_DEVICE_PROOF",
            "QPERIAPT_ALLOW_DIRTY_ANDROID_RUNTIME_PROOF",
            "QPERIAPT_ALLOW_DIRTY_PERFORMANCE_PROOF",
        )
        for flag in flags:
            with self.subTest(flag=flag):
                environment = {
                    name: value
                    for name, value in os.environ.items()
                    if not name.startswith("QPERIAPT_")
                }
                environment.update(
                    {
                        flag: "yes",
                        "QPERIAPT_EXPECTED_GIT_COMMIT": repository_head(),
                        "GITHUB_SHA": TEST_COMMIT,
                    }
                )
                result = subprocess.run(
                    ["sh", str(PROOF_SCRIPT)],
                    cwd=ROOT,
                    text=True,
                    capture_output=True,
                    check=False,
                    env=environment,
                )
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn(f"{flag} must be 0 or 1", result.stderr)
                self.assertEqual(result.stdout, "")

    def test_active_configuration_preflight_fails_before_proof_markers(self) -> None:
        outside = ROOT / "artifact" / "results.json"
        cases = (
            (
                "apple modes are mutually exclusive",
                {
                    "QPERIAPT_REQUIRE_APPLE_DEVICE": "1",
                    "QPERIAPT_REQUIRE_APPLE_DEVICE_MATRIX": "1",
                },
                "are mutually exclusive",
            ),
            (
                "camera bundle is required",
                {"QPERIAPT_REQUIRE_CAMERA_READY": "1"},
                "QPERIAPT_CAMERA_READY_BUNDLE must explicitly name",
            ),
            (
                "camera max age is numeric",
                {
                    "QPERIAPT_REQUIRE_CAMERA_READY": "1",
                    "QPERIAPT_CAMERA_READY_BUNDLE": str(ROOT / "target" / "bundle"),
                    "QPERIAPT_CAMERA_READY_MAX_AGE_SECONDS": "tomorrow",
                },
                "QPERIAPT_CAMERA_READY_MAX_AGE_SECONDS must be an ASCII base-10 integer",
            ),
            (
                "camera freshness is fixed",
                {
                    "QPERIAPT_REQUIRE_CAMERA_READY": "1",
                    "QPERIAPT_CAMERA_READY_BUNDLE": str(ROOT / "target" / "bundle"),
                    "QPERIAPT_CAMERA_READY_MAX_AGE_SECONDS": "2",
                },
                "fixes camera-ready freshness to 86400 seconds",
            ),
            (
                "apple result directory is contained",
                {
                    "QPERIAPT_REQUIRE_APPLE_DEVICE": "1",
                    "QPERIAPT_DEVICE_RESULT_DIR": str(ROOT / "target"),
                },
                "QPERIAPT_DEVICE_RESULT_DIR must be under",
            ),
            (
                "apple prefix is canonical",
                {
                    "QPERIAPT_REQUIRE_APPLE_DEVICE": "1",
                    "QPERIAPT_DEVICE_ARTIFACT_PREFIX": "../ipad",
                },
                "invalid QPERIAPT_DEVICE_ARTIFACT_PREFIX",
            ),
            (
                "apple prefix cannot be explicitly empty",
                {
                    "QPERIAPT_REQUIRE_APPLE_DEVICE": "1",
                    "QPERIAPT_DEVICE_ARTIFACT_PREFIX": "",
                },
                "invalid QPERIAPT_DEVICE_ARTIFACT_PREFIX",
            ),
            (
                "apple device type is recognized",
                {
                    "QPERIAPT_REQUIRE_APPLE_DEVICE": "1",
                    "QPERIAPT_EXPECT_DEVICE_TYPE": "Mac",
                },
                "invalid QPERIAPT_EXPECT_DEVICE_TYPE",
            ),
            (
                "apple max age is bounded",
                {
                    "QPERIAPT_REQUIRE_APPLE_DEVICE": "1",
                    "QPERIAPT_DEVICE_PROOF_MAX_AGE_SECONDS": "0",
                },
                "QPERIAPT_DEVICE_PROOF_MAX_AGE_SECONDS must be an ASCII base-10 integer",
            ),
            (
                "apple release freshness is fixed",
                {
                    "QPERIAPT_REQUIRE_APPLE_DEVICE": "1",
                    "QPERIAPT_DEVICE_PROOF_MAX_AGE_SECONDS": "2",
                },
                "fixes Apple proof freshness to 86400 seconds",
            ),
            (
                "matrix proof is contained",
                {
                    "QPERIAPT_REQUIRE_APPLE_DEVICE_MATRIX": "1",
                    "QPERIAPT_DEVICE_MATRIX_PROOF": str(outside),
                },
                "QPERIAPT_DEVICE_MATRIX_PROOF must be under",
            ),
            (
                "android proof is contained",
                {
                    "QPERIAPT_REQUIRE_ANDROID_RUNTIME": "1",
                    "QPERIAPT_ANDROID_DEVICE_PROOF": str(outside),
                },
                "QPERIAPT_ANDROID_DEVICE_PROOF must be under",
            ),
            (
                "physical android proof is explicitly required",
                {"QPERIAPT_REQUIRE_ANDROID_PHYSICAL_RUNTIME": "1"},
                "QPERIAPT_ANDROID_PHYSICAL_DEVICE_PROOF is required",
            ),
            (
                "physical android proof is contained",
                {
                    "QPERIAPT_REQUIRE_ANDROID_PHYSICAL_RUNTIME": "1",
                    "QPERIAPT_ANDROID_PHYSICAL_DEVICE_PROOF": str(outside),
                },
                "QPERIAPT_ANDROID_PHYSICAL_DEVICE_PROOF must be under",
            ),
            (
                "physical android freshness is fixed",
                {
                    "QPERIAPT_REQUIRE_ANDROID_PHYSICAL_RUNTIME": "1",
                    "QPERIAPT_ANDROID_PHYSICAL_DEVICE_PROOF": str(
                        ROOT / "target" / "android-physical" / "proof.json"
                    ),
                    "QPERIAPT_ANDROID_PHYSICAL_PROOF_MAX_AGE_SECONDS": "2",
                },
                "fixes proof freshness to 86400 seconds",
            ),
            (
                "physical android freshness is numeric",
                {
                    "QPERIAPT_REQUIRE_ANDROID_PHYSICAL_RUNTIME": "1",
                    "QPERIAPT_ANDROID_PHYSICAL_DEVICE_PROOF": str(
                        ROOT / "target" / "android-physical" / "proof.json"
                    ),
                    "QPERIAPT_ANDROID_PHYSICAL_PROOF_MAX_AGE_SECONDS": "tomorrow",
                },
                "QPERIAPT_ANDROID_PHYSICAL_PROOF_MAX_AGE_SECONDS must be an ASCII base-10 integer",
            ),
            (
                "android device kind is canonical emulator",
                {
                    "QPERIAPT_REQUIRE_ANDROID_RUNTIME": "1",
                    "QPERIAPT_ANDROID_DEVICE_PROOF": str(
                        ROOT / "target" / "android" / "proof.json"
                    ),
                    "QPERIAPT_ANDROID_EXPECT_DEVICE_KIND": "tablet",
                },
                "requires device kind emulator",
            ),
            (
                "android physical proof cannot replace the canonical emulator",
                {
                    "QPERIAPT_REQUIRE_ANDROID_RUNTIME": "1",
                    "QPERIAPT_ANDROID_DEVICE_PROOF": str(
                        ROOT / "target" / "android" / "proof.json"
                    ),
                    "QPERIAPT_ANDROID_EXPECT_DEVICE_KIND": "physical",
                },
                "requires device kind emulator",
            ),
            (
                "android device kind cannot be explicitly empty",
                {
                    "QPERIAPT_REQUIRE_ANDROID_RUNTIME": "1",
                    "QPERIAPT_ANDROID_DEVICE_PROOF": str(
                        ROOT / "target" / "android" / "proof.json"
                    ),
                    "QPERIAPT_ANDROID_EXPECT_DEVICE_KIND": "",
                },
                "requires device kind emulator",
            ),
            (
                "android device ABI is canonical arm64",
                {
                    "QPERIAPT_REQUIRE_ANDROID_RUNTIME": "1",
                    "QPERIAPT_ANDROID_DEVICE_PROOF": str(
                        ROOT / "target" / "android" / "proof.json"
                    ),
                    "QPERIAPT_ANDROID_EXPECT_DEVICE_ABI": "x86_64",
                },
                "requires device ABI arm64-v8a",
            ),
            (
                "android device ABI cannot be explicitly empty",
                {
                    "QPERIAPT_REQUIRE_ANDROID_RUNTIME": "1",
                    "QPERIAPT_ANDROID_DEVICE_PROOF": str(
                        ROOT / "target" / "android" / "proof.json"
                    ),
                    "QPERIAPT_ANDROID_EXPECT_DEVICE_ABI": "",
                },
                "requires device ABI arm64-v8a",
            ),
            (
                "dirty Android proof override is forbidden",
                {"QPERIAPT_ALLOW_DIRTY_ANDROID_RUNTIME_PROOF": "1"},
                "does not allow dirty proofs",
            ),
            (
                "local release consumer requires canonical Android runtime",
                {"QPERIAPT_REQUIRE_LOCAL_RELEASE_CONSUMER": "1"},
                "requires QPERIAPT_REQUIRE_ANDROID_RUNTIME=1",
            ),
            (
                "canonical android freshness is fixed",
                {
                    "QPERIAPT_REQUIRE_ANDROID_RUNTIME": "1",
                    "QPERIAPT_ANDROID_DEVICE_PROOF": str(
                        ROOT / "target" / "android" / "proof.json"
                    ),
                    "QPERIAPT_ANDROID_PROOF_MAX_AGE_SECONDS": "2",
                },
                "fixes proof freshness to 86400 seconds",
            ),
            (
                "performance proof is contained",
                {
                    "QPERIAPT_REQUIRE_PERFORMANCE": "1",
                    "QPERIAPT_PERFORMANCE_PROOF": str(outside),
                },
                "QPERIAPT_PERFORMANCE_PROOF must be under",
            ),
            (
                "performance max age is numeric",
                {
                    "QPERIAPT_REQUIRE_PERFORMANCE": "1",
                    "QPERIAPT_PERFORMANCE_PROOF_MAX_AGE_SECONDS": "1.5",
                },
                "QPERIAPT_PERFORMANCE_PROOF_MAX_AGE_SECONDS must be an ASCII base-10 integer",
            ),
            (
                "performance release freshness is fixed",
                {
                    "QPERIAPT_REQUIRE_PERFORMANCE": "1",
                    "QPERIAPT_PERFORMANCE_PROOF_MAX_AGE_SECONDS": "2",
                },
                "fixes performance proof freshness to 86400 seconds",
            ),
            (
                "later active gate fails before any gate starts",
                {
                    "QPERIAPT_REQUIRE_APPLE_DEVICE": "1",
                    "QPERIAPT_REQUIRE_PERFORMANCE": "1",
                    "QPERIAPT_PERFORMANCE_PROOF_MAX_AGE_SECONDS": "2",
                },
                "fixes performance proof freshness to 86400 seconds",
            ),
            (
                "freshness rejects non-ASCII digits",
                {
                    "QPERIAPT_REQUIRE_PERFORMANCE": "1",
                    "QPERIAPT_PERFORMANCE_PROOF_MAX_AGE_SECONDS": "１２",
                },
                "QPERIAPT_PERFORMANCE_PROOF_MAX_AGE_SECONDS must be an ASCII base-10 integer",
            ),
            (
                "freshness error is bounded",
                {
                    "QPERIAPT_REQUIRE_PERFORMANCE": "1",
                    "QPERIAPT_PERFORMANCE_PROOF_MAX_AGE_SECONDS": "9" * 10_000,
                },
                "QPERIAPT_PERFORMANCE_PROOF_MAX_AGE_SECONDS must be an ASCII base-10 integer",
            ),
        )
        for label, overrides, expected_error in cases:
            with self.subTest(label=label):
                environment = {
                    name: value
                    for name, value in os.environ.items()
                    if not name.startswith("QPERIAPT_")
                }
                environment.update(
                    {
                        "QPERIAPT_SKIP_SMOKE": "1",
                        "QPERIAPT_EXPECTED_GIT_COMMIT": repository_head(),
                        "GITHUB_SHA": TEST_COMMIT,
                        **overrides,
                    }
                )
                result = subprocess.run(
                    ["sh", str(PROOF_SCRIPT)],
                    cwd=ROOT,
                    text=True,
                    capture_output=True,
                    check=False,
                    env=environment,
                )
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn(expected_error, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertNotIn("Traceback", result.stderr)
                self.assertLess(len(result.stderr), 1024)

        with _temporary_release_test_directories(
            (ROOT / "artifact" / "device-runs", ROOT / "target")
        ) as (device_temporary, target_temporary):
            device_loop = device_temporary / "loop"
            performance_loop = target_temporary / "loop"
            device_loop.symlink_to(device_loop)
            performance_loop.symlink_to(performance_loop)
            loop_cases = (
                (
                    {
                        "QPERIAPT_REQUIRE_APPLE_DEVICE": "1",
                        "QPERIAPT_DEVICE_RESULT_DIR": str(device_loop),
                    },
                    "QPERIAPT_DEVICE_RESULT_DIR",
                ),
                (
                    {
                        "QPERIAPT_REQUIRE_PERFORMANCE": "1",
                        "QPERIAPT_PERFORMANCE_PROOF": str(performance_loop),
                    },
                    "QPERIAPT_PERFORMANCE_PROOF",
                ),
            )
            for overrides, expected_error in loop_cases:
                with self.subTest(symlink_loop=expected_error):
                    environment = {
                        name: value
                        for name, value in os.environ.items()
                        if not name.startswith("QPERIAPT_")
                    }
                    environment.update(
                        {
                            "QPERIAPT_SKIP_SMOKE": "1",
                            "QPERIAPT_EXPECTED_GIT_COMMIT": repository_head(),
                            "GITHUB_SHA": TEST_COMMIT,
                            **overrides,
                        }
                    )
                    result = subprocess.run(
                        ["sh", str(PROOF_SCRIPT)],
                        cwd=ROOT,
                        text=True,
                        capture_output=True,
                        check=False,
                        env=environment,
                    )
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn(expected_error, result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertNotIn("Traceback", result.stderr)

    def test_release_test_directories_have_safe_owned_lifecycles(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)

            fresh = (root / "fresh-device", root / "fresh-target")
            with _temporary_release_test_directories(fresh) as children:
                self.assertTrue(all(child.is_dir() for child in children))
            self.assertTrue(all(not os.path.lexists(parent) for parent in fresh))

            preexisting = (root / "existing-device", root / "existing-target")
            sentinels = []
            for parent in preexisting:
                parent.mkdir()
                sentinel = parent / "sentinel"
                sentinel.write_text("owned by caller\n", encoding="utf-8")
                sentinels.append(sentinel)
            with _temporary_release_test_directories(preexisting):
                pass
            self.assertTrue(all(parent.is_dir() for parent in preexisting))
            self.assertTrue(all(sentinel.is_file() for sentinel in sentinels))

            unsafe_target = root / "unsafe-target"
            unsafe_target.mkdir()
            unsafe_symlink = root / "unsafe-symlink"
            unsafe_symlink.symlink_to(unsafe_target, target_is_directory=True)
            with self.assertRaisesRegex(
                AssertionError, "release test path must be a real directory"
            ):
                with _temporary_release_test_directories((unsafe_symlink,)):
                    pass
            self.assertEqual(list(unsafe_target.iterdir()), [])

            unsafe_file = root / "unsafe-file"
            unsafe_file.write_text("not a directory\n", encoding="utf-8")
            with self.assertRaisesRegex(
                AssertionError, "release test path must be a real directory"
            ):
                with _temporary_release_test_directories((unsafe_file,)):
                    pass
            self.assertEqual(
                unsafe_file.read_text(encoding="utf-8"), "not a directory\n"
            )

            exceptional = (root / "exception-device", root / "exception-target")
            with self.assertRaisesRegex(RuntimeError, "synthetic fixture failure"):
                with _temporary_release_test_directories(exceptional):
                    raise RuntimeError("synthetic fixture failure")
            self.assertTrue(all(not os.path.lexists(parent) for parent in exceptional))

            partial = (root / "partial-device", root / "partial-unsafe-target")
            partial[1].write_text("owned by caller\n", encoding="utf-8")
            with self.assertRaisesRegex(
                AssertionError, "release test path must be a real directory"
            ):
                with _temporary_release_test_directories(partial):
                    pass
            self.assertFalse(os.path.lexists(partial[0]))
            self.assertEqual(
                partial[1].read_text(encoding="utf-8"), "owned by caller\n"
            )

            external_tree_target = root / "external-tree-target"
            external_tree_target.mkdir()
            external_tree_sentinel = external_tree_target / "sentinel"
            external_tree_sentinel.write_text("external data\n", encoding="utf-8")
            tree_parent = root / "tree-parent"
            with _temporary_release_test_directories((tree_parent,)) as (child,):
                nested = child / "nested"
                nested.mkdir()
                (nested / "fixture-data").write_text("fixture data\n", encoding="utf-8")
                (child / "external-link").symlink_to(
                    external_tree_target, target_is_directory=True
                )
            self.assertFalse(os.path.lexists(tree_parent))
            self.assertEqual(
                external_tree_sentinel.read_text(encoding="utf-8"),
                "external data\n",
            )

    def test_release_test_directory_cleanup_preserves_data_and_errors(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)

            contaminated = (root / "contaminated-device", root / "contaminated-target")
            foreign_file = contaminated[1] / "foreign-file"
            with self.assertRaisesRegex(
                AssertionError, "test-owned release parent is not empty after cleanup"
            ):
                with _temporary_release_test_directories(contaminated):
                    foreign_file.write_text("external data\n", encoding="utf-8")
            self.assertFalse(os.path.lexists(contaminated[0]))
            self.assertEqual(
                foreign_file.read_text(encoding="utf-8"), "external data\n"
            )
            foreign_file.unlink()
            contaminated[1].rmdir()

            combined = (root / "combined-device", root / "combined-target")
            combined_foreign_file = combined[1] / "foreign-file"
            with self.assertRaises(ExceptionGroup) as raised:
                with _temporary_release_test_directories(combined):
                    combined_foreign_file.write_text(
                        "external data\n", encoding="utf-8"
                    )
                    raise RuntimeError("synthetic fixture body failure")
            self.assertEqual(
                raised.exception.message,
                "release test fixture operation and cleanup both failed",
            )
            self.assertEqual(len(raised.exception.exceptions), 2)
            body_error, cleanup_error = raised.exception.exceptions
            self.assertIs(type(body_error), RuntimeError)
            self.assertEqual(str(body_error), "synthetic fixture body failure")
            self.assertIs(type(cleanup_error), AssertionError)
            self.assertEqual(
                str(cleanup_error),
                f"test-owned release parent is not empty after cleanup: {combined[1]}",
            )
            self.assertFalse(os.path.lexists(combined[0]))
            self.assertEqual(
                combined_foreign_file.read_text(encoding="utf-8"), "external data\n"
            )
            combined_foreign_file.unlink()
            combined[1].rmdir()

            multiply_contaminated = (
                root / "multiply-contaminated-device",
                root / "multiply-contaminated-target",
            )
            multiply_foreign_files = tuple(
                parent / "foreign-file" for parent in multiply_contaminated
            )
            with self.assertRaises(ExceptionGroup) as multiple_cleanup:
                with _temporary_release_test_directories(multiply_contaminated):
                    for foreign_file_path in multiply_foreign_files:
                        foreign_file_path.write_text(
                            "external data\n", encoding="utf-8"
                        )
            self.assertEqual(
                multiple_cleanup.exception.message,
                "multiple release test fixture cleanups failed",
            )
            self.assertEqual(len(multiple_cleanup.exception.exceptions), 2)
            for error, parent in zip(
                multiple_cleanup.exception.exceptions,
                reversed(multiply_contaminated),
                strict=True,
            ):
                self.assertIs(type(error), AssertionError)
                self.assertEqual(
                    str(error),
                    f"test-owned release parent is not empty after cleanup: {parent}",
                )
            for foreign_file_path, parent in zip(
                multiply_foreign_files, multiply_contaminated, strict=True
            ):
                self.assertEqual(
                    foreign_file_path.read_text(encoding="utf-8"),
                    "external data\n",
                )
                foreign_file_path.unlink()
                parent.rmdir()

            vanished = root / "vanished-parent"
            vanished_original = root / "vanished-parent-original"
            with self.assertRaisesRegex(
                AssertionError, "test-owned release parent disappeared before cleanup"
            ):
                with _temporary_release_test_directories((vanished,)):
                    vanished.rename(vanished_original)
            self.assertFalse(os.path.lexists(vanished))
            self.assertEqual(list(vanished_original.iterdir()), [])
            vanished_original.rmdir()

            replaced = root / "replaced-parent"
            replaced_original = root / "replaced-parent-original"
            with self.assertRaisesRegex(
                AssertionError, "test-owned release parent was replaced before cleanup"
            ):
                with _temporary_release_test_directories((replaced,)):
                    replaced.rename(replaced_original)
                    replaced.mkdir()
            self.assertTrue(replaced.is_dir())
            self.assertEqual(list(replaced_original.iterdir()), [])
            replaced.rmdir()
            replaced_original.rmdir()

            aba_replaced = root / "aba-replaced-parent"
            with self.assertRaises(ExceptionGroup) as aba_cleanup:
                with _temporary_release_test_directories((aba_replaced,)) as (child,):
                    child.rmdir()
                    aba_replaced.rmdir()
                    aba_replaced.mkdir()
            self.assertEqual(
                aba_cleanup.exception.message,
                "multiple release test fixture cleanups failed",
            )
            self.assertEqual(len(aba_cleanup.exception.exceptions), 2)
            child_error, parent_error = aba_cleanup.exception.exceptions
            self.assertIs(type(child_error), AssertionError)
            self.assertIn(
                "test-owned release child disappeared before cleanup", str(child_error)
            )
            self.assertIs(type(parent_error), AssertionError)
            self.assertEqual(
                str(parent_error),
                "test-owned release parent was replaced before cleanup: "
                f"{aba_replaced}",
            )
            self.assertTrue(aba_replaced.is_dir())
            aba_replaced.rmdir()

            symlink_replaced = root / "symlink-replaced-parent"
            symlink_original = root / "symlink-replaced-parent-original"
            external_target = root / "external-target"
            external_target.mkdir()
            external_payload: pathlib.Path
            with self.assertRaisesRegex(
                AssertionError, "test-owned release parent was replaced before cleanup"
            ):
                with _temporary_release_test_directories((symlink_replaced,)) as (
                    child,
                ):
                    symlink_replaced.rename(symlink_original)
                    external_child = external_target / child.name
                    external_child.mkdir()
                    external_payload = external_child / "foreign-data"
                    external_payload.write_text(
                        "must survive cleanup\n", encoding="utf-8"
                    )
                    symlink_replaced.symlink_to(
                        external_target, target_is_directory=True
                    )
            self.assertEqual(
                external_payload.read_text(encoding="utf-8"),
                "must survive cleanup\n",
            )
            self.assertEqual(list(symlink_original.iterdir()), [])
            symlink_replaced.unlink()
            external_payload.unlink()
            external_payload.parent.rmdir()
            external_target.rmdir()
            symlink_original.rmdir()

            preexisting_replaced = root / "preexisting-replaced-parent"
            preexisting_original = root / "preexisting-replaced-parent-original"
            preexisting_external = root / "preexisting-external-target"
            preexisting_replaced.mkdir()
            preexisting_sentinel = preexisting_replaced / "caller-sentinel"
            preexisting_sentinel.write_text("caller data\n", encoding="utf-8")
            preexisting_external.mkdir()
            preexisting_payload: pathlib.Path
            with self.assertRaisesRegex(
                AssertionError, "release parent was replaced before cleanup"
            ):
                with _temporary_release_test_directories((preexisting_replaced,)) as (
                    child,
                ):
                    preexisting_replaced.rename(preexisting_original)
                    preexisting_external_child = preexisting_external / child.name
                    preexisting_external_child.mkdir()
                    preexisting_payload = preexisting_external_child / "foreign-data"
                    preexisting_payload.write_text(
                        "must survive cleanup\n", encoding="utf-8"
                    )
                    preexisting_replaced.symlink_to(
                        preexisting_external, target_is_directory=True
                    )
            self.assertEqual(
                preexisting_payload.read_text(encoding="utf-8"),
                "must survive cleanup\n",
            )
            self.assertEqual(
                (preexisting_original / preexisting_sentinel.name).read_text(
                    encoding="utf-8"
                ),
                "caller data\n",
            )
            self.assertEqual(
                list(preexisting_original.iterdir()),
                [preexisting_original / preexisting_sentinel.name],
            )
            preexisting_replaced.unlink()
            preexisting_payload.unlink()
            preexisting_payload.parent.rmdir()
            preexisting_external.rmdir()
            (preexisting_original / preexisting_sentinel.name).unlink()
            preexisting_original.rmdir()

            child_replaced_parent = root / "child-replaced-parent"
            child_replacement_payload: pathlib.Path
            original_child: pathlib.Path
            with self.assertRaises(ExceptionGroup) as child_replacement_cleanup:
                with _temporary_release_test_directories((child_replaced_parent,)) as (
                    child,
                ):
                    original_child = child.with_name(f"{child.name}-original")
                    child.rename(original_child)
                    child.mkdir()
                    child_replacement_payload = child / "foreign-data"
                    child_replacement_payload.write_text(
                        "must survive cleanup\n", encoding="utf-8"
                    )
            self.assertEqual(
                child_replacement_cleanup.exception.message,
                "multiple release test fixture cleanups failed",
            )
            self.assertEqual(len(child_replacement_cleanup.exception.exceptions), 2)
            child_replacement_error, child_parent_error = (
                child_replacement_cleanup.exception.exceptions
            )
            self.assertIs(type(child_replacement_error), AssertionError)
            self.assertIn(
                "test-owned release child was replaced before cleanup",
                str(child_replacement_error),
            )
            self.assertIs(type(child_parent_error), AssertionError)
            self.assertEqual(
                str(child_parent_error),
                "test-owned release parent is not empty after cleanup: "
                f"{child_replaced_parent}",
            )
            self.assertEqual(
                child_replacement_payload.read_text(encoding="utf-8"),
                "must survive cleanup\n",
            )
            self.assertTrue(original_child.is_dir())
            child_replacement_payload.unlink()
            child_replacement_payload.parent.rmdir()
            original_child.rmdir()
            child_replaced_parent.rmdir()

    def test_release_test_child_cleanup_revalidates_after_clearing(self) -> None:
        replacement_paths: list[pathlib.Path] = []

        def replace_child_after_clear(
            directory_fd: int, child_path: pathlib.Path
        ) -> list[BaseException]:
            self.assertEqual(os.listdir(directory_fd), [])
            original_child = child_path.with_name(f"{child_path.name}-original")
            child_path.rename(original_child)
            child_path.mkdir()
            replacement_payload = child_path / "foreign-data"
            replacement_payload.write_text("must survive cleanup\n", encoding="utf-8")
            replacement_paths.extend((original_child, replacement_payload))
            return []

        with tempfile.TemporaryDirectory() as temporary:
            parent = pathlib.Path(temporary) / "check-use-parent"
            with mock.patch.object(
                sys.modules[__name__],
                "_clear_release_test_directory_contents",
                side_effect=replace_child_after_clear,
            ) as clear_contents:
                with self.assertRaises(ExceptionGroup) as cleanup:
                    with _temporary_release_test_directories((parent,)):
                        pass
            clear_contents.assert_called_once()
            self.assertEqual(len(replacement_paths), 2)
            original_child, replacement_payload = replacement_paths
            self.assertEqual(
                cleanup.exception.message,
                "multiple release test fixture cleanups failed",
            )
            self.assertEqual(len(cleanup.exception.exceptions), 2)
            child_error, parent_error = cleanup.exception.exceptions
            self.assertIs(type(child_error), AssertionError)
            self.assertIn(
                "test-owned release child was replaced before cleanup",
                str(child_error),
            )
            self.assertIs(type(parent_error), AssertionError)
            self.assertEqual(
                str(parent_error),
                f"test-owned release parent is not empty after cleanup: {parent}",
            )
            self.assertEqual(
                replacement_payload.read_text(encoding="utf-8"),
                "must survive cleanup\n",
            )
            self.assertTrue(original_child.is_dir())
            replacement_payload.unlink()
            replacement_payload.parent.rmdir()
            original_child.rmdir()
            parent.rmdir()

    def test_release_test_unexpected_cleanup_errors_still_close_resources(self) -> None:
        descriptor_directory = pathlib.Path("/proc/self/fd")
        if not descriptor_directory.is_dir():
            descriptor_directory = pathlib.Path("/dev/fd")
        self.assertTrue(descriptor_directory.is_dir())

        with tempfile.TemporaryDirectory() as temporary:
            parent = pathlib.Path(temporary) / "unexpected-cleanup-parent"
            descriptor_count_before = len(os.listdir(descriptor_directory))
            child: pathlib.Path
            with mock.patch.object(
                sys.modules[__name__],
                "_clear_release_test_directory_contents",
                side_effect=RuntimeError("synthetic unexpected cleanup failure"),
            ):
                with self.assertRaises(ExceptionGroup) as cleanup:
                    with _temporary_release_test_directories((parent,)) as (child,):
                        raise ValueError("synthetic fixture body failure")
            descriptor_count_after = len(os.listdir(descriptor_directory))
            self.assertEqual(descriptor_count_after, descriptor_count_before)
            self.assertEqual(
                cleanup.exception.message,
                "release test fixture operation and cleanup both failed",
            )
            self.assertEqual(len(cleanup.exception.exceptions), 3)
            body_error, unexpected_error, parent_error = cleanup.exception.exceptions
            self.assertIs(type(body_error), ValueError)
            self.assertEqual(str(body_error), "synthetic fixture body failure")
            self.assertIs(type(unexpected_error), RuntimeError)
            self.assertEqual(
                str(unexpected_error), "synthetic unexpected cleanup failure"
            )
            self.assertIs(type(parent_error), AssertionError)
            self.assertEqual(
                str(parent_error),
                f"test-owned release parent is not empty after cleanup: {parent}",
            )
            self.assertTrue(child.is_dir())
            child.rmdir()
            parent.rmdir()

    def test_release_test_close_interrupts_do_not_skip_later_descriptors(self) -> None:
        descriptor_directory = pathlib.Path("/proc/self/fd")
        if not descriptor_directory.is_dir():
            descriptor_directory = pathlib.Path("/dev/fd")
        self.assertTrue(descriptor_directory.is_dir())

        real_close = os.close
        close_call_count = 0

        def close_then_interrupt(directory_fd: int) -> None:
            nonlocal close_call_count
            real_close(directory_fd)
            close_call_count += 1
            if close_call_count == 1:
                raise KeyboardInterrupt("synthetic close interruption")

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            parents = (root / "close-device", root / "close-target")
            descriptor_count_before = len(os.listdir(descriptor_directory))
            with mock.patch.object(os, "close", side_effect=close_then_interrupt):
                with self.assertRaises(BaseExceptionGroup) as cleanup:
                    with _temporary_release_test_directories(parents):
                        raise ValueError("synthetic fixture body failure")
            descriptor_count_after = len(os.listdir(descriptor_directory))
            self.assertEqual(descriptor_count_after, descriptor_count_before)
            self.assertEqual(close_call_count, 4)
            self.assertEqual(
                cleanup.exception.message,
                "release test fixture operation and cleanup both failed",
            )
            self.assertEqual(len(cleanup.exception.exceptions), 2)
            body_error, close_error = cleanup.exception.exceptions
            self.assertIs(type(body_error), ValueError)
            self.assertEqual(str(body_error), "synthetic fixture body failure")
            self.assertIs(type(close_error), KeyboardInterrupt)
            self.assertEqual(str(close_error), "synthetic close interruption")
            self.assertTrue(all(not os.path.lexists(parent) for parent in parents))

    def test_release_test_directory_lock_serializes_processes(self) -> None:
        worker = """
import errno
import fcntl
import pathlib
import sys
import time

from test_proof_to_byte_release import (
    __file__ as fixture_module,
    _temporary_release_test_directories,
)

parents = (pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]))
attempting = pathlib.Path(sys.argv[3])
blocked = pathlib.Path(sys.argv[4])
entered = pathlib.Path(sys.argv[5])
release = pathlib.Path(sys.argv[6])
probe_required = sys.argv[7]
if probe_required not in {"0", "1"}:
    raise SystemExit("invalid lock probe mode")
attempting.write_text("attempting\\n", encoding="utf-8")
if probe_required == "1":
    with pathlib.Path(fixture_module).resolve().open("rb") as probe_handle:
        try:
            fcntl.flock(probe_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            if exc.errno not in {errno.EACCES, errno.EAGAIN}:
                raise
        else:
            fcntl.flock(probe_handle.fileno(), fcntl.LOCK_UN)
            raise SystemExit("release fixture lock was not held")
    blocked.write_text("blocked\\n", encoding="utf-8")
with _temporary_release_test_directories(parents):
    entered.write_text("entered\\n", encoding="utf-8")
    deadline = time.monotonic() + 10
    while not release.exists():
        if time.monotonic() >= deadline:
            raise SystemExit("timed out waiting for fixture release")
        time.sleep(0.01)
"""

        def wait_for(path: pathlib.Path) -> None:
            deadline = time.monotonic() + 10
            while not path.exists():
                if time.monotonic() >= deadline:
                    self.fail(f"timed out waiting for subprocess marker: {path.name}")
                time.sleep(0.01)

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            parents = (root / "device-runs", root / "target")
            attempting = (root / "first-attempting", root / "second-attempting")
            second_blocked = root / "second-blocked"
            entered = (root / "first-entered", root / "second-entered")
            release = (root / "release-first", root / "release-second")
            processes: list[subprocess.Popen[str]] = []
            try:
                first = subprocess.Popen(
                    [
                        "sh",
                        str(ROOT / "artifact" / "python-run.sh"),
                        "-c",
                        worker,
                        *(str(parent) for parent in parents),
                        str(attempting[0]),
                        str(second_blocked),
                        str(entered[0]),
                        str(release[0]),
                        "0",
                    ],
                    cwd=ROOT,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                processes.append(first)
                wait_for(attempting[0])
                wait_for(entered[0])

                second = subprocess.Popen(
                    [
                        "sh",
                        str(ROOT / "artifact" / "python-run.sh"),
                        "-c",
                        worker,
                        *(str(parent) for parent in parents),
                        str(attempting[1]),
                        str(second_blocked),
                        str(entered[1]),
                        str(release[1]),
                        "1",
                    ],
                    cwd=ROOT,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                processes.append(second)
                wait_for(attempting[1])
                wait_for(second_blocked)
                self.assertFalse(
                    entered[1].exists(),
                    "second process entered the locked fixture concurrently",
                )

                release[0].write_text("release\n", encoding="utf-8")
                first_stdout, first_stderr = first.communicate(timeout=10)
                self.assertEqual(first.returncode, 0, first_stderr or first_stdout)
                wait_for(entered[1])
                release[1].write_text("release\n", encoding="utf-8")
                second_stdout, second_stderr = second.communicate(timeout=10)
                self.assertEqual(second.returncode, 0, second_stderr or second_stdout)
                self.assertTrue(all(not os.path.lexists(parent) for parent in parents))
            finally:
                for marker in release:
                    marker.touch(exist_ok=True)
                for process in processes:
                    if process.poll() is None:
                        process.kill()
                    process.communicate()

    def test_required_tools_are_checked_before_proof_markers(self) -> None:
        environment = {
            name: value
            for name, value in os.environ.items()
            if not name.startswith("QPERIAPT_")
        }
        environment.update(
            {
                "HOME": "",
                "PATH": "/nonexistent",
                "QPERIAPT_SKIP_SMOKE": "1",
                "QPERIAPT_REQUIRE_FORMAL": "1",
                "QPERIAPT_EXPECTED_GIT_COMMIT": repository_head(),
                "GITHUB_SHA": TEST_COMMIT,
            }
        )
        result = subprocess.run(
            ["/bin/sh", str(PROOF_SCRIPT)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            env=environment,
        )
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("required tool not found: make", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_preflight_errors_escape_caller_controlled_values(self) -> None:
        hostile_value = "invalid\n::warning::injected\x1b[31m"
        cases = (
            {
                "QPERIAPT_REQUIRE_PERFORMANCE": "1",
                "QPERIAPT_PERFORMANCE_PROOF_MAX_AGE_SECONDS": hostile_value,
            },
            {
                "QPERIAPT_REQUIRE_APPLE_DEVICE": "1",
                "QPERIAPT_DEVICE_ARTIFACT_PREFIX": hostile_value,
            },
            {
                "QPERIAPT_REQUIRE_APPLE_DEVICE": "1",
                "QPERIAPT_EXPECT_DEVICE_TYPE": hostile_value,
            },
            {
                "QPERIAPT_REQUIRE_ANDROID_RUNTIME": "1",
                "QPERIAPT_ANDROID_EXPECT_DEVICE_KIND": hostile_value,
            },
        )
        for overrides in cases:
            with self.subTest(overrides=overrides):
                environment = {
                    name: value
                    for name, value in os.environ.items()
                    if not name.startswith("QPERIAPT_")
                }
                environment.update(
                    {
                        "QPERIAPT_SKIP_SMOKE": "1",
                        "QPERIAPT_EXPECTED_GIT_COMMIT": repository_head(),
                        "GITHUB_SHA": TEST_COMMIT,
                        **overrides,
                    }
                )
                result = subprocess.run(
                    ["sh", str(PROOF_SCRIPT)],
                    cwd=ROOT,
                    text=True,
                    capture_output=True,
                    check=False,
                    env=environment,
                )
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertNotIn("\n::warning::injected", result.stderr)
                self.assertNotIn("\x1b", result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                self.assertLess(len(result.stderr), 1024)

        path_cases = (
            (
                {
                    "QPERIAPT_REQUIRE_CAMERA_READY": "1",
                    "QPERIAPT_CAMERA_READY_BUNDLE": str(ROOT / "target" / "bundle"),
                    "QPERIAPT_CAMERA_READY_TRANSCRIPT": "",
                },
                "QPERIAPT_CAMERA_READY_TRANSCRIPT",
            ),
            (
                {
                    "QPERIAPT_REQUIRE_CAMERA_READY": "1",
                    "QPERIAPT_CAMERA_READY_BUNDLE": "",
                },
                "QPERIAPT_CAMERA_READY_BUNDLE",
            ),
            (
                {
                    "QPERIAPT_REQUIRE_APPLE_DEVICE": "1",
                    "QPERIAPT_DEVICE_RESULT_DIR": "",
                },
                "QPERIAPT_DEVICE_RESULT_DIR",
            ),
            (
                {
                    "QPERIAPT_REQUIRE_APPLE_DEVICE_MATRIX": "1",
                    "QPERIAPT_DEVICE_MATRIX_PROOF": "",
                },
                "QPERIAPT_DEVICE_MATRIX_PROOF",
            ),
            (
                {
                    "QPERIAPT_REQUIRE_ANDROID_RUNTIME": "1",
                    "QPERIAPT_ANDROID_DEVICE_PROOF": "",
                },
                "QPERIAPT_ANDROID_DEVICE_PROOF",
            ),
            (
                {
                    "QPERIAPT_REQUIRE_ANDROID_PHYSICAL_RUNTIME": "1",
                    "QPERIAPT_ANDROID_PHYSICAL_DEVICE_PROOF": "",
                },
                "QPERIAPT_ANDROID_PHYSICAL_DEVICE_PROOF",
            ),
            (
                {
                    "QPERIAPT_REQUIRE_PERFORMANCE": "1",
                    "QPERIAPT_PERFORMANCE_PROOF": "",
                },
                "QPERIAPT_PERFORMANCE_PROOF",
            ),
        )
        hostile_paths = (
            "invalid\n::warning::injected\x1b[31m",
            "invalid\N{RIGHT-TO-LEFT OVERRIDE}path",
            "x" * 10_000,
        )
        for template, expected_label in path_cases:
            for hostile_path in hostile_paths:
                with self.subTest(path=expected_label, hostile_path=hostile_path):
                    overrides = {
                        name: hostile_path if value == "" else value
                        for name, value in template.items()
                    }
                    environment = {
                        name: value
                        for name, value in os.environ.items()
                        if not name.startswith("QPERIAPT_")
                    }
                    environment.update(
                        {
                            "QPERIAPT_SKIP_SMOKE": "1",
                            "QPERIAPT_EXPECTED_GIT_COMMIT": repository_head(),
                            "GITHUB_SHA": TEST_COMMIT,
                            **overrides,
                        }
                    )
                    result = subprocess.run(
                        ["sh", str(PROOF_SCRIPT)],
                        cwd=ROOT,
                        text=True,
                        capture_output=True,
                        check=False,
                        env=environment,
                    )
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertIn(
                        f"{expected_label} must be a non-empty printable path of at most 4095 filesystem bytes",
                        result.stderr,
                    )
                    self.assertNotIn("\n::warning::injected", result.stderr)
                    self.assertNotIn("\x1b", result.stderr)
                    self.assertNotIn("\N{RIGHT-TO-LEFT OVERRIDE}", result.stderr)
                    self.assertNotIn("Traceback", result.stderr)
                    self.assertLess(len(result.stderr), 1024)

        empty_path_cases = (
            (
                {
                    "QPERIAPT_REQUIRE_CAMERA_READY": "1",
                    "QPERIAPT_CAMERA_READY_BUNDLE": str(ROOT / "target" / "bundle"),
                    "QPERIAPT_CAMERA_READY_TRANSCRIPT": "",
                },
                "QPERIAPT_CAMERA_READY_TRANSCRIPT",
            ),
            (
                {
                    "QPERIAPT_REQUIRE_APPLE_DEVICE": "1",
                    "QPERIAPT_DEVICE_RESULT_DIR": "",
                },
                "QPERIAPT_DEVICE_RESULT_DIR",
            ),
            (
                {
                    "QPERIAPT_REQUIRE_APPLE_DEVICE_MATRIX": "1",
                    "QPERIAPT_DEVICE_MATRIX_PROOF": "",
                },
                "QPERIAPT_DEVICE_MATRIX_PROOF",
            ),
            (
                {
                    "QPERIAPT_REQUIRE_ANDROID_RUNTIME": "1",
                    "QPERIAPT_ANDROID_DEVICE_PROOF": "",
                },
                "QPERIAPT_ANDROID_DEVICE_PROOF",
            ),
            (
                {
                    "QPERIAPT_REQUIRE_ANDROID_PHYSICAL_RUNTIME": "1",
                    "QPERIAPT_ANDROID_PHYSICAL_DEVICE_PROOF": "",
                },
                "QPERIAPT_ANDROID_PHYSICAL_DEVICE_PROOF",
            ),
            (
                {
                    "QPERIAPT_REQUIRE_PERFORMANCE": "1",
                    "QPERIAPT_PERFORMANCE_PROOF": "",
                },
                "QPERIAPT_PERFORMANCE_PROOF",
            ),
        )
        for overrides, expected_label in empty_path_cases:
            with self.subTest(empty_path=expected_label):
                environment = {
                    name: value
                    for name, value in os.environ.items()
                    if not name.startswith("QPERIAPT_")
                }
                environment.update(
                    {
                        "QPERIAPT_SKIP_SMOKE": "1",
                        "QPERIAPT_EXPECTED_GIT_COMMIT": repository_head(),
                        "GITHUB_SHA": TEST_COMMIT,
                        **overrides,
                    }
                )
                result = subprocess.run(
                    ["sh", str(PROOF_SCRIPT)],
                    cwd=ROOT,
                    text=True,
                    capture_output=True,
                    check=False,
                    env=environment,
                )
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertIn(
                    f"{expected_label} must be a non-empty printable path of at most 4095 filesystem bytes",
                    result.stderr,
                )
                self.assertNotIn("PROOF_TO_BYTE_", result.stdout)

    def test_clean_complete_state_requires_real_dependency_audit_pass(self) -> None:
        marker = format_marker(
            host_smoke=1,
            formal=1,
            apple_matrix=1,
            performance=1,
            dependency_audit=1,
            rust_package_contract=1,
        )
        self.assertEqual(
            marker,
            "PROOF_TO_BYTE_APPLE_LOCAL_CANDIDATE_PASS camera_ready_bundle=not_required"
            " rust_package_contract=1"
            " android_aar=0 android_runtime=0 android_physical_runtime=0"
            " local_release_consumer=0"
            f" commit={TEST_COMMIT} source_sha256={TEST_SOURCE_SHA256}"
            f" manifest_sha256={TEST_MANIFEST_SHA256}",
        )

    def test_apple_candidate_marker_exposes_each_android_gate(self) -> None:
        complete = {
            "host_smoke": 1,
            "formal": 1,
            "apple_matrix": 1,
            "performance": 1,
            "dependency_audit": 1,
            "rust_package_contract": 1,
        }
        baseline = format_marker(**complete)
        for state_name in (
            "android_aar",
            "android_runtime",
            "android_physical_runtime",
            "local_release_consumer",
        ):
            with self.subTest(state_name=state_name):
                changed = format_marker(**complete, **{state_name: 1})
                self.assertNotEqual(changed, baseline)
                self.assertIn(f" {state_name}=1", changed)
                for other_name in {
                    "android_aar",
                    "android_runtime",
                    "android_physical_runtime",
                    "local_release_consumer",
                } - {state_name}:
                    self.assertIn(f" {other_name}=0", changed)

    def test_android_production_marker_requires_all_four_bound_gates(self) -> None:
        required = (
            "android_aar",
            "android_runtime",
            "android_physical_runtime",
            "local_release_consumer",
        )
        all_pass = {name: 1 for name in required}
        marker = format_marker(**all_pass)
        self.assertEqual(
            marker,
            "PROOF_TO_BYTE_ANDROID_LOCAL_PRODUCTION_GATE_PASS"
            f" commit={TEST_COMMIT} source_sha256={TEST_SOURCE_SHA256}"
            f" manifest_sha256={TEST_MANIFEST_SHA256}",
        )
        for missing in required:
            with self.subTest(missing=missing):
                state = dict(all_pass)
                state[missing] = 0
                self.assertNotIn(
                    "PROOF_TO_BYTE_ANDROID_LOCAL_PRODUCTION_GATE_PASS",
                    format_marker(**state),
                )
        self.assertNotIn(
            "PROOF_TO_BYTE_ANDROID_LOCAL_PRODUCTION_GATE_PASS",
            format_marker(**all_pass, source_tree_dirty=1),
        )
        combined = format_marker(
            **all_pass,
            host_smoke=1,
            formal=1,
            apple_matrix=1,
            performance=1,
            dependency_audit=1,
            rust_package_contract=1,
        )
        self.assertIn("PROOF_TO_BYTE_APPLE_ANDROID_LOCAL_CANDIDATE_PASS", combined)

    def test_required_camera_bundle_is_part_of_release_state(self) -> None:
        missing = format_marker(
            host_smoke=1,
            formal=1,
            apple_matrix=1,
            performance=1,
            camera_required=1,
            dependency_audit=1,
            rust_package_contract=1,
        )
        self.assertIn("PROOF_TO_BYTE_RUN_FINISHED", missing)
        self.assertIn("camera_ready_bundle=0", missing)
        verified = format_marker(
            host_smoke=1,
            formal=1,
            apple_matrix=1,
            performance=1,
            camera_ready=1,
            camera_required=1,
            dependency_audit=1,
            rust_package_contract=1,
        )
        self.assertEqual(
            verified,
            "PROOF_TO_BYTE_APPLE_LOCAL_CANDIDATE_PASS camera_ready_bundle=verified"
            " rust_package_contract=1"
            " android_aar=0 android_runtime=0 android_physical_runtime=0"
            " local_release_consumer=0"
            f" commit={TEST_COMMIT} source_sha256={TEST_SOURCE_SHA256}"
            f" manifest_sha256={TEST_MANIFEST_SHA256}",
        )

    def test_missing_audit_is_scoped_summary_even_if_environment_claims_pass(
        self,
    ) -> None:
        with mock.patch.dict(os.environ, {"DEPENDENCY_AUDIT_PASSED": "1"}):
            marker = format_marker(
                host_smoke=1,
                formal=1,
                apple_matrix=1,
                performance=1,
            )
        self.assertIn("PROOF_TO_BYTE_RUN_FINISHED", marker)
        self.assertIn("dependency_audit=0", marker)
        self.assertNotIn("PROOF_TO_BYTE_APPLE_LOCAL_CANDIDATE_PASS", marker)

    def test_finalizer_never_claims_distribution_release(self) -> None:
        source = FINALIZER_SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn("PROOF_TO_BYTE_APPLE_RELEASE_PASS", source)

    def test_dirty_source_tree_cannot_emit_release_pass(self) -> None:
        marker = format_marker(
            host_smoke=1,
            formal=1,
            apple_matrix=1,
            performance=1,
            dependency_audit=1,
            rust_package_contract=1,
            source_tree_dirty=1,
        )
        self.assertEqual(
            marker,
            "PROOF_TO_BYTE_RELEASE_NOT_ATTESTED reason=dirty_source_tree"
            f" commit={TEST_COMMIT} source_sha256={TEST_SOURCE_SHA256}"
            f" manifest_sha256={TEST_MANIFEST_SHA256}",
        )

    def test_allow_dirty_proof_override_cannot_emit_release_pass(self) -> None:
        for apple_override, performance_override in ((1, 0), (0, 1)):
            with self.subTest(
                apple_override=apple_override,
                performance_override=performance_override,
            ):
                marker = format_marker(
                    host_smoke=1,
                    formal=1,
                    apple_matrix=1,
                    performance=1,
                    dependency_audit=1,
                    rust_package_contract=1,
                    allow_dirty_apple=apple_override,
                    allow_dirty_performance=performance_override,
                )
                self.assertEqual(
                    marker,
                    "PROOF_TO_BYTE_RELEASE_NOT_ATTESTED reason=diagnostic_proof_override"
                    f" commit={TEST_COMMIT} source_sha256={TEST_SOURCE_SHA256}"
                    f" manifest_sha256={TEST_MANIFEST_SHA256}",
                )

    def test_invalid_marker_state_fails_closed(self) -> None:
        with self.assertRaisesRegex(
            proof_to_byte_finalizer.FinalizerError,
            "release attestation state must be 0 or 1",
        ):
            format_marker(android_aar=2)

    def test_production_state_inserts_dirty_at_its_named_position(self) -> None:
        state = proof_to_byte_finalizer._production_state(
            (
                "1",  # host_smoke
                "0",  # formal
                "1",  # apple_device
                "0",  # apple_matrix
                "1",  # android_aar
                "0",  # android_runtime
                "1",  # android_physical_runtime
                "0",  # local_release_consumer
                "1",  # performance
                "0",  # camera_ready
                "1",  # camera_required
                "0",  # dependency_audit
                "1",  # allow_dirty_apple
                "0",  # allow_dirty_performance
                "1",  # rust_package_contract
            ),
            dirty=True,
        )
        self.assertEqual(
            dataclasses.asdict(state),
            {
                "host_smoke": True,
                "formal": False,
                "apple_device": True,
                "apple_matrix": False,
                "android_aar": True,
                "android_runtime": False,
                "android_physical_runtime": True,
                "local_release_consumer": False,
                "performance": True,
                "camera_ready": False,
                "camera_required": True,
                "dependency_audit": False,
                "source_tree_dirty": True,
                "allow_dirty_apple": True,
                "allow_dirty_performance": False,
                "rust_package_contract": True,
            },
        )
        with self.assertRaisesRegex(
            proof_to_byte_finalizer.FinalizerError,
            "finalize requires exactly 15 gate state values",
        ):
            proof_to_byte_finalizer._production_state(("0",) * 14, dirty=False)

    def test_format_cli_is_not_exposed(self) -> None:
        result = subprocess.run(
            [
                "sh",
                str(ROOT / "artifact" / "python-run.sh"),
                str(FINALIZER_SCRIPT),
                "format",
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("invalid choice: 'format'", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_finalizer_rejects_clean_commit_transition(self) -> None:
        first = "1" * 40
        second = "2" * 40
        inspection = WorktreeInspection(commit=second, dirty=False, reasons=())
        with (
            mock.patch.object(
                proof_to_byte_finalizer,
                "git_commit",
                side_effect=[first, second],
            ),
            mock.patch.object(
                proof_to_byte_finalizer,
                "validate_release_metadata",
                return_value=(TEST_COMMIT, "e" * 64),
            ),
            mock.patch.object(
                proof_to_byte_finalizer,
                "verify_claim_ledger",
                return_value=TEST_SOURCE_SHA256,
            ),
            mock.patch.object(
                proof_to_byte_finalizer,
                "inspect_worktree",
                return_value=inspection,
            ),
        ):
            with self.assertRaisesRegex(
                proof_to_byte_finalizer.FinalizerError,
                "Git commit changed while finalizing",
            ):
                proof_to_byte_finalizer.capture_source_snapshot(
                    ROOT,
                    ROOT / "artifact" / "claim-ledger.json",
                    ROOT / "artifact" / "results.json",
                    TEST_MANIFEST_SHA256,
                )

    def test_finalizer_rejects_digest_or_dirty_state_transition(self) -> None:
        inspection = WorktreeInspection(
            commit=TEST_COMMIT, dirty=True, reasons=("changed",)
        )
        with (
            mock.patch.object(
                proof_to_byte_finalizer,
                "git_commit",
                side_effect=[TEST_COMMIT, TEST_COMMIT],
            ),
            mock.patch.object(
                proof_to_byte_finalizer,
                "validate_release_metadata",
                return_value=(TEST_COMMIT, "e" * 64),
            ),
            mock.patch.object(
                proof_to_byte_finalizer,
                "verify_claim_ledger",
                side_effect=[TEST_SOURCE_SHA256, "d" * 64],
            ),
            mock.patch.object(
                proof_to_byte_finalizer,
                "inspect_worktree",
                return_value=inspection,
            ),
        ):
            with self.assertRaisesRegex(
                proof_to_byte_finalizer.FinalizerError,
                "canonical source digest changed",
            ):
                proof_to_byte_finalizer.capture_source_snapshot(
                    ROOT,
                    ROOT / "artifact" / "claim-ledger.json",
                    ROOT / "artifact" / "results.json",
                    TEST_MANIFEST_SHA256,
                )

        with (
            mock.patch.object(
                proof_to_byte_finalizer,
                "git_commit",
                side_effect=[TEST_COMMIT, TEST_COMMIT],
            ),
            mock.patch.object(
                proof_to_byte_finalizer,
                "validate_release_metadata",
                return_value=(TEST_COMMIT, "e" * 64),
            ),
            mock.patch.object(
                proof_to_byte_finalizer,
                "verify_claim_ledger",
                return_value=TEST_SOURCE_SHA256,
            ),
            mock.patch.object(
                proof_to_byte_finalizer,
                "inspect_worktree",
                return_value=inspection,
            ),
        ):
            with self.assertRaisesRegex(
                proof_to_byte_finalizer.FinalizerError,
                "source dirty state changed",
            ):
                proof_to_byte_finalizer.capture_source_snapshot(
                    ROOT,
                    ROOT / "artifact" / "claim-ledger.json",
                    ROOT / "artifact" / "results.json",
                    TEST_MANIFEST_SHA256,
                    expected_commit=TEST_COMMIT,
                    expected_source_sha256=TEST_SOURCE_SHA256,
                    expected_dirty=False,
                )

    def test_release_metadata_binds_snapshot_commit_and_footprint_csv(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            paper = root / "paper"
            paper.mkdir()
            footprint = paper / "footprint.csv"
            footprint.write_text(
                "# generated footprint\n"
                "host,rustc,artifact,bytes,kib\n"
                "Darwin 27.0.0 arm64,1.96.0,c-abi-cdylib-stripped,683800,667.8\n"
                "Darwin 27.0.0 arm64,1.96.0,wasm-lean-default,100034,97.7\n"
                "Darwin 27.0.0 arm64,1.96.0,wasm-signed-policy,340625,332.6\n",
                encoding="utf-8",
            )
            expected, footprint_sha256 = (
                proof_to_byte_finalizer.load_footprint_manifest_section(footprint)
            )
            self.assertEqual(expected["platform"], "Darwin 27.0.0 arm64, rustc 1.96.0")
            self.assertEqual(
                expected["c_abi_cdylib_stripped"],
                {"bytes": 683800, "kib": 667.8},
            )
            document = {
                "provenance": {"snapshot_commit": TEST_COMMIT},
                "footprint_bytes": expected,
            }
            manifest_snapshot = mock.Mock(value=document)
            with (
                mock.patch.object(
                    proof_to_byte_finalizer,
                    "load_results_manifest_snapshot",
                    return_value=manifest_snapshot,
                ),
                mock.patch.object(
                    proof_to_byte_finalizer,
                    "require_commit_or_evidence_successor",
                ) as require_successor,
                mock.patch.object(
                    proof_to_byte_finalizer,
                    "validate_release_publication_history",
                ) as validate_publication_history,
            ):
                self.assertEqual(
                    proof_to_byte_finalizer.validate_release_metadata(
                        root,
                        root / "artifact" / "results.json",
                        TEST_MANIFEST_SHA256,
                    ),
                    (TEST_COMMIT, footprint_sha256),
                )
                require_successor.assert_called_once_with(root, TEST_COMMIT)
                validate_publication_history.assert_called_once_with(
                    root, document
                )

                document["footprint_bytes"] = dict(expected)
                document["footprint_bytes"]["wasm_lean_default"] = {
                    "bytes": 100035,
                    "kib": 97.7,
                }
                with self.assertRaisesRegex(
                    proof_to_byte_finalizer.FinalizerError,
                    "footprint_bytes differs",
                ):
                    proof_to_byte_finalizer.validate_release_metadata(
                        root,
                        root / "artifact" / "results.json",
                        TEST_MANIFEST_SHA256,
                    )

    def test_first_parent_publication_history_is_loaded_and_enforced(self) -> None:
        parent_manifest = json.loads(
            (ROOT / "artifact" / "results.json").read_text(encoding="utf-8")
        )
        parent_bytes = json.dumps(
            parent_manifest,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary) / "repository"
            _initialize_first_parent_results_fixture(root, parent_bytes)
            self.assertEqual(
                proof_to_byte_finalizer._load_first_parent_results_manifest(
                    root
                ),
                parent_manifest,
            )
            migrated_manifest = copy.deepcopy(parent_manifest)
            migrated_manifest["release_publications"][
                apple_publication_contract.APPLE_ALPHA2_R1_PUBLICATION_KEY
            ] = alpha2_receipt()
            migrated_manifest["swift_xcframework"] = (
                release_publication_contract.neutral_swift_selector(
                    migrated_manifest
                )
            )
            proof_to_byte_finalizer.validate_release_publication_history(
                root, migrated_manifest
            )

            current_without_recorded_publications = copy.deepcopy(
                migrated_manifest
            )
            current_without_recorded_publications["release_publications"].pop(
                "platform_r2"
            )
            with self.assertRaisesRegex(
                proof_to_byte_finalizer.FinalizerError,
                "first-parent transition.*changed or was removed",
            ):
                proof_to_byte_finalizer.validate_release_publication_history(
                    root, current_without_recorded_publications
                )

    def test_first_parent_results_loading_fails_closed(self) -> None:
        valid_empty = b"{}\n"
        cases = (
            ("missing", None, "cannot load first-parent"),
            (
                "duplicate-key",
                b'{"release_publications":{},"release_publications":{}}',
                "duplicate JSON key",
            ),
            (
                "oversized",
                b" " * (proof_to_byte_finalizer.MAX_RESULTS_MANIFEST_BYTES + 1),
                "exceeds maximum size",
            ),
            ("non-object", b"[]", "root must be a JSON object"),
        )
        for label, parent_bytes, message in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary) / "repository"
                _initialize_first_parent_results_fixture(root, parent_bytes)
                with self.assertRaisesRegex(
                    proof_to_byte_finalizer.FinalizerError, message
                ):
                    proof_to_byte_finalizer._load_first_parent_results_manifest(
                        root
                    )

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary) / "root-commit-repository"
            subprocess.run(
                ["/usr/bin/git", "init", "-q", str(root)],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            artifact = root / "artifact"
            artifact.mkdir()
            (artifact / "results.json").write_bytes(valid_empty)
            _git_fixture_commit(root, "Record root results")
            with self.assertRaisesRegex(
                proof_to_byte_finalizer.FinalizerError,
                "cannot load first-parent",
            ):
                proof_to_byte_finalizer._load_first_parent_results_manifest(
                    root
                )

    def test_first_parent_history_does_not_read_a_merge_second_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary) / "merge-repository"
            _initialize_first_parent_results_fixture(root, b"{}\n")
            main_branch = subprocess.run(
                [
                    "/usr/bin/git",
                    "-C",
                    str(root),
                    "branch",
                    "--show-current",
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            ).stdout.strip()
            self.assertTrue(main_branch)
            _git_fixture_command(root, "checkout", "-qb", "publication-side")
            (root / "artifact" / "results.json").write_text(
                '{"second_parent":true}\n', encoding="utf-8"
            )
            _git_fixture_commit(root, "Record side publication data")
            _git_fixture_command(root, "checkout", "-q", main_branch)
            (root / "main-only.txt").write_text("main\n", encoding="utf-8")
            _git_fixture_commit(root, "Record main data")
            _git_fixture_command(
                root,
                "-c",
                "user.name=Proof Test",
                "-c",
                "user.email=proof@example.invalid",
                "merge",
                "--no-ff",
                "-qm",
                "Merge publication side",
                "publication-side",
            )
            self.assertEqual(
                proof_to_byte_finalizer._load_first_parent_results_manifest(
                    root
                ),
                {},
            )

    def test_footprint_csv_rejects_duplicate_and_inconsistent_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            footprint = pathlib.Path(temporary) / "footprint.csv"
            footprint.write_text(
                "host,rustc,artifact,bytes,kib\n"
                "host,1.96.0,c-abi-cdylib-stripped,1024,1.0\n"
                "host,1.96.0,wasm-lean-default,1024,1.0\n"
                "host,1.96.0,wasm-lean-default,1024,1.0\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                proof_to_byte_finalizer.FinalizerError,
                "unknown or duplicate artifact",
            ):
                proof_to_byte_finalizer.load_footprint_manifest_section(footprint)

            footprint.write_text(
                "host,rustc,artifact,bytes,kib\n"
                "host,1.96.0,c-abi-cdylib-stripped,1024,1.0\n"
                "host,1.96.0,wasm-lean-default,1024,1.0\n"
                "other,1.96.0,wasm-signed-policy,1024,1.0\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                proof_to_byte_finalizer.FinalizerError,
                "share one host",
            ):
                proof_to_byte_finalizer.load_footprint_manifest_section(footprint)

    def test_footprint_csv_numeric_failures_are_contextual_finalizer_errors(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            footprint = pathlib.Path(temporary) / "footprint.csv"
            trailing_rows = (
                "host,1.96.0,wasm-lean-default,1024,1.0\n"
                "host,1.96.0,wasm-signed-policy,1024,1.0\n"
            )
            cases = (
                (
                    "9" * 5000,
                    "1.0",
                    r"artifact 'c-abi-cdylib-stripped' field 'bytes' exceeds",
                ),
                (
                    "1024",
                    "1.1",
                    r"artifact 'c-abi-cdylib-stripped' field 'kib' differs from bytes",
                ),
            )
            for raw_bytes, raw_kib, message in cases:
                with self.subTest(message=message):
                    footprint.write_text(
                        "host,rustc,artifact,bytes,kib\n"
                        f"host,1.96.0,c-abi-cdylib-stripped,{raw_bytes},{raw_kib}\n"
                        + trailing_rows,
                        encoding="utf-8",
                    )
                    with self.assertRaisesRegex(
                        proof_to_byte_finalizer.FinalizerError,
                        message,
                    ):
                        proof_to_byte_finalizer.load_footprint_manifest_section(
                            footprint
                        )

    def test_release_metadata_rejects_extra_fields_and_wrong_numeric_types(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            paper = root / "paper"
            paper.mkdir()
            footprint = paper / "footprint.csv"
            footprint.write_text(
                "host,rustc,artifact,bytes,kib\n"
                "host,1.96.0,c-abi-cdylib-stripped,1024,1.0\n"
                "host,1.96.0,wasm-lean-default,2048,2.0\n"
                "host,1.96.0,wasm-signed-policy,3072,3.0\n",
                encoding="utf-8",
            )
            expected, _ = proof_to_byte_finalizer.load_footprint_manifest_section(
                footprint
            )
            document = {
                "provenance": {"snapshot_commit": TEST_COMMIT},
                "footprint_bytes": expected,
            }
            manifest_snapshot = mock.Mock(value=document)
            with (
                mock.patch.object(
                    proof_to_byte_finalizer,
                    "load_results_manifest_snapshot",
                    return_value=manifest_snapshot,
                ),
                mock.patch.object(
                    proof_to_byte_finalizer,
                    "require_commit_or_evidence_successor",
                ),
                mock.patch.object(
                    proof_to_byte_finalizer,
                    "validate_release_publication_history",
                ),
            ):
                invalid_cases = (
                    (
                        lambda value: value.update({"unexpected": {}}),
                        "footprint_bytes fields differ.*extra=\\['unexpected'\\]",
                    ),
                    (
                        lambda value: value["wasm_lean_default"].update(
                            {"unexpected": 0}
                        ),
                        "entry 'wasm_lean_default' fields differ.*unexpected",
                    ),
                    (
                        lambda value: value["wasm_lean_default"].update(
                            {"bytes": True}
                        ),
                        "entry 'wasm_lean_default' field 'bytes' must be an integer",
                    ),
                    (
                        lambda value: value["wasm_lean_default"].update({"kib": 2}),
                        "entry 'wasm_lean_default' field 'kib' must be a finite JSON float",
                    ),
                )
                for mutate, message in invalid_cases:
                    with self.subTest(message=message):
                        document["footprint_bytes"] = copy.deepcopy(expected)
                        mutate(document["footprint_bytes"])
                        with self.assertRaisesRegex(
                            proof_to_byte_finalizer.FinalizerError,
                            message,
                        ):
                            proof_to_byte_finalizer.validate_release_metadata(
                                root,
                                root / "artifact" / "results.json",
                                TEST_MANIFEST_SHA256,
                            )

    def test_audit_pass_state_is_set_only_after_warning_denied_command(self) -> None:
        source = PROOF_SCRIPT.read_text(encoding="utf-8")
        initial = source.index("DEPENDENCY_AUDIT_PASSED=0")
        gate_start = source.index(
            'if [ "$REQUIRE_DEPENDENCY_AUDIT" = "1" ]; then',
            initial,
        )
        command = source.index("verify-workspace-dependency-audit", gate_start)
        passed = source.index("DEPENDENCY_AUDIT_PASSED=1")
        self.assertLess(initial, gate_start)
        self.assertLess(gate_start, command)
        self.assertLess(command, passed)
        audit_gate = source[gate_start:passed]
        self.assertIn(
            "sh artifact/python-run.sh artifact/rust_publish_contract.py",
            audit_gate,
        )
        self.assertNotIn("--root", audit_gate)
        self.assertNotIn("--cargo-audit", audit_gate)
        self.assertNotIn("command -v cargo-audit", source)
        self.assertNotIn("||", audit_gate)
        self.assertNotIn("; true", audit_gate)
        self.assertNotIn("--ignore", source)

    def test_ci_uses_warning_denied_audit_without_suppression(self) -> None:
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")
        guide = " ".join(ARTIFACT_GUIDE.read_text(encoding="utf-8").split())
        audit_job = extract_workflow_job(workflow, "audit")
        audit_step = extract_named_workflow_step(
            audit_job,
            "Verify workspace dependency audit",
        )
        self.assertEqual(audit_step.count("verify-workspace-dependency-audit"), 1)
        self.assertEqual(
            audit_job.count(
                "cargo +1.96.1 install cargo-audit --version 0.22.2 "
                "--locked \\\n"
                "            --root target/qperiapt-audit-tool"
            ),
            1,
        )
        install_step = extract_named_workflow_step(
            audit_job,
            "Install fixed dependency-audit tool",
        )
        self.assertIn(
            'export PATH="$GITHUB_WORKSPACE/target/qperiapt-audit-tool/bin:$PATH"',
            install_step,
        )
        self.assertNotIn("--root", audit_step)
        self.assertNotIn("--cargo-audit", audit_step)
        self.assertNotIn("command -v cargo-audit", audit_step)
        self.assertNotIn("GITHUB_WORKSPACE", audit_step)
        self.assertNotIn("cargo audit --deny warnings", audit_job)
        self.assertNotIn("cargo audit --ignore", audit_job)
        self.assertNotIn("continue-on-error:", audit_step)
        self.assertNotIn("|| true", audit_step)
        self.assertIn(
            "accepts no source-root or executable-path argument", guide
        )
        self.assertIn(
            "`target/qperiapt-audit-tool/bin/cargo-audit`", guide
        )
        self.assertIn(
            "path is fixed by code rather than accepted from a CLI argument "
            "or ambient `PATH`",
            guide,
        )

    def test_ci_runs_lean_and_signed_policy_wasm_node_suites(self) -> None:
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")
        wasm_job = extract_workflow_job(workflow, "bindings-wasm")
        self.assertEqual(
            wasm_job.count("wasm-pack test --node crates/q-periapt-wasm\n"),
            1,
        )
        self.assertEqual(
            wasm_job.count(
                "wasm-pack test --node crates/q-periapt-wasm --features signed-policy\n"
            ),
            1,
        )
        self.assertNotIn("continue-on-error", wasm_job)

    def test_formal_tool_release_assets_use_one_bounded_verifier(self) -> None:
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")
        tamarin_job = extract_workflow_job(workflow, "tamarin-proof")
        tamarin_install = extract_named_workflow_step(
            tamarin_job, "Install Maude + Tamarin"
        )
        proverif_job = extract_workflow_job(workflow, "proverif-proof")
        proverif_install = extract_named_workflow_step(
            proverif_job, "Install ProVerif"
        )
        calls = (
            "sh artifact/python-run.sh artifact/formal_tool_asset.py "
            "--asset maude-3.5.1",
            "sh artifact/python-run.sh artifact/formal_tool_asset.py "
            "--asset tamarin-1.12.0",
            "sh artifact/python-run.sh artifact/formal_tool_asset.py "
            "--asset opam-2.5.2",
        )
        combined = tamarin_install + proverif_install
        self.assertEqual(combined.count("artifact/formal_tool_asset.py"), 3)
        for call in calls:
            with self.subTest(call=call):
                self.assertEqual(combined.count(call), 1)
        for token in (
            "set -euo pipefail",
            "/tmp/qperiapt-formal-tool-asset.?*",
            'case "${asset_parent#/tmp/}" in',
            'case "${opam_parent#/tmp/}" in',
            'asset_suffix=${asset_parent#/tmp/qperiapt-formal-tool-asset.}',
            'opam_suffix=${opam_parent#/tmp/qperiapt-formal-tool-asset.}',
            "*[!0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._-]*",
            '[ "${#asset_suffix}" -gt 64 ]',
            '[ "${#opam_suffix}" -gt 64 ]',
            '[ -L "$asset_parent" ]',
            '[ ! -d "$asset_parent" ]',
            '[ -L "$opam_parent" ]',
            '[ ! -d "$opam_parent" ]',
            '[ -L "$asset_path" ]',
            'rm -- "$asset_path"',
            'rmdir -- "$asset_parent"',
            "trap cleanup_formal_tool_assets EXIT",
            "trap cleanup_opam_asset EXIT",
        ):
            with self.subTest(token=token):
                self.assertIn(token, combined)
        self.assertNotIn("RUNNER_TEMP", combined)
        self.assertLess(
            tamarin_install.index(calls[0]), tamarin_install.index("unzip -q")
        )
        self.assertLess(
            tamarin_install.index(calls[1]), tamarin_install.index("tar -xzf")
        )
        self.assertLess(
            proverif_install.index(calls[2]),
            proverif_install.index('sudo install -m 0755 "$OPAM_BIN"'),
        )
        self.assertIn(
            "make -C formal/tamarin TAMARIN=tamarin-prover \\\n"
            "              DERIVCHECK_TIMEOUT=60 prove",
            tamarin_job,
        )
        self.assertIn(
            "make -C formal/proverif PROVERIF=proverif prove", proverif_job
        )
        for forbidden in (
            "continue-on-error",
            "|| true",
            "curl ",
            "sha256sum",
            "github.com/maude-lang",
            "github.com/tamarin-prover",
            "github.com/ocaml/opam/releases",
            "--continue-at",
            "--insecure",
            "--retry-all-errors",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, tamarin_job + proverif_job)

    def test_ci_verifies_formal_tool_identities_before_machine_checks(self) -> None:
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")
        easycrypt_job = extract_workflow_job(workflow, "formal-easycrypt")
        easycrypt_check = extract_named_workflow_step(
            easycrypt_job,
            "Machine-check proof, countermodels, and dependency controls (HARD GATE)",
        )
        tamarin_job = extract_workflow_job(workflow, "tamarin-proof")
        tamarin_lemma_names = extract_named_workflow_step(
            tamarin_job, "Handshake and migration lemma names present (hard gate)"
        )
        tamarin_install = extract_named_workflow_step(
            tamarin_job, "Install Maude + Tamarin"
        )
        tamarin_identity = extract_named_workflow_step(
            tamarin_job, "Verify pinned Tamarin and Maude identities"
        )
        proverif_job = extract_workflow_job(workflow, "proverif-proof")
        proverif_identity = extract_named_workflow_step(
            proverif_job, "Verify pinned ProVerif identity"
        )

        easycrypt_call = (
            "sh artifact/python-run.sh artifact/formal_toolchain_contract.py "
            "verify-installed --tool easycrypt"
        )
        nested_make_environment = (
            'MAKEFLAGS="" GNUMAKEFLAGS="" MAKEFILES="" '
        )
        workflow_make_environment = "MAKEFLAGS='' GNUMAKEFLAGS='' MAKEFILES='' "
        self.assertEqual(easycrypt_check.count(easycrypt_call), 1)
        self.assertEqual(easycrypt_check.count(nested_make_environment), 2)
        self.assertIn(
            '-v "${{ github.workspace }}/artifact:/work/artifact:ro"',
            easycrypt_check,
        )
        for inline_parser in ("easycrypt config", "2>&1", "grep -c"):
            with self.subTest(inline_parser=inline_parser):
                self.assertNotIn(inline_parser, easycrypt_check)
        self.assertLess(
            easycrypt_check.index(easycrypt_call),
            easycrypt_check.index("make EC=easycrypt check"),
        )
        dockerfile = (ROOT / "formal" / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("z3 git make ca-certificates sudo python3 &&", dockerfile)
        self.assertIn("/usr/bin/python3 -I -S -c", dockerfile)
        self.assertIn("sys.version_info >= (3, 11)", dockerfile)
        for command in (
            "verify-installed \\\n#              --tool easycrypt",
            "mkdir -p /tmp/ec",
            "rm -f *.eco continuity/*.eco",
            'MAKEFLAGS="" GNUMAKEFLAGS="" \\\n',
            'MAKEFILES="" make EC=easycrypt check',
            "make EC=easycrypt check",
            "EASYCRYPT=easycrypt sh negative-controls.sh",
            'MAKEFLAGS="" GNUMAKEFLAGS="" MAKEFILES="" \\\n',
            "make -C continuity EC=easycrypt check",
        ):
            with self.subTest(dockerfile_command=command):
                self.assertIn(command, dockerfile)

        tamarin_call = (
            "sh artifact/python-run.sh artifact/formal_toolchain_contract.py "
            "verify-installed --tool tamarin"
        )
        proverif_call = (
            "opam exec -- sh artifact/python-run.sh "
            "artifact/formal_toolchain_contract.py verify-installed --tool proverif"
        )
        self.assertEqual(tamarin_identity.count(tamarin_call), 1)
        self.assertEqual(proverif_identity.count(proverif_call), 1)
        self.assertEqual(tamarin_job.count(workflow_make_environment), 2)
        self.assertEqual(proverif_job.count(workflow_make_environment), 1)
        self.assertEqual(
            tamarin_lemma_names,
            "      - name: Handshake and migration lemma names present (hard gate)\n"
            "        run: MAKEFLAGS='' GNUMAKEFLAGS='' MAKEFILES='' "
            "make -C formal/tamarin check-lemma-names\n",
        )
        self.assertLess(
            tamarin_job.index(tamarin_call),
            tamarin_job.index(
                "make -C formal/tamarin TAMARIN=tamarin-prover \\\n"
                "              DERIVCHECK_TIMEOUT=60 prove"
            ),
        )
        self.assertLess(
            proverif_job.index(proverif_call),
            proverif_job.index(
                "make -C formal/proverif PROVERIF=proverif prove"
            ),
        )
        for authority, ambient_override in (
            (easycrypt_check, "EC=easycrypt make check"),
            (easycrypt_check, "&& sh negative-controls.sh"),
            (tamarin_job, "make -C formal/tamarin prove"),
            (proverif_job, "make -C formal/proverif prove"),
            (dockerfile, "EC=easycrypt make check"),
            (dockerfile, "#              sh negative-controls.sh"),
        ):
            with self.subTest(ambient_override=ambient_override):
                self.assertNotIn(ambient_override, authority)
        self.assertNotIn('test "$(maude --version)"', tamarin_install)
        self.assertNotIn("tamarin-prover --version", tamarin_install)
        for step in (easycrypt_check, tamarin_identity, proverif_identity):
            with self.subTest(step=step[:80]):
                self.assertNotIn("continue-on-error", step)
                self.assertNotIn("|| true", step)

    def test_ci_check_fetches_full_history_for_evidence_successors(self) -> None:
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")
        validate_ci_check_checkout(extract_ci_check_job(workflow))

    def test_checkout_git_init_configuration_is_exact_and_step_scoped(self) -> None:
        workflows = (
            CI_WORKFLOW,
            CODEQL_WORKFLOW,
            ABI2_PLATFORM_CANDIDATE_WORKFLOW,
        )
        for path in workflows:
            source = path.read_text(encoding="utf-8")
            checkout_steps = extract_action_steps(source, PINNED_CHECKOUT_ACTION)
            self.assertTrue(checkout_steps, path.name)
            for step in checkout_steps:
                with self.subTest(workflow=path.name, checkout_step=step[:80]):
                    self.assertEqual(step.count(EXPECTED_CHECKOUT_GIT_ENV), 1)
                    self.assertEqual(step.count("        env:\n"), 1)
            for setting in (
                'GIT_CONFIG_COUNT: "1"',
                "GIT_CONFIG_KEY_0: init.defaultBranch",
                "GIT_CONFIG_VALUE_0: main",
            ):
                with self.subTest(workflow=path.name, setting=setting):
                    self.assertEqual(source.count(setting), len(checkout_steps))

    def test_canonical_rust_toolchain_is_source_pinned_and_provisioned(self) -> None:
        document = tomllib.loads(RUST_TOOLCHAIN_FILE.read_text(encoding="utf-8"))
        self.assertEqual(
            document,
            {
                "toolchain": {
                    "channel": CANONICAL_RUST_TOOLCHAIN,
                    "profile": "minimal",
                    "components": ["rustfmt", "clippy"],
                }
            },
        )
        self.assertFalse(os.path.lexists(ROOT / "rust-toolchain"))

        workflows = (
            (CI_WORKFLOW, 20, 2),
            (ABI2_PLATFORM_CANDIDATE_WORKFLOW, 3, 1),
        )
        for path, expected_count, windows_count in workflows:
            with self.subTest(workflow=path.name):
                source = path.read_text(encoding="utf-8")
                steps = extract_action_steps(source, PINNED_CANONICAL_RUST_ACTION)
                self.assertEqual(len(steps), expected_count)
                canonical = f"          toolchain: {CANONICAL_RUST_TOOLCHAIN}\n"
                windows = f"          toolchain: {WINDOWS_RELEASE_RUST_TOOLCHAIN}\n"
                self.assertEqual(
                    sum(step.count(canonical) for step in steps),
                    expected_count - windows_count,
                )
                self.assertEqual(
                    sum(step.count(windows) for step in steps), windows_count
                )
                for step in steps:
                    self.assertEqual(step.count(canonical) + step.count(windows), 1)
                self.assertNotIn("cargo +stable", source)
                self.assertNotIn("toolchain: stable", source)
                self.assertNotIn("RUSTUP_TOOLCHAIN", source)
                self.assertNotIn("rustup override", source)
                self.assertNotIn("rustup default", source)

        windows_jobs = (
            (CI_WORKFLOW, ("windows", "abi2-windows-package-2022")),
            (ABI2_PLATFORM_CANDIDATE_WORKFLOW, ("windows",)),
        )
        for path, names in windows_jobs:
            source = path.read_text(encoding="utf-8")
            for name in names:
                with self.subTest(workflow=path.name, windows_job=name):
                    job = extract_workflow_job(source, name)
                    steps = extract_action_steps(
                        job,
                        PINNED_CANONICAL_RUST_ACTION,
                    )
                    self.assertEqual(len(steps), 1)
                    self.assertEqual(
                        steps[0].count(
                            f"          toolchain: {WINDOWS_RELEASE_RUST_TOOLCHAIN}\n"
                        ),
                        1,
                    )

        install_jobs = (
            (
                CI_WORKFLOW,
                {
                    "check": CANONICAL_RUST_TOOLCHAIN,
                    "rust-publish-contract": CANONICAL_RUST_TOOLCHAIN,
                    "windows": WINDOWS_RELEASE_RUST_TOOLCHAIN,
                    "abi2-windows-package-2022": WINDOWS_RELEASE_RUST_TOOLCHAIN,
                    "abi2-linux-package": CANONICAL_RUST_TOOLCHAIN,
                    "bindings-wasm": CANONICAL_RUST_TOOLCHAIN,
                    "fuzz": "nightly",
                    "bindings-swift": CANONICAL_RUST_TOOLCHAIN,
                    "bindings-android-aar": CANONICAL_RUST_TOOLCHAIN,
                    "audit": CANONICAL_RUST_TOOLCHAIN,
                    "hqc-draft-candidate": CANONICAL_RUST_TOOLCHAIN,
                },
            ),
            (
                ABI2_PLATFORM_CANDIDATE_WORKFLOW,
                {
                    "linux": CANONICAL_RUST_TOOLCHAIN,
                    "windows": WINDOWS_RELEASE_RUST_TOOLCHAIN,
                    "android": CANONICAL_RUST_TOOLCHAIN,
                },
            ),
        )
        install_pattern = re.compile(r"\bcargo(?: \+(?P<selector>\S+))? install\b")
        for path, expected_jobs in install_jobs:
            source = path.read_text(encoding="utf-8")
            all_installs = list(install_pattern.finditer(source))
            self.assertEqual(len(all_installs), len(expected_jobs))
            self.assertTrue(all(match.group("selector") for match in all_installs))
            for job_name, expected_selector in expected_jobs.items():
                with self.subTest(workflow=path.name, install_job=job_name):
                    job = extract_workflow_job(source, job_name)
                    matches = list(install_pattern.finditer(job))
                    self.assertEqual(len(matches), 1)
                    self.assertEqual(
                        matches[0].group("selector"), expected_selector
                    )

        ci = CI_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn(
            "cargo +${{ matrix.toolchain }} test --workspace --locked",
            extract_workflow_job(ci, "cross-compiler"),
        )
        self.assertIn(
            "cargo +1.85 build --workspace --locked",
            extract_workflow_job(ci, "msrv"),
        )
        fuzz = extract_workflow_job(ci, "fuzz")
        self.assertIn("cargo +nightly fetch", fuzz)
        self.assertIn("cargo +nightly fuzz build", fuzz)

    def test_pretag_windows_2022_package_gate_matches_candidate_substrate(self) -> None:
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")
        job = extract_workflow_job(workflow, "abi2-windows-package-2022")
        self.assertIn("    runs-on: windows-2022\n", job)
        self.assertIn("          fetch-depth: 0\n", job)
        self.assertIn(f"          toolchain: {WINDOWS_RELEASE_RUST_TOOLCHAIN}\n", job)
        self.assertIn("          components: llvm-tools\n", job)
        self.assertIn(
            f"cargo +{WINDOWS_RELEASE_RUST_TOOLCHAIN} install cbindgen --version 0.29.4 --locked",
            job,
        )
        self.assertNotIn("continue-on-error:", job)
        self.assertNotRegex(job, r"(?m)^    if:")

        pretag_toolchain = extract_named_workflow_step(
            job, "Verify exact Windows 2022 source and toolchain"
        )
        for token in (
            f"rustc +{WINDOWS_RELEASE_RUST_TOOLCHAIN} --version",
            WINDOWS_RELEASE_RUSTC_VERSION,
            f"cargo +{WINDOWS_RELEASE_RUST_TOOLCHAIN} --version",
            WINDOWS_RELEASE_CARGO_VERSION,
            "host: x86_64-pc-windows-msvc",
        ):
            self.assertIn(token, pretag_toolchain)
        self.assertNotIn("rustc --version", pretag_toolchain)
        self.assertNotIn("cargo --version", pretag_toolchain)

        trust = extract_named_workflow_step(
            job, "Test Windows 2022 package trust boundary"
        )
        self.assertIn("test_windows_package", trust)
        self.assertIn("./windows-toolchain-tests.ps1", trust)
        build = extract_named_workflow_step(
            job, "Build, archive, extract, and consume the Windows 2022 SDK"
        )
        self.assertIn("QPERIAPT_EXPECTED_GIT_COMMIT: ${{ github.sha }}", build)
        self.assertIn("run: artifact/windows-package.ps1", build)
        verify = extract_named_workflow_step(
            job, "Reconsume only the Windows 2022 candidate archive"
        )
        self.assertIn("-Mode VerifyArchive", verify)
        self.assertIn("-ExpectedGitCommit $gitCommit", verify)
        self.assertIn("-ExpectedGitTree $gitTree", verify)
        self.assertNotIn("SilentlyContinue", verify)

        latest = extract_workflow_job(workflow, "windows")
        self.assertIn(
            f"          toolchain: {WINDOWS_RELEASE_RUST_TOOLCHAIN}\n",
            latest,
        )
        self.assertIn(
            f"cargo +{WINDOWS_RELEASE_RUST_TOOLCHAIN} test --workspace --locked",
            latest,
        )
        windows_c_smoke = WINDOWS_C_SMOKE_SCRIPT.read_text(encoding="utf-8")
        self.assertIn(
            f"cargo +{WINDOWS_RELEASE_RUST_TOOLCHAIN} build -p q-periapt-ffi --release --locked",
            windows_c_smoke,
        )
        self.assertNotIn(
            "cargo build -p q-periapt-ffi",
            windows_c_smoke,
        )
        latest_verify = extract_named_workflow_step(
            latest, "Reconsume only the Windows candidate archive"
        )
        self.assertNotIn("SilentlyContinue", latest_verify)
        self.assertIn("-ErrorAction Stop", latest_verify)

        candidate = ABI2_PLATFORM_CANDIDATE_WORKFLOW.read_text(encoding="utf-8")
        candidate_windows = extract_workflow_job(candidate, "windows")
        self.assertIn("    runs-on: windows-2022\n", candidate_windows)
        self.assertIn(
            f"          toolchain: {WINDOWS_RELEASE_RUST_TOOLCHAIN}\n",
            candidate_windows,
        )
        self.assertIn("          components: llvm-tools\n", candidate_windows)
        self.assertIn(
            f"cargo +{WINDOWS_RELEASE_RUST_TOOLCHAIN} install cbindgen --version 0.29.4 --locked",
            candidate_windows,
        )
        candidate_windows_toolchain = extract_named_workflow_step(
            candidate_windows, "Verify exact source and toolchain"
        )
        for token in (
            f"rustc +{WINDOWS_RELEASE_RUST_TOOLCHAIN} --version",
            WINDOWS_RELEASE_RUSTC_VERSION,
            f"cargo +{WINDOWS_RELEASE_RUST_TOOLCHAIN} --version",
            WINDOWS_RELEASE_CARGO_VERSION,
            "host: x86_64-pc-windows-msvc",
        ):
            self.assertIn(token, candidate_windows_toolchain)
        self.assertNotIn("rustc --version", candidate_windows_toolchain)
        self.assertNotIn("cargo --version", candidate_windows_toolchain)

        candidate_linux = extract_workflow_job(candidate, "linux")
        candidate_linux_toolchain = extract_named_workflow_step(
            candidate_linux, "Verify exact source and native host"
        )
        for token in (
            "rustc -vV",
            '"$EXPECTED_TARGET"',
            CANONICAL_RUSTC_VERSION,
            CANONICAL_CARGO_VERSION,
        ):
            self.assertIn(token, candidate_linux_toolchain)
        self.assertNotIn("rustc +", candidate_linux_toolchain)
        self.assertNotIn("cargo +", candidate_linux_toolchain)

        candidate_android = extract_workflow_job(candidate, "android")
        candidate_android_toolchain = extract_named_workflow_step(
            candidate_android, "Verify exact source and toolchain"
        )
        for token in (
            'test "$(rustc -vV | sed -n \'s/^host: //p\')" = "x86_64-unknown-linux-gnu"',
            CANONICAL_RUSTC_VERSION,
            CANONICAL_CARGO_VERSION,
            "rustup target list --installed",
            "aarch64-linux-android x86_64-linux-android armv7-linux-androideabi i686-linux-android",
        ):
            self.assertIn(token, candidate_android_toolchain)
        self.assertNotIn("rustc +", candidate_android_toolchain)
        self.assertNotIn("cargo +", candidate_android_toolchain)
        candidate_build = extract_named_workflow_step(
            candidate_windows,
            "Build, archive, extract, and consume the unsupported Windows diagnostic SDK",
        )
        self.assertIn(
            "QPERIAPT_EXPECTED_GIT_COMMIT: ${{ needs.preflight.outputs.commit }}",
            candidate_build,
        )
        self.assertIn("run: artifact/windows-package.ps1", candidate_build)
        candidate_verify = extract_named_workflow_step(
            candidate_windows,
            "Reconsume only the unsupported Windows diagnostic archive",
        )
        self.assertNotIn("SilentlyContinue", candidate_verify)
        self.assertIn("-ErrorAction Stop", candidate_verify)
        self.assertIn("-Mode VerifyArchive", candidate_verify)
        self.assertIn("-ExpectedGitCommit $gitCommit", candidate_verify)
        self.assertIn("-ExpectedGitTree $gitTree", candidate_verify)
        preflight = extract_workflow_job(candidate, "preflight")
        self.assertIn(
            "source_parent=$(/usr/bin/jq -er "
            "'.provenance.snapshot_commit' artifact/results.json)",
            preflight,
        )
        self.assertIn(
            'checkout-verify-release "$commit" "$source_parent"',
            preflight,
        )
        self.assertIn(
            "platform_candidate_attestation.py \\\n            stable-source-currentness \"$source_parent\"",
            preflight,
        )
        self.assertIn(
            "release_publication_contract.validate_stable_source_currentness",
            (ROOT / "artifact" / "platform_candidate_attestation.py").read_text(
                encoding="utf-8"
            ),
        )
        self.assertIn(
            "printf 'source_parent=%s\\n' \"$source_parent\" >> \"$GITHUB_OUTPUT\"",
            preflight,
        )
        self.assertNotIn("actions/workflows/ci.yml/runs?", preflight)
        for job_name in ("linux", "windows", "android"):
            with self.subTest(candidate_job=job_name):
                self.assertIn(
                    "    needs: preflight\n",
                    extract_workflow_job(candidate, job_name),
                )
        self.assertIn(
            "    name: Windows compatibility diagnostic (not a stable release asset)\n",
            candidate_windows,
        )
        self.assertNotIn(PINNED_UPLOAD_ARTIFACT_ACTION, candidate_windows)
        attest = extract_workflow_job(candidate, "attest")
        self.assertIn("    needs: [preflight, linux, android]\n", attest)
        self.assertNotIn("windows", attest)
        self.assertIn("      actions: read\n", attest)
        self.assertIn("      security-events: read\n", attest)
        source_security_gate = extract_named_workflow_step(
            attest, "Bind the exact-R CI and CodeQL security gates"
        )
        for token in (
            'test -n "$GH_TOKEN" && test -z "${GITHUB_TOKEN:-}"',
            "platform_candidate_attestation.py \\\n            security-gate-live",
            "ABI2_SOURCE_SECURITY_GATE.json",
        ):
            self.assertIn(token, source_security_gate)
        self.assertNotIn("/usr/bin/gh", source_security_gate)
        candidate_attestation_source = (
            ROOT / "artifact" / "platform_candidate_attestation.py"
        ).read_text(encoding="utf-8")
        for token in (
            'WORKFLOW_GITHUB_CLI = pathlib.Path("/usr/bin/gh")',
            'selected = max(candidates, key=lambda run: run["id"])',
            "actions/workflows/ci.yml/runs?",
            "actions/workflows/codeql.yml/runs?",
            "/jobs?filter=all&per_page=100",
            "/git/ref/heads/main",
            "code-scanning/analyses?",
            "tool_name=CodeQL",
            "code-scanning/alerts?",
            "_require_source_security_samples_stable",
            "_workflow_github_cli_identity() == tool",
            '"GH_CONFIG_DIR": str(directory)',
        ):
            self.assertIn(token, candidate_attestation_source)
        self.assertIn(
            "candidate/ABI2_SOURCE_SECURITY_GATE.json",
            extract_named_workflow_step(
                attest, "Generate GitHub build provenance attestations"
            ),
        )

        constant_time = extract_workflow_job(workflow, "constant-time")
        for token in (
            "    name: Binary CT [${{ matrix.gate_identity }}]\n",
            "gate_identity: x86_64-portable",
            "rust_host: x86_64-unknown-linux-gnu",
            "uname_machine: x86_64",
            "gate_identity: aarch64-native",
            "rust_host: aarch64-unknown-linux-gnu",
            "uname_machine: aarch64",
            "Verify the fixed CT architecture identity",
            "EXPECTED_GATE_IDENTITY: ${{ matrix.gate_identity }}",
            "x86_64-portable:x86_64-unknown-linux-gnu:x86_64",
            "aarch64-native:aarch64-unknown-linux-gnu:aarch64",
        ):
            self.assertIn(token, constant_time)

    def test_ci_checkout_mutations_fail_closed(self) -> None:
        check_job = extract_ci_check_job(CI_WORKFLOW.read_text(encoding="utf-8"))
        mutations = {
            "unpinned action": check_job.replace(
                PINNED_CHECKOUT_ACTION,
                "actions/checkout@main",
                1,
            ),
            "ref override": check_job.replace(
                "          fetch-depth: 0\n",
                "          fetch-depth: 0\n          ref: deadbeef\n",
                1,
            ),
            "repository override": check_job.replace(
                "          fetch-depth: 0\n",
                "          fetch-depth: 0\n          repository: other/project\n",
                1,
            ),
            "duplicate with": check_job.replace(
                "          fetch-depth: 0\n",
                "          fetch-depth: 0\n        with:\n          ref: deadbeef\n",
                1,
            ),
            "missing provenance check": check_job.replace(
                EXPECTED_CHECKOUT_PROVENANCE_STEP,
                "",
                1,
            ),
            "non-blocking provenance check": check_job.replace(
                EXPECTED_CHECKOUT_PROVENANCE_STEP,
                EXPECTED_CHECKOUT_PROVENANCE_STEP + "        continue-on-error: true\n",
                1,
            ),
            "post-check provenance mutation": check_job.replace(
                EXPECTED_CHECKOUT_PROVENANCE_STEP,
                EXPECTED_CHECKOUT_PROVENANCE_STEP
                + "          git checkout --detach HEAD^\n",
                1,
            ),
            "non-blocking proof": check_job.replace(
                EXPECTED_PROOF_TO_BYTE_STEP,
                EXPECTED_PROOF_TO_BYTE_STEP + "        continue-on-error: true\n",
                1,
            ),
            "conditional proof": check_job.replace(
                EXPECTED_PROOF_TO_BYTE_STEP,
                EXPECTED_PROOF_TO_BYTE_STEP + "        if: failure()\n",
                1,
            ),
            "PR head instead of tested merge commit": check_job.replace(
                EXPECTED_PROOF_TO_BYTE_STEP,
                EXPECTED_PROOF_TO_BYTE_STEP.replace(
                    "${{ github.sha }}",
                    "${{ github.event.pull_request.head.sha }}",
                ),
                1,
            ),
            "numeric alias": check_job + "      - uses: *1\n",
            "hyphen alias": check_job + "      - uses: *-foo\n",
            "merge alias": check_job + "        <<: *checkout-settings\n",
            "second checkout": check_job
            + "      - uses: Actions/Checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0\n",
        }
        for label, mutation in mutations.items():
            with self.subTest(label=label):
                with self.assertRaises(ValueError):
                    validate_ci_check_checkout(mutation)

    def test_freeze_expected_commit_argument_is_optional_and_exact(self) -> None:
        arguments = [
            "freeze",
            "--root",
            str(ROOT),
            "--ledger",
            str(ROOT / "artifact" / "claim-ledger.json"),
            "--manifest",
            str(ROOT / "artifact" / "results.json"),
            "--expected-manifest-sha256",
            TEST_MANIFEST_SHA256,
        ]
        parser = proof_to_byte_finalizer.build_parser()
        self.assertIsNone(parser.parse_args(arguments).expected_git_commit)
        self.assertEqual(
            parser.parse_args(
                [*arguments, "--expected-git-commit", TEST_COMMIT]
            ).expected_git_commit,
            TEST_COMMIT,
        )
        snapshot = proof_to_byte_finalizer.SourceSnapshot(
            commit=TEST_COMMIT,
            source_sha256=TEST_SOURCE_SHA256,
            manifest_sha256=TEST_MANIFEST_SHA256,
            dirty=False,
        )
        for expected_commit, extra_arguments in (
            (None, ()),
            (TEST_COMMIT, ("--expected-git-commit", TEST_COMMIT)),
        ):
            with self.subTest(expected_commit=expected_commit):
                parsed = parser.parse_args([*arguments, *extra_arguments])
                with (
                    mock.patch.object(
                        proof_to_byte_finalizer,
                        "capture_source_snapshot",
                        return_value=snapshot,
                    ) as capture,
                    mock.patch("builtins.print") as output,
                ):
                    proof_to_byte_finalizer.run(parsed)
                capture.assert_called_once_with(
                    ROOT.resolve(),
                    (ROOT / "artifact" / "claim-ledger.json").resolve(),
                    (ROOT / "artifact" / "results.json").resolve(),
                    TEST_MANIFEST_SHA256,
                    expected_commit=expected_commit,
                )
                output.assert_called_once_with(f"{TEST_COMMIT}:{TEST_SOURCE_SHA256}:0")

    def test_proof_to_byte_validates_explicit_expected_commit(self) -> None:
        source = PROOF_SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn("GITHUB_SHA", source)

        def run_with_expected_commit(value: str) -> subprocess.CompletedProcess[str]:
            environment = {
                name: current
                for name, current in os.environ.items()
                if not name.startswith("QPERIAPT_")
            }
            environment.update(
                {
                    "QPERIAPT_SKIP_SMOKE": "1",
                    "QPERIAPT_EXPECTED_GIT_COMMIT": value,
                    "GITHUB_SHA": TEST_COMMIT,
                    "GIT_DIR": str(ROOT / "does-not-exist"),
                    "GIT_WORK_TREE": str(ROOT / "does-not-exist"),
                    "GIT_CONFIG_GLOBAL": str(ROOT / "does-not-exist"),
                    "GIT_NO_REPLACE_OBJECTS": "0",
                }
            )
            return subprocess.run(
                ["sh", str(PROOF_SCRIPT)],
                cwd=ROOT,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )

        for label, malformed in (
            ("short", "0" * 39),
            ("long", "0" * 41),
            ("uppercase", "A" * 40),
            ("non-hex", "g" * 40),
        ):
            with self.subTest(label=label):
                result = run_with_expected_commit(malformed)
                self.assertEqual(result.returncode, 2)
                self.assertIn("exactly 40 lowercase hexadecimal", result.stderr)
                self.assertNotIn("PROOF_TO_BYTE_", result.stdout)

        result = run_with_expected_commit("0" * 40)
        self.assertEqual(result.returncode, 2)
        self.assertIn(
            "checked-out Git commit does not match expected provenance",
            result.stderr,
        )
        self.assertIn(f"got {repository_head()}", result.stderr)
        self.assertNotIn("PROOF_TO_BYTE_", result.stdout)

        with tempfile.TemporaryDirectory() as temporary:
            alternate = pathlib.Path(temporary) / "alternate-repository"
            subprocess.run(
                ["/usr/bin/git", "init", "-q", str(alternate)],
                check=True,
                capture_output=True,
            )
            (alternate / "fixture.txt").write_text("alternate\n", encoding="utf-8")
            subprocess.run(
                ["/usr/bin/git", "-C", str(alternate), "add", "fixture.txt"],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [
                    "/usr/bin/git",
                    "-C",
                    str(alternate),
                    "-c",
                    "user.name=Proof Test",
                    "-c",
                    "user.email=proof@example.invalid",
                    "commit",
                    "-qm",
                    "alternate",
                ],
                check=True,
                capture_output=True,
            )
            alternate_head = git_commit(alternate)
            self.assertNotEqual(alternate_head, repository_head())
            environment = {
                name: value
                for name, value in os.environ.items()
                if not name.startswith("QPERIAPT_")
            }
            environment.update(
                {
                    "QPERIAPT_SKIP_SMOKE": "1",
                    "QPERIAPT_EXPECTED_GIT_COMMIT": alternate_head,
                    "GITHUB_SHA": TEST_COMMIT,
                    "GIT_DIR": str(alternate / ".git"),
                    "GIT_WORK_TREE": str(alternate),
                    "GIT_COMMON_DIR": str(alternate / ".git"),
                    "GIT_OBJECT_DIRECTORY": str(alternate / ".git" / "objects"),
                }
            )
            spoofed = subprocess.run(
                ["sh", str(PROOF_SCRIPT)],
                cwd=ROOT,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(spoofed.returncode, 2, spoofed.stderr)
            self.assertIn(f"got {repository_head()}", spoofed.stderr)
            self.assertIn(f"expected {alternate_head}", spoofed.stderr)
            self.assertEqual(spoofed.stdout, "")

    def test_ci_release_package_paths_use_the_current_stable_version(self) -> None:
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")
        wrong_version_probe = (
            'if verify_archive "$archive_sha256" "$EXPECTED_TARGET" '
            '"0.1.0-alpha.2" "$manifest_sha256" "$contract_sha256"; '
            "then exit 1; fi"
        )
        self.assertEqual(workflow.count(wrong_version_probe), 1)
        self.assertNotIn("q-periapt-c-abi2-0.1.0-alpha.2", workflow)
        self.assertNotIn("q-periapt-android-0.1.0-alpha.2", workflow)
        for expected in (
            "q-periapt-c-abi2-0.1.0-x86_64-pc-windows-msvc.zip",
            "q-periapt-c-abi2-0.1.0-$EXPECTED_TARGET",
            "q-periapt-c-abi2-0.1.0-${{ matrix.target }}.tar.gz",
            "q-periapt-android-0.1.0.aar",
            "q-periapt-android-0.1.0/MANIFEST.json",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, workflow)

    def test_release_package_jobs_pin_and_bind_hardened_python(self) -> None:
        setup_action = (
            "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1 # v6.3.0"
        )
        binding = (
            "          QPERIAPT_PYTHON: ${{ steps.proof_python.outputs.python-path }}\n"
        )
        provisioning = (
            "      - name: Provision hardened proof Python\n"
            "        id: proof_python\n"
            f"        uses: {setup_action}\n"
            "        with:\n"
            '          python-version: "3.13.14"\n'
            "          check-latest: false\n"
            "          update-environment: false\n"
        )
        exact_version_check = (
            '          "$QPERIAPT_PYTHON" -I -S -c \'import sys; '
            'raise SystemExit(0 if sys.implementation.name == "cpython" and '
            "sys.version_info[:3] == (3, 13, 14) else 2)'\n"
        )
        cases = (
            (
                CI_WORKFLOW,
                "abi2-linux-package",
                (
                    "Build, archive, extract, and consume the native Linux ABI2 SDK",
                    "Verify the archive through the isolated public-consumer path",
                ),
                True,
            ),
            (
                CI_WORKFLOW,
                "bindings-android-aar",
                ("Android AAR/JNI packaging proof",),
                False,
            ),
            (
                ABI2_PLATFORM_CANDIDATE_WORKFLOW,
                "linux",
                (
                    "Verify exact source and native host",
                    "Build and consume the native Linux package",
                    "Reconsume only the candidate archive",
                ),
                True,
            ),
            (
                ABI2_PLATFORM_CANDIDATE_WORKFLOW,
                "android",
                (
                    "Verify exact source and toolchain",
                    "Build and verify the four-ABI 16 KiB-compatible AAR",
                ),
                False,
            ),
        )
        for workflow_path, job_name, package_steps, native_linux in cases:
            with self.subTest(workflow=workflow_path.name, job=job_name):
                workflow = workflow_path.read_text(encoding="utf-8")
                job = extract_workflow_job(workflow, job_name)
                self.assertEqual(job.count(setup_action), 1)
                self.assertEqual(job.count("id: proof_python"), 1)
                self.assertIn(provisioning, job)
                self.assertNotIn("\n    env:", job)
                self.assertNotIn("GITHUB_ENV", job)

                setup_step = extract_named_workflow_step(
                    job, "Provision hardened proof Python"
                )
                self.assertNotIn("continue-on-error:", setup_step)
                self.assertNotRegex(setup_step, r"(?m)^        if:")
                verification_step = extract_named_workflow_step(
                    job, "Verify hardened proof Python"
                )
                self.assertNotIn("continue-on-error:", verification_step)
                self.assertNotRegex(verification_step, r"(?m)^        if:")
                self.assertEqual(verification_step.count(binding), 1)
                self.assertIn('case "$QPERIAPT_PYTHON" in /*) ;; *)', verification_step)
                self.assertIn(exact_version_check, verification_step)

                setup_position = job.index(provisioning)
                verification_position = job.index(verification_step)
                expected_binding_count = 1
                for package_step_name in package_steps:
                    package_step = extract_named_workflow_step(job, package_step_name)
                    self.assertNotIn("continue-on-error:", package_step)
                    self.assertNotRegex(package_step, r"(?m)^        if:")
                    self.assertEqual(package_step.count(binding), 1)
                    self.assertLess(setup_position, job.index(package_step))
                    self.assertLess(verification_position, job.index(package_step))
                    expected_binding_count += 1
                self.assertEqual(job.count(binding), expected_binding_count)

                if native_linux:
                    matrix_pairs = re.findall(
                        r"(?m)^          - runner: ([^\n]+)\n"
                        r"            target: ([^\n]+)$",
                        job,
                    )
                    self.assertEqual(
                        matrix_pairs,
                        [
                            ("ubuntu-22.04", "x86_64-unknown-linux-gnu"),
                            ("ubuntu-22.04-arm", "aarch64-unknown-linux-gnu"),
                        ],
                    )

    def test_ci_discovers_every_artifact_python_test(self) -> None:
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn(
            "sh artifact/python-run.sh -m unittest discover -s artifact -p 'test_*.py' -v",
            workflow,
        )
        self.assertNotIn("python3 -m unittest", workflow)

    def test_ci_repository_python_calls_use_one_shot_runner(self) -> None:
        workflows = sorted((ROOT / ".github" / "workflows").glob("*.y*ml"))
        self.assertTrue(workflows)
        direct_python = re.compile(r"(?<![A-Za-z0-9_])python3(?![A-Za-z0-9_])")
        repository_script = re.compile(r"artifact/[A-Za-z0-9_.-]+\.py(?:\s|$)")
        runner_calls = 0
        for workflow in workflows:
            for number, line in enumerate(
                workflow.read_text(encoding="utf-8").splitlines(), start=1
            ):
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                self.assertIsNone(
                    direct_python.search(line),
                    f"{workflow.relative_to(ROOT)}:{number} invokes Python directly",
                )
                if repository_script.search(line):
                    self.assertIn(
                        "sh artifact/python-run.sh",
                        line,
                        f"{workflow.relative_to(ROOT)}:{number} bypasses the one-shot runner",
                    )
                runner_calls += line.count("sh artifact/python-run.sh")
        self.assertGreaterEqual(runner_calls, 2)


class CameraReadyEvidenceGateTests(unittest.TestCase):
    def test_unconfirmed_host_fails_without_success_marker(self) -> None:
        environment = os.environ.copy()
        environment.pop("QPERIAPT_BARE_METAL_CONFIRMED", None)
        result = subprocess.run(
            ["sh", str(CAMERA_READY_SCRIPT)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            env=environment,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("CAMERA_READY_BARE_METAL_PASS", result.stdout)

    def test_script_has_no_skip_or_shellcheck_suppression_path(self) -> None:
        source = CAMERA_READY_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("set -eu", source)
        self.assertNotIn("SKIP:", source)
        self.assertNotIn("|| true", source)
        self.assertNotIn("shellcheck disable", source)
        self.assertEqual(source.count("CAMERA_READY_BARE_METAL_PASS"), 1)

    def test_documented_camera_ready_invocation_preserves_script_failure(self) -> None:
        script = CAMERA_READY_SCRIPT.read_text(encoding="utf-8")
        guide = ARTIFACT_GUIDE.read_text(encoding="utf-8")
        paper = PAPER_SOURCE.read_text(encoding="utf-8")
        for source in (script, guide):
            self.assertIn("QPERIAPT_BARE_METAL_CONFIRMED=1", source)
            self.assertIn("bash -o pipefail", source)
            self.assertNotIn("sudo -E", source)
            self.assertNotIn("sudo sh camera-ready-bare-metal.sh", source)
        self.assertIn(r"QPERIAPT\_BARE\_METAL\_CONFIRMED=1", paper)
        self.assertNotIn("sudo sh", paper)

    def test_privileged_state_has_narrow_ownership_checked_contract(self) -> None:
        source = CAMERA_READY_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("root process is the narrow host-state supervisor", source)
        self.assertIn("--clear-groups", source)
        self.assertIn("--no-new-privs", source)
        self.assertIn("--inh-caps=-all", source)
        self.assertIn("cgroup.kill", source)
        self.assertIn("QPERIAPT_FROZEN_LAUNCHER=1", source)
        self.assertIn(
            "dedicated runner account must have a nologin/false shell", source
        )
        self.assertIn("source snapshot is not root-owned read-only", source)
        self.assertIn("cargo must be root-owned and not group/world writable", source)
        self.assertIn(
            "/sys/devices/system/cpu/cpufreq/policy*/scaling_governor", source
        )
        self.assertNotIn(
            "/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor", source
        )
        self.assertIn("NETEM_HANDLE=51ab:", source)
        self.assertIn('qdisc del dev lo root handle "$NETEM_HANDLE"', source)
        self.assertIn("refusing to delete non-identical state", source)
        self.assertIn("changed concurrently; refusing to overwrite it", source)
        self.assertIn("validate_sysctl_record", source)
        self.assertIn("validate_sysfs_record", source)
        self.assertIn('SYSFS_RECORDS=""', source)
        self.assertIn('SYSCTL_RECORDS=""', source)
        self.assertNotIn("governors.state", source)
        self.assertNotIn("sysctls.state", source)
        self.assertNotIn("docker run", source)
        self.assertIn("ct_mode=native", source)

    def test_root_launcher_and_early_cleanup_precede_runner_code(self) -> None:
        source = CAMERA_READY_SCRIPT.read_text(encoding="utf-8")
        launcher = source.index("QPERIAPT_FROZEN_LAUNCHER=1")
        early_trap = source.index("trap early_exit EXIT")
        work = source.index('WORK=$("$MKTEMP" -d "$WORK_ROOT/qperiapt-camera-ready.')
        runner = source.index("run_as_runner()")
        first_runner_call = source.index(
            "FROZEN_SOURCE_TREE_SHA256=$(canonical_source_digest)"
        )
        self.assertLess(launcher, early_trap)
        self.assertLess(early_trap, work)
        self.assertLess(work, runner)
        self.assertLess(runner, first_runner_call)
        self.assertIn(
            "executed root-owned launcher does not match the clean Git archive", source
        )

    def test_runner_descendants_and_measurement_binaries_are_frozen(self) -> None:
        source = CAMERA_READY_SCRIPT.read_text(encoding="utf-8")
        self.assertIn('>"$run_group/cgroup.procs"', source)
        self.assertIn('>"$run_group/cgroup.kill"', source)
        self.assertIn("cgroup_has_processes", source)
        netem_copy = source.index('freeze_runner_binary "$BUILT_NETEM_BIN" "$BIN"')
        netem_run = source.index('"$TASKSET" -c "$PIN" "$BIN"')
        ct_copy = source.index(
            'freeze_runner_binary "$BUILT_CT_ROOT/ct_leaky_control" '
            '"$LEAKY_CONTROL_BIN"'
        )
        ct_run = source.index('run_memcheck "$LEAKY_CONTROL_BIN" planted leaky-control')
        self.assertLess(netem_copy, netem_run)
        self.assertLess(ct_copy, ct_run)
        self.assertIn('HOME="$VALIDATION_HOME"', source)
        self.assertIn('"$CHMOD" 0550 "$binary_target"', source)

    def test_runner_sandbox_is_bounded_locked_and_cleaned_before_work_removal(
        self,
    ) -> None:
        source = CAMERA_READY_SCRIPT.read_text(encoding="utf-8")
        sandbox = CAMERA_SANDBOX_SCRIPT.read_text(encoding="utf-8")
        lock = source.index('"$FLOCK" -n 9')
        process_scan = source.index('pathlib.Path("/proc").glob')
        restore_unmount = source.rindex("if ! cleanup_runner_fs; then")
        work_remove = source.index('if ! "$RM" -rf -- "$WORK"; then')
        self.assertLess(lock, process_scan)
        self.assertLess(restore_unmount, work_remove)
        self.assertIn("size=8589934592,nr_inodes=524288", source)
        self.assertIn('"$UNSHARE" --mount --ipc --net', source)
        self.assertIn('"$UNSHARE" --mount --ipc --', source)
        self.assertIn("run_as_measurement", source)
        self.assertIn("ro=recursive", sandbox)
        self.assertIn("writable mount escaped camera-ready sandbox", sandbox)
        self.assertIn("qperiapt-private-tmp", sandbox)

    def test_camera_gate_requires_raw_bundle_and_scoped_marker(self) -> None:
        source = PROOF_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("QPERIAPT_CAMERA_READY_BUNDLE", source)
        self.assertIn("must explicitly name the root-owned run-id bundle", source)
        self.assertNotIn(
            "QPERIAPT_CAMERA_READY_BUNDLE:-$ROOT/target/camera-ready/bundle", source
        )
        self.assertIn("camera_ready_proof.py verify", source)
        self.assertIn("--bundle", source)
        self.assertIn("--max-age-seconds", source)
        self.assertIn("PROOF_TO_BYTE_CAMERA_READY_CAPTURE_EVIDENCE_PASS", source)
        self.assertIn("producer_origin_not_independent_attestation", source)
        self.assertNotIn("PROOF_TO_BYTE_CAMERA_READY_PASS", source)

    def test_primary_transcript_freezes_source_toolchain_and_binaries(self) -> None:
        source = CAMERA_READY_SCRIPT.read_text(encoding="utf-8")
        self.assertIn(
            "camera-ready primary evidence requires a clean source tree", source
        )
        self.assertIn("build --frozen --release", source)
        self.assertIn('CARGO_TARGET_DIR="$RUNNER_ROOT/target-$build_lane"', source)
        self.assertIn("validate-cargo-seed", source)
        self.assertIn("run_as_builder", source)
        self.assertIn('"$UNSHARE" --net --', source)
        self.assertIn('>"$run_group/pids.max"', source)
        self.assertIn('>"$run_group/memory.max"', source)
        self.assertIn("archive --format=tar", source)
        self.assertIn("source-archive-sha256", source)
        self.assertIn("FROZEN_SOURCE_TREE_SHA256=$(canonical_source_digest)", source)
        self.assertIn("FINAL_SOURCE_TREE_SHA256=$(canonical_source_digest)", source)
        self.assertIn("camera-ready bundle", source)
        self.assertIn("netem-binary-sha256", source)
        self.assertIn("mlkem-ct-binary-sha256", source)
        self.assertIn("leaky-control-ct-binary-sha256", source)
        self.assertNotIn("hqc-ct-binary-sha256", source)
        self.assertEqual(
            proof_to_byte_inputs.PROOF_TO_BYTE_INPUT_PATHS.get(
                "camera_ready_sandbox_script_sha256"
            ),
            "artifact/camera-ready-sandbox.sh",
        )

    def test_camera_harness_and_verifier_tool_sets_match(self) -> None:
        source = CAMERA_READY_SCRIPT.read_text(encoding="utf-8")
        recorded = set(re.findall(r'"([a-z0-9-]+)\|\$[A-Z0-9_]+"', source))
        self.assertEqual(recorded, EXPECTED_TOOLS)

    def test_success_marker_follows_complete_matrix_and_discriminator_assertions(
        self,
    ) -> None:
        source = CAMERA_READY_SCRIPT.read_text(encoding="utf-8")
        marker = source.index("CAMERA_READY_BARE_METAL_PASS")
        matrix_gate = source.index('[ "$NETEM_RUNS" -eq "$EXPECTED_NETEM_RUNS" ]')
        mlkem_gate = source.index('[ "$MLKEM_PROBE_ERRORS" -eq 0 ]')
        leaky_control_gate = source.index('[ "$LEAKY_CONTROL_ERRORS" -gt 0 ]')
        cleanup_gate = source.rindex("if ! restore; then")
        source_recheck = source.index(
            '[ "$FINAL_SOURCE_TREE_SHA256" = "$FROZEN_SOURCE_TREE_SHA256" ]'
        )
        binary_recheck = source.index(
            '[ "$(sha256_file "$LEAKY_CONTROL_BIN")" = "$LEAKY_CONTROL_BIN_SHA256" ]'
        )
        self.assertLess(matrix_gate, marker)
        self.assertLess(mlkem_gate, marker)
        self.assertLess(leaky_control_gate, marker)
        self.assertLess(binary_recheck, marker)
        self.assertLess(source_recheck, marker)
        self.assertLess(cleanup_gate, marker)


if __name__ == "__main__":
    unittest.main()
