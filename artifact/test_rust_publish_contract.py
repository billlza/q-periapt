#!/usr/bin/env python3

from __future__ import annotations

import json
import hashlib
import os
import pathlib
import subprocess
import tempfile
import threading
import unittest
import urllib.error
from unittest import mock

import rust_publish_contract
from bounded_process import BoundedProcessError, BoundedResult, REAP_TIMEOUT_SECONDS
from git_provenance import GIT, GitProvenanceError, WorktreeInspection

from rust_publish_contract import (
    RUSTSEC_ADVISORY_DB_URL,
    RUST_CRATES_IO_SPARSE_INDEX,
    RUST_FUZZ_LOCAL_CRATES,
    RUST_NORMALIZED_LOCAL_CRATES,
    RUST_PUBLISHABLE_CRATES,
    RUST_SPARSE_LOCK_MAX_BYTES,
    RUST_SPARSE_MAX_REGISTRY_PACKAGES,
    RUST_SPARSE_INDEX_MAX_BYTES,
    RUST_SPARSE_REQUEST_TIMEOUT_SECONDS,
    RUST_SPARSE_INDEX_USER_AGENT,
    RUST_SPARSE_HELPER_ENVIRONMENT,
    RUST_SPARSE_HELPER_MAX_OUTPUT_BYTES,
    RUST_SPARSE_HELPER_TIMEOUT_SECONDS,
    RUST_SPARSE_AGGREGATE_MAX_BYTES,
    RUST_SPARSE_TOTAL_TIMEOUT_SECONDS,
    RUST_WORKSPACE_AUDIT_MARKER_PREFIX,
    RUST_WORKSPACE_DEPENDENCY_AUDIT_TIMEOUT_SECONDS,
    RUST_WORKSPACE_LOCAL_CRATES,
    RustPublishContractError,
    create_owned_package_directory,
    inspect_package_source,
    remove_owned_package_directory,
    validate_cargo_output,
    validate_cargo_package_completion,
    validate_mlkem_native_build_surface,
    validate_packaged_mlkem_native_local_sources,
    validate_crates_io_sparse_yanked,
    validate_rust_package_contract_transcript,
    validate_rustsec_advisory_database,
)


ROOT = pathlib.Path(__file__).resolve().parents[1]
SYS_CRATE = ROOT / "crates" / "q-periapt-mlkem-native-sys"
ADVISORY_COMMIT = "0123456789abcdef0123456789abcdef01234567"
SOURCE_COMMIT = "89abcdef0123456789abcdef0123456789abcdef"
NORMALIZED_LOCK_SHA256 = "c" * 64
REGISTRY_PACKAGES = (
    ("itoa", "1.0.15", "a" * 64),
    ("serde", "1.0.228", "b" * 64),
)


def normalized_cargo_lock(
    *,
    local_names: set[str] | frozenset[str] = RUST_NORMALIZED_LOCAL_CRATES,
    registry_packages: tuple[tuple[str, str, str], ...] = REGISTRY_PACKAGES,
    registry_source: str = "registry+https://github.com/rust-lang/crates.io-index",
) -> bytes:
    lines = ["version = 4", ""]
    for name in sorted(local_names):
        lines.extend(
            (
                "[[package]]",
                f'name = "{name}"',
                'version = "0.1.0-alpha.2"',
                "",
            )
        )
    for name, version, checksum in registry_packages:
        lines.extend(
            (
                "[[package]]",
                f'name = "{name}"',
                f'version = "{version}"',
                f'source = "{registry_source}"',
                f'checksum = "{checksum}"',
                "",
            )
        )
    return "\n".join(lines).encode("utf-8")


def sparse_index_payload(
    name: str,
    records: tuple[tuple[str, str, bool], ...],
) -> bytes:
    return b"".join(
        json.dumps(
            {
                "name": name,
                "vers": version,
                "deps": [],
                "cksum": checksum,
                "features": {},
                "yanked": yanked,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
        for version, checksum, yanked in records
    )


class SparseResponse:
    def __init__(
        self,
        url: str,
        payload: bytes,
        *,
        status: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status = status
        self.headers = {} if headers is None else headers
        self._url = url
        self._payload = payload
        self._offset = 0

    def __enter__(self) -> SparseResponse:
        return self

    def __exit__(self, *_arguments: object) -> None:
        return None

    def geturl(self) -> str:
        return self._url

    def read(self, maximum: int) -> bytes:
        chunk = self._payload[self._offset : self._offset + maximum]
        self._offset += len(chunk)
        return chunk


def valid_rust_package_contract_transcript() -> list[str]:
    lines = [
        "RUST_CARGO_HOME_ISOLATION_PASS mode=0700 "
        "ambient_cargo_home_data=unused",
        "RUST_PACKAGE_TOOLCHAIN_PASS "
        "rustc=1.96.1 cargo=1.96.1 cargo-audit=0.22.2",
        f"RUST_PACKAGE_SOURCE_PASS commit={SOURCE_COMMIT} clean=1",
    ]
    lines.extend(
        f"RUST_PACKAGE_LIST_PASS {crate} files=1"
        for crate in RUST_PUBLISHABLE_CRATES
    )
    lines.extend(
            "RUST_PACKAGE_VERIFICATION_PASS "
        f"{crate} registry=crates-io upload=not-attempted"
        for crate in RUST_PUBLISHABLE_CRATES
    )
    lines.extend(
        (
            "RUST_CRATES_IO_LOCK_VERIFY_PASS registry_packages=2 "
            "index=sparse-https checksums=exact yanked=0 "
            f"normalized_lock_sha256={NORMALIZED_LOCK_SHA256}",
            "RUST_BACKENDS_NORMALIZED_AUDIT_PASS",
            "RUST_ADVISORY_DB_PASS "
            f"origin={RUSTSEC_ADVISORY_DB_URL} commit={ADVISORY_COMMIT} "
            "clean=1 isolated_cargo_home=1",
            f"RUST_NORMALIZED_LOCK_STABILITY_PASS sha256={NORMALIZED_LOCK_SHA256}",
            "RUST_OWNED_PACKAGE_DIRECTORY_CLEANUP_PASS cargo-home",
            "RUST_PACKAGE_CONTRACT_PASS dirty=0 registry=crates-io "
            "upload=not-attempted completed_at=2026-08-13T03:04:05Z",
        )
    )
    return lines


class RustPublishContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.build_rs = (SYS_CRATE / "build.rs").read_text(encoding="utf-8")
        cls.build_support = (SYS_CRATE / "src" / "build_support.rs").read_text(
            encoding="utf-8"
        )
        cls.bridge_c = (SYS_CRATE / "src" / "mlkem_bridge.c").read_text(
            encoding="utf-8"
        )
        cls.bridge_h = (SYS_CRATE / "src" / "mlkem_bridge.h").read_text(
            encoding="utf-8"
        )
        cls.local_config = (SYS_CRATE / "src" / "mlkem_config.h").read_text(
            encoding="utf-8"
        )
        cls.publish_contract_script = (
            ROOT / "artifact" / "rust-publish-contract.sh"
        ).read_text(encoding="utf-8")

    def validate(
        self,
        *,
        build_rs: str | None = None,
        build_support: str | None = None,
        bridge_c: str | None = None,
        bridge_h: str | None = None,
        local_config: str | None = None,
    ) -> None:
        validate_mlkem_native_build_surface(
            build_rs=self.build_rs if build_rs is None else build_rs,
            build_support=(
                self.build_support if build_support is None else build_support
            ),
            bridge_c=self.bridge_c if bridge_c is None else bridge_c,
            bridge_h=self.bridge_h if bridge_h is None else bridge_h,
            local_config=self.local_config if local_config is None else local_config,
        )

    @staticmethod
    def advisory_database(temporary_root: str) -> pathlib.Path:
        database = pathlib.Path(temporary_root) / "advisory-db"
        database.mkdir()
        (database / ".git").mkdir()
        return database

    def test_repository_build_surface_passes(self) -> None:
        self.validate()

    def test_warning_free_complete_cargo_package_output_passes(self) -> None:
        streams = (
            "",
            "\n".join(
                (
                    "   Packaging q-periapt-core v0.1.0-alpha.2 (/source)",
                    "    Packaged 6 files, 90.6KiB (31.5KiB compressed)",
                    "   Verifying q-periapt-core v0.1.0-alpha.2 (/package)",
                    "    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.1s",
                )
            ),
        )
        validate_cargo_output("cargo-package-q-periapt-core", streams)
        validate_cargo_package_completion("q-periapt-core", streams)

    def test_every_cargo_warning_is_rejected_without_an_allowlist(self) -> None:
        for warning in (
            "warning: aborting upload due to dry run",
            "warning: manifest has no description",
            "WARNING: future incompatibility",
        ):
            with self.subTest(warning=warning):
                with self.assertRaisesRegex(
                    RustPublishContractError,
                    "emitted a warning",
                ):
                    validate_cargo_output("cargo-package", ("normal output", warning))

    def test_incomplete_cargo_package_phases_are_rejected(self) -> None:
        complete = (
            "Packaging q-periapt-core ",
            "Packaged ",
            "Verifying q-periapt-core ",
            "Finished `dev` profile",
        )
        for omitted in complete:
            with self.subTest(omitted=omitted):
                output = "\n".join(marker for marker in complete if marker != omitted)
                with self.assertRaisesRegex(
                    RustPublishContractError,
                    "is incomplete",
                ):
                    validate_cargo_package_completion("q-periapt-core", (output,))

    def test_owned_package_directory_cleanup_is_anchored_and_no_follow(self) -> None:
        package_path, package_device, package_inode = create_owned_package_directory(
            "qperiapt-package-verification."
        )
        external_path, external_device, external_inode = create_owned_package_directory(
            "qperiapt-package-inspection."
        )
        try:
            nested = package_path / "nested"
            nested.mkdir()
            (nested / "payload").write_text("package payload", encoding="utf-8")
            (package_path / "external-link").symlink_to(
                external_path, target_is_directory=True
            )
            (external_path / "must-remain").write_text("external", encoding="utf-8")

            remove_owned_package_directory(
                package_path, package_device, package_inode
            )
            self.assertFalse(package_path.exists())
            self.assertEqual(
                (external_path / "must-remain").read_text(encoding="utf-8"),
                "external",
            )
        finally:
            if package_path.exists() and not package_path.is_symlink():
                remove_owned_package_directory(
                    package_path, package_device, package_inode
                )
            if external_path.exists() and not external_path.is_symlink():
                remove_owned_package_directory(
                    external_path, external_device, external_inode
                )

    def test_owned_package_directory_replacement_is_preserved_and_rejected(self) -> None:
        package_path, package_device, package_inode = create_owned_package_directory(
            "qperiapt-package-verification."
        )
        detached_path = package_path.with_name(package_path.name + ".detached")
        os.rename(package_path, detached_path)
        package_path.mkdir(mode=0o700)
        try:
            with self.assertRaisesRegex(
                RustPublishContractError,
                "identity changed before cleanup",
            ):
                remove_owned_package_directory(
                    package_path, package_device, package_inode
                )
            self.assertTrue(package_path.is_dir())
        finally:
            package_path.rmdir()
            os.rename(detached_path, package_path)
            remove_owned_package_directory(package_path, package_device, package_inode)

    def test_owned_package_directory_symlink_replacement_is_not_followed(self) -> None:
        package_path, package_device, package_inode = create_owned_package_directory(
            "qperiapt-package-verification."
        )
        external_path, external_device, external_inode = create_owned_package_directory(
            "qperiapt-package-inspection."
        )
        detached_path = package_path.with_name(package_path.name + ".detached")
        os.rename(package_path, detached_path)
        package_path.symlink_to(external_path, target_is_directory=True)
        try:
            with self.assertRaisesRegex(
                RustPublishContractError,
                "not a directory",
            ):
                remove_owned_package_directory(
                    package_path, package_device, package_inode
                )
            self.assertTrue(package_path.is_symlink())
            self.assertTrue(external_path.is_dir())
        finally:
            package_path.unlink()
            os.rename(detached_path, package_path)
            remove_owned_package_directory(package_path, package_device, package_inode)
            remove_owned_package_directory(external_path, external_device, external_inode)

    def test_owned_cargo_home_creation_and_cleanup_uses_the_same_boundary(self) -> None:
        cargo_home, cargo_home_device, cargo_home_inode = (
            create_owned_package_directory("qperiapt-package-cargo-home.")
        )
        try:
            metadata = cargo_home.lstat()
            self.assertEqual(metadata.st_uid, os.getuid())
            self.assertEqual(metadata.st_mode & 0o777, 0o700)
            (cargo_home / "registry").mkdir()
            (cargo_home / "registry" / "cache").write_bytes(b"cache")
            remove_owned_package_directory(
                cargo_home,
                cargo_home_device,
                cargo_home_inode,
            )
            self.assertFalse(cargo_home.exists())
        finally:
            if cargo_home.exists() and not cargo_home.is_symlink():
                remove_owned_package_directory(
                    cargo_home,
                    cargo_home_device,
                    cargo_home_inode,
                )

    def test_package_source_inspection_ignores_hostile_git_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_root:
            repository = pathlib.Path(temporary_root) / "source"

            def git(*arguments: str) -> str:
                process = subprocess.run(
                    [GIT, *arguments],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                return process.stdout.strip()

            git("init", "--quiet", str(repository))
            git("-C", str(repository), "config", "user.name", "Contract Test")
            git(
                "-C",
                str(repository),
                "config",
                "user.email",
                "contract-test@example.invalid",
            )
            (repository / "source.txt").write_text("source\n", encoding="utf-8")
            git("-C", str(repository), "add", "source.txt")
            git("-C", str(repository), "commit", "--quiet", "-m", "fixture")
            expected_commit = git("-C", str(repository), "rev-parse", "HEAD")

            hostile_environment = {
                "GIT_DIR": "/hostile/git-dir",
                "GIT_WORK_TREE": "/hostile/work-tree",
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "core.fsmonitor",
                "GIT_CONFIG_VALUE_0": "!false",
                "GIT_CONFIG_PARAMETERS": "'core.hooksPath'='/hostile/hooks'",
                "GIT_OBJECT_DIRECTORY": "/hostile/objects",
                "GIT_ALTERNATE_OBJECT_DIRECTORIES": "/hostile/alternates",
                "HOME": "/hostile/home",
                "PATH": "/hostile/bin",
            }
            with mock.patch.dict(os.environ, hostile_environment, clear=False):
                self.assertEqual(
                    inspect_package_source(repository, allow_dirty=False),
                    (expected_commit, False),
                )
                (repository / "untracked.txt").write_text(
                    "dirty\n",
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(
                    RustPublishContractError,
                    "source worktree is dirty",
                ):
                    inspect_package_source(repository, allow_dirty=False)
                self.assertEqual(
                    inspect_package_source(repository, allow_dirty=True),
                    (expected_commit, True),
                )

    def test_package_source_inspection_rejects_or_reports_dirty_state(self) -> None:
        dirty = WorktreeInspection(
            commit=SOURCE_COMMIT,
            dirty=True,
            reasons=("untracked source-input paths present: 1",),
        )
        with mock.patch.object(
            rust_publish_contract,
            "inspect_worktree",
            return_value=dirty,
        ):
            with self.assertRaisesRegex(
                RustPublishContractError,
                "source worktree is dirty.*untracked",
            ):
                inspect_package_source(ROOT, allow_dirty=False)
            self.assertEqual(
                inspect_package_source(ROOT, allow_dirty=True),
                (SOURCE_COMMIT, True),
            )

    def test_package_source_inspection_translates_provenance_failures(self) -> None:
        with mock.patch.object(
            rust_publish_contract,
            "inspect_worktree",
            side_effect=GitProvenanceError("synthetic failure"),
        ):
            with self.assertRaisesRegex(
                RustPublishContractError,
                "source provenance: synthetic failure",
            ):
                inspect_package_source(ROOT, allow_dirty=False)

        malformed = WorktreeInspection(
            commit="not-a-commit",
            dirty=False,
            reasons=(),
        )
        with mock.patch.object(
            rust_publish_contract,
            "inspect_worktree",
            return_value=malformed,
        ):
            with self.assertRaisesRegex(
                RustPublishContractError,
                "source commit is malformed",
            ):
                inspect_package_source(ROOT, allow_dirty=False)

        with self.assertRaisesRegex(
            RustPublishContractError,
            "dirty policy must be a boolean",
        ):
            inspect_package_source(ROOT, allow_dirty=1)

    def test_sparse_yanked_verifier_accepts_exact_normalized_lock(self) -> None:
        requested: list[str] = []
        expected = {
            name: sparse_index_payload(name, ((version, checksum, False),))
            for name, version, checksum in REGISTRY_PACKAGES
        }

        def fetch(url: str) -> bytes:
            requested.append(url)
            return expected[url.rsplit("/", 1)[-1]]

        self.assertEqual(
            rust_publish_contract._validate_crates_io_sparse_yanked_with_fetcher(
                normalized_cargo_lock(),
                fetcher=fetch,
            ),
            2,
        )
        self.assertEqual(
            requested,
            [
                f"{RUST_CRATES_IO_SPARSE_INDEX}/it/oa/itoa",
                f"{RUST_CRATES_IO_SPARSE_INDEX}/se/rd/serde",
            ],
        )

        multi_version_lock = normalized_cargo_lock(
            registry_packages=(
                ("serde", "1.0.227", "c" * 64),
                ("serde", "1.0.228", "b" * 64),
            )
        )
        multi_version_requests: list[str] = []

        def fetch_multi_version(url: str) -> bytes:
            multi_version_requests.append(url)
            return sparse_index_payload(
                "serde",
                (
                    ("1.0.227", "c" * 64, False),
                    ("1.0.228", "b" * 64, False),
                ),
            )

        self.assertEqual(
            rust_publish_contract._validate_crates_io_sparse_yanked_with_fetcher(
                multi_version_lock,
                fetcher=fetch_multi_version,
            ),
            2,
        )
        self.assertEqual(
            multi_version_requests,
            [f"{RUST_CRATES_IO_SPARSE_INDEX}/se/rd/serde"],
        )

    def test_sparse_index_path_is_canonical_for_every_length_class(self) -> None:
        expected = {
            "A": "1/a",
            "Ab": "2/ab",
            "Abc": "3/a/abc",
            "Abcd": "ab/cd/abcd",
            "Serde_JSON": "se/rd/serde_json",
        }
        for name, path in expected.items():
            with self.subTest(name=name):
                self.assertEqual(
                    rust_publish_contract._crates_io_sparse_path(name),
                    path,
                )

    def test_sparse_yanked_verifier_rejects_malformed_lock_boundaries(self) -> None:
        base = normalized_cargo_lock()
        duplicate_registry = base + b"\n" + b"\n".join(
            (
                b"[[package]]",
                b'name = "itoa"',
                b'version = "1.0.15"',
                b'source = "registry+https://github.com/rust-lang/crates.io-index"',
                f'checksum = {json.dumps("a" * 64)}'.encode(),
                b"",
            )
        )
        local_checksum = base.replace(
            b'name = "q-periapt-backends"\nversion = "0.1.0-alpha.2"',
            b'name = "q-periapt-backends"\nversion = "0.1.0-alpha.2"\n'
            + f'checksum = {json.dumps("c" * 64)}'.encode(),
            1,
        )
        cases = {
            "non-UTF-8": b"\xff",
            "invalid TOML": b"version = [",
            "wrong schema": base.replace(b"version = 4", b"version = 3", 1),
            "missing local": normalized_cargo_lock(
                local_names=set(RUST_NORMALIZED_LOCAL_CRATES)
                - {"q-periapt-core"}
            ),
            "extra local": normalized_cargo_lock(
                local_names=set(RUST_NORMALIZED_LOCAL_CRATES) | {"local-extra"}
            ),
            "non-crates source": normalized_cargo_lock(
                registry_source="git+https://example.invalid/source.git"
            ),
            "invalid registry name": normalized_cargo_lock(
                registry_packages=(("bad/name", "1.0.0", "a" * 64),)
            ),
            "invalid version": normalized_cargo_lock(
                registry_packages=(("itoa", "01.0.0", "a" * 64),)
            ),
            "invalid checksum": normalized_cargo_lock(
                registry_packages=(("itoa", "1.0.0", "A" * 64),)
            ),
            "local resolved from registry": normalized_cargo_lock(
                registry_packages=(
                    ("q-periapt-core", "0.1.0-alpha.2", "a" * 64),
                )
            ),
            "duplicate registry": duplicate_registry,
            "local checksum": local_checksum,
            "no registry": normalized_cargo_lock(registry_packages=()),
            "lock oversize": b"#" * (RUST_SPARSE_LOCK_MAX_BYTES + 1),
            "package limit": normalized_cargo_lock(
                registry_packages=tuple(
                    (f"limit{index:03d}", "1.0.0", f"{index:064x}")
                    for index in range(RUST_SPARSE_MAX_REGISTRY_PACKAGES + 1)
                )
            ),
            "case ambiguous": normalized_cargo_lock(
                registry_packages=(
                    ("Serde", "1.0.227", "a" * 64),
                    ("serde", "1.0.228", "b" * 64),
                )
            ),
        }

        def unused_fetch(_url: str) -> bytes:
            self.fail("malformed lock must fail before any sparse index request")

        for label, lock_data in cases.items():
            with self.subTest(label=label):
                with self.assertRaises(RustPublishContractError):
                    rust_publish_contract._validate_crates_io_sparse_yanked_with_fetcher(
                        lock_data,
                        fetcher=unused_fetch,
                    )

    def test_sparse_yanked_verifier_rejects_every_index_failure(self) -> None:
        lock_data = normalized_cargo_lock(
            registry_packages=(("itoa", "1.0.15", "a" * 64),)
        )
        valid = sparse_index_payload("itoa", (("1.0.15", "a" * 64, False),))
        cases: dict[str, object] = {
            "missing": sparse_index_payload(
                "itoa", (("1.0.14", "a" * 64, False),)
            ),
            "duplicate": valid + valid,
            "malformed JSON": b"{\n",
            "duplicate JSON key": (
                b'{"name":"itoa","name":"itoa","vers":"1.0.15",'
                + f'"cksum":"{"a" * 64}","yanked":false}}\n'.encode()
            ),
            "wrong name": sparse_index_payload(
                "other", (("1.0.15", "a" * 64, False),)
            ),
            "bad version": (
                b'{"name":"itoa","vers":"01.0.0",'
                + f'"cksum":"{"a" * 64}","yanked":false}}\n'.encode()
            ),
            "bad checksum": sparse_index_payload(
                "itoa", (("1.0.15", "A" * 64, False),)
            ),
            "checksum mismatch": sparse_index_payload(
                "itoa", (("1.0.15", "b" * 64, False),)
            ),
            "yanked": sparse_index_payload(
                "itoa", (("1.0.15", "a" * 64, True),)
            ),
            "missing yanked": (
                b'{"name":"itoa","vers":"1.0.15",'
                + f'"cksum":"{"a" * 64}"}}\n'.encode()
            ),
            "bad yanked": (
                b'{"name":"itoa","vers":"1.0.15",'
                + f'"cksum":"{"a" * 64}","yanked":0}}\n'.encode()
            ),
            "no final newline": valid.rstrip(b"\n"),
            "blank line": valid + b"\n",
            "oversize": b"x" * (RUST_SPARSE_INDEX_MAX_BYTES + 1),
            "non-bytes": "not bytes",
            "network": RuntimeError("synthetic network failure"),
        }
        for label, outcome in cases.items():
            with self.subTest(label=label):
                def fetch(_url: str, result: object = outcome) -> bytes:
                    if isinstance(result, Exception):
                        raise result
                    return result

                with self.assertRaises(RustPublishContractError):
                    rust_publish_contract._validate_crates_io_sparse_yanked_with_fetcher(
                        lock_data,
                        fetcher=fetch,
                    )

        def interrupted_fetch(_url: str) -> bytes:
            raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            rust_publish_contract._validate_crates_io_sparse_yanked_with_fetcher(
                lock_data,
                fetcher=interrupted_fetch,
            )

    def test_sparse_yanked_verifier_uses_at_most_eight_workers(self) -> None:
        registry_packages = tuple(
            (f"crate{index:02d}", "1.0.0", f"{index:064x}")
            for index in range(12)
        )
        state_lock = threading.Lock()
        eight_active = threading.Event()
        active = 0
        maximum_active = 0

        def fetch(url: str) -> bytes:
            nonlocal active, maximum_active
            name = url.rsplit("/", 1)[-1]
            index = int(name.removeprefix("crate"))
            with state_lock:
                active += 1
                maximum_active = max(maximum_active, active)
                if active == 8:
                    eight_active.set()
            if not eight_active.wait(timeout=2):
                raise RuntimeError("sparse verifier did not schedule eight workers")
            try:
                return sparse_index_payload(
                    name,
                    (("1.0.0", f"{index:064x}", False),),
                )
            finally:
                with state_lock:
                    active -= 1

        self.assertEqual(
            rust_publish_contract._validate_crates_io_sparse_yanked_with_fetcher(
                normalized_cargo_lock(registry_packages=registry_packages),
                fetcher=fetch,
            ),
            12,
        )
        self.assertEqual(maximum_active, 8)

    def test_sparse_yanked_verifier_never_submits_more_than_eight_futures(
        self,
    ) -> None:
        registry_packages = tuple(
            (f"crate{index:02d}", "1.0.0", f"{index:064x}")
            for index in range(12)
        )

        class ImmediateFuture:
            def __init__(
                self,
                owner: RecordingExecutor,
                function: object,
                arguments: tuple[object, ...],
            ) -> None:
                self.owner = owner
                self.function = function
                self.arguments = arguments
                self.resolved = False

            def result(self, *, timeout: float) -> bytes:
                self.owner.timeouts.append(timeout)
                if not self.resolved:
                    self.resolved = True
                    self.owner.outstanding -= 1
                return self.function(*self.arguments)

            def cancel(self) -> bool:
                if not self.resolved:
                    self.resolved = True
                    self.owner.outstanding -= 1
                return True

        class RecordingExecutor:
            instance: RecordingExecutor | None = None

            def __init__(self, *, max_workers: int, thread_name_prefix: str) -> None:
                self.max_workers = max_workers
                self.thread_name_prefix = thread_name_prefix
                self.outstanding = 0
                self.maximum_outstanding = 0
                self.timeouts: list[float] = []
                self.shutdown_calls: list[tuple[bool, bool]] = []
                RecordingExecutor.instance = self

            def submit(
                self,
                function: object,
                *arguments: object,
            ) -> ImmediateFuture:
                self.outstanding += 1
                self.maximum_outstanding = max(
                    self.maximum_outstanding,
                    self.outstanding,
                )
                return ImmediateFuture(self, function, arguments)

            def shutdown(
                self,
                *,
                wait: bool,
                cancel_futures: bool = False,
            ) -> None:
                self.shutdown_calls.append((wait, cancel_futures))

        def fetch(url: str) -> bytes:
            name = url.rsplit("/", 1)[-1]
            index = int(name.removeprefix("crate"))
            return sparse_index_payload(
                name,
                (("1.0.0", f"{index:064x}", False),),
            )

        with mock.patch.object(
            rust_publish_contract,
            "ThreadPoolExecutor",
            RecordingExecutor,
        ):
            self.assertEqual(
                rust_publish_contract._validate_crates_io_sparse_yanked_with_fetcher(
                    normalized_cargo_lock(registry_packages=registry_packages),
                    fetcher=fetch,
                ),
                12,
            )
        executor = RecordingExecutor.instance
        self.assertIsNotNone(executor)
        self.assertEqual(executor.max_workers, 8)
        self.assertEqual(executor.maximum_outstanding, 8)
        self.assertEqual(executor.outstanding, 0)
        self.assertEqual(executor.shutdown_calls, [(True, False)])
        self.assertEqual(len(executor.timeouts), 12)

        def interrupted_fetch(_url: str) -> bytes:
            raise KeyboardInterrupt

        RecordingExecutor.instance = None
        with (
            mock.patch.object(
                rust_publish_contract,
                "ThreadPoolExecutor",
                RecordingExecutor,
            ),
            self.assertRaises(KeyboardInterrupt),
        ):
            rust_publish_contract._validate_crates_io_sparse_yanked_with_fetcher(
                normalized_cargo_lock(
                    registry_packages=(("itoa", "1.0.15", "a" * 64),)
                ),
                fetcher=interrupted_fetch,
            )
        failed_executor = RecordingExecutor.instance
        self.assertIsNotNone(failed_executor)
        self.assertEqual(failed_executor.outstanding, 0)
        self.assertEqual(failed_executor.shutdown_calls, [(True, True)])

        RecordingExecutor.instance = None
        with (
            mock.patch.object(
                rust_publish_contract,
                "ThreadPoolExecutor",
                RecordingExecutor,
            ),
            mock.patch.object(
                rust_publish_contract,
                "RUST_SPARSE_AGGREGATE_MAX_BYTES",
                2 * RUST_SPARSE_INDEX_MAX_BYTES,
            ),
        ):
            self.assertEqual(
                rust_publish_contract._validate_crates_io_sparse_yanked_with_fetcher(
                    normalized_cargo_lock(registry_packages=registry_packages),
                    fetcher=fetch,
                ),
                12,
            )
        reserved_executor = RecordingExecutor.instance
        self.assertIsNotNone(reserved_executor)
        self.assertEqual(reserved_executor.maximum_outstanding, 2)
        self.assertEqual(reserved_executor.outstanding, 0)

    def test_sparse_yanked_verifier_enforces_the_total_deadline(self) -> None:
        lock_data = normalized_cargo_lock(
            registry_packages=(("itoa", "1.0.15", "a" * 64),)
        )
        payload = sparse_index_payload(
            "itoa",
            (("1.0.15", "a" * 64, False),),
        )
        with mock.patch.object(
            rust_publish_contract.time,
            "monotonic",
            side_effect=(100.0, 100.0 + RUST_SPARSE_TOTAL_TIMEOUT_SECONDS + 1),
        ):
            with self.assertRaisesRegex(
                RustPublishContractError,
                "exceeded the total deadline",
            ):
                rust_publish_contract._validate_crates_io_sparse_yanked_with_fetcher(
                    lock_data,
                    fetcher=lambda _url: payload,
                )

    def test_sparse_yanked_verifier_enforces_aggregate_payload_budget(self) -> None:
        lock_data = normalized_cargo_lock(
            registry_packages=(
                ("crate00", "1.0.0", "0" * 64),
                ("crate01", "1.0.0", "1" * 64),
            )
        )

        def fetch(url: str) -> bytes:
            name = url.rsplit("/", 1)[-1]
            checksum = "0" * 64 if name == "crate00" else "1" * 64
            return sparse_index_payload(name, (("1.0.0", checksum, False),))

        single_payload_size = len(fetch(f"{RUST_CRATES_IO_SPARSE_INDEX}/crate00"))
        with mock.patch.object(
            rust_publish_contract,
            "RUST_SPARSE_AGGREGATE_MAX_BYTES",
            single_payload_size,
        ):
            with self.assertRaisesRegex(
                RustPublishContractError,
                "aggregate.*(?:exceeds|cannot admit)",
            ):
                rust_publish_contract._validate_crates_io_sparse_yanked_with_fetcher(
                    lock_data,
                    fetcher=fetch,
                )
        self.assertEqual(RUST_SPARSE_AGGREGATE_MAX_BYTES, 128 * 1024 * 1024)

    def test_default_sparse_fetcher_fixes_request_and_resource_boundaries(self) -> None:
        url = f"{RUST_CRATES_IO_SPARSE_INDEX}/it/oa/itoa"
        payload = b"payload\n"
        response = SparseResponse(
            url,
            payload,
            headers={"Content-Length": str(len(payload))},
        )
        with mock.patch.object(
            rust_publish_contract.urllib.request,
            "urlopen",
            return_value=response,
        ) as urlopen:
            self.assertEqual(
                rust_publish_contract._fetch_crates_io_sparse_entry(url),
                payload,
            )
        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url, url)
        self.assertEqual(
            urlopen.call_args.kwargs["timeout"],
            RUST_SPARSE_REQUEST_TIMEOUT_SECONDS,
        )
        headers = {key.casefold(): value for key, value in request.header_items()}
        self.assertEqual(headers["user-agent"], RUST_SPARSE_INDEX_USER_AGENT)
        self.assertEqual(headers["accept-encoding"], "identity")
        self.assertEqual(headers["accept"], "application/json")

        failures = {
            "status": SparseResponse(url, payload, status=404),
            "redirect": SparseResponse(
                "https://example.invalid/redirect",
                payload,
            ),
            "malformed length": SparseResponse(
                url,
                payload,
                headers={"Content-Length": "unknown"},
            ),
            "declared oversize": SparseResponse(
                url,
                payload,
                headers={
                    "Content-Length": str(RUST_SPARSE_INDEX_MAX_BYTES + 1)
                },
            ),
            "actual oversize": SparseResponse(
                url,
                b"x" * (RUST_SPARSE_INDEX_MAX_BYTES + 1),
            ),
            "network": urllib.error.URLError("synthetic network failure"),
        }
        for label, outcome in failures.items():
            with self.subTest(label=label):
                with mock.patch.object(
                    rust_publish_contract.urllib.request,
                    "urlopen",
                    side_effect=outcome if isinstance(outcome, Exception) else None,
                    return_value=None if isinstance(outcome, Exception) else outcome,
                ):
                    with self.assertRaises(RustPublishContractError):
                        rust_publish_contract._fetch_crates_io_sparse_entry(url)

    def test_public_sparse_verifier_uses_one_hard_wall_helper_and_cleans_input(
        self,
    ) -> None:
        lock_data = normalized_cargo_lock()
        lock_sha256 = hashlib.sha256(lock_data).hexdigest()
        calls: list[tuple[tuple[str, ...], dict[str, object]]] = []
        helper_input: pathlib.Path | None = None

        def runner(
            command: tuple[str, ...],
            **arguments: object,
        ) -> BoundedResult:
            nonlocal helper_input
            calls.append((command, arguments))
            helper_input = pathlib.Path(command[-2])
            self.assertEqual(helper_input.read_bytes(), lock_data)
            self.assertEqual(command[-1], lock_sha256)
            return BoundedResult(
                0,
                json.dumps(
                    {
                        "lock_sha256": lock_sha256,
                        "ok": True,
                        "registry_packages": 2,
                        "schema": 1,
                    },
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8"),
            )

        self.assertEqual(
            rust_publish_contract._validate_crates_io_sparse_via_helper(
                lock_data,
                runner=runner,
            ),
            2,
        )
        self.assertIsNotNone(helper_input)
        self.assertFalse(helper_input.parent.exists())
        self.assertEqual(len(calls), 1)
        command, arguments = calls[0]
        self.assertEqual(command[0], "/bin/sh")
        self.assertTrue(command[1].endswith("/artifact/python-run.sh"))
        self.assertTrue(command[2].endswith("/artifact/rust_publish_contract.py"))
        self.assertEqual(command[3], "verify-crates-io-sparse-worker")
        self.assertEqual(
            arguments,
            {
                "environment": RUST_SPARSE_HELPER_ENVIRONMENT,
                "maximum_bytes": RUST_SPARSE_HELPER_MAX_OUTPUT_BYTES,
                "stderr": subprocess.STDOUT,
                "timeout_seconds": RUST_SPARSE_HELPER_TIMEOUT_SECONDS,
            },
        )
        self.assertEqual(
            RUST_SPARSE_HELPER_TIMEOUT_SECONDS + REAP_TIMEOUT_SECONDS,
            RUST_SPARSE_TOTAL_TIMEOUT_SECONDS,
        )

    def test_public_sparse_verifier_fails_closed_on_every_helper_boundary(
        self,
    ) -> None:
        lock_data = normalized_cargo_lock()
        lock_sha256 = hashlib.sha256(lock_data).hexdigest()
        outcomes: tuple[object, ...] = (
            BoundedProcessError("timeout", "synthetic hard timeout"),
            BoundedResult(7, b"helper failure"),
            BoundedResult(1, b"\xff"),
            BoundedResult(0, b"not JSON"),
            BoundedResult(0, b'{"schema":1,"registry_packages":2}'),
            BoundedResult(
                0,
                json.dumps(
                    {
                        "lock_sha256": "0" * 64,
                        "registry_packages": 2,
                        "schema": 1,
                    }
                ).encode(),
            ),
            BoundedResult(
                0,
                json.dumps(
                    {
                        "lock_sha256": lock_sha256,
                        "registry_packages": True,
                        "schema": 1,
                    }
                ).encode(),
            ),
            BoundedResult(
                1,
                json.dumps(
                    {
                        "error_kind": "verification",
                        "message": "synthetic checksum mismatch",
                        "ok": False,
                        "schema": 1,
                    }
                ).encode(),
            ),
        )
        for outcome in outcomes:
            with self.subTest(outcome=outcome):
                directories: list[pathlib.Path] = []

                def runner(
                    command: tuple[str, ...],
                    **_arguments: object,
                ) -> BoundedResult:
                    directories.append(pathlib.Path(command[-2]).parent)
                    if isinstance(outcome, Exception):
                        raise outcome
                    return outcome

                expected = (
                    "synthetic checksum mismatch"
                    if isinstance(outcome, BoundedResult)
                    and outcome.returncode == 1
                    and b"checksum" in outcome.stdout
                    else None
                )
                if expected is None:
                    with self.assertRaises(RustPublishContractError):
                        rust_publish_contract._validate_crates_io_sparse_via_helper(
                            lock_data,
                            runner=runner,
                        )
                else:
                    with self.assertRaisesRegex(RustPublishContractError, expected):
                        rust_publish_contract._validate_crates_io_sparse_via_helper(
                            lock_data,
                            runner=runner,
                        )
                self.assertEqual(len(directories), 1)
                self.assertFalse(directories[0].exists())

    def test_public_sparse_verifier_has_no_fetcher_injection(self) -> None:
        with mock.patch.object(
            rust_publish_contract,
            "_validate_crates_io_sparse_via_helper",
            return_value=2,
        ) as helper:
            self.assertEqual(validate_crates_io_sparse_yanked(b"lock"), 2)
        helper.assert_called_once_with(
            b"lock",
            runner=rust_publish_contract.capture_stdout,
            scope="normalized-backends",
            deadline=None,
        )

    def test_sparse_worker_validates_input_hash_and_returns_strict_json(self) -> None:
        lock_data = normalized_cargo_lock()
        lock_sha256 = hashlib.sha256(lock_data).hexdigest()
        with tempfile.TemporaryDirectory() as temporary_root:
            lock_path = pathlib.Path(temporary_root) / "Cargo.lock"
            lock_path.write_bytes(lock_data)
            with mock.patch.object(
                rust_publish_contract,
                "_validate_crates_io_sparse_yanked_with_fetcher",
                return_value=2,
            ) as verifier:
                with mock.patch("builtins.print") as output:
                    self.assertEqual(
                        rust_publish_contract._verify_crates_io_sparse_worker(
                            ["normalized-backends", str(lock_path), lock_sha256]
                        ),
                        0,
                    )
            verifier.assert_called_once()
            parsed = json.loads(output.call_args.args[0])
            self.assertEqual(
                parsed,
                {
                    "lock_sha256": lock_sha256,
                    "ok": True,
                    "registry_packages": 2,
                    "schema": 1,
                },
            )
            with mock.patch("builtins.print"):
                self.assertEqual(
                    rust_publish_contract._verify_crates_io_sparse_worker(
                        ["normalized-backends", str(lock_path), "0" * 64]
                    ),
                    1,
                )

    def test_workspace_and_fuzz_lock_scopes_are_exact(self) -> None:
        workspace = (ROOT / "Cargo.lock").read_bytes()
        fuzz = (ROOT / "fuzz" / "Cargo.lock").read_bytes()
        self.assertEqual(
            len(
                rust_publish_contract._parse_cargo_lock_scope(
                    workspace,
                    scope="workspace",
                )
            ),
            203,
        )
        self.assertEqual(
            len(
                rust_publish_contract._parse_cargo_lock_scope(
                    fuzz,
                    scope="fuzz",
                )
            ),
            38,
        )
        for scope, local_crates in (
            ("workspace", RUST_WORKSPACE_LOCAL_CRATES),
            ("fuzz", RUST_FUZZ_LOCAL_CRATES),
        ):
            with self.subTest(scope=scope):
                with self.assertRaisesRegex(
                    RustPublishContractError,
                    "local package set differs",
                ):
                    rust_publish_contract._parse_cargo_lock_scope(
                        normalized_cargo_lock(
                            local_names=set(local_crates) - {next(iter(local_crates))}
                        ),
                        scope=scope,
                    )
        with self.assertRaisesRegex(RustPublishContractError, "unsupported"):
            rust_publish_contract._parse_cargo_lock_scope(
                workspace,
                scope="caller-selected",
            )

    def test_workspace_dependency_audit_isolated_argv_environment_and_cleanup(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_root:
            fixture = pathlib.Path(temporary_root)
            source = fixture / "source"
            (source / "fuzz").mkdir(parents=True)
            (source / "Cargo.lock").write_bytes(
                normalized_cargo_lock(local_names=RUST_WORKSPACE_LOCAL_CRATES)
            )
            (source / "fuzz" / "Cargo.lock").write_bytes(
                normalized_cargo_lock(local_names=RUST_FUZZ_LOCAL_CRATES)
            )
            executable = (fixture / "cargo-audit").resolve()
            executable.write_bytes(b"fixture executable\n")
            executable.chmod(0o700)
            calls: list[tuple[tuple[str, ...], dict[str, object]]] = []
            cargo_home: pathlib.Path | None = None

            def capture(
                argv: tuple[str, ...],
                **kwargs: object,
            ) -> BoundedResult:
                nonlocal cargo_home
                calls.append((argv, kwargs))
                if argv[-1] == "--version":
                    return BoundedResult(0, b"cargo-audit 0.22.2\n")
                if argv[0] == GIT:
                    database = pathlib.Path(argv[-1])
                    cargo_home = database.parent
                    database.mkdir()
                    (database / ".git").mkdir()
                    return BoundedResult(0, b"Cloning into advisory-db\n")
                database = pathlib.Path(argv[argv.index("--db") + 1])
                cargo_home = database.parent
                if not database.exists():
                    database.mkdir()
                    (database / ".git").mkdir()
                return BoundedResult(0, b"No vulnerabilities found\n")

            hostile = {
                "HOME": "/hostile/home",
                "CARGO_HOME": "/hostile/cargo",
                "PATH": "/hostile/bin",
                "RUSTSEC_DB": "/hostile/db",
            }
            with (
                mock.patch.dict(os.environ, hostile, clear=False),
                mock.patch.object(
                    rust_publish_contract,
                    "validate_crates_io_sparse_yanked",
                    side_effect=lambda _data, *, scope, deadline: {
                        "workspace": 203,
                        "fuzz": 38,
                    }[scope],
                ) as sparse,
                mock.patch.object(
                    rust_publish_contract,
                    "capture_stdout",
                    side_effect=capture,
                ),
                mock.patch.object(
                    rust_publish_contract,
                    "validate_rustsec_advisory_database",
                    return_value=ADVISORY_COMMIT,
                ) as advisory,
            ):
                receipt = rust_publish_contract._verify_workspace_dependency_audit(
                    source,
                    executable,
                )

            self.assertEqual(receipt.workspace_registry_packages, 203)
            self.assertEqual(receipt.fuzz_registry_packages, 38)
            self.assertEqual(receipt.advisory_db_commit, ADVISORY_COMMIT)
            self.assertEqual(sparse.call_count, 2)
            self.assertEqual(advisory.call_count, 3)
            sparse_deadlines = {
                call.kwargs["deadline"] for call in sparse.call_args_list
            }
            advisory_deadlines = {
                call.kwargs["deadline"] for call in advisory.call_args_list
            }
            self.assertEqual(len(sparse_deadlines), 1)
            self.assertEqual(advisory_deadlines, sparse_deadlines)
            self.assertEqual(len(calls), 4)
            version, clone, workspace_audit, fuzz_audit = calls
            self.assertEqual(version[0], (str(executable), "--version"))
            self.assertEqual(clone[0][0], GIT)
            self.assertIn("protocol.file.allow=never", clone[0])
            self.assertIn("--depth=1", clone[0])
            self.assertIn("--no-tags", clone[0])
            self.assertEqual(clone[0][-2], RUSTSEC_ADVISORY_DB_URL)
            self.assertEqual(workspace_audit[0].count("--no-fetch"), 1)
            self.assertEqual(fuzz_audit[0].count("--no-fetch"), 1)
            for argv, kwargs in (workspace_audit, fuzz_audit):
                self.assertEqual(argv[0:5], (
                    str(executable),
                    "audit",
                    "--deny",
                    "warnings",
                    "--no-yanked",
                ))
                self.assertNotIn("--ignore", argv)
                self.assertNotIn("--stale", argv)
                environment = kwargs["environment"]
                self.assertEqual(environment["HOME"], environment["CARGO_HOME"])
                self.assertNotEqual(environment["HOME"], hostile["HOME"])
                self.assertEqual(environment["PATH"], "/usr/bin:/bin")
                self.assertNotIn("RUSTSEC_DB", environment)
            for _argv, kwargs in calls:
                self.assertEqual(
                    kwargs["timeout_seconds"],
                    rust_publish_contract.RUST_DEPENDENCY_AUDIT_TIMEOUT_SECONDS,
                )
            self.assertEqual(
                workspace_audit[0][workspace_audit[0].index("--db") + 1],
                fuzz_audit[0][fuzz_audit[0].index("--db") + 1],
            )
            self.assertIsNotNone(cargo_home)
            self.assertFalse(cargo_home.exists())

    def test_workspace_dependency_audit_global_deadline_stops_before_second_sparse(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_root:
            fixture = pathlib.Path(temporary_root)
            source = fixture / "source"
            (source / "fuzz").mkdir(parents=True)
            (source / "Cargo.lock").write_bytes(
                normalized_cargo_lock(local_names=RUST_WORKSPACE_LOCAL_CRATES)
            )
            (source / "fuzz" / "Cargo.lock").write_bytes(
                normalized_cargo_lock(local_names=RUST_FUZZ_LOCAL_CRATES)
            )
            executable = (fixture / "cargo-audit").resolve()
            executable.write_bytes(b"fixture executable\n")
            executable.chmod(0o700)
            started_at = 100.0
            now = [started_at]
            scopes: list[str] = []

            def sparse(
                _data: bytes,
                *,
                scope: str,
                deadline: float,
            ) -> int:
                self.assertEqual(
                    deadline,
                    started_at
                    + RUST_WORKSPACE_DEPENDENCY_AUDIT_TIMEOUT_SECONDS,
                )
                scopes.append(scope)
                now[0] = deadline
                return 2

            with (
                mock.patch.object(
                    rust_publish_contract.time,
                    "monotonic",
                    side_effect=lambda: now[0],
                ),
                mock.patch.object(
                    rust_publish_contract,
                    "validate_crates_io_sparse_yanked",
                    side_effect=sparse,
                ),
                mock.patch.object(
                    rust_publish_contract,
                    "create_owned_package_directory",
                ) as create_owned,
                self.assertRaisesRegex(
                    RustPublishContractError,
                    "total deadline.*workspace crates.io sparse verification",
                ),
            ):
                rust_publish_contract._verify_workspace_dependency_audit(
                    source,
                    executable,
                )

            self.assertEqual(scopes, ["workspace"])
            create_owned.assert_not_called()

    def test_workspace_dependency_audit_global_deadline_cleans_later_audit(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_root:
            fixture = pathlib.Path(temporary_root)
            source = fixture / "source"
            (source / "fuzz").mkdir(parents=True)
            (source / "Cargo.lock").write_bytes(
                normalized_cargo_lock(local_names=RUST_WORKSPACE_LOCAL_CRATES)
            )
            (source / "fuzz" / "Cargo.lock").write_bytes(
                normalized_cargo_lock(local_names=RUST_FUZZ_LOCAL_CRATES)
            )
            executable = (fixture / "cargo-audit").resolve()
            executable.write_bytes(b"fixture executable\n")
            executable.chmod(0o700)
            started_at = 200.0
            deadline = (
                started_at + RUST_WORKSPACE_DEPENDENCY_AUDIT_TIMEOUT_SECONDS
            )
            now = [started_at]
            calls: list[tuple[str, ...]] = []
            cargo_home: pathlib.Path | None = None
            audit_calls = 0

            def capture(
                argv: tuple[str, ...],
                **_kwargs: object,
            ) -> BoundedResult:
                nonlocal audit_calls, cargo_home
                calls.append(argv)
                if argv[-1] == "--version":
                    return BoundedResult(0, b"cargo-audit 0.22.2\n")
                if argv[0] == GIT:
                    database = pathlib.Path(argv[-1])
                    cargo_home = database.parent
                    database.mkdir()
                    (database / ".git").mkdir()
                    return BoundedResult(0, b"Cloning into advisory-db\n")
                audit_calls += 1
                if audit_calls == 1:
                    now[0] = deadline
                return BoundedResult(0, b"No vulnerabilities found\n")

            with (
                mock.patch.object(
                    rust_publish_contract.time,
                    "monotonic",
                    side_effect=lambda: now[0],
                ),
                mock.patch.object(
                    rust_publish_contract,
                    "validate_crates_io_sparse_yanked",
                    return_value=2,
                ),
                mock.patch.object(
                    rust_publish_contract,
                    "capture_stdout",
                    side_effect=capture,
                ),
                mock.patch.object(
                    rust_publish_contract,
                    "validate_rustsec_advisory_database",
                    return_value=ADVISORY_COMMIT,
                ) as advisory,
                self.assertRaisesRegex(
                    RustPublishContractError,
                    "total deadline.*cargo-audit-workspace",
                ),
            ):
                rust_publish_contract._verify_workspace_dependency_audit(
                    source,
                    executable,
                )

            self.assertEqual(len(calls), 3)
            self.assertEqual(audit_calls, 1)
            self.assertEqual(advisory.call_count, 1)
            self.assertIsNotNone(cargo_home)
            self.assertFalse(cargo_home.exists())

    def test_workspace_dependency_audit_fails_closed_and_cleans_owned_home(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_root:
            fixture = pathlib.Path(temporary_root)
            source = fixture / "source"
            (source / "fuzz").mkdir(parents=True)
            (source / "Cargo.lock").write_bytes(
                normalized_cargo_lock(local_names=RUST_WORKSPACE_LOCAL_CRATES)
            )
            (source / "fuzz" / "Cargo.lock").write_bytes(
                normalized_cargo_lock(local_names=RUST_FUZZ_LOCAL_CRATES)
            )
            executable = (fixture / "cargo-audit").resolve()
            executable.write_bytes(b"fixture executable\n")
            executable.chmod(0o700)
            owned_homes: list[pathlib.Path] = []

            def capture(argv: tuple[str, ...], **_kwargs: object) -> BoundedResult:
                if argv[-1] == "--version":
                    return BoundedResult(0, b"cargo-audit 0.22.2\n")
                if argv[0] == GIT:
                    database = pathlib.Path(argv[-1])
                    owned_homes.append(database.parent)
                    database.mkdir()
                    (database / ".git").mkdir()
                    return BoundedResult(0, b"Cloning into advisory-db\n")
                database = pathlib.Path(argv[argv.index("--db") + 1])
                return BoundedResult(7, b"synthetic failure\n")

            with (
                mock.patch.object(
                    rust_publish_contract,
                    "validate_crates_io_sparse_yanked",
                    return_value=2,
                ),
                mock.patch.object(
                    rust_publish_contract,
                    "capture_stdout",
                    side_effect=capture,
                ),
                mock.patch.object(
                    rust_publish_contract,
                    "validate_rustsec_advisory_database",
                    return_value=ADVISORY_COMMIT,
                ),
                self.assertRaisesRegex(RustPublishContractError, r"failed \(exit=7\)"),
            ):
                rust_publish_contract._verify_workspace_dependency_audit(
                    source,
                    executable,
                )
            self.assertEqual(len(owned_homes), 1)
            self.assertFalse(owned_homes[0].exists())

    def test_workspace_dependency_audit_rejects_lock_and_advisory_drift(self) -> None:
        for failure in ("lock", "advisory"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary_root:
                fixture = pathlib.Path(temporary_root)
                source = fixture / "source"
                (source / "fuzz").mkdir(parents=True)
                (source / "Cargo.lock").write_bytes(
                    normalized_cargo_lock(local_names=RUST_WORKSPACE_LOCAL_CRATES)
                )
                fuzz_lock = source / "fuzz" / "Cargo.lock"
                fuzz_lock.write_bytes(
                    normalized_cargo_lock(local_names=RUST_FUZZ_LOCAL_CRATES)
                )
                executable = (fixture / "cargo-audit").resolve()
                executable.write_bytes(b"fixture executable\n")
                executable.chmod(0o700)
                audit_count = 0

                def capture(argv: tuple[str, ...], **_kwargs: object) -> BoundedResult:
                    nonlocal audit_count
                    if argv[-1] == "--version":
                        return BoundedResult(0, b"cargo-audit 0.22.2\n")
                    if argv[0] == GIT:
                        database = pathlib.Path(argv[-1])
                        database.mkdir()
                        (database / ".git").mkdir()
                        return BoundedResult(0, b"Cloning into advisory-db\n")
                    audit_count += 1
                    database = pathlib.Path(argv[argv.index("--db") + 1])
                    if not database.exists():
                        database.mkdir()
                        (database / ".git").mkdir()
                    if failure == "lock" and audit_count == 2:
                        fuzz_lock.write_bytes(fuzz_lock.read_bytes() + b"# drift\n")
                    return BoundedResult(0, b"No vulnerabilities found\n")

                advisory_results = (
                    (ADVISORY_COMMIT, "f" * 40)
                    if failure == "advisory"
                    else (ADVISORY_COMMIT, ADVISORY_COMMIT, ADVISORY_COMMIT)
                )
                with (
                    mock.patch.object(
                        rust_publish_contract,
                        "validate_crates_io_sparse_yanked",
                        return_value=2,
                    ),
                    mock.patch.object(
                        rust_publish_contract,
                        "capture_stdout",
                        side_effect=capture,
                    ),
                    mock.patch.object(
                        rust_publish_contract,
                        "validate_rustsec_advisory_database",
                        side_effect=advisory_results,
                    ),
                    self.assertRaisesRegex(
                        RustPublishContractError,
                        "Cargo.lock changed|database commit changed",
                    ),
                ):
                    rust_publish_contract._verify_workspace_dependency_audit(
                        source,
                        executable,
                    )

    def test_workspace_dependency_audit_cli_emits_one_strict_marker(self) -> None:
        receipt = rust_publish_contract.WorkspaceDependencyAuditReceipt(
            workspace_registry_packages=203,
            fuzz_registry_packages=38,
            advisory_db_commit=ADVISORY_COMMIT,
            workspace_lock_sha256="a" * 64,
            fuzz_lock_sha256="b" * 64,
        )
        with (
            mock.patch.object(
                rust_publish_contract,
                "verify_workspace_dependency_audit",
                return_value=receipt,
            ) as verify,
            mock.patch("builtins.print") as output,
        ):
            self.assertEqual(
                rust_publish_contract._main(
                    ["verify-workspace-dependency-audit"]
                ),
                0,
            )
        verify.assert_called_once_with()
        marker = output.call_args.args[0]
        self.assertEqual(
            marker,
            f"{RUST_WORKSPACE_AUDIT_MARKER_PREFIX} "
            "workspace_registry_packages=203 fuzz_registry_packages=38 "
            f"advisory_db_commit={ADVISORY_COMMIT} "
            f"workspace_lock_sha256={'a' * 64} "
            f"fuzz_lock_sha256={'b' * 64} "
            "locks_stable=1 sparse_checksums=exact yanked=0 "
            "warnings=denied ambient_cargo_home_data=unused",
        )

    def test_workspace_dependency_audit_rejects_all_cli_path_arguments(self) -> None:
        with (
            mock.patch.object(
                rust_publish_contract,
                "verify_workspace_dependency_audit",
            ) as verify,
            mock.patch("builtins.print") as output,
        ):
            self.assertEqual(
                rust_publish_contract._main(
                    [
                        "verify-workspace-dependency-audit",
                        "--root",
                        str(ROOT),
                    ]
                ),
                2,
            )
        verify.assert_not_called()
        self.assertEqual(
            output.call_args.args[0],
            "error: verify-workspace-dependency-audit accepts no arguments",
        )

    def test_workspace_dependency_audit_uses_only_fixed_code_derived_paths(
        self,
    ) -> None:
        expected_root = ROOT.resolve(strict=True)
        self.assertEqual(
            rust_publish_contract.RUST_DEPENDENCY_AUDIT_TOOL_COMPONENTS,
            (
                "target",
                "qperiapt-audit-tool",
                "bin",
                "cargo-audit",
            ),
        )
        expected_tool = expected_root.joinpath(
            *rust_publish_contract.RUST_DEPENDENCY_AUDIT_TOOL_COMPONENTS
        )
        with tempfile.TemporaryDirectory() as hostile_cwd:
            original_cwd = pathlib.Path.cwd()
            try:
                os.chdir(hostile_cwd)
                with mock.patch.dict(
                    os.environ,
                    {
                        "GITHUB_WORKSPACE": hostile_cwd,
                        "QPERIAPT_ROOT": hostile_cwd,
                        "CARGO_AUDIT": "/hostile/cargo-audit",
                    },
                    clear=False,
                ):
                    fixed_paths = (
                        rust_publish_contract._fixed_workspace_dependency_audit_paths()
                    )
                    self.assertEqual(
                        fixed_paths,
                        (expected_root, expected_tool),
                    )
            finally:
                os.chdir(original_cwd)
        receipt = rust_publish_contract.WorkspaceDependencyAuditReceipt(
            workspace_registry_packages=203,
            fuzz_registry_packages=38,
            advisory_db_commit=ADVISORY_COMMIT,
            workspace_lock_sha256="a" * 64,
            fuzz_lock_sha256="b" * 64,
        )
        with mock.patch.object(
            rust_publish_contract,
            "_verify_workspace_dependency_audit",
            return_value=receipt,
        ) as verify:
            self.assertEqual(
                rust_publish_contract.verify_workspace_dependency_audit(),
                receipt,
            )
        verify.assert_called_once_with(expected_root, expected_tool)

    def test_workspace_dependency_audit_rejects_executable_symlink_and_drift(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_root:
            fixture = pathlib.Path(temporary_root)
            executable = (fixture / "cargo-audit").resolve()
            executable.write_bytes(b"fixture executable\n")
            executable.chmod(0o700)
            link = fixture / "cargo-audit-link"
            link.symlink_to(executable)
            with self.assertRaisesRegex(
                RustPublishContractError,
                "current-user-owned real executable",
            ):
                rust_publish_contract._dependency_audit_executable_identity(link)

            identity = rust_publish_contract._dependency_audit_executable_identity(
                executable
            )[1]
            replacement = fixture / "replacement"
            replacement.write_bytes(b"replacement executable\n")
            replacement.chmod(0o700)
            os.replace(replacement, executable)
            with self.assertRaisesRegex(
                RustPublishContractError,
                "identity changed",
            ):
                rust_publish_contract._revalidate_dependency_audit_executable(
                    executable,
                    identity,
                )

    def test_rustsec_advisory_database_uses_fixed_git_and_minimal_environment(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_root:
            database = self.advisory_database(temporary_root)
            results = [
                BoundedResult(0, (RUSTSEC_ADVISORY_DB_URL + "\n").encode()),
                BoundedResult(0, (ADVISORY_COMMIT + "\n").encode()),
                BoundedResult(0, b""),
            ]
            hostile_environment = {
                "GIT_DIR": "/hostile/git-dir",
                "GIT_WORK_TREE": "/hostile/work-tree",
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "alias.status",
                "GIT_CONFIG_VALUE_0": "!false",
                "GIT_CONFIG_PARAMETERS": "'core.fsmonitor'='!false'",
                "GIT_OBJECT_DIRECTORY": "/hostile/objects",
                "GIT_ALTERNATE_OBJECT_DIRECTORIES": "/hostile/alternates",
                "HOME": "/hostile/home",
                "PATH": "/hostile/bin",
            }
            with (
                mock.patch.dict(os.environ, hostile_environment, clear=False),
                mock.patch.object(
                    rust_publish_contract,
                    "capture_stdout",
                    side_effect=results,
                ) as capture,
            ):
                self.assertEqual(
                    validate_rustsec_advisory_database(database),
                    ADVISORY_COMMIT,
                )

            expected_environment = {
                "PATH": "/usr/bin:/bin",
                "LC_ALL": "C",
                "LANG": "C",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_CONFIG_SYSTEM": "/dev/null",
                "GIT_NO_REPLACE_OBJECTS": "1",
                "GIT_OPTIONAL_LOCKS": "0",
            }
            expected_suffixes = (
                [
                    "config",
                    "--local",
                    "--no-includes",
                    "--get-all",
                    "remote.origin.url",
                ],
                ["rev-parse", "--verify", "HEAD^{commit}"],
                [
                    "status",
                    "--porcelain=v1",
                    "--untracked-files=all",
                    "--ignored=matching",
                    "--ignore-submodules=none",
                    "--no-renames",
                ],
            )
            self.assertEqual(capture.call_count, 3)
            for call, expected_suffix in zip(
                capture.call_args_list,
                expected_suffixes,
            ):
                argv = call.args[0]
                self.assertEqual(argv[0], GIT)
                self.assertNotIn("-C", argv)
                self.assertIn(f"--git-dir={database.resolve() / '.git'}", argv)
                self.assertIn(f"--work-tree={database.resolve()}", argv)
                self.assertEqual(argv[-len(expected_suffix) :], expected_suffix)
                self.assertEqual(
                    call.kwargs["environment"],
                    expected_environment,
                )
                self.assertEqual(call.kwargs["stderr"], subprocess.STDOUT)

    def test_rustsec_advisory_database_global_deadline_stops_later_git_calls(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_root:
            database = self.advisory_database(temporary_root)
            started_at = 300.0
            deadline = (
                started_at + RUST_WORKSPACE_DEPENDENCY_AUDIT_TIMEOUT_SECONDS
            )
            now = [started_at]

            def capture(
                _argv: list[str],
                **_kwargs: object,
            ) -> BoundedResult:
                now[0] = deadline
                return BoundedResult(
                    0,
                    (RUSTSEC_ADVISORY_DB_URL + "\n").encode(),
                )

            with (
                mock.patch.object(
                    rust_publish_contract.time,
                    "monotonic",
                    side_effect=lambda: now[0],
                ),
                mock.patch.object(
                    rust_publish_contract,
                    "capture_stdout",
                    side_effect=capture,
                ) as runner,
                self.assertRaisesRegex(
                    RustPublishContractError,
                    "total deadline.*RustSec advisory database origin inspection",
                ),
            ):
                validate_rustsec_advisory_database(
                    database,
                    deadline=deadline,
                )

            self.assertEqual(runner.call_count, 1)

    def test_dependency_audit_stage_timeout_reserves_bounded_reap_window(
        self,
    ) -> None:
        with mock.patch.object(
            rust_publish_contract.time,
            "monotonic",
            return_value=400.0,
        ):
            self.assertEqual(
                rust_publish_contract._dependency_audit_stage_timeout(
                    412.9,
                    maximum_seconds=300,
                    label="synthetic stage",
                ),
                7,
            )
            with self.assertRaisesRegex(
                RustPublishContractError,
                "total deadline before synthetic stage",
            ):
                rust_publish_contract._dependency_audit_stage_timeout(
                    405.9,
                    maximum_seconds=300,
                    label="synthetic stage",
                )

    def test_rustsec_advisory_database_accepts_a_real_clean_pinned_repository(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_root:
            database = pathlib.Path(temporary_root) / "advisory-db"

            def git(*arguments: str) -> str:
                process = subprocess.run(
                    [GIT, *arguments],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                return process.stdout.strip()

            git("init", "--quiet", str(database))
            git("-C", str(database), "config", "user.name", "Contract Test")
            git(
                "-C",
                str(database),
                "config",
                "user.email",
                "contract-test@example.invalid",
            )
            (database / "advisory.json").write_text("{}\n", encoding="utf-8")
            git("-C", str(database), "add", "advisory.json")
            git("-C", str(database), "commit", "--quiet", "-m", "fixture")
            git(
                "-C",
                str(database),
                "remote",
                "add",
                "origin",
                RUSTSEC_ADVISORY_DB_URL,
            )
            expected_commit = git("-C", str(database), "rev-parse", "HEAD")

            self.assertEqual(
                validate_rustsec_advisory_database(database),
                expected_commit,
            )

    def test_rustsec_advisory_database_rejects_wrong_origin(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_root:
            database = self.advisory_database(temporary_root)
            with mock.patch.object(
                rust_publish_contract,
                "capture_stdout",
                return_value=BoundedResult(0, b"https://example.invalid/db.git\n"),
            ):
                with self.assertRaisesRegex(
                    RustPublishContractError,
                    "origin differs",
                ):
                    validate_rustsec_advisory_database(database)

    def test_rustsec_advisory_database_rejects_malformed_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_root:
            database = self.advisory_database(temporary_root)
            with mock.patch.object(
                rust_publish_contract,
                "capture_stdout",
                side_effect=(
                    BoundedResult(0, (RUSTSEC_ADVISORY_DB_URL + "\n").encode()),
                    BoundedResult(0, b"not-a-commit\n"),
                ),
            ):
                with self.assertRaisesRegex(
                    RustPublishContractError,
                    "commit is malformed",
                ):
                    validate_rustsec_advisory_database(database)

    def test_rustsec_advisory_database_rejects_dirty_and_untracked_content(
        self,
    ) -> None:
        for status in (b" M advisory.json\n", b"?? untracked.json\n", b"!! cache\n"):
            with self.subTest(status=status):
                with tempfile.TemporaryDirectory() as temporary_root:
                    database = self.advisory_database(temporary_root)
                    with mock.patch.object(
                        rust_publish_contract,
                        "capture_stdout",
                        side_effect=(
                            BoundedResult(
                                0,
                                (RUSTSEC_ADVISORY_DB_URL + "\n").encode(),
                            ),
                            BoundedResult(0, (ADVISORY_COMMIT + "\n").encode()),
                            BoundedResult(0, status),
                        ),
                    ):
                        with self.assertRaisesRegex(
                            RustPublishContractError,
                            "worktree is not clean",
                        ):
                            validate_rustsec_advisory_database(database)

    def test_rustsec_advisory_database_translates_git_failures(self) -> None:
        failures = (
            BoundedProcessError("timeout", "synthetic timeout"),
            BoundedResult(7, b"sensitive failure detail"),
        )
        for failure in failures:
            with self.subTest(failure=failure):
                with tempfile.TemporaryDirectory() as temporary_root:
                    database = self.advisory_database(temporary_root)
                    with mock.patch.object(
                        rust_publish_contract,
                        "capture_stdout",
                        side_effect=failure
                        if isinstance(failure, BoundedProcessError)
                        else None,
                        return_value=(
                            failure if isinstance(failure, BoundedResult) else None
                        ),
                    ):
                        with self.assertRaisesRegex(
                            RustPublishContractError,
                            "origin inspection failed",
                        ):
                            validate_rustsec_advisory_database(database)

    def test_rustsec_advisory_database_rejects_non_utf8_git_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_root:
            database = self.advisory_database(temporary_root)
            with mock.patch.object(
                rust_publish_contract,
                "capture_stdout",
                return_value=BoundedResult(0, b"\xff"),
            ):
                with self.assertRaisesRegex(
                    RustPublishContractError,
                    "non-UTF-8",
                ):
                    validate_rustsec_advisory_database(database)

    def test_rustsec_advisory_database_requires_real_database_and_git_dirs(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_root:
            root = pathlib.Path(temporary_root)
            database = self.advisory_database(temporary_root)
            database_link = root / "advisory-db-link"
            database_link.symlink_to(database, target_is_directory=True)
            with self.assertRaisesRegex(
                RustPublishContractError,
                "database must be a current-user-owned real directory",
            ):
                validate_rustsec_advisory_database(database_link)

        with tempfile.TemporaryDirectory() as temporary_root:
            root = pathlib.Path(temporary_root)
            database = root / "advisory-db"
            database.mkdir()
            external_git = root / "external-git"
            external_git.mkdir()
            (database / ".git").symlink_to(
                external_git,
                target_is_directory=True,
            )
            with self.assertRaisesRegex(
                RustPublishContractError,
                r"\.git directory must be a current-user-owned real directory",
            ):
                validate_rustsec_advisory_database(database)

    def test_complete_rust_package_contract_transcript_passes(self) -> None:
        transcript = "\n".join(valid_rust_package_contract_transcript()) + "\n"
        receipt = validate_rust_package_contract_transcript(
            transcript.encode("utf-8")
        )
        self.assertEqual(receipt.advisory_db_commit, ADVISORY_COMMIT)
        self.assertEqual(receipt.completed_at, "2026-08-13T03:04:05Z")
        self.assertEqual(
            receipt.normalized_cargo_lock_sha256,
            NORMALIZED_LOCK_SHA256,
        )
        self.assertEqual(receipt.registry_package_count, 2)
        self.assertEqual(receipt.source_commit, SOURCE_COMMIT)
        self.assertEqual(receipt.package_list_crates, RUST_PUBLISHABLE_CRATES)
        self.assertEqual(
            receipt.package_verification_crates,
            RUST_PUBLISHABLE_CRATES,
        )

    def test_rust_package_transcript_rejects_duplicate_missing_and_extra_crates(
        self,
    ) -> None:
        base = valid_rust_package_contract_transcript()
        first_list_index = next(
            index
            for index, line in enumerate(base)
            if line.startswith("RUST_PACKAGE_LIST_PASS")
        )
        mutations = {
            "duplicate": (
                base[: first_list_index + 1]
                + [base[first_list_index]]
                + base[first_list_index + 1 :]
            ),
            "missing": [
                line
                for line in base
                if line
                != "RUST_PACKAGE_VERIFICATION_PASS q-periapt-core "
                "registry=crates-io upload=not-attempted"
            ],
            "extra": base[:first_list_index]
            + ["RUST_PACKAGE_LIST_PASS q-periapt-extra files=1"]
            + base[first_list_index:],
        }
        expected_messages = {
            "duplicate": "duplicate package-list",
            "missing": "verification crate set differs",
            "extra": "package-list crate set differs",
        }
        for label, lines in mutations.items():
            with self.subTest(label=label):
                with self.assertRaisesRegex(
                    RustPublishContractError,
                    expected_messages[label],
                ):
                    validate_rust_package_contract_transcript("\n".join(lines))

    def test_rust_package_transcript_rejects_crate_and_phase_reordering(self) -> None:
        base = valid_rust_package_contract_transcript()
        crate_reordered = base.copy()
        first_list_index = next(
            index
            for index, line in enumerate(base)
            if line.startswith("RUST_PACKAGE_LIST_PASS")
        )
        crate_reordered[first_list_index], crate_reordered[first_list_index + 1] = (
            crate_reordered[first_list_index + 1],
            crate_reordered[first_list_index],
        )
        phase_reordered = base.copy()
        audit_index = phase_reordered.index("RUST_BACKENDS_NORMALIZED_AUDIT_PASS")
        phase_reordered.insert(2, phase_reordered.pop(audit_index))
        for label, lines, message in (
            ("crate", crate_reordered, "package-list crate order differs"),
            ("phase", phase_reordered, "phase marker order differs"),
        ):
            with self.subTest(label=label):
                with self.assertRaisesRegex(RustPublishContractError, message):
                    validate_rust_package_contract_transcript("\n".join(lines))

    def test_rust_package_transcript_requires_exact_contract_metadata(self) -> None:
        base = valid_rust_package_contract_transcript()
        mutations = {
            "toolchain": (
                "cargo-audit=0.22.2",
                "cargo-audit=0.22.1",
            ),
            "cargo home": (
                "ambient_cargo_home_data=unused",
                "ambient_cargo_home_data=used",
            ),
            "source": (
                f"commit={SOURCE_COMMIT} clean=1",
                "commit=not-a-commit clean=1",
            ),
            "yanked count": (
                "registry_packages=2",
                "registry_packages=0",
            ),
            "normalized lock hash": (
                f"normalized_lock_sha256={NORMALIZED_LOCK_SHA256}",
                "normalized_lock_sha256=invalid",
            ),
            "yanked count limit": (
                "registry_packages=2 index=sparse-https checksums=exact yanked=0",
                f"registry_packages={RUST_SPARSE_MAX_REGISTRY_PACKAGES + 1} "
                "index=sparse-https checksums=exact yanked=0",
            ),
            "advisory origin": (
                RUSTSEC_ADVISORY_DB_URL,
                "https://example.invalid/advisory-db.git",
            ),
            "advisory clean": ("clean=1", "clean=0"),
            "registry": ("registry=crates-io", "registry=other"),
            "upload": ("upload=not-attempted", "upload=attempted"),
        }
        for label, (old, new) in mutations.items():
            with self.subTest(label=label):
                lines = base.copy()
                matching_indices = [
                    index for index, line in enumerate(lines) if old in line
                ]
                self.assertTrue(matching_indices)
                index = matching_indices[-1]
                lines[index] = lines[index].replace(old, new, 1)
                with self.assertRaises(RustPublishContractError):
                    validate_rust_package_contract_transcript("\n".join(lines))

    def test_rust_package_transcript_requires_one_ordered_source_marker(self) -> None:
        base = valid_rust_package_contract_transcript()
        source_marker = f"RUST_PACKAGE_SOURCE_PASS commit={SOURCE_COMMIT} clean=1"
        missing = [line for line in base if line != source_marker]
        with self.assertRaisesRegex(
            RustPublishContractError,
            "exactly one source marker",
        ):
            validate_rust_package_contract_transcript("\n".join(missing))

        reordered = base.copy()
        source_index = reordered.index(source_marker)
        source = reordered.pop(source_index)
        first_list_index = next(
            index
            for index, line in enumerate(reordered)
            if line.startswith("RUST_PACKAGE_LIST_PASS")
        )
        reordered.insert(first_list_index + 1, source)
        with self.assertRaisesRegex(
            RustPublishContractError,
            "phase marker order differs",
        ):
            validate_rust_package_contract_transcript("\n".join(reordered))

    def test_rust_package_transcript_requires_one_ordered_lock_marker(self) -> None:
        base = valid_rust_package_contract_transcript()
        yanked_marker = (
            "RUST_CRATES_IO_LOCK_VERIFY_PASS registry_packages=2 "
            "index=sparse-https checksums=exact yanked=0 "
            f"normalized_lock_sha256={NORMALIZED_LOCK_SHA256}"
        )
        missing = [line for line in base if line != yanked_marker]
        with self.assertRaisesRegex(
            RustPublishContractError,
            "exactly one crates.io lock marker",
        ):
            validate_rust_package_contract_transcript("\n".join(missing))

        reordered = base.copy()
        yanked = reordered.pop(reordered.index(yanked_marker))
        advisory_index = next(
            index
            for index, line in enumerate(reordered)
            if line.startswith("RUST_ADVISORY_DB_PASS")
        )
        reordered.insert(advisory_index + 1, yanked)
        with self.assertRaisesRegex(
            RustPublishContractError,
            "phase marker order differs",
        ):
            validate_rust_package_contract_transcript("\n".join(reordered))

    def test_rust_package_transcript_requires_matching_lock_stability(self) -> None:
        base = valid_rust_package_contract_transcript()
        stability_marker = (
            f"RUST_NORMALIZED_LOCK_STABILITY_PASS sha256={NORMALIZED_LOCK_SHA256}"
        )
        missing = [line for line in base if line != stability_marker]
        with self.assertRaisesRegex(
            RustPublishContractError,
            "exactly one lock stability marker",
        ):
            validate_rust_package_contract_transcript("\n".join(missing))

        mismatch = base.copy()
        index = mismatch.index(stability_marker)
        mismatch[index] = "RUST_NORMALIZED_LOCK_STABILITY_PASS sha256=" + "d" * 64
        with self.assertRaisesRegex(
            RustPublishContractError,
            "normalized lock hashes differ",
        ):
            validate_rust_package_contract_transcript("\n".join(mismatch))

        reordered = base.copy()
        stability = reordered.pop(reordered.index(stability_marker))
        audit_index = reordered.index("RUST_BACKENDS_NORMALIZED_AUDIT_PASS")
        reordered.insert(audit_index, stability)
        with self.assertRaisesRegex(
            RustPublishContractError,
            "phase marker order differs",
        ):
            validate_rust_package_contract_transcript("\n".join(reordered))

    def test_rust_package_transcript_rejects_duplicate_singleton_markers(self) -> None:
        base = valid_rust_package_contract_transcript()
        singleton_markers = (
            base[0],
            base[1],
            base[2],
            "RUST_CRATES_IO_LOCK_VERIFY_PASS registry_packages=2 "
            "index=sparse-https checksums=exact yanked=0 "
            f"normalized_lock_sha256={NORMALIZED_LOCK_SHA256}",
            "RUST_BACKENDS_NORMALIZED_AUDIT_PASS",
            f"RUST_NORMALIZED_LOCK_STABILITY_PASS sha256={NORMALIZED_LOCK_SHA256}",
            "RUST_OWNED_PACKAGE_DIRECTORY_CLEANUP_PASS cargo-home",
        )
        for marker in singleton_markers:
            with self.subTest(marker=marker):
                lines = base.copy()
                lines.insert(lines.index(marker) + 1, marker)
                with self.assertRaises(RustPublishContractError):
                    validate_rust_package_contract_transcript("\n".join(lines))

    def test_rust_package_transcript_rejects_warning_and_error_lines(self) -> None:
        base = valid_rust_package_contract_transcript()
        for diagnostic in (
            "warning: dependency warning",
            "  WARNING: indented warning",
            "Error: package failure",
        ):
            with self.subTest(diagnostic=diagnostic):
                lines = base[:-1] + [diagnostic, base[-1]]
                with self.assertRaisesRegex(
                    RustPublishContractError,
                    "warning or error diagnostic",
                ):
                    validate_rust_package_contract_transcript("\n".join(lines))

    def test_rust_package_transcript_rejects_dirty_diagnostic_receipts(self) -> None:
        base = valid_rust_package_contract_transcript()
        for diagnostic in (
            "DIRTY_RUST_PACKAGE_CONTRACT_DIAGNOSTIC_ONLY",
            "  DIRTY_RUST_PACKAGE_CONTRACT_DIAGNOSTIC_ONLY",
            "RUST_PACKAGE_CONTRACT_DIAGNOSTIC_PASS "
            "dirty=1 registry=crates-io upload=not-attempted",
        ):
            with self.subTest(diagnostic=diagnostic):
                lines = base[:-1] + [diagnostic]
                with self.assertRaisesRegex(
                    RustPublishContractError,
                    "dirty diagnostic receipt",
                ):
                    validate_rust_package_contract_transcript("\n".join(lines))

    def test_rust_package_transcript_rejects_noncanonical_completion_time(self) -> None:
        base = valid_rust_package_contract_transcript()
        malformed_times = (
            "2026-8-13T03:04:05Z",
            "2026-08-32T03:04:05Z",
            "2026-08-13T03:04:05+00:00",
        )
        for malformed in malformed_times:
            with self.subTest(malformed=malformed):
                lines = base.copy()
                lines[-1] = lines[-1].replace(
                    "2026-08-13T03:04:05Z",
                    malformed,
                )
                with self.assertRaises(RustPublishContractError):
                    validate_rust_package_contract_transcript("\n".join(lines))

    def test_rust_package_transcript_requires_final_marker_to_be_last(self) -> None:
        lines = valid_rust_package_contract_transcript() + ["trailing output"]
        with self.assertRaisesRegex(
            RustPublishContractError,
            "not the last non-empty line",
        ):
            validate_rust_package_contract_transcript("\n".join(lines))

    def test_rust_package_transcript_rejects_non_utf8_bytes(self) -> None:
        with self.assertRaisesRegex(RustPublishContractError, "valid UTF-8"):
            validate_rust_package_contract_transcript(b"\xff")

    def test_rust_package_script_locks_isolated_cargo_home_and_fresh_audit(
        self,
    ) -> None:
        script = self.publish_contract_script
        cargo_home_creation = script.index(
            "create_owned_package_target qperiapt-package-cargo-home."
        )
        cargo_home_export = script.index("export CARGO_HOME")
        first_cargo_invocation = script.index("cargo +1.96.1")
        self.assertLess(cargo_home_creation, cargo_home_export)
        self.assertLess(cargo_home_export, first_cargo_invocation)
        self.assertIn(
            "RUST_CARGO_HOME_ISOLATION_PASS mode=0700 "
            "ambient_cargo_home_data=unused",
            script,
        )
        self.assertNotIn("trap cleanup_contract_state 0 1 2 15", script)
        self.assertIn("trap 'cleanup_contract_exit $?' 0", script)
        self.assertIn("trap 'cleanup_contract_signal 1' 1", script)
        self.assertIn("trap 'cleanup_contract_signal 2' 2", script)
        self.assertIn("trap 'cleanup_contract_signal 15' 15", script)

        sparse_verifier = "validate_crates_io_sparse_yanked(lock_snapshot.data)"
        sparse_marker = "RUST_CRATES_IO_LOCK_VERIFY_PASS "
        advisory_absence_guard = (
            'if [ -e "$CARGO_HOME/advisory-db" ] || '
            '[ -L "$CARGO_HOME/advisory-db" ]; then'
        )
        audit_invocation = script.index(
            '"$CARGO_AUDIT_BIN" audit --deny warnings'
        )
        self.assertIn(advisory_absence_guard, script)
        self.assertIn(sparse_verifier, script)
        self.assertIn(sparse_marker, script)
        self.assertIn("checksums=exact yanked=0", script)
        self.assertIn("normalized_lock_sha256=%s", script)
        self.assertIn("read_regular_snapshot(", script)
        self.assertIn("maximum=RUST_SPARSE_LOCK_MAX_BYTES", script)
        self.assertLess(script.index(sparse_verifier), audit_invocation)
        self.assertLess(script.index(sparse_marker), audit_invocation)
        self.assertLess(script.index(advisory_absence_guard), audit_invocation)
        self.assertIn(
            'env -i \\\n\tPATH=/usr/bin:/bin HOME="$CARGO_HOME" CARGO_HOME="$CARGO_HOME"',
            script,
        )
        self.assertIn('--db "$CARGO_HOME/advisory-db"', script)
        self.assertIn("--no-yanked", script)
        self.assertNotIn("CARGO_REGISTRIES_CRATES_IO_PROTOCOL=git", script)
        self.assertNotIn("git fetch", script)
        stability_marker = "RUST_NORMALIZED_LOCK_STABILITY_PASS sha256="
        self.assertIn(stability_marker, script)
        self.assertEqual(script.count("lock_snapshot = read_regular_snapshot("), 1)
        self.assertEqual(script.count("snapshot = read_regular_snapshot("), 2)
        self.assertIn(
            "snapshot.sha256 != sys.argv[2] or snapshot.size != expected_size",
            script,
        )
        self.assertLess(audit_invocation, script.index(stability_marker))
        self.assertIn("RUST_ADVISORY_DB_PASS ", script)
        self.assertIn(
            "RUST_OWNED_PACKAGE_DIRECTORY_CLEANUP_PASS cargo-home",
            script,
        )

        final_marker = "RUST_PACKAGE_CONTRACT_PASS dirty=0 registry=crates-io"
        explicit_cleanup = script.rindex("\ncleanup_contract_state\n")
        self.assertLess(explicit_cleanup, script.index(final_marker))
        self.assertIn(
            "RUST_PACKAGE_TOOLCHAIN_PASS "
            "rustc=1.96.1 cargo=1.96.1 cargo-audit=0.22.2",
            script,
        )
        self.assertNotIn("git status --porcelain", script)
        self.assertEqual(script.count("inspect_package_source("), 2)
        self.assertIn(
            "RUST_PACKAGE_SOURCE_PASS commit=%s clean=1",
            script,
        )
        cargo_home_marker = script.index(
            "RUST_CARGO_HOME_ISOLATION_PASS mode=0700 "
            "ambient_cargo_home_data=unused"
        )
        exit_trap = script.index("trap 'cleanup_contract_exit $?' 0")
        self.assertLess(exit_trap, cargo_home_export)
        self.assertLess(exit_trap, cargo_home_marker)
        toolchain_marker = script.index(
            "RUST_PACKAGE_TOOLCHAIN_PASS rustc=1.96.1 "
            "cargo=1.96.1 cargo-audit=0.22.2"
        )
        source_marker = script.index("RUST_PACKAGE_SOURCE_PASS commit=%s clean=1")
        metadata_invocation = script.index(
            "cargo +1.96.1 metadata --locked --format-version 1"
        )
        self.assertLess(cargo_home_marker, toolchain_marker)
        self.assertLess(toolchain_marker, source_marker)
        self.assertLess(source_marker, metadata_invocation)
        self.assertIn(
            'if [ "$final_package_source_state" != "$package_source_state" ]; then',
            script,
        )
        self.assertIn(
            "Rust package source provenance changed during the contract run",
            script,
        )
        for ambient_reference in (
            "~/.cargo",
            "$HOME/.cargo",
            "${HOME}/.cargo",
            '"$HOME"/.cargo',
        ):
            self.assertNotIn(ambient_reference, script)

    def test_packaged_local_source_set_is_exact(self) -> None:
        repository_sources = {
            path.relative_to(SYS_CRATE).as_posix()
            for path in (SYS_CRATE / "src").rglob("*")
            if path.is_file()
        }
        validate_packaged_mlkem_native_local_sources(repository_sources)

        for label, mutation in (
            ("extra C source", repository_sources | {"src/extra.c"}),
            ("shadow header", repository_sources | {"src/mlkem_native.h"}),
            ("missing source", repository_sources - {"src/raw.rs"}),
        ):
            with self.subTest(label=label):
                with self.assertRaisesRegex(
                    RustPublishContractError,
                    "packaged local source set differs",
                ):
                    validate_packaged_mlkem_native_local_sources(mutation)

    def test_every_external_rust_source_edge_fails_closed(self) -> None:
        cases = {
            "public module": {"build_rs": self.build_rs + "\npub mod hidden;\n"},
            "scoped public module": {
                "build_rs": self.build_rs + "\npub(crate) mod hidden;\n"
            },
            "comment-separated module": {
                "build_rs": self.build_rs + "\nmod /* hidden */ extra;\n"
            },
            "nested support module": {
                "build_support": self.build_support + "\nmod nested;\n"
            },
            "include macro": {
                "build_support": self.build_support + '\ninclude!("hidden.rs");\n'
            },
            "comment-separated include": {
                "build_support": self.build_support
                + '\ninclude /* hidden */ !("hidden.rs");\n'
            },
            "comment-separated include_str": {
                "build_support": self.build_support
                + '\ninclude_str /* hidden */ !("hidden.rs");\n'
            },
            "reserved token in a comment": {
                "build_support": self.build_support + "\n// mod is reserved here\n"
            },
        }
        for label, mutation in cases.items():
            with self.subTest(label=label):
                with self.assertRaisesRegex(
                    RustPublishContractError, "module graph differs"
                ):
                    self.validate(**mutation)

    def test_extra_or_dynamic_translation_units_fail_closed(self) -> None:
        cases = {
            "literal file": self.build_support
            + '\nfn extra(build: &mut cc::Build) { build.file("extra.c"); }\n',
            "dynamic file": self.build_support
            + "\nfn extra(build: &mut cc::Build, path: &str) { build.file(path); }\n",
            "comment-separated file": self.build_support
            + '\nfn extra(build: &mut cc::Build) { build.file /* hidden */ ("extra.c"); }\n',
            "files collection": self.build_support
            + '\nfn extra(build: &mut cc::Build) { build.files(["extra.c"]); }\n',
        }
        for label, build_support in cases.items():
            with self.subTest(label=label):
                with self.assertRaisesRegex(
                    RustPublishContractError, "single portable bridge translation unit"
                ):
                    self.validate(build_support=build_support)

    def test_equivalent_rust_and_c_spellings_fail_closed(self) -> None:
        rust_mutations = {
            "UFCS": self.build_support
            + '\nfn extra(build: &mut cc::Build) { cc::Build::file(build, "extra.c"); }\n',
            "qualified UFCS": self.build_support
            + '\nfn extra(build: &mut cc::Build) { <cc::Build>::file(build, "extra.c"); }\n',
            "comment-separated method": self.build_support
            + '\nfn extra(build: &mut cc::Build) { build./* hidden */file("extra.c"); }\n',
            "split native flag": self.build_support
            + '\nfn extra(build: &mut cc::Build) { build.flag(concat!("-DMLK_CONFIG_USE_NATIVE_BACKEND_", "ARITH")); }\n',
        }
        raw_calls = {
            "file": 'build.r#file("extra.c");',
            "files": 'build.r#files(["extra.c"]);',
            "object": 'build.r#object("extra.o");',
            "objects": 'build.r#objects(["extra.o"]);',
            "define": 'build.r#define("OTHER", None);',
            "try_compile": 'let _ = build.r#try_compile("extra");',
        }
        for method, call in raw_calls.items():
            rust_mutations[f"raw {method}"] = self.build_support + (
                f"\nfn extra(build: &mut cc::Build) {{ {call} }}\n"
            )
        for label, build_support in rust_mutations.items():
            with self.subTest(label=label):
                with self.assertRaisesRegex(
                    RustPublishContractError,
                    "packaged build-surface bytes differ|single portable bridge|"
                    "portable allowlist|portable-only",
                ):
                    self.validate(build_support=build_support)

        c_mutations = {
            "quoted bridge include": {
                "bridge_c": self.bridge_c + '\n#include "extra.c"\n'
            },
            "angle bridge include": {
                "bridge_c": self.bridge_c + "\n#include <extra.c>\n"
            },
            "header include": {
                "bridge_h": self.bridge_h + '\n#include "extra.h"\n'
            },
            "commented error directive": {
                "local_config": self.local_config.replace(
                    "#error External or native mlkem-native backends are not supported by this portable-only crate",
                    "/* #error External or native mlkem-native backends are not supported by this portable-only crate */",
                    1,
                )
            },
            "disabled guard": {
                "local_config": self.local_config.replace(
                    "#if defined(MLK_CONFIG_USE_NATIVE_BACKEND_ARITH)",
                    "#if 0\n#if defined(MLK_CONFIG_USE_NATIVE_BACKEND_ARITH)",
                    1,
                ).replace(
                    "#endif\n\n#ifndef QPN_MLKEM_CONFIG_H",
                    "#endif\n#endif\n\n#ifndef QPN_MLKEM_CONFIG_H",
                    1,
                )
            },
        }
        for label, mutation in c_mutations.items():
            with self.subTest(label=label):
                with self.assertRaises(RustPublishContractError):
                    self.validate(**mutation)

    def test_config_bridge_guards_and_native_shapes_fail_closed(self) -> None:
        cases = {
            "missing config selection": {
                "build_rs": self.build_rs.replace(
                    '"MLK_CONFIG_FILE"', '"OTHER_CONFIG_FILE"', 1
                ),
                "message": "select packaged mlkem_config.h exactly once",
            },
            "missing pinned bridge": {
                "bridge_c": self.bridge_c.replace(
                    '#include "mlkem_native.c"', '#include "other.c"', 1
                ),
                "message": "portable C include graph differs",
            },
            "missing guard": {
                "local_config": self.local_config.replace(
                    "MLK_CONFIG_FIPS202X4_CUSTOM_HEADER", "REMOVED_GUARD", 1
                ),
                "message": "active fail-fast native-backend guard prefix",
            },
            "native backend define": {
                "local_config": self.local_config
                + "\n#define MLK_CONFIG_USE_NATIVE_BACKEND_ARITH 1\n",
                "message": "active fail-fast native-backend guard prefix",
            },
            "prebuilt object": {
                "build_support": self.build_support
                + '\nfn extra(build: &mut cc::Build) { build.object("extra.o"); }\n',
                "message": "release build is not portable-only",
            },
            "prebuilt objects": {
                "build_support": self.build_support
                + '\nfn extra(build: &mut cc::Build) { build.objects(["extra.o"]); }\n',
                "message": "release build is not portable-only",
            },
            "comment-separated object": {
                "build_support": self.build_support
                + '\nfn extra(build: &mut cc::Build) { build.object /* hidden */ ("extra.o"); }\n',
                "message": "release build is not portable-only",
            },
            "dynamic define": {
                "build_support": self.build_support
                + "\nfn extra(build: &mut cc::Build, name: &str) { build.define(name, None); }\n",
                "message": "build-script API surface differs",
            },
            "native backend flag": {
                "build_support": self.build_support
                + '\nfn extra(build: &mut cc::Build) { build.flag("-DMLK_CONFIG_USE_NATIVE_BACKEND_ARITH"); }\n',
                "message": "build-script API surface differs",
            },
            "second compilation": {
                "build_support": self.build_support
                + '\nfn extra(build: &mut cc::Build) { let _ = build.try_compile("extra"); }\n',
                "message": "build-script API surface differs",
            },
        }
        for label, case in cases.items():
            message = case["message"]
            mutation = {key: value for key, value in case.items() if key != "message"}
            with self.subTest(label=label):
                with self.assertRaisesRegex(RustPublishContractError, message):
                    self.validate(**mutation)


if __name__ == "__main__":
    unittest.main()
