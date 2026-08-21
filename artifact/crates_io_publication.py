#!/usr/bin/env python3
"""Verify and safely advance the ABI-2 crates.io publication transaction.

``dry-run`` validates exact local package inputs and ``verify`` additionally
collects an official API+sparse-index receipt.  The ``publish`` CLI remains a
separate, fail-closed irreversible boundary: it requires an explicit external
private state root, a controlled exact-byte uploader and credential, a
fixed same-host/same-account cross-worktree lock, and two explicit
acknowledgements.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import datetime as dt
import errno
import hashlib
import os
import pathlib
import re
import secrets
import signal
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterator, Mapping, Sequence
from typing import Any, ContextManager, Literal, Never, TextIO

import rust_package_handoff
from bounded_process import BoundedResult, capture_stdout
from crates_io_publication_contract import (
    ABI_VERSION,
    CRATE_DEPENDENCIES,
    CRATE_PUBLICATION_TOPOLOGY,
    CRATE_STATUS_ABSENT,
    CRATE_STATUS_PUBLISHED_VERIFIED,
    CRATES_IO_PUBLICATION_BOUNDARY,
    CRATES_IO_PUBLICATION_KEY,
    CRATES_IO_PUBLICATION_KIND,
    CRATES_IO_PUBLICATION_SCHEMA_VERSION,
    CRATES_IO_REGISTRY,
    CRATES_IO_SPARSE_INDEX,
    PRODUCT_VERSION,
    PUBLICATION_STATUS_PARTIAL,
    PUBLICATION_STATUS_PUBLISHED_VERIFIED,
    CratesIoPublicationContractError,
    parse_utc_timestamp,
    validate_crates_io_publication_receipt,
)
from release_publication_contract import (
    ReleasePublicationContractError,
    validate_stable_source_currentness,
)
from evidence_io import (
    EvidenceIOError,
    FileDigestSnapshot,
    FileSnapshot,
    consume_regular_snapshot_at,
    consume_regular_snapshot,
    parse_strict_json_bytes,
    read_regular_snapshot,
)
from git_provenance import (
    GitProvenanceError,
    inspect_worktree,
    require_direct_results_only_child,
    require_results_only_descendant,
    run_git_bytes,
    run_git_text,
)
from publication_receipt_io import (
    PRIVATE_DIRECTORY_MODE,
    PRIVATE_FILE_MODE,
    PrivateDirectoryHandle,
    PublicationReceiptCommittedError,
    PublicationReceiptIOError,
    canonical_json_bytes,
    create_private_direct_child_handle,
    create_private_transaction_json,
    ensure_private_safe_root,
    normalize_safe_root,
    open_private_directory,
    open_private_directory_at,
    prepare_private_json_noreplace_at,
    read_fixed_json_snapshot,
    verify_exact_directory_inventory_at,
    write_private_bytes_noreplace_at,
)
from rust_publish_contract import (
    RustPackageContractReceipt,
    RustPublishContractError,
    remove_owned_package_directory,
    validate_rust_package_contract_transcript,
    validate_rust_package_diagnostic_transcript,
)

try:
    import fcntl
except ImportError:
    fcntl = None

try:
    import pwd
except ImportError:
    pwd = None


REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parent.parent
CRATES_IO_PUBLICATION_RECEIPT_ROOT = (
    REPOSITORY_ROOT / "target" / "qperiapt-crates-io-publication-receipts"
)
CRATES_IO_PUBLICATION_JOURNAL_ROOT = (
    REPOSITORY_ROOT / "target" / "qperiapt-crates-io-publication-journal"
)
RUST_PACKAGE_HANDOFF_ROOT = rust_package_handoff.RUST_PACKAGE_HANDOFF_ROOT
CRATES_IO_PUBLICATION_RECEIPT_NAME = "crates-io-v0.1.1-publication-receipt.json"
CRATES_IO_PUBLICATION_JOURNAL_NAME = "crates-io-v0.1.1-upload-attempt.json"
CRATES_IO_PUBLICATION_LOCK_NAME = "qperiapt-crates-io-v0.1.1.lock"
CRATES_IO_PUBLICATION_UPLOADER_NAME = "qperiapt-crates-io-uploader"
RUST_PACKAGE_HANDOFF_MANIFEST_NAME = (
    rust_package_handoff.RUST_PACKAGE_HANDOFF_MANIFEST_NAME
)
RUST_PACKAGE_HANDOFF_TRANSCRIPT_NAME = (
    rust_package_handoff.RUST_PACKAGE_HANDOFF_TRANSCRIPT_NAME
)
RUST_PACKAGE_HANDOFF_STDERR_NAME = "rust-package-contract.stderr.log"
RUST_PACKAGE_HANDOFF_STAGING_MANIFEST_NAME = "rust-package-staging.json"

MAX_RECEIPT_BYTES = 1024 * 1024
MAX_HANDOFF_MANIFEST_BYTES = rust_package_handoff.MAX_HANDOFF_MANIFEST_BYTES
MAX_TRANSCRIPT_BYTES = rust_package_handoff.MAX_TRANSCRIPT_BYTES
MAX_HANDOFF_STDERR_BYTES = 1024 * 1024
MAX_CRATE_BYTES = rust_package_handoff.MAX_CRATE_BYTES
MAX_TOTAL_CRATE_BYTES = rust_package_handoff.MAX_TOTAL_CRATE_BYTES
MAX_API_BYTES = 1024 * 1024
MAX_SPARSE_BYTES = 8 * 1024 * 1024
MAX_SPARSE_RECORDS = 16_384
MAX_JOURNAL_RECORDS = 4096
HTTP_TIMEOUT_SECONDS = 15
REMOTE_POLL_ATTEMPTS = 12
REMOTE_POLL_INTERVAL_SECONDS = 5.0
HTTP_USER_AGENT = "q-periapt-crates-io-publication/1"
UPLOAD_TIMEOUT_SECONDS = 300
MAX_UPLOADER_OUTPUT_BYTES = 64 * 1024
MAX_UPLOADER_BYTES = 512 * 1024 * 1024

REAL_UPLOAD_ACKNOWLEDGEMENT = (
    "publish-q-periapt-abi2-v0.1.1-to-crates.io-is-irreversible"
)

_SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_TOKEN_RE = re.compile(r"^[\x21-\x7e]{16,512}$")
_ATTEMPT_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_TRANSACTION_DIRECTORY_RE = re.compile(r"^transaction\.[1-9][0-9]*-[0-9]{1,3}$")
_JOURNAL_TRANSACTION_RE = re.compile(
    r"^transaction\.([1-9][0-9]*)-([0-9]{1,3})$"
)
_HANDOFF_TRANSACTION_RE = (
    rust_package_handoff.RUST_PACKAGE_HANDOFF_TRANSACTION_RE
)
_HANDOFF_STAGE_NAME_RE = re.compile(
    r"^qperiapt-rust-package-handoff-stage\.[0-9a-f]{24}$"
)
_ABSOLUTE_DIAGNOSTIC_PATH_RE = re.compile(
    rb"(?:^|[\x09\x0a\x20\x22\x27\x28\x2c\x3a\x3d\x3e\x5b\x7b])"
    rb"/(?!/)(?:[^\x00-\x20]+)"
)
_DOUBLE_ABSOLUTE_DIAGNOSTIC_PATH_RE = re.compile(
    rb"(?:^|[\x09\x0a\x20\x22\x27\x28\x2c\x3a\x3d\x3e\x5b\x7b])"
    rb"//(?:[^\x00-\x20]+)"
)
_RESERVED_HANDOFF_MARKERS = (
    b"RUST_PACKAGE_HANDOFF_PASS",
    b"RUST_PACKAGE_HANDOFF_COMMITTED",
)
_CREDENTIAL_DIAGNOSTIC_TERMS = (
    b"authorization:",
    b"bearer ",
    b"cargo_credential_alias_",
    b"cargo_registries_",
    b"cargo_registry_global_credential_providers",
    b"cargo_registry_token",
    b"credential-provider",
    b"credential_provider",
)
_RUST_PACKAGE_CONTRACT_FAILURE_RE = re.compile(
    rb"^RUST_PACKAGE_CONTRACT_FAILURE "
    rb"stage=(handoff-staging) "
    rb"category=(contract|filesystem|input|publication-io|committed)\n$"
)
_DANGEROUS_REMOTE_TRUST_ENVIRONMENT = frozenset(
    {
        "ALL_PROXY",
        "CURL_CA_BUNDLE",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NODE_EXTRA_CA_CERTS",
        "NO_PROXY",
        "PIP_CERT",
        "PYTHONHTTPSVERIFY",
        "REQUESTS_CA_BUNDLE",
        "SSLKEYLOGFILE",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
        "all_proxy",
        "http_proxy",
        "https_proxy",
        "no_proxy",
    }
)

RUST_PACKAGE_HANDOFF_SCHEMA_VERSION = (
    rust_package_handoff.RUST_PACKAGE_HANDOFF_SCHEMA_VERSION
)
RUST_PACKAGE_HANDOFF_KIND = rust_package_handoff.RUST_PACKAGE_HANDOFF_KIND
RUST_PACKAGE_HANDOFF_STAGING_KIND = "qperiapt.rust_package_handoff_staging"
RUST_PACKAGE_HANDOFF_BOUNDARY = rust_package_handoff.RUST_PACKAGE_HANDOFF_BOUNDARY

UPLOAD_JOURNAL_SCHEMA_VERSION = 1
UPLOAD_JOURNAL_KIND = "qperiapt.crates_io_upload_attempt"
UPLOAD_JOURNAL_INTENT = "upload_intent"
UPLOAD_JOURNAL_UNKNOWN = "upload_outcome_unknown"
UPLOAD_JOURNAL_PUBLISHED = "upload_outcome_published_verified"

RunMode = Literal["dry-run", "verify", "publish"]
HttpFetcher = Callable[..., "HttpResponse"]
Clock = Callable[[], dt.datetime]
Sleeper = Callable[[float], None]
CredentialProvider = Callable[[], str]
PublicationLockFactory = Callable[[], ContextManager[None]]
UploadRunner = Callable[..., BoundedResult]
ReceiptWriter = Callable[[dict[str, object]], tuple[pathlib.Path, str]]
SourceTreeResolver = Callable[[str], str]
SourceTransitionVerifier = Callable[
    ["SourceIdentity", pathlib.Path, str],
    None,
]


class CratesIoPublicationError(ValueError):
    """Local evidence, registry output, or a publication transition is invalid."""


class CratesIoRemoteObservationUnknownError(CratesIoPublicationError):
    """The exact crates.io API+sparse state cannot currently be classified."""


class CratesIoUploadOutcomeUnknownError(CratesIoPublicationError):
    """An attempted upload may have taken effect and must not be retried blindly."""

    def __init__(
        self,
        crate_name: str,
        *,
        verified_receipt: dict[str, object],
        written_receipts: tuple["WrittenReceipt", ...],
    ) -> None:
        super().__init__(
            f"upload outcome is unknown for {crate_name}; "
            "poll exact crates.io API and sparse state before any retry"
        )
        self.crate_name = crate_name
        self.verified_receipt = verified_receipt
        self.written_receipts = written_receipts


class CratesIoPublicationLockHeldError(CratesIoPublicationError):
    """Another process currently owns the shared crates.io publication lane."""


class _HandoffPrecommitSignal(BaseException):
    """A catchable termination signal arrived before manifest visibility."""

    def __init__(self, signal_number: int) -> None:
        self.signal_number = signal_number
        super().__init__(128 + signal_number)


@dataclasses.dataclass(frozen=True, slots=True)
class SourceIdentity:
    source_parent_commit: str
    tag_commit: str
    tag_tree: str
    canonical_source_tree_sha256: str

    def document(self) -> dict[str, str]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True, slots=True)
class ResultsSelectedHandoff:
    """The sole Rust package handoff selected by results commit R."""

    path: pathlib.Path
    relative_path: pathlib.PurePosixPath
    sha256: str


RustPackageHandoffSource = rust_package_handoff.RustPackageHandoffSource
RustPackageHandoffCrateSnapshot = (
    rust_package_handoff.RustPackageHandoffCrateSnapshot
)
RustPackageHandoffSnapshot = rust_package_handoff.RustPackageHandoffSnapshot


@dataclasses.dataclass(frozen=True, slots=True)
class HttpResponse:
    status: int
    final_url: str
    body: bytes


class _RejectRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Keep registry observations on the exact requested HTTPS origin."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Mapping[str, str],
        newurl: str,
    ) -> Never:
        del req, fp, code, msg, headers, newurl
        _fail("crates.io HTTP response redirected")


@dataclasses.dataclass(frozen=True, slots=True)
class LocalCrate:
    name: str
    version: str
    dependencies: tuple[str, ...]
    path: pathlib.Path
    size: int
    sha256: str
    payload: bytes = dataclasses.field(repr=False, compare=False)

    def base_document(self) -> dict[str, object]:
        return {
            "crate_file": self.path.name,
            "crate_sha256": self.sha256,
            "crate_size": self.size,
            "dependencies": list(self.dependencies),
            "name": self.name,
            "state": CRATE_STATUS_ABSENT,
            "version": self.version,
        }


@dataclasses.dataclass(frozen=True, slots=True)
class LocalPublicationEvidence:
    source: SourceIdentity
    handoff_snapshot: RustPackageHandoffSnapshot
    handoff_root: pathlib.Path
    handoff_manifest_path: pathlib.Path
    handoff_manifest_sha256: str
    handoff_source_tree: str
    handoff_inventory: frozenset[str]
    source_tree_resolver: SourceTreeResolver = dataclasses.field(
        repr=False, compare=False
    )
    source_transition_verifier: SourceTransitionVerifier = dataclasses.field(
        repr=False, compare=False
    )
    transcript_path: pathlib.Path
    transcript_sha256: str
    package_contract: RustPackageContractReceipt
    package_root: pathlib.Path
    crates: tuple[LocalCrate, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class RemotePublishedRecord:
    api_checksum: str
    sparse_checksum: str
    verified_at: str


@dataclasses.dataclass(frozen=True, slots=True)
class PublicationRun:
    mode: RunMode
    receipt: dict[str, object] | None
    written_receipts: tuple["WrittenReceipt", ...]
    upload_attempts: tuple[str, ...]
    planned_crates: tuple[str, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class WrittenReceipt:
    path: pathlib.Path
    sha256: str


@dataclasses.dataclass(frozen=True, slots=True)
class UploadIntent:
    attempt_id: str
    crate_name: str
    digest: str
    path: pathlib.Path
    recorded_at: str


@dataclasses.dataclass(frozen=True, slots=True)
class UploadOutcome:
    attempt_id: str
    crate_name: str
    intent_sha256: str
    state: str
    recorded_at: str


def _fail(message: str) -> Never:
    raise CratesIoPublicationError(message)


def _unknown(message: str) -> Never:
    raise CratesIoRemoteObservationUnknownError(message)


def _require(condition: bool, message: str) -> None:
    if not condition:
        _fail(message)


def _canonical_timestamp(clock: Clock) -> str:
    observed = clock()
    _require(
        isinstance(observed, dt.datetime)
        and observed.tzinfo is not None
        and observed.utcoffset() is not None,
        "publication clock must return a timezone-aware datetime",
    )
    return observed.astimezone(dt.UTC).replace(microsecond=0).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _source_identity_document(source: SourceIdentity) -> dict[str, str]:
    _require(isinstance(source, SourceIdentity), "source identity type differs")
    document = source.document()
    _require(
        _SHA1_RE.fullmatch(source.source_parent_commit) is not None,
        "source parent commit is malformed",
    )
    _require(
        _SHA1_RE.fullmatch(source.tag_commit) is not None,
        "tag commit is malformed",
    )
    _require(
        _SHA1_RE.fullmatch(source.tag_tree) is not None,
        "tag tree is malformed",
    )
    _require(
        _SHA256_RE.fullmatch(source.canonical_source_tree_sha256) is not None,
        "canonical source tree digest is malformed",
    )
    _require(
        source.source_parent_commit != source.tag_commit,
        "tag commit must differ from its source parent",
    )
    return document


def source_identity_from_document(value: object) -> SourceIdentity:
    """Parse the exact four-field stable source identity."""

    _require(
        isinstance(value, dict)
        and all(isinstance(key, str) for key in value),
        "source identity must be a JSON object with string keys",
    )
    expected = frozenset(
        {
            "canonical_source_tree_sha256",
            "source_parent_commit",
            "tag_commit",
            "tag_tree",
        }
    )
    actual = frozenset(value)
    _require(
        actual == expected,
        f"source identity keys differ: missing={sorted(expected - actual)!r} "
        f"extra={sorted(actual - expected)!r}",
    )
    source = SourceIdentity(
        source_parent_commit=value["source_parent_commit"],
        tag_commit=value["tag_commit"],
        tag_tree=value["tag_tree"],
        canonical_source_tree_sha256=value["canonical_source_tree_sha256"],
    )
    _source_identity_document(source)
    return source


def _owned_regular_metadata(
    metadata: os.stat_result,
    *,
    label: str,
    require_executable: bool = False,
) -> None:
    uid_getter = getattr(os, "geteuid", None)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or not callable(uid_getter)
        or metadata.st_uid != uid_getter()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) & 0o022 != 0
        or (require_executable and metadata.st_mode & stat.S_IXUSR == 0)
    ):
        raise EvidenceIOError(
            f"{label} must be an owned, single-link, non-writable-by-others file"
        )


def _canonical_input_file(path: pathlib.Path, *, label: str) -> pathlib.Path:
    _require(isinstance(path, pathlib.Path), f"{label} path must be pathlib.Path")
    supplied = os.fspath(path)
    _require(path.is_absolute(), f"{label} path must be absolute")
    _require(
        os.path.abspath(supplied) == supplied
        and all(part not in {"", ".", ".."} for part in path.parts[1:]),
        f"{label} path must be canonically spelled",
    )
    return path


def _digest_file(
    path: pathlib.Path,
    *,
    maximum: int,
    label: str,
    require_executable: bool = False,
) -> FileDigestSnapshot:
    path = _canonical_input_file(path, label=label)
    try:
        return consume_regular_snapshot(
            path,
            maximum=maximum,
            label=label,
            consume=lambda _chunk: None,
            validate_metadata=lambda metadata: _owned_regular_metadata(
                metadata,
                label=label,
                require_executable=require_executable,
            ),
        )
    except EvidenceIOError as exc:
        raise CratesIoPublicationError(str(exc)) from exc


def _validated_publication_state_root(
    state_root: pathlib.Path,
) -> pathlib.Path:
    _require(
        isinstance(state_root, pathlib.Path) and state_root.is_absolute(),
        "publication state root must be an explicit absolute pathlib.Path",
    )
    account_home = _publication_account_home()
    expected_root = (
        account_home
        / ".q-periapt"
        / "publication-state"
        / "crates.io-v0.1.1"
    )
    _require(
        state_root == expected_root
        and os.fspath(state_root) == os.fspath(expected_root),
        "publication state root must equal the fixed account publication root",
    )
    private_ancestors = (
        account_home / ".q-periapt",
        account_home / ".q-periapt" / "publication-state",
        expected_root,
    )
    uid_getter = getattr(os, "geteuid", None)
    _require(
        callable(uid_getter),
        "publication state root requires a POSIX effective user identity",
    )
    for directory in private_ancestors:
        try:
            metadata = directory.lstat()
            resolved = directory.resolve(strict=True)
        except OSError as exc:
            raise CratesIoPublicationError(
                "fixed account publication directories must be created explicitly"
            ) from exc
        _require(
            stat.S_ISDIR(metadata.st_mode)
            and metadata.st_uid == uid_getter()
            and stat.S_IMODE(metadata.st_mode) == PRIVATE_DIRECTORY_MODE
            and resolved == directory,
            "fixed account publication directories must be owned real mode-0700 directories",
        )
    try:
        normalized = normalize_safe_root(
            state_root,
            label="shared crates.io publication state root",
            required_mode=PRIVATE_DIRECTORY_MODE,
        )
    except (OSError, PublicationReceiptIOError) as exc:
        raise CratesIoPublicationError(
            "shared crates.io publication state root is unsafe"
        ) from exc
    for worktree in _registered_git_worktree_roots():
        _require(
            isinstance(worktree, pathlib.Path) and worktree.is_absolute(),
            "registered Git worktree root is malformed",
        )
        canonical_worktree = pathlib.Path(
            os.path.realpath(os.fspath(worktree))
        )
        _require(
            os.path.abspath(os.fspath(worktree)) == os.fspath(worktree),
            "registered Git worktree root is not canonically spelled",
        )
        _require(
            normalized != canonical_worktree
            and not normalized.is_relative_to(canonical_worktree),
            "publication state root must be outside every registered Git worktree",
        )
    return normalized


def _publication_account_home_path() -> pathlib.Path:
    """Return the canonical passwd spelling without touching caller paths."""

    uid_getter = getattr(os, "geteuid", None)
    _require(
        os.name == "posix" and pwd is not None and callable(uid_getter),
        "production crates.io publication state requires POSIX passwd data",
    )
    try:
        record = pwd.getpwuid(uid_getter())
        home_text = record.pw_dir
    except (KeyError, OSError) as exc:
        raise CratesIoPublicationError(
            "cannot resolve the publication account home"
        ) from exc
    _require(
        isinstance(home_text, str)
        and home_text
        and os.path.isabs(home_text)
        and os.path.abspath(home_text) == home_text,
        "publication account home is malformed",
    )
    home = pathlib.Path(home_text)
    _require(
        os.fspath(home) == home_text,
        "publication account home is not canonically spelled",
    )
    return home


def _expected_publication_state_root() -> pathlib.Path:
    """Derive the sole production authority without consuming a CLI path."""

    return (
        _publication_account_home_path()
        / ".q-periapt"
        / "publication-state"
        / "crates.io-v0.1.1"
    )


def _publication_account_home() -> pathlib.Path:
    """Resolve the sole same-account publication namespace from passwd data."""

    home = _publication_account_home_path()
    uid_getter = getattr(os, "geteuid", None)
    _require(
        callable(uid_getter),
        "production crates.io publication state requires POSIX passwd data",
    )
    for ancestor in (home, *home.parents):
        try:
            metadata = ancestor.lstat()
        except OSError as exc:
            raise CratesIoPublicationError(
                "cannot inspect publication account home ancestry"
            ) from exc
        _require(
            stat.S_ISDIR(metadata.st_mode)
            and metadata.st_uid in {0, uid_getter()}
            and stat.S_IMODE(metadata.st_mode) & 0o022 == 0,
            "publication account home ancestry is not trusted",
        )
        if ancestor == home:
            _require(
                metadata.st_uid == uid_getter(),
                "publication account home must be owned by the effective user",
            )
    try:
        resolved = home.resolve(strict=True)
    except OSError as exc:
        raise CratesIoPublicationError(
            "cannot resolve publication account home"
        ) from exc
    _require(
        resolved == home,
        "publication account home must be a canonical real directory",
    )
    return home


def _registered_git_worktree_roots() -> tuple[pathlib.Path, ...]:
    """Parse Git's NUL-delimited registered-worktree inventory."""

    try:
        payload = run_git_bytes(
            REPOSITORY_ROOT,
            ["worktree", "list", "--porcelain", "-z"],
        )
    except GitProvenanceError as exc:
        raise CratesIoPublicationError(
            "cannot enumerate registered Git worktrees"
        ) from exc
    _require(
        payload.endswith(b"\0\0") and payload != b"\0\0",
        "registered Git worktree inventory is malformed",
    )
    roots: list[pathlib.Path] = []
    for record in payload[:-2].split(b"\0\0"):
        fields = record.split(b"\0")
        _require(
            bool(fields) and fields[0].startswith(b"worktree "),
            "registered Git worktree record is malformed",
        )
        try:
            path_text = fields[0].removeprefix(b"worktree ").decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CratesIoPublicationError(
                "registered Git worktree path is not UTF-8"
            ) from exc
        path = pathlib.Path(path_text)
        _require(
            path.is_absolute()
            and all(part not in {"", ".", ".."} for part in path.parts[1:])
            and os.path.abspath(path_text) == path_text,
            "registered Git worktree path is malformed",
        )
        canonical = pathlib.Path(os.path.realpath(path_text))
        _require(
            canonical not in roots,
            "registered Git worktree inventory contains a duplicate root",
        )
        roots.append(canonical)
    _require(bool(roots), "registered Git worktree inventory is empty")
    return tuple(roots)


@contextlib.contextmanager
def _production_publication_lock(
    state_root: pathlib.Path,
) -> Iterator[None]:
    """Hold one persistent-inode, crash-released POSIX publication lock."""

    if os.name != "posix" or fcntl is None:
        _fail("production crates.io publication locking requires POSIX flock")
    root = _validated_publication_state_root(state_root)
    try:
        root_descriptor = open_private_directory(
            root, label="shared crates.io publication state root"
        )
    except PublicationReceiptIOError as exc:
        raise CratesIoPublicationError(str(exc)) from exc
    lock_descriptor = -1
    acquired = False
    primary_error: BaseException | None = None
    try:
        flags = (
            os.O_RDWR
            | os.O_CREAT
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            lock_descriptor = os.open(
                CRATES_IO_PUBLICATION_LOCK_NAME,
                flags,
                PRIVATE_FILE_MODE,
                dir_fd=root_descriptor,
            )
            metadata = os.fstat(lock_descriptor)
            named = os.stat(
                CRATES_IO_PUBLICATION_LOCK_NAME,
                dir_fd=root_descriptor,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise CratesIoPublicationError(
                "cannot open persistent crates.io publication lock"
            ) from exc
        uid_getter = getattr(os, "geteuid", None)
        _require(
            stat.S_ISREG(metadata.st_mode)
            and callable(uid_getter)
            and metadata.st_uid == uid_getter()
            and metadata.st_nlink == 1
            and stat.S_IMODE(metadata.st_mode) == PRIVATE_FILE_MODE
            and metadata.st_size == 0,
            "persistent publication lock must be an owned empty mode-0600 single-link file",
        )
        _require(
            named.st_dev == metadata.st_dev and named.st_ino == metadata.st_ino,
            "persistent publication lock path identity differs",
        )
        try:
            os.fsync(lock_descriptor)
            os.fsync(root_descriptor)
            fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            acquired = True
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK}:
                raise CratesIoPublicationLockHeldError(
                    "shared crates.io publication lock is already held"
                ) from None
            raise CratesIoPublicationError(
                "cannot acquire shared crates.io publication lock"
            ) from exc
        locked = os.fstat(lock_descriptor)
        named_locked = os.stat(
            CRATES_IO_PUBLICATION_LOCK_NAME,
            dir_fd=root_descriptor,
            follow_symlinks=False,
        )
        root_named = root.lstat()
        root_opened = os.fstat(root_descriptor)
        _require(
            locked.st_dev == metadata.st_dev
            and locked.st_ino == metadata.st_ino
            and named_locked.st_dev == metadata.st_dev
            and named_locked.st_ino == metadata.st_ino,
            "persistent publication lock identity changed during acquisition",
        )
        _require(
            root_named.st_dev == root_opened.st_dev
            and root_named.st_ino == root_opened.st_ino,
            "publication state root identity changed during lock acquisition",
        )
        yield
        root_after = root.lstat()
        lock_after = os.stat(
            CRATES_IO_PUBLICATION_LOCK_NAME,
            dir_fd=root_descriptor,
            follow_symlinks=False,
        )
        _require(
            root_after.st_dev == root_opened.st_dev
            and root_after.st_ino == root_opened.st_ino
            and lock_after.st_dev == locked.st_dev
            and lock_after.st_ino == locked.st_ino,
            "publication lock ancestry changed while held",
        )
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        cleanup_errors: list[BaseException] = []
        if acquired and lock_descriptor >= 0:
            try:
                fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
            except BaseException as exc:
                cleanup_errors.append(exc)
        for descriptor in (lock_descriptor, root_descriptor):
            if descriptor < 0:
                continue
            try:
                os.close(descriptor)
            except BaseException as exc:
                cleanup_errors.append(exc)
        if cleanup_errors:
            if primary_error is not None:
                primary_error.add_note(
                    "cannot fully release shared crates.io publication lock"
                )
            elif isinstance(cleanup_errors[0], Exception):
                raise CratesIoPublicationError(
                    "cannot fully release shared crates.io publication lock"
                ) from cleanup_errors[0]
            else:
                raise cleanup_errors[0]


def production_lock_factory(
    state_root: pathlib.Path,
) -> PublicationLockFactory:
    """Return the fixed same-host/same-account cross-worktree lock callback."""

    normalized = _validated_publication_state_root(state_root)

    def acquire() -> ContextManager[None]:
        return _production_publication_lock(normalized)

    return acquire


def production_upload_runner(
    uploader_command: pathlib.Path,
    *,
    state_root: pathlib.Path,
) -> UploadRunner:
    """Adapt the fixed state-root-owned exact-byte uploader to the bounded runner API.

    The executable receives only non-secret argv.  The crates.io token is in a
    three-entry environment and both output streams are withheld from operator
    logs.  The external program must upload the bytes supplied through stdin under
    the ``--crate-stdin`` contract exactly; this module confirms that claim from
    API+sparse checksums afterward.  Requiring the fixed mode-0700 child of the
    separately reviewed state root narrows the residual hash-to-exec mutation
    capability to the trusted owner of that private publication root.
    """

    normalized_state_root = _validated_publication_state_root(state_root)
    command = _canonical_input_file(
        uploader_command, label="crates.io exact-byte uploader"
    )
    _require(
        command == normalized_state_root / CRATES_IO_PUBLICATION_UPLOADER_NAME,
        "crates.io exact-byte uploader must equal the fixed publication uploader path",
    )
    try:
        state_metadata = normalized_state_root.lstat()
        command_metadata = command.lstat()
    except OSError as exc:
        raise CratesIoPublicationError(
            "cannot inspect controlled crates.io uploader"
        ) from exc
    _require(
        stat.S_ISREG(command_metadata.st_mode)
        and command_metadata.st_uid == os.geteuid()
        and command_metadata.st_nlink == 1
        and stat.S_IMODE(command_metadata.st_mode) == 0o700,
        "controlled crates.io uploader must be an owned mode-0700 single-link executable",
    )
    snapshot = _digest_file(
        command,
        maximum=MAX_UPLOADER_BYTES,
        label="crates.io exact-byte uploader",
        require_executable=True,
    )

    def upload(
        package: LocalCrate,
        *,
        credential: str,
    ) -> BoundedResult:
        try:
            current_state = normalized_state_root.lstat()
        except OSError as exc:
            raise CratesIoPublicationError(
                "cannot resample crates.io publication state root"
            ) from exc
        _require(
            current_state.st_dev == state_metadata.st_dev
            and current_state.st_ino == state_metadata.st_ino
            and stat.S_IMODE(current_state.st_mode) == PRIVATE_DIRECTORY_MODE,
            "crates.io publication state root changed before uploader invocation",
        )
        current = _digest_file(
            command,
            maximum=MAX_UPLOADER_BYTES,
            label="crates.io exact-byte uploader",
            require_executable=True,
        )
        _require(
            current.size == snapshot.size and current.sha256 == snapshot.sha256,
            "crates.io exact-byte uploader changed before invocation",
        )
        _require(
            len(package.payload) == package.size
            and hashlib.sha256(package.payload).hexdigest() == package.sha256,
            "pinned .crate bytes differ before uploader staging",
        )
        with tempfile.NamedTemporaryFile(
            mode="w+b", prefix="qperiapt-crate-upload-"
        ) as upload_input:
            descriptor = upload_input.fileno()
            offset = 0
            while offset < len(package.payload):
                written = os.write(descriptor, package.payload[offset:])
                _require(written > 0, "exact-byte uploader staging made no progress")
                offset += written
            os.fchmod(descriptor, PRIVATE_FILE_MODE)
            os.fsync(descriptor)
            before = os.fstat(descriptor)
            _require(
                stat.S_ISREG(before.st_mode)
                and before.st_uid == os.geteuid()
                and before.st_nlink == 1
                and stat.S_IMODE(before.st_mode) == PRIVATE_FILE_MODE
                and before.st_size == package.size,
                "exact-byte uploader staging file is unsafe",
            )
            os.lseek(descriptor, 0, os.SEEK_SET)
            result = capture_stdout(
                [
                    os.fspath(command),
                    "--crate-stdin",
                    "--name",
                    package.name,
                    "--version",
                    package.version,
                    "--size",
                    str(package.size),
                    "--sha256",
                    package.sha256,
                ],
                timeout_seconds=UPLOAD_TIMEOUT_SECONDS,
                maximum_bytes=MAX_UPLOADER_OUTPUT_BYTES,
                stdin_fd=descriptor,
                stderr=subprocess.DEVNULL,
                environment={
                    "CARGO_REGISTRY_TOKEN": credential,
                    "LANG": "C",
                    "LC_ALL": "C",
                },
            )
            after = os.fstat(descriptor)
            _require(
                after.st_dev == before.st_dev
                and after.st_ino == before.st_ino
                and after.st_nlink == 1
                and after.st_size == package.size,
                "exact-byte uploader staging identity changed during invocation",
            )
            digest = hashlib.sha256()
            read_offset = 0
            while read_offset < package.size:
                chunk = os.pread(
                    descriptor,
                    min(64 * 1024, package.size - read_offset),
                    read_offset,
                )
                _require(chunk, "exact-byte uploader staging bytes became truncated")
                digest.update(chunk)
                read_offset += len(chunk)
            _require(
                digest.hexdigest() == package.sha256,
                "exact-byte uploader staging bytes changed during invocation",
            )
        observed = _digest_file(
            command,
            maximum=MAX_UPLOADER_BYTES,
            label="crates.io exact-byte uploader",
            require_executable=True,
        )
        _require(
            observed.size == snapshot.size and observed.sha256 == snapshot.sha256,
            "crates.io exact-byte uploader changed during invocation",
        )
        try:
            final_state = normalized_state_root.lstat()
        except OSError as exc:
            raise CratesIoPublicationError(
                "cannot resample crates.io publication state root after upload"
            ) from exc
        _require(
            final_state.st_dev == state_metadata.st_dev
            and final_state.st_ino == state_metadata.st_ino
            and stat.S_IMODE(final_state.st_mode) == PRIVATE_DIRECTORY_MODE,
            "crates.io publication state root changed during uploader invocation",
        )
        secret = credential.encode("utf-8")
        if secret in result.stdout:
            return BoundedResult(returncode=1)
        return BoundedResult(returncode=result.returncode)

    return upload


def _private_regular_metadata(metadata: os.stat_result, *, label: str) -> None:
    uid_getter = getattr(os, "geteuid", None)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or not callable(uid_getter)
        or metadata.st_uid != uid_getter()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != PRIVATE_FILE_MODE
    ):
        raise EvidenceIOError(
            f"{label} must be an owned mode-0600 single-link regular file"
        )


def _read_private_file_at(
    directory_fd: int,
    leaf: str,
    *,
    display_path: pathlib.Path,
    maximum: int,
    label: str,
) -> FileSnapshot:
    chunks: list[bytes] = []
    try:
        digest = consume_regular_snapshot_at(
            directory_fd,
            leaf,
            display_path=display_path,
            maximum=maximum,
            label=label,
            consume=chunks.append,
            validate_metadata=lambda metadata: _private_regular_metadata(
                metadata, label=label
            ),
        )
    except EvidenceIOError as exc:
        raise CratesIoPublicationError(str(exc)) from exc
    data = b"".join(chunks)
    _require(len(data) == digest.size, f"{label} byte count changed while reading")
    return FileSnapshot(
        path=display_path,
        data=data,
        size=digest.size,
        sha256=digest.sha256,
    )


_expected_crate_files = rust_package_handoff.expected_crate_files
_handoff_inventory = rust_package_handoff.handoff_inventory


def validate_rust_package_contract_stderr(stderr: bytes) -> None:
    """Reject inner diagnostics that could spoof or expose the outer boundary."""

    _require(
        isinstance(stderr, bytes),
        "Rust package contract stderr must be bytes",
    )
    _require(
        len(stderr) <= MAX_HANDOFF_STDERR_BYTES,
        "Rust package contract stderr exceeds the byte limit",
    )
    _require(
        b"\x00" not in stderr and b"\r" not in stderr,
        "Rust package contract stderr contains invalid control bytes",
    )
    try:
        stderr.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise CratesIoPublicationError(
            "Rust package contract stderr is not valid UTF-8"
        ) from exc
    lowered = stderr.lower()
    _require(
        not any(marker.lower() in lowered for marker in _RESERVED_HANDOFF_MARKERS),
        "Rust package contract stderr contains a reserved handoff marker",
    )
    _require(
        not any(term in lowered for term in _CREDENTIAL_DIAGNOSTIC_TERMS),
        "Rust package contract stderr contains a credential-related term",
    )
    _require(
        b"file:///" not in lowered
        and _DOUBLE_ABSOLUTE_DIAGNOSTIC_PATH_RE.search(stderr) is None
        and _ABSOLUTE_DIAGNOSTIC_PATH_RE.search(stderr) is None,
        "Rust package contract stderr contains an absolute path",
    )


def validated_rust_package_contract_failure_marker(
    result: BoundedResult,
) -> bytes:
    """Return one allowlisted inner failure marker without exposing raw output."""

    _require(
        isinstance(result, BoundedResult)
        and type(result.returncode) is int
        and result.returncode != 0,
        "Rust package contract failure result is invalid",
    )
    validate_rust_package_contract_stderr(result.stderr)
    _require(
        _RUST_PACKAGE_CONTRACT_FAILURE_RE.fullmatch(result.stderr) is not None,
        "inner Rust package contract failure marker is not allowlisted",
    )
    return result.stderr


def _validated_rust_package_capture(
    result: BoundedResult,
) -> tuple[bytes, bytes]:
    _require(
        isinstance(result, BoundedResult) and type(result.returncode) is int,
        "bounded Rust package contract result type differs",
    )
    _require(
        result.returncode == 0,
        "inner Rust package contract did not complete successfully",
    )
    _require(
        isinstance(result.stdout, bytes)
        and 0 < len(result.stdout) <= MAX_TRANSCRIPT_BYTES,
        "bounded Rust package contract transcript size is invalid",
    )
    validate_rust_package_contract_stderr(result.stderr)
    return result.stdout, result.stderr


def persist_rust_package_contract_capture(
    staging_fd: int,
    result: BoundedResult,
) -> tuple[str, str]:
    """Commit one strictly clean bounded capture into a full handoff stage."""

    stdout, stderr = _validated_rust_package_capture(result)
    try:
        validate_rust_package_contract_transcript(stdout)
    except RustPublishContractError as exc:
        raise CratesIoPublicationError(str(exc)) from exc
    transcript_digest = write_private_bytes_noreplace_at(
        staging_fd,
        RUST_PACKAGE_HANDOFF_TRANSCRIPT_NAME,
        stdout,
        label="bounded Rust package contract transcript",
        maximum=MAX_TRANSCRIPT_BYTES,
    )
    stderr_digest = write_private_bytes_noreplace_at(
        staging_fd,
        RUST_PACKAGE_HANDOFF_STDERR_NAME,
        stderr,
        label="bounded Rust package contract stderr",
        maximum=MAX_HANDOFF_STDERR_BYTES,
    )
    verify_exact_directory_inventory_at(
        staging_fd,
        frozenset(
            {
                RUST_PACKAGE_HANDOFF_STAGING_MANIFEST_NAME,
                RUST_PACKAGE_HANDOFF_TRANSCRIPT_NAME,
                RUST_PACKAGE_HANDOFF_STDERR_NAME,
                *_expected_crate_files(),
            }
        ),
        label="captured Rust package handoff stage",
    )
    return transcript_digest, stderr_digest


def persist_rust_package_diagnostic_capture(
    staging_fd: int,
    result: BoundedResult,
) -> tuple[str, str]:
    """Commit one strict diagnostic capture into an ephemeral two-leaf stage."""

    stdout, stderr = _validated_rust_package_capture(result)
    try:
        validate_rust_package_diagnostic_transcript(stdout)
    except RustPublishContractError as exc:
        raise CratesIoPublicationError(str(exc)) from exc
    transcript_digest = write_private_bytes_noreplace_at(
        staging_fd,
        RUST_PACKAGE_HANDOFF_TRANSCRIPT_NAME,
        stdout,
        label="bounded Rust package diagnostic transcript",
        maximum=MAX_TRANSCRIPT_BYTES,
    )
    stderr_digest = write_private_bytes_noreplace_at(
        staging_fd,
        RUST_PACKAGE_HANDOFF_STDERR_NAME,
        stderr,
        label="bounded Rust package diagnostic stderr",
        maximum=MAX_HANDOFF_STDERR_BYTES,
    )
    verify_exact_directory_inventory_at(
        staging_fd,
        frozenset(
            {
                RUST_PACKAGE_HANDOFF_TRANSCRIPT_NAME,
                RUST_PACKAGE_HANDOFF_STDERR_NAME,
            }
        ),
        label="captured Rust package diagnostic stage",
    )
    return transcript_digest, stderr_digest


def _validate_handoff_source(value: object) -> RustPackageHandoffSource:
    try:
        return rust_package_handoff.validate_rust_package_handoff_source(value)
    except rust_package_handoff.RustPackageHandoffError as exc:
        raise CratesIoPublicationError(str(exc)) from exc


def _validate_handoff_crates(value: object, *, label: str) -> tuple[dict[str, object], ...]:
    try:
        return rust_package_handoff.validate_rust_package_handoff_crates(
            value,
            label=label,
        )
    except rust_package_handoff.RustPackageHandoffError as exc:
        raise CratesIoPublicationError(str(exc)) from exc


def _validate_staging_manifest(value: object) -> tuple[dict[str, object], ...]:
    _require(
        isinstance(value, dict) and all(isinstance(key, str) for key in value),
        "Rust package staging manifest must be an object with string keys",
    )
    _require(
        set(value) == {"crates", "kind", "schema_version"},
        "Rust package staging manifest keys differ",
    )
    _require(
        value["schema_version"] == RUST_PACKAGE_HANDOFF_SCHEMA_VERSION,
        "Rust package staging manifest schema differs",
    )
    _require(
        value["kind"] == RUST_PACKAGE_HANDOFF_STAGING_KIND,
        "Rust package staging manifest kind differs",
    )
    return _validate_handoff_crates(
        value["crates"], label="Rust package staging manifest"
    )


def _validate_handoff_manifest(
    value: object,
) -> tuple[
    RustPackageHandoffSource,
    dict[str, object],
    tuple[dict[str, object], ...],
]:
    try:
        return rust_package_handoff.validate_rust_package_handoff_manifest(
            value
        )
    except rust_package_handoff.RustPackageHandoffError as exc:
        raise CratesIoPublicationError(str(exc)) from exc


def _validated_owned_temporary_root(
    path: pathlib.Path,
    *,
    expected_device: int,
    expected_inode: int,
    name_pattern: re.Pattern[str],
    label: str,
) -> pathlib.Path:
    _require(
        isinstance(expected_device, int)
        and expected_device >= 0
        and isinstance(expected_inode, int)
        and expected_inode > 0,
        f"{label} identity is malformed",
    )
    try:
        normalized = normalize_safe_root(path, label=label)
        temporary_parent = pathlib.Path("/tmp").resolve(strict=True)
        metadata = normalized.lstat()
    except (OSError, PublicationReceiptIOError) as exc:
        raise CratesIoPublicationError(f"{label} is unsafe") from exc
    _require(
        normalized.parent == temporary_parent
        and name_pattern.fullmatch(normalized.name) is not None,
        f"{label} is outside the fixed owned-temporary namespace",
    )
    _require(
        metadata.st_dev == expected_device and metadata.st_ino == expected_inode,
        f"{label} identity differs",
    )
    return normalized


def stage_verified_crate_handoff(
    package_root: pathlib.Path,
    staging_root: pathlib.Path,
    *,
    package_device: int,
    package_inode: int,
    staging_device: int,
    staging_inode: int,
) -> str:
    """Copy the exact ten already-verified Cargo archives into an owned stage."""

    package_root = _validated_owned_temporary_root(
        package_root,
        expected_device=package_device,
        expected_inode=package_inode,
        name_pattern=re.compile(
            r"^qperiapt-package-verification\.[0-9a-f]{24}$"
        ),
        label="Rust package verification root",
    )
    staging_root = _validated_owned_temporary_root(
        staging_root,
        expected_device=staging_device,
        expected_inode=staging_inode,
        name_pattern=_HANDOFF_STAGE_NAME_RE,
        label="Rust package handoff stage",
    )
    package_fd = open_private_directory(
        package_root, label="Rust package verification root"
    )
    try:
        package_metadata = os.fstat(package_fd)
    except OSError as exc:
        try:
            os.close(package_fd)
        except OSError as close_error:
            exc.add_note("cannot close failed Rust package verification root")
        raise CratesIoPublicationError(
            "cannot inspect Rust package verification root"
        ) from exc
    package_handle = PrivateDirectoryHandle(
        path=package_root,
        descriptor=package_fd,
        parent_descriptor=-1,
        name=package_root.name,
        device=package_metadata.st_dev,
        inode=package_metadata.st_ino,
        mode=PRIVATE_DIRECTORY_MODE,
    )
    try:
        staging_fd = open_private_directory(
            staging_root, label="Rust package handoff stage"
        )
    except BaseException as exc:
        try:
            os.close(package_fd)
        except OSError as close_error:
            exc.add_note("cannot close Rust package verification root")
        raise
    primary_error: BaseException | None = None
    try:
        with open_private_directory_at(
            parent=package_handle,
            direct_child_name="package",
            label="Rust Cargo package archive directory",
        ) as archive_handle:
            archive_fd = archive_handle.descriptor
            archive_root = archive_handle.path
            with os.scandir(archive_fd) as iterator:
                archive_entries = frozenset(
                    entry.name
                    for entry in iterator
                    if entry.name.endswith(".crate")
                )
            expected_files = frozenset(_expected_crate_files())
            _require(
                archive_entries == expected_files,
                "Rust Cargo package archive inventory differs",
            )
            with os.scandir(staging_fd) as iterator:
                initial_stage_entries = frozenset(entry.name for entry in iterator)
            _require(
                not initial_stage_entries,
                "Rust package handoff stage contains an unexpected preexisting entry",
            )
            records: list[dict[str, object]] = []
            total_size = 0
            for (name, dependencies), crate_file in zip(
                CRATE_PUBLICATION_TOPOLOGY, _expected_crate_files()
            ):
                snapshot = _read_private_file_at(
                    archive_fd,
                    crate_file,
                    display_path=archive_root / crate_file,
                    maximum=MAX_CRATE_BYTES,
                    label=f"verified {name} .crate archive",
                )
                _require(snapshot.size > 0, f"verified {name} archive is empty")
                total_size += snapshot.size
                _require(
                    total_size <= MAX_TOTAL_CRATE_BYTES,
                    "verified aggregate .crate input exceeds the byte limit",
                )
                written_digest = write_private_bytes_noreplace_at(
                    staging_fd,
                    crate_file,
                    snapshot.data,
                    label=f"staged {name} .crate archive",
                    maximum=MAX_CRATE_BYTES,
                )
                _require(
                    written_digest == snapshot.sha256,
                    f"staged {name} archive digest differs",
                )
                records.append(
                    {
                        "crate_file": crate_file,
                        "crate_sha256": snapshot.sha256,
                        "crate_size": snapshot.size,
                        "dependencies": list(dependencies),
                        "name": name,
                        "version": PRODUCT_VERSION,
                    }
                )
            staging_manifest = {
                "crates": records,
                "kind": RUST_PACKAGE_HANDOFF_STAGING_KIND,
                "schema_version": RUST_PACKAGE_HANDOFF_SCHEMA_VERSION,
            }
            manifest_payload = canonical_json_bytes(staging_manifest)
            manifest_digest = write_private_bytes_noreplace_at(
                staging_fd,
                RUST_PACKAGE_HANDOFF_STAGING_MANIFEST_NAME,
                manifest_payload,
                label="Rust package staging manifest",
                maximum=MAX_HANDOFF_MANIFEST_BYTES,
            )
            verify_exact_directory_inventory_at(
                staging_fd,
                frozenset(
                    {
                        *_expected_crate_files(),
                        RUST_PACKAGE_HANDOFF_STAGING_MANIFEST_NAME,
                    }
                ),
                label="Rust package handoff stage",
            )
            for record in records:
                crate_file = record["crate_file"]
                _require(
                    isinstance(crate_file, str),
                    "staged archive name type differs",
                )
                source_snapshot = _read_private_file_at(
                    archive_fd,
                    crate_file,
                    display_path=archive_root / crate_file,
                    maximum=MAX_CRATE_BYTES,
                    label=f"resampled {record['name']} .crate archive",
                )
                _require(
                    source_snapshot.size == record["crate_size"]
                    and source_snapshot.sha256 == record["crate_sha256"],
                    f"verified {record['name']} archive changed while staging",
                )
            return manifest_digest
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        close_errors: list[OSError] = []
        for descriptor in (staging_fd, package_fd):
            try:
                os.close(descriptor)
            except OSError as exc:
                close_errors.append(exc)
        if close_errors:
            if primary_error is not None:
                primary_error.add_note("cannot close Rust package handoff staging descriptors")
            else:
                raise CratesIoPublicationError(
                    "cannot close Rust package handoff staging descriptors"
                ) from close_errors[0]


def inspect_rust_package_handoff_source(
    repository_root: pathlib.Path = REPOSITORY_ROOT,
) -> RustPackageHandoffSource:
    """Bind one handoff to the clean source-changing commit S and its tree."""

    try:
        inspection = inspect_worktree(repository_root)
        _require(not inspection.dirty, "Rust package handoff source is dirty")
        source_tree = run_git_text(
            repository_root, ["rev-parse", "--verify", "HEAD^{tree}"]
        )
        from claim_ledger import canonical_tree_digest, repository_paths

        canonical_digest = canonical_tree_digest(
            repository_root, repository_paths(repository_root)
        )
    except (GitProvenanceError, ValueError) as exc:
        raise CratesIoPublicationError(str(exc)) from exc
    return _validate_handoff_source(
        {
            "canonical_source_tree_sha256": canonical_digest,
            "source_commit": inspection.commit,
            "source_tree": source_tree,
        }
    )


def _read_staging_manifest(
    staging_fd: int, staging_root: pathlib.Path
) -> tuple[FileSnapshot, tuple[dict[str, object], ...]]:
    snapshot = _read_private_file_at(
        staging_fd,
        RUST_PACKAGE_HANDOFF_STAGING_MANIFEST_NAME,
        display_path=staging_root / RUST_PACKAGE_HANDOFF_STAGING_MANIFEST_NAME,
        maximum=MAX_HANDOFF_MANIFEST_BYTES,
        label="Rust package staging manifest",
    )
    try:
        value = parse_strict_json_bytes(
            snapshot.data, label="Rust package staging manifest"
        )
    except EvidenceIOError as exc:
        raise CratesIoPublicationError(str(exc)) from exc
    return snapshot, _validate_staging_manifest(value)


def finalize_rust_package_handoff(
    staging_root: pathlib.Path,
    *,
    staging_device: int,
    staging_inode: int,
    handoff_root: pathlib.Path = RUST_PACKAGE_HANDOFF_ROOT,
    source_inspector: Callable[[], RustPackageHandoffSource] = (
        inspect_rust_package_handoff_source
    ),
    before_commit: Callable[[], None] | None = None,
) -> tuple[pathlib.Path, str]:
    """Commit one exact package handoff; the manifest is always the last leaf."""

    _require(
        before_commit is None or callable(before_commit),
        "Rust package handoff before-commit hook is invalid",
    )
    staging_root = _validated_owned_temporary_root(
        staging_root,
        expected_device=staging_device,
        expected_inode=staging_inode,
        name_pattern=_HANDOFF_STAGE_NAME_RE,
        label="Rust package handoff stage",
    )
    staging_fd = open_private_directory(
        staging_root, label="Rust package handoff stage"
    )
    primary_error: BaseException | None = None
    try:
        expected_stage_inventory = frozenset(
            {
                RUST_PACKAGE_HANDOFF_STAGING_MANIFEST_NAME,
                RUST_PACKAGE_HANDOFF_TRANSCRIPT_NAME,
                RUST_PACKAGE_HANDOFF_STDERR_NAME,
                *_expected_crate_files(),
            }
        )
        verify_exact_directory_inventory_at(
            staging_fd,
            expected_stage_inventory,
            label="completed Rust package handoff stage",
        )
        staging_manifest, crate_records = _read_staging_manifest(
            staging_fd, staging_root
        )
        transcript = _read_private_file_at(
            staging_fd,
            RUST_PACKAGE_HANDOFF_TRANSCRIPT_NAME,
            display_path=staging_root / RUST_PACKAGE_HANDOFF_TRANSCRIPT_NAME,
            maximum=MAX_TRANSCRIPT_BYTES,
            label="complete Rust package contract transcript",
        )
        stderr = _read_private_file_at(
            staging_fd,
            RUST_PACKAGE_HANDOFF_STDERR_NAME,
            display_path=staging_root / RUST_PACKAGE_HANDOFF_STDERR_NAME,
            maximum=MAX_HANDOFF_STDERR_BYTES,
            label="complete Rust package contract stderr",
        )
        validate_rust_package_contract_stderr(stderr.data)
        try:
            package_contract = validate_rust_package_contract_transcript(
                transcript.data
            )
        except RustPublishContractError as exc:
            raise CratesIoPublicationError(str(exc)) from exc
        source = source_inspector()
        _validate_handoff_source(source.document())
        _require(
            package_contract.source_commit == source.source_commit,
            "Rust package transcript source differs from handoff source commit",
        )
        try:
            normalized_handoff_root = ensure_private_safe_root(
                handoff_root, label="Rust package handoff root"
            )
        except PublicationReceiptIOError as exc:
            raise CratesIoPublicationError(str(exc)) from exc
        transaction_name = f"transaction.{os.getpid()}-{secrets.token_hex(16)}"
        _require(
            _HANDOFF_TRANSACTION_RE.fullmatch(transaction_name) is not None,
            "Rust package handoff transaction name is malformed",
        )
        manifest_path = (
            normalized_handoff_root
            / transaction_name
            / RUST_PACKAGE_HANDOFF_MANIFEST_NAME
        )
        committed_digest: str | None = None
        try:
            with create_private_direct_child_handle(
                safe_root=normalized_handoff_root,
                direct_child_name=transaction_name,
                label="Rust package handoff transaction",
            ) as transaction:
                transcript_digest = write_private_bytes_noreplace_at(
                    transaction.descriptor,
                    RUST_PACKAGE_HANDOFF_TRANSCRIPT_NAME,
                    transcript.data,
                    label="Rust package handoff transcript",
                    maximum=MAX_TRANSCRIPT_BYTES,
                )
                _require(
                    transcript_digest == transcript.sha256,
                    "Rust package handoff transcript digest differs",
                )
                for record in crate_records:
                    crate_file = record["crate_file"]
                    _require(
                        isinstance(crate_file, str),
                        "Rust package handoff archive name type differs",
                    )
                    archive = _read_private_file_at(
                        staging_fd,
                        crate_file,
                        display_path=staging_root / crate_file,
                        maximum=MAX_CRATE_BYTES,
                        label=f"staged {record['name']} .crate archive",
                    )
                    _require(
                        archive.size == record["crate_size"]
                        and archive.sha256 == record["crate_sha256"],
                        f"staged {record['name']} archive differs from its manifest",
                    )
                    written_digest = write_private_bytes_noreplace_at(
                        transaction.descriptor,
                        crate_file,
                        archive.data,
                        label=f"Rust package handoff {record['name']} archive",
                        maximum=MAX_CRATE_BYTES,
                    )
                    _require(
                        written_digest == record["crate_sha256"],
                        f"Rust package handoff {record['name']} digest differs",
                    )
                handoff_manifest = {
                    "boundary": RUST_PACKAGE_HANDOFF_BOUNDARY,
                    "crates": list(crate_records),
                    "kind": RUST_PACKAGE_HANDOFF_KIND,
                    "schema_version": RUST_PACKAGE_HANDOFF_SCHEMA_VERSION,
                    "source": source.document(),
                    "transcript": {
                        "file": RUST_PACKAGE_HANDOFF_TRANSCRIPT_NAME,
                        "sha256": transcript.sha256,
                        "size": transcript.size,
                    },
                    "upload_attempted": False,
                }
                _validate_handoff_manifest(handoff_manifest)
                with prepare_private_json_noreplace_at(
                    transaction,
                    RUST_PACKAGE_HANDOFF_MANIFEST_NAME,
                    handoff_manifest,
                    label="Rust package handoff manifest",
                    maximum=MAX_HANDOFF_MANIFEST_BYTES,
                ) as prepared:
                    def verify_transaction_payloads(phase: str) -> None:
                        transaction_transcript = _read_private_file_at(
                            transaction.descriptor,
                            RUST_PACKAGE_HANDOFF_TRANSCRIPT_NAME,
                            display_path=(
                                transaction.path
                                / RUST_PACKAGE_HANDOFF_TRANSCRIPT_NAME
                            ),
                            maximum=MAX_TRANSCRIPT_BYTES,
                            label=f"{phase} Rust package handoff transcript",
                        )
                        _require(
                            transaction_transcript.data == transcript.data,
                            f"{phase} Rust package handoff transcript differs",
                        )
                        for crate_record in crate_records:
                            crate_file = crate_record["crate_file"]
                            _require(
                                isinstance(crate_file, str),
                                "Rust package handoff archive name type differs",
                            )
                            transaction_archive = _read_private_file_at(
                                transaction.descriptor,
                                crate_file,
                                display_path=transaction.path / crate_file,
                                maximum=MAX_CRATE_BYTES,
                                label=(
                                    f"{phase} Rust package handoff "
                                    f"{crate_record['name']} archive"
                                ),
                            )
                            _require(
                                transaction_archive.size
                                == crate_record["crate_size"]
                                and transaction_archive.sha256
                                == crate_record["crate_sha256"],
                                f"{phase} Rust package handoff "
                                f"{crate_record['name']} archive differs",
                            )

                    verify_exact_directory_inventory_at(
                        transaction.descriptor,
                        frozenset(
                            {
                                RUST_PACKAGE_HANDOFF_TRANSCRIPT_NAME,
                                *_expected_crate_files(),
                                prepared.staging_leaf,
                            }
                        ),
                        label="prepared Rust package handoff transaction",
                    )
                    verify_transaction_payloads("prepared")
                    current_source = source_inspector()
                    _require(
                        current_source == source,
                        "Rust package handoff source changed before commit",
                    )
                    current_staging_manifest, _records = _read_staging_manifest(
                        staging_fd, staging_root
                    )
                    _require(
                        current_staging_manifest.sha256
                        == staging_manifest.sha256,
                        "Rust package staging manifest changed before commit",
                    )
                    current_transcript = _read_private_file_at(
                        staging_fd,
                        RUST_PACKAGE_HANDOFF_TRANSCRIPT_NAME,
                        display_path=(
                            staging_root / RUST_PACKAGE_HANDOFF_TRANSCRIPT_NAME
                        ),
                        maximum=MAX_TRANSCRIPT_BYTES,
                        label="resampled Rust package contract transcript",
                    )
                    _require(
                        current_transcript.data == transcript.data,
                        "Rust package transcript changed before handoff commit",
                    )
                    current_stderr = _read_private_file_at(
                        staging_fd,
                        RUST_PACKAGE_HANDOFF_STDERR_NAME,
                        display_path=(
                            staging_root / RUST_PACKAGE_HANDOFF_STDERR_NAME
                        ),
                        maximum=MAX_HANDOFF_STDERR_BYTES,
                        label="resampled Rust package contract stderr",
                    )
                    _require(
                        current_stderr.data == stderr.data,
                        "Rust package stderr changed before handoff commit",
                    )
                    validate_rust_package_contract_stderr(current_stderr.data)
                    if before_commit is not None:
                        before_commit()
                    committed_digest = prepared.commit_after_revalidation()
                verify_exact_directory_inventory_at(
                    transaction.descriptor,
                    _handoff_inventory(),
                    label="committed Rust package handoff transaction",
                )
                verify_transaction_payloads("committed")
                committed_manifest = _read_private_file_at(
                    transaction.descriptor,
                    RUST_PACKAGE_HANDOFF_MANIFEST_NAME,
                    display_path=manifest_path,
                    maximum=MAX_HANDOFF_MANIFEST_BYTES,
                    label="committed Rust package handoff manifest",
                )
                _require(
                    committed_manifest.sha256 == committed_digest,
                    "committed Rust package handoff manifest digest differs",
                )
                _require(
                    source_inspector() == source,
                    "Rust package handoff source changed after commit",
                )
            _require(
                committed_digest is not None,
                "Rust package handoff manifest was not committed",
            )
            return manifest_path, committed_digest
        except PublicationReceiptCommittedError as exc:
            if exc.path is None:
                exc.path = manifest_path
            raise
        except BaseException as exc:
            if committed_digest is not None:
                raise PublicationReceiptCommittedError(
                    "Rust package handoff manifest committed but postcommit verification failed",
                    leaf=RUST_PACKAGE_HANDOFF_MANIFEST_NAME,
                    digest=committed_digest,
                    path=manifest_path,
                ) from exc
            raise
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        try:
            os.close(staging_fd)
        except OSError as exc:
            if primary_error is not None:
                primary_error.add_note("cannot close Rust package handoff stage")
            else:
                raise CratesIoPublicationError(
                    "cannot close Rust package handoff stage"
                ) from exc


def _source_tree_for_commit(source_commit: str) -> str:
    try:
        tree = run_git_text(
            REPOSITORY_ROOT,
            ["rev-parse", "--verify", f"{source_commit}^{{tree}}"],
        )
    except GitProvenanceError as exc:
        raise CratesIoPublicationError(str(exc)) from exc
    _require(_SHA1_RE.fullmatch(tree) is not None, "source commit tree is malformed")
    return tree


def _verify_stable_source_transition(
    source: SourceIdentity,
    handoff_manifest_path: pathlib.Path,
    handoff_manifest_sha256: str,
) -> None:
    """Require S->R plus a clean linear results-only R/current transition."""

    _source_identity_document(source)
    try:
        inspection = inspect_worktree(REPOSITORY_ROOT)
        _require(
            not inspection.dirty,
            "crates.io publication checkout must be clean",
        )
        require_direct_results_only_child(
            REPOSITORY_ROOT,
            source.source_parent_commit,
            source.tag_commit,
        )
        results_tree = run_git_text(
            REPOSITORY_ROOT,
            ["rev-parse", "--verify", f"{source.tag_commit}^{{tree}}"],
        )
        if inspection.commit != source.tag_commit:
            merge_commits = run_git_text(
                REPOSITORY_ROOT,
                ["rev-list", "--merges", f"{source.tag_commit}..{inspection.commit}"],
            )
            _require(
                merge_commits == "",
                "crates.io publication checkout contains a merge after results commit R",
            )
            require_results_only_descendant(
                REPOSITORY_ROOT,
                source.tag_commit,
                inspection.commit,
            )
    except GitProvenanceError as exc:
        raise CratesIoPublicationError(str(exc)) from exc
    _require(
        results_tree == source.tag_tree,
        "crates.io publication results tree differs from tag_tree",
    )
    _verify_results_selected_handoff(
        source,
        handoff_manifest_path,
        handoff_manifest_sha256,
    )


def _load_tag_results_manifest(tag_commit: str) -> dict[str, object]:
    object_name = f"{tag_commit}:artifact/results.json"
    try:
        object_type = run_git_text(
            REPOSITORY_ROOT,
            ["cat-file", "-t", object_name],
        )
        raw_size = run_git_text(
            REPOSITORY_ROOT,
            ["cat-file", "-s", object_name],
        )
        _require(object_type == "blob", "results commit R does not contain a results blob")
        _require(
            re.fullmatch(r"(?:0|[1-9][0-9]*)", raw_size) is not None,
            "results commit R manifest size is malformed",
        )
        size = int(raw_size, 10)
        _require(
            0 < size <= 4 * 1024 * 1024,
            "results commit R manifest size is outside policy",
        )
        payload = run_git_bytes(
            REPOSITORY_ROOT,
            ["cat-file", "blob", object_name],
        )
    except GitProvenanceError as exc:
        raise CratesIoPublicationError(
            "cannot read the results manifest from commit R"
        ) from exc
    _require(
        len(payload) == size,
        "results commit R manifest size changed while reading",
    )
    try:
        value = parse_strict_json_bytes(
            payload,
            label="results commit R manifest",
        )
    except EvidenceIOError as exc:
        raise CratesIoPublicationError(
            "results commit R manifest is not strict JSON"
        ) from exc
    _require(
        isinstance(value, dict)
        and all(isinstance(key, str) for key in value),
        "results commit R manifest must be an object with string keys",
    )
    return value


def _validate_results_selected_handoff(
    manifest: dict[str, object],
    source: SourceIdentity,
    handoff_manifest_relative: str,
    handoff_manifest_sha256: str,
) -> None:
    """Bind the irreversible registry lane to R's selected clean-S handoff."""

    try:
        validate_stable_source_currentness(manifest)
    except ReleasePublicationContractError as exc:
        raise CratesIoPublicationError(
            "results commit R stable source currentness is invalid"
        ) from exc
    provenance = manifest.get("provenance")
    _require(isinstance(provenance, dict), "results commit R provenance is missing")
    _require(
        provenance.get("snapshot_commit") == source.source_parent_commit
        and manifest.get("proof_source_tree_sha256")
        == source.canonical_source_tree_sha256,
        "results commit R source identity differs from registry source S",
    )
    rust_publish = manifest.get("rust_publish")
    _require(
        isinstance(rust_publish, dict),
        "results commit R lacks selected Rust package evidence",
    )
    _require(
        rust_publish.get("current_source_status")
        == "current_clean_tree_rust_package_contract_pass"
        and rust_publish.get("status") == "pass"
        and rust_publish.get("upload_attempted") is False
        and rust_publish.get("source_commit") == source.source_parent_commit
        and rust_publish.get("proof_source_tree_sha256")
        == source.canonical_source_tree_sha256
        and rust_publish.get("source_tree_dirty") is False,
        "results commit R Rust package evidence is not current clean S",
    )
    _require(
        isinstance(handoff_manifest_relative, str),
        "registry handoff path is outside the fixed repository namespace",
    )
    handoff_relative = pathlib.PurePosixPath(handoff_manifest_relative)
    _require(
        handoff_relative.as_posix() == handoff_manifest_relative
        and len(handoff_relative.parts) == 4
        and handoff_relative.parts[:2]
        == ("target", "qperiapt-rust-package-handoffs")
        and _HANDOFF_TRANSACTION_RE.fullmatch(handoff_relative.parts[2])
        is not None
        and handoff_relative.parts[3] == RUST_PACKAGE_HANDOFF_MANIFEST_NAME
        and ".." not in handoff_relative.parts
        and "\\" not in handoff_manifest_relative,
        "registry handoff path is outside the fixed repository namespace",
    )
    _require(
        isinstance(handoff_manifest_sha256, str)
        and _SHA256_RE.fullmatch(handoff_manifest_sha256) is not None,
        "registry handoff digest is malformed",
    )
    _require(
        rust_publish.get("handoff_manifest_path") == handoff_manifest_relative
        and rust_publish.get("handoff_manifest_sha256")
        == handoff_manifest_sha256,
        "registry handoff differs from the exact handoff selected by results commit R",
    )


def _results_selected_handoff(source: SourceIdentity) -> ResultsSelectedHandoff:
    """Load R's selected handoff and reconstruct its fixed repository path."""

    manifest = _load_tag_results_manifest(source.tag_commit)
    rust_publish = manifest.get("rust_publish")
    _require(
        isinstance(rust_publish, dict),
        "results commit R lacks selected Rust package evidence",
    )
    relative_text = rust_publish.get("handoff_manifest_path")
    digest = rust_publish.get("handoff_manifest_sha256")
    _require(
        isinstance(relative_text, str) and isinstance(digest, str),
        "results commit R selected Rust handoff is malformed",
    )
    _validate_results_selected_handoff(
        manifest,
        source,
        relative_text,
        digest,
    )
    relative = pathlib.PurePosixPath(relative_text)
    selected = REPOSITORY_ROOT.joinpath(*relative.parts)
    _require(
        selected.parent.parent == RUST_PACKAGE_HANDOFF_ROOT,
        "results commit R selected Rust handoff escaped its fixed root",
    )
    return ResultsSelectedHandoff(
        path=selected,
        relative_path=relative,
        sha256=digest,
    )


def _verify_results_selected_handoff(
    source: SourceIdentity,
    handoff_manifest_path: pathlib.Path,
    handoff_manifest_sha256: str,
) -> None:
    selected = _results_selected_handoff(source)
    _require(
        handoff_manifest_path == selected.path
        and os.fspath(handoff_manifest_path) == os.fspath(selected.path)
        and handoff_manifest_sha256 == selected.sha256,
        "registry handoff differs from the exact handoff selected by results commit R",
    )


def load_rust_package_handoff_snapshot(
    handoff_manifest_path: pathlib.Path,
    handoff_manifest_sha256: str,
    expected_source: RustPackageHandoffSource,
    *,
    handoff_root: pathlib.Path = RUST_PACKAGE_HANDOFF_ROOT,
) -> RustPackageHandoffSnapshot:
    """Adapt the neutral committed-handoff loader to registry errors."""

    try:
        return rust_package_handoff.load_rust_package_handoff_snapshot(
            handoff_manifest_path,
            handoff_manifest_sha256,
            expected_source,
            handoff_root=handoff_root,
        )
    except rust_package_handoff.RustPackageHandoffError as exc:
        raise CratesIoPublicationError(str(exc)) from exc


def load_local_publication_evidence(
    source: SourceIdentity,
    handoff_manifest_path: pathlib.Path,
    handoff_manifest_sha256: str,
    *,
    handoff_root: pathlib.Path = RUST_PACKAGE_HANDOFF_ROOT,
    source_tree_resolver: SourceTreeResolver = _source_tree_for_commit,
    source_transition_verifier: SourceTransitionVerifier = (
        _verify_stable_source_transition
    ),
) -> LocalPublicationEvidence:
    """Snapshot one explicit committed handoff; no directory discovery exists."""

    _source_identity_document(source)
    try:
        source_transition_verifier(
            source,
            handoff_manifest_path,
            handoff_manifest_sha256,
        )
    except CratesIoPublicationError:
        raise
    except Exception as exc:
        raise CratesIoPublicationError(
            "cannot verify stable S-to-R source transition"
        ) from exc
    try:
        resolved_source_tree = source_tree_resolver(source.source_parent_commit)
    except CratesIoPublicationError:
        raise
    except Exception as exc:
        raise CratesIoPublicationError(
            "cannot resolve the stable source parent tree"
        ) from exc
    expected_handoff_source = RustPackageHandoffSource(
        source_commit=source.source_parent_commit,
        source_tree=resolved_source_tree,
        canonical_source_tree_sha256=source.canonical_source_tree_sha256,
    )
    handoff = load_rust_package_handoff_snapshot(
        handoff_manifest_path,
        handoff_manifest_sha256,
        expected_handoff_source,
        handoff_root=handoff_root,
    )
    packages = tuple(
        LocalCrate(
            name=crate.name,
            version=crate.version,
            dependencies=crate.dependencies,
            path=crate.file.path,
            size=crate.file.size,
            sha256=crate.file.sha256,
            payload=crate.file.data,
        )
        for crate in handoff.crates
    )
    return LocalPublicationEvidence(
        source=source,
        handoff_snapshot=handoff,
        handoff_root=handoff.handoff_root,
        handoff_manifest_path=handoff.manifest.path,
        handoff_manifest_sha256=handoff_manifest_sha256,
        handoff_source_tree=handoff.source.source_tree,
        handoff_inventory=handoff.inventory,
        source_tree_resolver=source_tree_resolver,
        source_transition_verifier=source_transition_verifier,
        transcript_path=handoff.transcript.path,
        transcript_sha256=handoff.transcript.sha256,
        package_contract=handoff.package_contract,
        package_root=handoff.manifest.path.parent,
        crates=packages,
    )


def _resample_local_evidence(evidence: LocalPublicationEvidence) -> None:
    try:
        evidence.source_transition_verifier(
            evidence.source,
            evidence.handoff_manifest_path,
            evidence.handoff_manifest_sha256,
        )
        source_tree = evidence.source_tree_resolver(
            evidence.source.source_parent_commit
        )
    except CratesIoPublicationError:
        raise
    except Exception as exc:
        raise CratesIoPublicationError(
            "cannot resample stable S-to-R source transition"
        ) from exc
    _require(
        source_tree == evidence.handoff_source_tree,
        "Rust package handoff source tree changed during publication",
    )
    current = load_rust_package_handoff_snapshot(
        evidence.handoff_manifest_path,
        evidence.handoff_manifest_sha256,
        evidence.handoff_snapshot.source,
        handoff_root=evidence.handoff_root,
    )
    _require(
        current.manifest.data == evidence.handoff_snapshot.manifest.data,
        "Rust package handoff manifest changed during publication",
    )
    _require(
        current.transcript.data == evidence.handoff_snapshot.transcript.data,
        "Rust package transcript changed during publication",
    )
    for package, crate in zip(evidence.crates, current.crates):
        _require(
            crate.file.size == package.size
            and crate.file.sha256 == package.sha256
            and crate.file.data == package.payload,
            f"{package.name} .crate archive changed during publication",
        )


def _sparse_path(crate_name: str) -> str:
    # Names are taken solely from the frozen topology.  Keep Cargo's canonical
    # lowercase sparse-index sharding local to the registry adapter.
    _require(
        crate_name in CRATE_DEPENDENCIES,
        "sparse-index crate is outside the frozen topology",
    )
    lowered = crate_name.lower()
    if len(lowered) == 1:
        return f"1/{lowered}"
    if len(lowered) == 2:
        return f"2/{lowered}"
    if len(lowered) == 3:
        return f"3/{lowered[0]}/{lowered}"
    return f"{lowered[:2]}/{lowered[2:4]}/{lowered}"


def _bounded_response_body(
    response: Any,
    *,
    maximum: int,
    label: str,
) -> bytes:
    content_length = response.headers.get("Content-Length")
    if content_length is not None:
        _require(
            isinstance(content_length, str)
            and content_length.isascii()
            and content_length.isdigit(),
            f"{label} Content-Length is malformed",
        )
        _require(
            int(content_length) <= maximum,
            f"{label} response exceeds the byte limit",
        )
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = response.read(min(64 * 1024, maximum + 1 - total))
        _require(isinstance(chunk, bytes), f"{label} response is not bytes")
        if not chunk:
            break
        total += len(chunk)
        _require(total <= maximum, f"{label} response exceeds the byte limit")
        chunks.append(chunk)
    return b"".join(chunks)


def _reject_remote_trust_environment(
    source: Mapping[str, str],
) -> None:
    overridden = sorted(
        name
        for name in _DANGEROUS_REMOTE_TRUST_ENVIRONMENT
        if name in source
    )
    _require(
        not overridden,
        "crates.io production observation rejects proxy or TLS trust overrides",
    )


def _validate_official_https_url(url: str) -> None:
    _require(
        isinstance(url, str) and 0 < len(url) <= 8_192,
        "crates.io HTTP URL is malformed",
    )
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise CratesIoPublicationError(
            "crates.io HTTP URL is malformed"
        ) from exc
    allowed_path = (
        parsed.hostname == "crates.io"
        and parsed.path.startswith("/api/v1/crates/")
    ) or (
        parsed.hostname == "index.crates.io"
        and parsed.path.startswith("/")
    )
    _require(
        parsed.scheme == "https"
        and port in {None, 443}
        and parsed.username is None
        and parsed.password is None
        and not parsed.fragment
        and allowed_path,
        "HTTP request is outside the official crates.io HTTPS origins",
    )


def _https_get(
    url: str,
    *,
    timeout_seconds: int,
    maximum_bytes: int,
) -> HttpResponse:
    _validate_official_https_url(url)
    _reject_remote_trust_environment(os.environ)
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "User-Agent": HTTP_USER_AGENT,
        },
        method="GET",
    )
    try:
        tls_context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
        _require(
            tls_context.check_hostname is True
            and tls_context.verify_mode == ssl.CERT_REQUIRED,
            "crates.io TLS context is not verification-enforcing",
        )
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=tls_context),
            _RejectRedirectHandler(),
        )
    except CratesIoPublicationError:
        raise
    except (OSError, ssl.SSLError, ValueError):
        _unknown("crates.io TLS context could not be established")
    try:
        response = opener.open(request, timeout=timeout_seconds)
        with response:
            status = getattr(response, "status", None)
            final_url = response.geturl()
            body = _bounded_response_body(
                response,
                maximum=maximum_bytes,
                label="crates.io HTTP",
            )
    except urllib.error.HTTPError as exc:
        with contextlib.closing(exc):
            status = exc.code
            final_url = exc.geturl()
            try:
                body = _bounded_response_body(
                    exc,
                    maximum=maximum_bytes,
                    label="crates.io HTTP error",
                )
            except CratesIoPublicationError:
                raise
            except Exception:
                _unknown("crates.io HTTP error body could not be read safely")
    except CratesIoPublicationError:
        raise
    except (OSError, TimeoutError, urllib.error.URLError):
        _unknown("crates.io HTTPS observation failed")
    _require(type(status) is int, "crates.io HTTP status is malformed")
    _require(final_url == url, "crates.io HTTP response redirected")
    return HttpResponse(status=status, final_url=final_url, body=body)


def _call_fetcher(
    fetcher: HttpFetcher,
    url: str,
    *,
    maximum_bytes: int,
) -> HttpResponse:
    _require(callable(fetcher), "crates.io HTTP fetcher must be callable")
    try:
        response = fetcher(
            url,
            timeout_seconds=HTTP_TIMEOUT_SECONDS,
            maximum_bytes=maximum_bytes,
        )
    except CratesIoPublicationError:
        raise
    except Exception:
        _unknown("crates.io HTTP fetcher failed")
    _require(isinstance(response, HttpResponse), "HTTP fetcher result type differs")
    _require(type(response.status) is int, "HTTP fetcher status is malformed")
    _require(response.final_url == url, "HTTP fetcher redirected from the exact URL")
    _require(isinstance(response.body, bytes), "HTTP fetcher body is not bytes")
    _require(
        len(response.body) <= maximum_bytes,
        "HTTP fetcher body exceeds its byte limit",
    )
    return response


def _remote_record_fields(
    record: Mapping[str, object],
    *,
    version_key: str,
    label: str,
) -> tuple[str, str, bool]:
    version = record.get(version_key)
    checksum = record.get("checksum" if version_key == "num" else "cksum")
    yanked = record.get("yanked")
    _require(
        isinstance(version, str) and 0 < len(version) <= 128,
        f"{label} version is malformed",
    )
    _require(
        isinstance(checksum, str) and _SHA256_RE.fullmatch(checksum) is not None,
        f"{label} checksum is malformed",
    )
    _require(type(yanked) is bool, f"{label} yanked flag is malformed")
    return version, checksum, yanked


def _parse_api_observation(
    package: LocalCrate,
    response: HttpResponse,
) -> tuple[str, bool] | None:
    if response.status == 404:
        return None
    if response.status != 200:
        _unknown(f"crates.io API status is indeterminate for {package.name}")
    try:
        value = parse_strict_json_bytes(
            response.body, label=f"crates.io API {package.name}"
        )
    except EvidenceIOError as exc:
        raise CratesIoPublicationError(str(exc)) from exc
    _require(
        isinstance(value, dict)
        and all(isinstance(key, str) for key in value),
        f"crates.io API {package.name} root must be an object",
    )
    record = value.get("version")
    _require(
        isinstance(record, dict)
        and all(isinstance(key, str) for key in record),
        f"crates.io API {package.name} version must be an object",
    )
    version, checksum, yanked = _remote_record_fields(
        record,
        version_key="num",
        label=f"crates.io API {package.name}",
    )
    _require(version == package.version, f"crates.io API version differs for {package.name}")
    crate_name = record.get("crate")
    _require(
        crate_name is None or crate_name == package.name,
        f"crates.io API crate name differs for {package.name}",
    )
    return checksum, yanked


def _parse_sparse_observation(
    package: LocalCrate,
    response: HttpResponse,
) -> tuple[str, bool] | None:
    if response.status == 404:
        return None
    if response.status != 200:
        _unknown(f"crates.io sparse status is indeterminate for {package.name}")
    payload = response.body
    _require(
        payload.endswith(b"\n") and b"\r" not in payload,
        f"crates.io sparse response is not canonical JSON-lines for {package.name}",
    )
    lines = payload[:-1].split(b"\n")
    _require(
        len(lines) <= MAX_SPARSE_RECORDS,
        f"crates.io sparse response has too many records for {package.name}",
    )
    records: dict[str, tuple[str, bool]] = {}
    for line_number, line in enumerate(lines, start=1):
        _require(bool(line), f"crates.io sparse response contains a blank line for {package.name}")
        try:
            value = parse_strict_json_bytes(
                line,
                label=f"crates.io sparse {package.name} line {line_number}",
            )
        except EvidenceIOError as exc:
            raise CratesIoPublicationError(str(exc)) from exc
        _require(
            isinstance(value, dict)
            and all(isinstance(key, str) for key in value),
            f"crates.io sparse record is not an object for {package.name}",
        )
        _require(
            value.get("name") == package.name,
            f"crates.io sparse record name differs for {package.name}",
        )
        version, checksum, yanked = _remote_record_fields(
            value,
            version_key="vers",
            label=f"crates.io sparse {package.name} line {line_number}",
        )
        _require(
            version not in records,
            f"crates.io sparse index contains duplicate version {version} for {package.name}",
        )
        records[version] = checksum, yanked
    return records.get(package.version)


def observe_remote_crate(
    package: LocalCrate,
    *,
    api_fetcher: HttpFetcher = _https_get,
    sparse_fetcher: HttpFetcher = _https_get,
    clock: Clock = lambda: dt.datetime.now(dt.UTC),
) -> RemotePublishedRecord | None:
    """Classify one version only when API and sparse observations agree."""

    _require(isinstance(package, LocalCrate), "local crate observation type differs")
    api_url = f"{CRATES_IO_REGISTRY}/api/v1/crates/{package.name}/{package.version}"
    sparse_url = f"{CRATES_IO_SPARSE_INDEX}/{_sparse_path(package.name)}"
    api = _parse_api_observation(
        package,
        _call_fetcher(api_fetcher, api_url, maximum_bytes=MAX_API_BYTES),
    )
    sparse = _parse_sparse_observation(
        package,
        _call_fetcher(
            sparse_fetcher, sparse_url, maximum_bytes=MAX_SPARSE_BYTES
        ),
    )
    if api is None and sparse is None:
        return None
    if api is None or sparse is None:
        _unknown(
            f"crates.io API and sparse index disagree on presence for {package.name}"
        )
    api_checksum, api_yanked = api
    sparse_checksum, sparse_yanked = sparse
    _require(
        api_checksum == package.sha256,
        f"crates.io API checksum differs from the exact local archive for {package.name}",
    )
    _require(
        sparse_checksum == package.sha256,
        f"crates.io sparse checksum differs from the exact local archive for {package.name}",
    )
    _require(
        api_yanked is False and sparse_yanked is False,
        f"crates.io marks {package.name} {package.version} as yanked",
    )
    return RemotePublishedRecord(
        api_checksum=api_checksum,
        sparse_checksum=sparse_checksum,
        verified_at=_canonical_timestamp(clock),
    )


def observe_remote_prefix(
    evidence: LocalPublicationEvidence,
    *,
    api_fetcher: HttpFetcher = _https_get,
    sparse_fetcher: HttpFetcher = _https_get,
    clock: Clock = lambda: dt.datetime.now(dt.UTC),
) -> tuple[RemotePublishedRecord | None, ...]:
    """Observe all ten crates and require one exact published prefix."""

    observations = tuple(
        observe_remote_crate(
            package,
            api_fetcher=api_fetcher,
            sparse_fetcher=sparse_fetcher,
            clock=clock,
        )
        for package in evidence.crates
    )
    published_count = sum(item is not None for item in observations)
    _require(
        observations
        == observations[:published_count]
        + (None,) * (len(observations) - published_count)
        and all(item is not None for item in observations[:published_count]),
        "remote crates.io versions do not form the fixed topology prefix",
    )
    return observations


def assemble_publication_receipt(
    evidence: LocalPublicationEvidence,
    observations: Sequence[RemotePublishedRecord | None],
    *,
    observed_at: str,
) -> dict[str, object]:
    """Build and self-validate one public receipt from exact observations."""

    _require(
        len(observations) == len(evidence.crates),
        "remote observation count differs from the ten local crates",
    )
    crate_documents: list[dict[str, object]] = []
    published_count = 0
    saw_absent = False
    for package, remote in zip(evidence.crates, observations):
        document = package.base_document()
        if remote is None:
            saw_absent = True
        else:
            _require(
                not saw_absent,
                "published observations must form one exact topology prefix",
            )
            published_count += 1
            document.update(
                {
                    "crates_io_api": {
                        "checksum": remote.api_checksum,
                        "version": package.version,
                        "yanked": False,
                    },
                    "sparse_index": {
                        "checksum": remote.sparse_checksum,
                        "version": package.version,
                        "yanked": False,
                    },
                    "state": CRATE_STATUS_PUBLISHED_VERIFIED,
                    "verified_at": remote.verified_at,
                }
            )
        crate_documents.append(document)
    receipt: dict[str, object] = {
        "boundary": CRATES_IO_PUBLICATION_BOUNDARY,
        "crates": crate_documents,
        "identity": {
            "abi_version": ABI_VERSION,
            "product_version": PRODUCT_VERSION,
            "publication_key": CRATES_IO_PUBLICATION_KEY,
            "registry": CRATES_IO_REGISTRY,
        },
        "kind": CRATES_IO_PUBLICATION_KIND,
        "observation": {
            "observed_at": observed_at,
            "package_contract": {
                "completed_at": evidence.package_contract.completed_at,
                "handoff_sha256": evidence.handoff_manifest_sha256,
                "source_commit": evidence.package_contract.source_commit,
                "transcript_sha256": evidence.transcript_sha256,
            },
            "source": _source_identity_document(evidence.source),
        },
        "schema_version": CRATES_IO_PUBLICATION_SCHEMA_VERSION,
        "status": (
            PUBLICATION_STATUS_PUBLISHED_VERIFIED
            if published_count == len(evidence.crates)
            else PUBLICATION_STATUS_PARTIAL
        ),
    }
    try:
        validate_crates_io_publication_receipt(receipt)
    except CratesIoPublicationContractError as exc:
        raise CratesIoPublicationError(str(exc)) from exc
    return receipt


def _previous_published_count(
    previous_receipt: Mapping[str, object] | None,
    *,
    evidence: LocalPublicationEvidence,
) -> int:
    if previous_receipt is None:
        return 0
    try:
        validate_crates_io_publication_receipt(previous_receipt)
    except CratesIoPublicationContractError as exc:
        raise CratesIoPublicationError(str(exc)) from exc
    observation = previous_receipt["observation"]
    _require(isinstance(observation, dict), "prior observation type differs")
    _require(
        observation["source"] == _source_identity_document(evidence.source),
        "prior receipt source identity differs",
    )
    expected_package_contract = {
        "completed_at": evidence.package_contract.completed_at,
        "handoff_sha256": evidence.handoff_manifest_sha256,
        "source_commit": evidence.package_contract.source_commit,
        "transcript_sha256": evidence.transcript_sha256,
    }
    _require(
        observation["package_contract"] == expected_package_contract,
        "prior receipt package contract differs",
    )
    previous_crates = previous_receipt["crates"]
    _require(isinstance(previous_crates, list), "prior crate records type differs")
    published_count = 0
    for package, prior in zip(evidence.crates, previous_crates):
        _require(isinstance(prior, dict), "prior crate record type differs")
        expected_base = package.base_document()
        for key in (
            "crate_file",
            "crate_sha256",
            "crate_size",
            "dependencies",
            "name",
            "version",
        ):
            _require(
                prior.get(key) == expected_base[key],
                f"prior receipt local archive differs for {package.name}",
            )
        if prior.get("state") == CRATE_STATUS_PUBLISHED_VERIFIED:
            published_count += 1
    return published_count


def load_previous_receipt(
    path: pathlib.Path,
    *,
    safe_root: pathlib.Path = CRATES_IO_PUBLICATION_RECEIPT_ROOT,
) -> dict[str, object]:
    """Read one private no-link receipt from a transaction below the fixed root."""

    try:
        snapshot = read_fixed_json_snapshot(
            path,
            safe_root=safe_root,
            expected_leaf=CRATES_IO_PUBLICATION_RECEIPT_NAME,
            label="crates.io prior publication receipt",
            parent_depth=1,
            maximum=MAX_RECEIPT_BYTES,
            file_mode=PRIVATE_FILE_MODE,
            root_mode=PRIVATE_DIRECTORY_MODE,
            parent_mode=PRIVATE_DIRECTORY_MODE,
        )
        validate_crates_io_publication_receipt(snapshot.value)
    except (PublicationReceiptIOError, CratesIoPublicationContractError) as exc:
        raise CratesIoPublicationError(str(exc)) from exc
    return snapshot.value


def write_publication_receipt(
    receipt: dict[str, object],
    *,
    receipt_root: pathlib.Path = CRATES_IO_PUBLICATION_RECEIPT_ROOT,
) -> tuple[pathlib.Path, str]:
    """Write one immutable private receipt in a fresh no-replace transaction."""

    try:
        validate_crates_io_publication_receipt(receipt)
        return create_private_transaction_json(
            safe_root=receipt_root,
            transaction_prefix="transaction.",
            expected_leaf=CRATES_IO_PUBLICATION_RECEIPT_NAME,
            value=receipt,
            label="crates.io publication receipt",
            maximum=MAX_RECEIPT_BYTES,
        )
    except CratesIoPublicationContractError as exc:
        raise CratesIoPublicationError(str(exc)) from exc


def _journal_crate_document(package: LocalCrate) -> dict[str, str]:
    return {
        "crate_sha256": package.sha256,
        "name": package.name,
        "version": package.version,
    }


def _journal_record(
    evidence: LocalPublicationEvidence,
    package: LocalCrate,
    *,
    state: str,
    attempt_id: str,
    recorded_at: str,
    intent_sha256: str | None = None,
) -> dict[str, object]:
    _require(
        state
        in {
            UPLOAD_JOURNAL_INTENT,
            UPLOAD_JOURNAL_UNKNOWN,
            UPLOAD_JOURNAL_PUBLISHED,
        },
        "upload journal state is invalid",
    )
    _require(
        _ATTEMPT_ID_RE.fullmatch(attempt_id) is not None,
        "upload attempt id is malformed",
    )
    try:
        parse_utc_timestamp(recorded_at, "upload journal recorded_at")
    except CratesIoPublicationContractError as exc:
        raise CratesIoPublicationError(str(exc)) from exc
    value: dict[str, object] = {
        "attempt_id": attempt_id,
        "crate": _journal_crate_document(package),
        "handoff_sha256": evidence.handoff_manifest_sha256,
        "kind": UPLOAD_JOURNAL_KIND,
        "recorded_at": recorded_at,
        "schema_version": UPLOAD_JOURNAL_SCHEMA_VERSION,
        "source": _source_identity_document(evidence.source),
        "state": state,
    }
    if state == UPLOAD_JOURNAL_INTENT:
        _require(intent_sha256 is None, "upload intent cannot reference itself")
    else:
        _require(
            isinstance(intent_sha256, str)
            and _SHA256_RE.fullmatch(intent_sha256) is not None,
            "upload outcome intent digest is malformed",
        )
        value["intent_sha256"] = intent_sha256
    return value


def _write_upload_journal_record(
    value: dict[str, object],
    *,
    journal_root: pathlib.Path,
) -> tuple[pathlib.Path, str]:
    try:
        return create_private_transaction_json(
            safe_root=journal_root,
            transaction_prefix="transaction.",
            expected_leaf=CRATES_IO_PUBLICATION_JOURNAL_NAME,
            value=value,
            label="crates.io upload journal",
            maximum=256 * 1024,
        )
    except PublicationReceiptIOError:
        raise


def write_upload_intent(
    evidence: LocalPublicationEvidence,
    package: LocalCrate,
    *,
    journal_root: pathlib.Path = CRATES_IO_PUBLICATION_JOURNAL_ROOT,
    clock: Clock = lambda: dt.datetime.now(dt.UTC),
) -> UploadIntent:
    """Durably record one exact upload intent before invoking the uploader."""

    _require(package in evidence.crates, "upload intent crate is outside the evidence")
    attempt_id = secrets.token_hex(16)
    recorded_at = _canonical_timestamp(clock)
    value = _journal_record(
        evidence,
        package,
        state=UPLOAD_JOURNAL_INTENT,
        attempt_id=attempt_id,
        recorded_at=recorded_at,
    )
    path, digest = _write_upload_journal_record(
        value,
        journal_root=journal_root,
    )
    return UploadIntent(
        attempt_id=attempt_id,
        crate_name=package.name,
        digest=digest,
        path=path,
        recorded_at=recorded_at,
    )


def write_upload_outcome(
    evidence: LocalPublicationEvidence,
    package: LocalCrate,
    intent: UploadIntent,
    *,
    state: Literal[
        "upload_outcome_unknown", "upload_outcome_published_verified"
    ],
    journal_root: pathlib.Path = CRATES_IO_PUBLICATION_JOURNAL_ROOT,
    clock: Clock = lambda: dt.datetime.now(dt.UTC),
) -> tuple[pathlib.Path, str]:
    """Append one outcome cross-linked to an immutable upload intent."""

    _require(package in evidence.crates, "upload outcome crate is outside the evidence")
    _require(
        isinstance(intent, UploadIntent) and intent.crate_name == package.name,
        "upload outcome intent refers to a different crate",
    )
    value = _journal_record(
        evidence,
        package,
        state=state,
        attempt_id=intent.attempt_id,
        intent_sha256=intent.digest,
        recorded_at=_canonical_timestamp(clock),
    )
    return _write_upload_journal_record(value, journal_root=journal_root)


def _journal_transaction_names(journal_root: pathlib.Path) -> tuple[str, ...]:
    try:
        journal_root.lstat()
    except FileNotFoundError:
        return ()
    except OSError as exc:
        raise CratesIoPublicationError(
            "cannot inspect crates.io upload journal root"
        ) from exc
    try:
        normalized = normalize_safe_root(
            journal_root,
            label="crates.io upload journal root",
            required_mode=PRIVATE_DIRECTORY_MODE,
        )
        descriptor = open_private_directory(
            normalized, label="crates.io upload journal root"
        )
    except PublicationReceiptIOError as exc:
        raise CratesIoPublicationError(str(exc)) from exc
    names: list[str] = []
    primary_error: BaseException | None = None
    try:
        opened = os.fstat(descriptor)
        with os.scandir(descriptor) as entries:
            for entry in entries:
                name = entry.name
                _require(
                    isinstance(name, str)
                    and _TRANSACTION_DIRECTORY_RE.fullmatch(name) is not None,
                    "upload journal contains an unexpected entry",
                )
                metadata = entry.stat(follow_symlinks=False)
                uid_getter = getattr(os, "geteuid", None)
                _require(
                    stat.S_ISDIR(metadata.st_mode)
                    and callable(uid_getter)
                    and metadata.st_uid == uid_getter()
                    and stat.S_IMODE(metadata.st_mode) == PRIVATE_DIRECTORY_MODE,
                    "upload journal transaction must be an owned mode-0700 directory",
                )
                names.append(name)
                _require(
                    len(names) <= MAX_JOURNAL_RECORDS,
                    "upload journal exceeds the record limit",
                )
        named = normalized.lstat()
        _require(
            named.st_dev == opened.st_dev and named.st_ino == opened.st_ino,
            "upload journal root identity changed during inventory",
        )
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        try:
            os.close(descriptor)
        except OSError as exc:
            if primary_error is not None:
                primary_error.add_note("cannot close upload journal root descriptor")
            else:
                raise CratesIoPublicationError(
                    "cannot close upload journal root descriptor"
                ) from exc
    return tuple(sorted(names))


def _recover_incomplete_upload_journal_transactions(
    journal_root: pathlib.Path,
) -> tuple[str, ...]:
    """Remove only descriptor-proven precommit residue while the caller holds the lock."""

    try:
        journal_root.lstat()
    except FileNotFoundError:
        return ()
    except OSError as exc:
        raise CratesIoPublicationError(
            "cannot inspect crates.io upload journal root for recovery"
        ) from exc
    try:
        normalized = normalize_safe_root(
            journal_root,
            label="crates.io upload journal recovery root",
            required_mode=PRIVATE_DIRECTORY_MODE,
        )
        root_fd = open_private_directory(
            normalized,
            label="crates.io upload journal recovery root",
        )
    except PublicationReceiptIOError as exc:
        raise CratesIoPublicationError(str(exc)) from exc
    root_identity = os.fstat(root_fd)
    candidates: list[tuple[str, str | None, int, int]] = []
    primary_error: BaseException | None = None
    try:
        with os.scandir(root_fd) as iterator:
            entries = tuple(iterator)
        _require(
            len(entries) <= MAX_JOURNAL_RECORDS,
            "upload journal exceeds the record limit",
        )
        for entry in entries:
            match = _JOURNAL_TRANSACTION_RE.fullmatch(entry.name)
            _require(
                match is not None,
                "upload journal contains an unexpected entry",
            )
            transaction_name = entry.name
            transaction_pid = match.group(1)
            flags = (
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0)
            )
            transaction_fd = -1
            try:
                transaction_fd = os.open(
                    transaction_name,
                    flags,
                    dir_fd=root_fd,
                )
                opened = os.fstat(transaction_fd)
                named = os.stat(
                    transaction_name,
                    dir_fd=root_fd,
                    follow_symlinks=False,
                )
                uid_getter = getattr(os, "geteuid", None)
                _require(
                    stat.S_ISDIR(opened.st_mode)
                    and callable(uid_getter)
                    and opened.st_uid == uid_getter()
                    and stat.S_IMODE(opened.st_mode) == PRIVATE_DIRECTORY_MODE
                    and named.st_dev == opened.st_dev
                    and named.st_ino == opened.st_ino,
                    "upload journal recovery transaction is unsafe",
                )
                with os.scandir(transaction_fd) as transaction_entries:
                    inventory = frozenset(
                        transaction_entry.name
                        for transaction_entry in transaction_entries
                    )
                if CRATES_IO_PUBLICATION_JOURNAL_NAME in inventory:
                    # A visible final leaf is never recovery residue. The
                    # ordinary loader will either validate the exact singleton
                    # inventory or fail closed on any mixed transaction.
                    continue
                pending_leaf = (
                    f".{CRATES_IO_PUBLICATION_JOURNAL_NAME}.pending-"
                    f"{transaction_pid}"
                )
                _require(
                    inventory in {frozenset(), frozenset({pending_leaf})},
                    "upload journal precommit residue inventory is unsafe",
                )
                if inventory:
                    pending_fd = -1
                    try:
                        pending_fd = os.open(
                            pending_leaf,
                            os.O_RDONLY
                            | getattr(os, "O_NOFOLLOW", 0)
                            | getattr(os, "O_CLOEXEC", 0)
                            | getattr(os, "O_NONBLOCK", 0),
                            dir_fd=transaction_fd,
                        )
                        pending_opened = os.fstat(pending_fd)
                        pending_named = os.stat(
                            pending_leaf,
                            dir_fd=transaction_fd,
                            follow_symlinks=False,
                        )
                        _require(
                            stat.S_ISREG(pending_opened.st_mode)
                            and pending_opened.st_uid == uid_getter()
                            and pending_opened.st_nlink == 1
                            and stat.S_IMODE(pending_opened.st_mode)
                            == PRIVATE_FILE_MODE
                            and pending_opened.st_size <= 256 * 1024
                            and pending_named.st_dev == pending_opened.st_dev
                            and pending_named.st_ino == pending_opened.st_ino,
                            "upload journal pending residue is unsafe",
                        )
                    finally:
                        if pending_fd >= 0:
                            os.close(pending_fd)
                candidates.append(
                    (
                        transaction_name,
                        pending_leaf if inventory else None,
                        opened.st_dev,
                        opened.st_ino,
                    )
                )
            finally:
                if transaction_fd >= 0:
                    os.close(transaction_fd)

        recovered: list[str] = []
        for transaction_name, pending_leaf, expected_device, expected_inode in candidates:
            transaction_fd = -1
            try:
                transaction_fd = os.open(
                    transaction_name,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=root_fd,
                )
                opened = os.fstat(transaction_fd)
                named = os.stat(
                    transaction_name,
                    dir_fd=root_fd,
                    follow_symlinks=False,
                )
                _require(
                    opened.st_dev == expected_device
                    and opened.st_ino == expected_inode
                    and named.st_dev == expected_device
                    and named.st_ino == expected_inode
                    and stat.S_ISDIR(opened.st_mode)
                    and opened.st_uid == os.geteuid()
                    and stat.S_IMODE(opened.st_mode) == PRIVATE_DIRECTORY_MODE,
                    "upload journal residue identity changed before recovery",
                )
                with os.scandir(transaction_fd) as iterator:
                    current_inventory = frozenset(entry.name for entry in iterator)
                expected_inventory = (
                    frozenset()
                    if pending_leaf is None
                    else frozenset({pending_leaf})
                )
                _require(
                    current_inventory == expected_inventory,
                    "upload journal residue changed before recovery",
                )
                if pending_leaf is not None:
                    pending_fd = -1
                    try:
                        pending_fd = os.open(
                            pending_leaf,
                            os.O_RDONLY
                            | getattr(os, "O_NOFOLLOW", 0)
                            | getattr(os, "O_CLOEXEC", 0)
                            | getattr(os, "O_NONBLOCK", 0),
                            dir_fd=transaction_fd,
                        )
                        pending_opened = os.fstat(pending_fd)
                        pending_named = os.stat(
                            pending_leaf,
                            dir_fd=transaction_fd,
                            follow_symlinks=False,
                        )
                        _require(
                            stat.S_ISREG(pending_opened.st_mode)
                            and pending_opened.st_uid == os.geteuid()
                            and pending_opened.st_nlink == 1
                            and stat.S_IMODE(pending_opened.st_mode)
                            == PRIVATE_FILE_MODE
                            and pending_opened.st_size <= 256 * 1024
                            and pending_named.st_dev == pending_opened.st_dev
                            and pending_named.st_ino == pending_opened.st_ino,
                            "upload journal pending residue changed before recovery",
                        )
                        os.unlink(pending_leaf, dir_fd=transaction_fd)
                        os.fsync(transaction_fd)
                    finally:
                        if pending_fd >= 0:
                            os.close(pending_fd)
                with os.scandir(transaction_fd) as iterator:
                    _require(
                        not tuple(iterator),
                        "upload journal residue directory is not empty after recovery",
                    )
                os.rmdir(transaction_name, dir_fd=root_fd)
                os.fsync(root_fd)
                recovered.append(transaction_name)
            except OSError as exc:
                raise CratesIoPublicationError(
                    "cannot recover exact upload journal precommit residue"
                ) from exc
            finally:
                if transaction_fd >= 0:
                    os.close(transaction_fd)
        named_root = normalized.lstat()
        opened_root = os.fstat(root_fd)
        _require(
            named_root.st_dev == root_identity.st_dev
            and named_root.st_ino == root_identity.st_ino
            and opened_root.st_dev == root_identity.st_dev
            and opened_root.st_ino == root_identity.st_ino,
            "upload journal root identity changed during recovery",
        )
        return tuple(recovered)
    except OSError as exc:
        error = CratesIoPublicationError(
            "cannot inspect or recover upload journal precommit residue"
        )
        error.__cause__ = exc
        primary_error = error
        raise error
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        try:
            os.close(root_fd)
        except OSError as exc:
            if primary_error is not None:
                primary_error.add_note(
                    "cannot close upload journal recovery root descriptor"
                )
            else:
                raise CratesIoPublicationError(
                    "cannot close upload journal recovery root descriptor"
                ) from exc


def _validated_journal_value(
    value: object,
    *,
    digest: str,
    path: pathlib.Path,
    evidence: LocalPublicationEvidence,
) -> UploadIntent | UploadOutcome:
    _require(
        isinstance(value, dict)
        and all(isinstance(key, str) for key in value),
        "upload journal record must be a JSON object with string keys",
    )
    state = value.get("state")
    expected_keys = {
        "attempt_id",
        "crate",
        "handoff_sha256",
        "kind",
        "recorded_at",
        "schema_version",
        "source",
        "state",
    }
    if state != UPLOAD_JOURNAL_INTENT:
        expected_keys.add("intent_sha256")
    _require(
        set(value) == expected_keys,
        "upload journal record keys differ",
    )
    _require(
        value["schema_version"] == UPLOAD_JOURNAL_SCHEMA_VERSION
        and type(value["schema_version"]) is int,
        "upload journal schema differs",
    )
    _require(value["kind"] == UPLOAD_JOURNAL_KIND, "upload journal kind differs")
    _require(
        state
        in {
            UPLOAD_JOURNAL_INTENT,
            UPLOAD_JOURNAL_UNKNOWN,
            UPLOAD_JOURNAL_PUBLISHED,
        },
        "upload journal state is invalid",
    )
    attempt_id = value["attempt_id"]
    _require(
        isinstance(attempt_id, str)
        and _ATTEMPT_ID_RE.fullmatch(attempt_id) is not None,
        "upload journal attempt id is malformed",
    )
    recorded_at = value["recorded_at"]
    _require(
        isinstance(recorded_at, str),
        "upload journal recorded_at must be a string",
    )
    try:
        parse_utc_timestamp(recorded_at, "upload journal recorded_at")
    except CratesIoPublicationContractError as exc:
        raise CratesIoPublicationError(str(exc)) from exc
    _require(
        value["source"] == _source_identity_document(evidence.source),
        "upload journal source identity differs",
    )
    _require(
        value["handoff_sha256"] == evidence.handoff_manifest_sha256,
        "upload journal Rust package handoff differs",
    )
    crate = value["crate"]
    _require(
        isinstance(crate, dict)
        and set(crate) == {"crate_sha256", "name", "version"},
        "upload journal crate record differs",
    )
    by_name = {package.name: package for package in evidence.crates}
    crate_name = crate.get("name")
    _require(
        isinstance(crate_name, str) and crate_name in by_name,
        "upload journal crate is outside the frozen topology",
    )
    package = by_name[crate_name]
    _require(
        crate == _journal_crate_document(package),
        f"upload journal local archive differs for {crate_name}",
    )
    if state == UPLOAD_JOURNAL_INTENT:
        return UploadIntent(
            attempt_id=attempt_id,
            crate_name=crate_name,
            digest=digest,
            path=path,
            recorded_at=recorded_at,
        )
    intent_sha256 = value["intent_sha256"]
    _require(
        isinstance(intent_sha256, str)
        and _SHA256_RE.fullmatch(intent_sha256) is not None,
        "upload journal intent digest is malformed",
    )
    return UploadOutcome(
        attempt_id=attempt_id,
        crate_name=crate_name,
        intent_sha256=intent_sha256,
        state=state,
        recorded_at=recorded_at,
    )


def load_unresolved_upload_intents(
    evidence: LocalPublicationEvidence,
    *,
    journal_root: pathlib.Path = CRATES_IO_PUBLICATION_JOURNAL_ROOT,
) -> tuple[UploadIntent, ...]:
    """Return intents lacking an exact published outcome; reject ambiguity."""

    intents: dict[str, UploadIntent] = {}
    outcomes: dict[str, dict[str, UploadOutcome]] = {}
    for transaction_name in _journal_transaction_names(journal_root):
        path = (
            journal_root
            / transaction_name
            / CRATES_IO_PUBLICATION_JOURNAL_NAME
        )
        try:
            snapshot = read_fixed_json_snapshot(
                path,
                safe_root=journal_root,
                expected_leaf=CRATES_IO_PUBLICATION_JOURNAL_NAME,
                label="crates.io upload journal record",
                parent_depth=1,
                maximum=256 * 1024,
                file_mode=PRIVATE_FILE_MODE,
                root_mode=PRIVATE_DIRECTORY_MODE,
                parent_mode=PRIVATE_DIRECTORY_MODE,
                expected_parent_entries=frozenset(
                    {CRATES_IO_PUBLICATION_JOURNAL_NAME}
                ),
            )
        except PublicationReceiptIOError as exc:
            raise CratesIoPublicationError(str(exc)) from exc
        record = _validated_journal_value(
            snapshot.value,
            digest=snapshot.file.sha256,
            path=path,
            evidence=evidence,
        )
        if isinstance(record, UploadIntent):
            _require(
                record.digest not in intents,
                "upload journal contains a duplicate intent digest",
            )
            intents[record.digest] = record
        else:
            states = outcomes.setdefault(record.intent_sha256, {})
            _require(
                record.state not in states,
                "upload journal contains a duplicate outcome state",
            )
            states[record.state] = record
    for intent_sha256, outcome_states in outcomes.items():
        _require(
            intent_sha256 in intents,
            "upload journal outcome references an unknown intent",
        )
        intent = intents[intent_sha256]
        _require(
            all(
                outcome.attempt_id == intent.attempt_id
                and outcome.crate_name == intent.crate_name
                and parse_utc_timestamp(
                    outcome.recorded_at,
                    "upload journal outcome recorded_at",
                )
                >= parse_utc_timestamp(
                    intent.recorded_at,
                    "upload journal intent recorded_at",
                )
                for outcome in outcome_states.values()
            ),
            "upload journal outcome identity differs from its intent",
        )
    unresolved = tuple(
        intent
        for digest, intent in intents.items()
        if UPLOAD_JOURNAL_PUBLISHED not in outcomes.get(digest, {})
    )
    unresolved_names = [intent.crate_name for intent in unresolved]
    _require(
        len(unresolved_names) == len(set(unresolved_names)),
        "upload journal has multiple unresolved intents for one crate",
    )
    order = {
        name: index
        for index, (name, _dependencies) in enumerate(
            CRATE_PUBLICATION_TOPOLOGY
        )
    }
    return tuple(sorted(unresolved, key=lambda intent: order[intent.crate_name]))


def _validate_remote_resume(
    observations: tuple[RemotePublishedRecord | None, ...],
    *,
    prior_published_count: int,
) -> None:
    _require(
        all(
            observation is not None
            for observation in observations[:prior_published_count]
        ),
        "a previously verified crates.io prefix no longer has exact observations",
    )


def _validated_upload_authorization(
    *,
    execute_real_upload: bool,
    irreversible_acknowledgement: str | None,
    credential_provider: CredentialProvider | None,
    lock_factory: PublicationLockFactory | None,
    upload_runner: UploadRunner | None,
) -> tuple[CredentialProvider, PublicationLockFactory, UploadRunner]:
    _require(
        execute_real_upload is True,
        "real crates.io upload requires execute_real_upload=True",
    )
    _require(
        irreversible_acknowledgement == REAL_UPLOAD_ACKNOWLEDGEMENT,
        "real crates.io upload requires the exact irreversible acknowledgement",
    )
    _require(
        callable(credential_provider),
        "real crates.io upload requires an external credential provider",
    )
    _require(
        callable(lock_factory),
        "real crates.io upload requires a cross-worktree publication lock",
    )
    _require(
        callable(upload_runner),
        "real crates.io upload requires an external exact-byte uploader",
    )
    return credential_provider, lock_factory, upload_runner


def _credential(provider: CredentialProvider) -> str:
    try:
        token = provider()
    except Exception:
        raise CratesIoPublicationError(
            "crates.io credential provider failed"
        ) from None
    _require(
        isinstance(token, str)
        and _SAFE_TOKEN_RE.fullmatch(token) is not None
        and not token.isspace(),
        "crates.io credential is malformed",
    )
    return token


def _poll_after_upload_attempt(
    package: LocalCrate,
    *,
    api_fetcher: HttpFetcher,
    sparse_fetcher: HttpFetcher,
    clock: Clock,
    sleeper: Sleeper,
    poll_attempts: int,
    poll_interval_seconds: float,
) -> RemotePublishedRecord | None:
    _require(
        type(poll_attempts) is int and 1 <= poll_attempts <= 60,
        "remote poll attempts must be an integer from 1 through 60",
    )
    _require(
        type(poll_interval_seconds) in {int, float}
        and not isinstance(poll_interval_seconds, bool)
        and 0 <= poll_interval_seconds <= 30,
        "remote poll interval must be from 0 through 30 seconds",
    )
    last_observation: RemotePublishedRecord | None = None
    for attempt in range(poll_attempts):
        try:
            last_observation = observe_remote_crate(
                package,
                api_fetcher=api_fetcher,
                sparse_fetcher=sparse_fetcher,
                clock=clock,
            )
        except CratesIoRemoteObservationUnknownError:
            last_observation = None
        if last_observation is not None:
            return last_observation
        if attempt + 1 < poll_attempts:
            sleeper(float(poll_interval_seconds))
    return None


def run_publication_transaction(
    source: SourceIdentity,
    handoff_manifest_path: pathlib.Path,
    handoff_manifest_sha256: str,
    *,
    handoff_root: pathlib.Path = RUST_PACKAGE_HANDOFF_ROOT,
    source_tree_resolver: SourceTreeResolver = _source_tree_for_commit,
    source_transition_verifier: SourceTransitionVerifier = (
        _verify_stable_source_transition
    ),
    previous_receipt: Mapping[str, object] | None = None,
    mode: RunMode = "dry-run",
    api_fetcher: HttpFetcher = _https_get,
    sparse_fetcher: HttpFetcher = _https_get,
    clock: Clock = lambda: dt.datetime.now(dt.UTC),
    sleeper: Sleeper = time.sleep,
    receipt_writer: ReceiptWriter | None = None,
    receipt_root: pathlib.Path = CRATES_IO_PUBLICATION_RECEIPT_ROOT,
    journal_root: pathlib.Path = CRATES_IO_PUBLICATION_JOURNAL_ROOT,
    write_verify_receipt: bool = True,
    execute_real_upload: bool = False,
    irreversible_acknowledgement: str | None = None,
    credential_provider: CredentialProvider | None = None,
    lock_factory: PublicationLockFactory | None = None,
    upload_runner: UploadRunner | None = None,
    poll_attempts: int = REMOTE_POLL_ATTEMPTS,
    poll_interval_seconds: float = REMOTE_POLL_INTERVAL_SECONDS,
) -> PublicationRun:
    """Dry-run, verify, or monotonically advance the fixed publication prefix.

    ``upload_runner`` must upload the exact ``LocalCrate.path`` bytes.  It is
    intentionally injected because this domain must not reconstruct Cargo's
    publish metadata or create a second package-validation implementation.
    """

    _require(mode in {"dry-run", "verify", "publish"}, "publication mode is invalid")
    evidence = load_local_publication_evidence(
        source,
        handoff_manifest_path,
        handoff_manifest_sha256,
        handoff_root=handoff_root,
        source_tree_resolver=source_tree_resolver,
        source_transition_verifier=source_transition_verifier,
    )
    prior_published_count = _previous_published_count(
        previous_receipt, evidence=evidence
    )
    planned = tuple(package.name for package in evidence.crates[prior_published_count:])
    if mode == "dry-run":
        _require(
            execute_real_upload is False,
            "dry-run cannot enable real upload",
        )
        _resample_local_evidence(evidence)
        return PublicationRun(
            mode=mode,
            receipt=None,
            written_receipts=(),
            upload_attempts=(),
            planned_crates=planned,
        )

    writer = receipt_writer
    if writer is None:
        writer = lambda value: write_publication_receipt(
            value, receipt_root=receipt_root
        )

    def collect() -> tuple[
        tuple[RemotePublishedRecord | None, ...],
        dict[str, object],
    ]:
        _resample_local_evidence(evidence)
        remote = observe_remote_prefix(
            evidence,
            api_fetcher=api_fetcher,
            sparse_fetcher=sparse_fetcher,
            clock=clock,
        )
        _validate_remote_resume(
            remote,
            prior_published_count=prior_published_count,
        )
        receipt = assemble_publication_receipt(
            evidence,
            remote,
            observed_at=_canonical_timestamp(clock),
        )
        return remote, receipt

    written_receipts: list[WrittenReceipt] = []
    upload_attempts: list[str] = []
    if mode == "verify":
        _require(
            execute_real_upload is False,
            "verify cannot enable real upload",
        )
        _remote, receipt = collect()
        if write_verify_receipt:
            path, digest = writer(receipt)
            written_receipts.append(WrittenReceipt(path=path, sha256=digest))
        _resample_local_evidence(evidence)
        return PublicationRun(
            mode=mode,
            receipt=receipt,
            written_receipts=tuple(written_receipts),
            upload_attempts=(),
            planned_crates=planned,
        )

    provider, publication_lock, uploader = _validated_upload_authorization(
        execute_real_upload=execute_real_upload,
        irreversible_acknowledgement=irreversible_acknowledgement,
        credential_provider=credential_provider,
        lock_factory=lock_factory,
        upload_runner=upload_runner,
    )
    try:
        lock_context = publication_lock()
    except Exception:
        raise CratesIoPublicationError(
            "cross-worktree publication lock acquisition failed"
        ) from None
    _require(
        isinstance(lock_context, contextlib.AbstractContextManager),
        "publication lock factory did not return a context manager",
    )
    try:
        with lock_context:
            _recover_incomplete_upload_journal_transactions(journal_root)
            remote, receipt = collect()
            path, digest = writer(receipt)
            written_receipts.append(WrittenReceipt(path=path, sha256=digest))
            package_indices = {
                package.name: index
                for index, package in enumerate(evidence.crates)
            }
            for intent in load_unresolved_upload_intents(
                evidence, journal_root=journal_root
            ):
                index = package_indices[intent.crate_name]
                package = evidence.crates[index]
                if remote[index] is None:
                    raise CratesIoUploadOutcomeUnknownError(
                        package.name,
                        verified_receipt=receipt,
                        written_receipts=tuple(written_receipts),
                    )
                write_upload_outcome(
                    evidence,
                    package,
                    intent,
                    state=UPLOAD_JOURNAL_PUBLISHED,
                    journal_root=journal_root,
                    clock=clock,
                )
            token: str | None = None
            for index, package in enumerate(evidence.crates):
                if remote[index] is not None:
                    continue
                _resample_local_evidence(evidence)
                if token is None:
                    token = _credential(provider)
                intent = write_upload_intent(
                    evidence,
                    package,
                    journal_root=journal_root,
                    clock=clock,
                )
                upload_attempts.append(package.name)
                try:
                    result = uploader(package, credential=token)
                    _require(
                        isinstance(result, BoundedResult)
                        and type(result.returncode) is int,
                        "exact-byte uploader result type differs",
                    )
                except Exception:
                    result = BoundedResult(returncode=1)
                observed = _poll_after_upload_attempt(
                    package,
                    api_fetcher=api_fetcher,
                    sparse_fetcher=sparse_fetcher,
                    clock=clock,
                    sleeper=sleeper,
                    poll_attempts=poll_attempts,
                    poll_interval_seconds=poll_interval_seconds,
                )
                if observed is None:
                    write_upload_outcome(
                        evidence,
                        package,
                        intent,
                        state=UPLOAD_JOURNAL_UNKNOWN,
                        journal_root=journal_root,
                        clock=clock,
                    )
                    raise CratesIoUploadOutcomeUnknownError(
                        package.name,
                        verified_receipt=receipt,
                        written_receipts=tuple(written_receipts),
                    )
                write_upload_outcome(
                    evidence,
                    package,
                    intent,
                    state=UPLOAD_JOURNAL_PUBLISHED,
                    journal_root=journal_root,
                    clock=clock,
                )
                remote = remote[:index] + (observed,) + remote[index + 1 :]
                receipt = assemble_publication_receipt(
                    evidence,
                    remote,
                    observed_at=_canonical_timestamp(clock),
                )
                path, digest = writer(receipt)
                written_receipts.append(WrittenReceipt(path=path, sha256=digest))
            _resample_local_evidence(evidence)
    except CratesIoUploadOutcomeUnknownError:
        raise
    except PublicationReceiptCommittedError:
        raise
    except CratesIoPublicationError:
        raise
    return PublicationRun(
        mode=mode,
        receipt=receipt,
        written_receipts=tuple(written_receipts),
        upload_attempts=tuple(upload_attempts),
        planned_crates=planned,
    )


def _source_from_json(path: pathlib.Path) -> SourceIdentity:
    path = _canonical_input_file(path, label="source identity")
    try:
        snapshot = read_regular_snapshot(
            path,
            maximum=64 * 1024,
            label="source identity",
            validate_metadata=lambda metadata: _owned_regular_metadata(
                metadata, label="source identity"
            ),
        )
        value = parse_strict_json_bytes(snapshot.data, label="source identity")
    except EvidenceIOError as exc:
        raise CratesIoPublicationError(str(exc)) from exc
    return source_identity_from_document(value)


def _verified_cli_receipt(receipt: WrittenReceipt) -> WrittenReceipt:
    _require(
        isinstance(receipt, WrittenReceipt),
        "CLI receipt publication type differs",
    )
    _require(
        receipt.path.parent.parent == CRATES_IO_PUBLICATION_RECEIPT_ROOT
        and receipt.path.name == CRATES_IO_PUBLICATION_RECEIPT_NAME
        and _TRANSACTION_DIRECTORY_RE.fullmatch(receipt.path.parent.name) is not None,
        "CLI receipt path differs from the fixed publication root",
    )
    try:
        snapshot = read_fixed_json_snapshot(
            receipt.path,
            safe_root=CRATES_IO_PUBLICATION_RECEIPT_ROOT,
            expected_leaf=CRATES_IO_PUBLICATION_RECEIPT_NAME,
            label="crates.io CLI publication receipt",
            parent_depth=1,
            maximum=MAX_RECEIPT_BYTES,
            expected_parent_entries=frozenset(
                {CRATES_IO_PUBLICATION_RECEIPT_NAME}
            ),
        )
    except PublicationReceiptIOError as exc:
        raise CratesIoPublicationError(str(exc)) from exc
    _require(
        snapshot.file.sha256 == receipt.sha256,
        "CLI publication receipt digest changed before marker output",
    )
    return receipt


def _controlled_repository_relative_path(
    path: pathlib.Path,
    *,
    fixed_root: pathlib.Path,
    expected_leaf: str,
    transaction_pattern: re.Pattern[str],
) -> str:
    _require(isinstance(path, pathlib.Path), "controlled output path type differs")
    _require(
        path.parent.parent == fixed_root
        and path.name == expected_leaf
        and transaction_pattern.fullmatch(path.parent.name) is not None,
        "controlled output path shape differs",
    )
    try:
        relative = path.relative_to(REPOSITORY_ROOT).as_posix()
    except ValueError as exc:
        raise CratesIoPublicationError(
            "controlled output path is outside the repository"
        ) from exc
    _require(
        relative.startswith("target/")
        and not any(character.isspace() for character in relative),
        "controlled output marker path is malformed",
    )
    return relative


def controlled_handoff_marker_path(path: pathlib.Path) -> str:
    """Return the only repository-relative handoff path allowed in a marker."""

    return _controlled_repository_relative_path(
        path,
        fixed_root=RUST_PACKAGE_HANDOFF_ROOT,
        expected_leaf=RUST_PACKAGE_HANDOFF_MANIFEST_NAME,
        transaction_pattern=_HANDOFF_TRANSACTION_RE,
    )


class _HandoffCommitSignalFence:
    """Interrupt before commit, then defer catchable signals through the marker."""

    _SIGNALS = (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)

    def __init__(self) -> None:
        self._previous: dict[signal.Signals, object] = {}
        self._commit_boundary = False
        self.pending_signal: int | None = None

    def _handle(self, signal_number: int, _frame: object) -> None:
        if not self._commit_boundary:
            raise _HandoffPrecommitSignal(signal_number)
        if self.pending_signal is None:
            self.pending_signal = signal_number

    def install(self) -> None:
        _require(
            os.name == "posix"
            and threading.current_thread() is threading.main_thread(),
            "Rust package handoff signal fence requires the POSIX main thread",
        )
        installed: list[signal.Signals] = []
        try:
            for signal_number in self._SIGNALS:
                self._previous[signal_number] = signal.getsignal(signal_number)
                signal.signal(signal_number, self._handle)
                installed.append(signal_number)
        except BaseException as exc:
            for signal_number in reversed(installed):
                signal.signal(signal_number, self._previous[signal_number])
            raise CratesIoPublicationError(
                "cannot install Rust package handoff signal fence"
            ) from exc

    def begin_commit_boundary(
        self,
        hook: Callable[[], None] | None,
    ) -> None:
        self._commit_boundary = True
        if hook is not None:
            hook()

    def defer_for_cleanup(self) -> None:
        self._commit_boundary = True

    def block_through_process_exit(self) -> None:
        masker = getattr(signal, "pthread_sigmask", None)
        _require(
            callable(masker) and hasattr(signal, "SIG_BLOCK"),
            "Rust package handoff marker boundary requires pthread_sigmask",
        )
        try:
            masker(signal.SIG_BLOCK, set(self._SIGNALS))
        except (OSError, ValueError) as exc:
            raise CratesIoPublicationError(
                "cannot block Rust package handoff signals through process exit"
            ) from exc

    def restore(self) -> None:
        failures: list[BaseException] = []
        for signal_number in reversed(self._SIGNALS):
            previous = self._previous.get(signal_number)
            if previous is None:
                continue
            try:
                signal.signal(signal_number, previous)
            except BaseException as exc:
                failures.append(exc)
        if failures:
            raise CratesIoPublicationError(
                "cannot restore Rust package handoff signal handlers"
            ) from failures[0]


def _write_handoff_marker(stream: TextIO, marker: str) -> None:
    _require(
        isinstance(marker, str)
        and marker
        and not any(character in marker for character in "\r\n\x00"),
        "Rust package handoff marker is malformed",
    )
    try:
        written = stream.write(marker + "\n")
        stream.flush()
    except (BrokenPipeError, OSError) as exc:
        raise CratesIoPublicationError(
            "cannot write Rust package handoff marker"
        ) from exc
    _require(
        written == len(marker) + 1,
        "Rust package handoff marker write was incomplete",
    )


def finalize_rust_package_handoff_for_cli(
    staging_root: pathlib.Path,
    *,
    staging_device: int,
    staging_inode: int,
    handoff_root: pathlib.Path = RUST_PACKAGE_HANDOFF_ROOT,
    source_inspector: Callable[[], RustPackageHandoffSource] = (
        inspect_rust_package_handoff_source
    ),
    marker_stream: TextIO = sys.stderr,
    marker_path_formatter: Callable[[pathlib.Path], str] = (
        controlled_handoff_marker_path
    ),
    precommit_hook: Callable[[], None] | None = None,
    commit_boundary_hook: Callable[[], None] | None = None,
    postcommit_hook: Callable[[], None] | None = None,
) -> Never:
    """Finalize, clean the stage, and emit the sole marker under one signal fence."""

    for hook, label in (
        (precommit_hook, "precommit"),
        (commit_boundary_hook, "commit-boundary"),
        (postcommit_hook, "postcommit"),
    ):
        _require(
            hook is None or callable(hook),
            f"Rust package handoff {label} hook is invalid",
        )
    _require(
        callable(marker_path_formatter),
        "Rust package handoff marker formatter is invalid",
    )
    fence = _HandoffCommitSignalFence()
    fence.install()
    stage_present = True

    def cleanup_stage() -> bool:
        nonlocal stage_present
        if not stage_present:
            return True
        try:
            remove_owned_package_directory(
                staging_root,
                staging_device,
                staging_inode,
            )
        except (RustPublishContractError, OSError, ValueError):
            return False
        stage_present = False
        return True

    def finish_uncommitted(status: int) -> Never:
        fence.defer_for_cleanup()
        cleanup_stage()
        try:
            fence.restore()
        except CratesIoPublicationError:
            status = 1
        raise SystemExit(status)

    def finish_committed(
        *,
        visibility: str,
        path: pathlib.Path | None,
        digest: str | None,
        cleanup_ok: bool,
    ) -> Never:
        fence.defer_for_cleanup()
        marker_path = "unavailable"
        if path is not None:
            try:
                marker_path = marker_path_formatter(path)
            except Exception:
                marker_path = "unavailable"
        marker_digest = (
            digest
            if isinstance(digest, str)
            and _SHA256_RE.fullmatch(digest) is not None
            else "unavailable"
        )
        suffixes: list[str] = []
        if not cleanup_ok:
            suffixes.append("stage_cleanup_failed=1")
        try:
            fence.block_through_process_exit()
        except CratesIoPublicationError:
            suffixes.append("signal_block_failed=1")
        suffix = "" if not suffixes else " " + " ".join(suffixes)
        _write_handoff_marker(
            marker_stream,
            "error: RUST_PACKAGE_HANDOFF_COMMITTED "
            f"visibility={visibility} path={marker_path} "
            f"sha256={marker_digest}{suffix}",
        )
        raise SystemExit(125)

    try:
        if precommit_hook is not None:
            precommit_hook()
        path, digest = finalize_rust_package_handoff(
            staging_root,
            staging_device=staging_device,
            staging_inode=staging_inode,
            handoff_root=handoff_root,
            source_inspector=source_inspector,
            before_commit=lambda: fence.begin_commit_boundary(
                commit_boundary_hook
            ),
        )
    except _HandoffPrecommitSignal as exc:
        finish_uncommitted(128 + exc.signal_number)
    except PublicationReceiptCommittedError as exc:
        finish_committed(
            visibility=exc.visibility,
            path=exc.path,
            digest=exc.digest,
            cleanup_ok=cleanup_stage(),
        )
    except BaseException:
        finish_uncommitted(1)

    if postcommit_hook is not None:
        try:
            postcommit_hook()
        except BaseException:
            finish_committed(
                visibility="committed",
                path=path,
                digest=digest,
                cleanup_ok=cleanup_stage(),
            )

    cleanup_ok = cleanup_stage()
    try:
        marker_path = marker_path_formatter(path)
    except Exception:
        marker_path = "unavailable"
        cleanup_ok = False
    if not cleanup_ok:
        finish_committed(
            visibility="committed",
            path=path,
            digest=digest,
            cleanup_ok=False,
        )
    try:
        fence.block_through_process_exit()
    except CratesIoPublicationError:
        finish_committed(
            visibility="committed",
            path=path,
            digest=digest,
            cleanup_ok=True,
        )
    if fence.pending_signal is not None:
        finish_committed(
            visibility="committed",
            path=path,
            digest=digest,
            cleanup_ok=True,
        )
    _write_handoff_marker(
        marker_stream,
        f"RUST_PACKAGE_HANDOFF_PASS path={marker_path} sha256={digest}",
    )
    raise SystemExit(0)


def _controlled_receipt_marker_path(path: pathlib.Path) -> str:
    return _controlled_repository_relative_path(
        path,
        fixed_root=CRATES_IO_PUBLICATION_RECEIPT_ROOT,
        expected_leaf=CRATES_IO_PUBLICATION_RECEIPT_NAME,
        transaction_pattern=_TRANSACTION_DIRECTORY_RE,
    )


def _safe_cli_error_message(error: BaseException) -> str:
    message = str(error)
    if (
        not message
        or "/" in message
        or "\\" in message
        or any(character in message for character in "\r\n\x00")
    ):
        return "crates.io publication command failed safely"
    return message


def _controlled_cli_input_path(
    path: pathlib.Path,
    *,
    fixed_root: pathlib.Path,
    expected_leaf: str,
    transaction_pattern: re.Pattern[str],
) -> pathlib.Path:
    _require(isinstance(path, pathlib.Path), "controlled CLI path type differs")
    if path.is_absolute():
        return path
    _require(
        all(part not in {"", ".", ".."} for part in path.parts),
        "controlled CLI path must be canonically spelled",
    )
    expected_root = fixed_root.relative_to(REPOSITORY_ROOT)
    _require(
        len(path.parts) == len(expected_root.parts) + 2
        and path.parts[: len(expected_root.parts)] == expected_root.parts
        and transaction_pattern.fullmatch(path.parts[-2]) is not None
        and path.parts[-1] == expected_leaf,
        "controlled CLI path differs from the fixed transaction shape",
    )
    return REPOSITORY_ROOT / path


def _require_exact_cli_path_confirmation(
    supplied: pathlib.Path,
    authoritative: pathlib.Path,
    *,
    label: str,
) -> None:
    """Compare a CLI acknowledgement without granting it path authority."""

    _require(
        isinstance(supplied, pathlib.Path)
        and supplied == authoritative
        and os.fspath(supplied) == os.fspath(authoritative),
        f"{label} must exactly confirm the fixed authority",
    )


def _require_handoff_confirmation(
    supplied_path: pathlib.Path,
    supplied_sha256: str,
    selected: ResultsSelectedHandoff,
) -> None:
    """Require the CLI marker to echo R's selection, then discard the marker."""

    _require(
        isinstance(supplied_path, pathlib.Path),
        "registry handoff confirmation path type differs",
    )
    expected_path = (
        selected.path
        if supplied_path.is_absolute()
        else pathlib.Path(*selected.relative_path.parts)
    )
    _require(
        supplied_path == expected_path
        and os.fspath(supplied_path) == os.fspath(expected_path)
        and supplied_sha256 == selected.sha256,
        "registry handoff confirmation differs from results commit R",
    )


def _main(arguments: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Validate, verify, or explicitly execute the ABI-2 0.1.1 "
            "crates.io publication domain"
        )
    )
    parser.add_argument("mode", choices=("dry-run", "verify", "publish"))
    parser.add_argument("source_identity", type=pathlib.Path)
    parser.add_argument("handoff_manifest", type=pathlib.Path)
    parser.add_argument("handoff_sha256")
    parser.add_argument("--previous-receipt", type=pathlib.Path)
    parser.add_argument(
        "--state-root",
        type=pathlib.Path,
        help=(
            "explicit confirmation of the fixed passwd-home mode-0700 "
            "~/.q-periapt/publication-state/crates.io-v0.1.1 authority; "
            "required for publish"
        ),
    )
    parser.add_argument(
        "--uploader-command",
        type=pathlib.Path,
        help=(
            "explicit confirmation of the fixed qperiapt-crates-io-uploader "
            "child of --state-root; required for publish"
        ),
    )
    parser.add_argument("--execute-real-upload", action="store_true")
    parser.add_argument(
        "--acknowledge-irreversible-publish",
        action="store_true",
    )
    namespace = parser.parse_args(arguments)
    try:
        state_root_authority: pathlib.Path | None = None
        uploader_authority: pathlib.Path | None = None
        if namespace.mode == "publish":
            _require(
                namespace.state_root is not None,
                "publish requires an explicit --state-root",
            )
            _require(
                namespace.uploader_command is not None,
                "publish requires an absolute --uploader-command",
            )
            _require(
                namespace.execute_real_upload is True,
                "publish requires --execute-real-upload",
            )
            _require(
                namespace.acknowledge_irreversible_publish is True,
                "publish requires --acknowledge-irreversible-publish",
            )
            state_root_authority = _expected_publication_state_root()
            _require_exact_cli_path_confirmation(
                namespace.state_root,
                state_root_authority,
                label="publication state root confirmation",
            )
            uploader_authority = (
                state_root_authority / CRATES_IO_PUBLICATION_UPLOADER_NAME
            )
            _require_exact_cli_path_confirmation(
                namespace.uploader_command,
                uploader_authority,
                label="publication uploader confirmation",
            )

        source = _source_from_json(namespace.source_identity)
        selected_handoff = _results_selected_handoff(source)
        _require_handoff_confirmation(
            namespace.handoff_manifest,
            namespace.handoff_sha256,
            selected_handoff,
        )
        handoff_manifest = selected_handoff.path
        handoff_sha256 = selected_handoff.sha256
        previous = (
            None
            if namespace.previous_receipt is None
            else load_previous_receipt(
                _controlled_cli_input_path(
                    namespace.previous_receipt,
                    fixed_root=CRATES_IO_PUBLICATION_RECEIPT_ROOT,
                    expected_leaf=CRATES_IO_PUBLICATION_RECEIPT_NAME,
                    transaction_pattern=_TRANSACTION_DIRECTORY_RE,
                ),
                safe_root=CRATES_IO_PUBLICATION_RECEIPT_ROOT,
            )
        )
        lock_factory: PublicationLockFactory | None = None
        uploader: UploadRunner | None = None
        credential_provider: CredentialProvider | None = None
        acknowledgement: str | None = None
        journal_root = CRATES_IO_PUBLICATION_JOURNAL_ROOT
        if namespace.mode == "publish":
            _require(
                state_root_authority is not None and uploader_authority is not None,
                "publish authority confirmation is incomplete",
            )
            state_root = _validated_publication_state_root(state_root_authority)
            lock_factory = production_lock_factory(state_root)
            uploader = production_upload_runner(
                uploader_authority,
                state_root=state_root,
            )
            journal_root = state_root / "journal"
            credential_provider = lambda: os.environ.get(
                "CARGO_REGISTRY_TOKEN", ""
            )
            acknowledgement = REAL_UPLOAD_ACKNOWLEDGEMENT
        result = run_publication_transaction(
            source,
            handoff_manifest,
            handoff_sha256,
            previous_receipt=previous,
            mode=namespace.mode,
            receipt_root=CRATES_IO_PUBLICATION_RECEIPT_ROOT,
            journal_root=journal_root,
            execute_real_upload=namespace.execute_real_upload,
            irreversible_acknowledgement=acknowledgement,
            credential_provider=credential_provider,
            lock_factory=lock_factory,
            upload_runner=uploader,
        )
    except PublicationReceiptCommittedError as exc:
        path = "unavailable"
        if exc.path is not None:
            try:
                path = _controlled_receipt_marker_path(exc.path)
            except CratesIoPublicationError:
                path = "unavailable"
        digest = (
            exc.digest
            if isinstance(exc.digest, str)
            and _SHA256_RE.fullmatch(exc.digest) is not None
            else "unavailable"
        )
        print(
            "error: publication receipt committed but command did not complete "
            f"visibility={exc.visibility} path={path} sha256={digest}",
            file=sys.stderr,
        )
        return 125
    except (CratesIoPublicationError, PublicationReceiptIOError) as exc:
        print(f"error: {_safe_cli_error_message(exc)}", file=sys.stderr)
        return 1
    try:
        if result.receipt is None:
            print(
                "CRATES_IO_PUBLICATION_DRY_RUN_PASS "
                f"version={PRODUCT_VERSION} crates={len(result.planned_crates)} "
                "upload=not-attempted"
            )
        elif result.mode == "verify":
            _require(
                len(result.written_receipts) == 1,
                "verify must publish exactly one controlled receipt",
            )
            receipt = _verified_cli_receipt(result.written_receipts[0])
            receipt_marker_path = _controlled_receipt_marker_path(receipt.path)
            print(
                "CRATES_IO_PUBLICATION_VERIFY_PASS "
                f"version={PRODUCT_VERSION} status={result.receipt['status']} "
                f"receipt_path={receipt_marker_path} "
                f"receipt_sha256={receipt.sha256} upload=not-attempted"
            )
        else:
            _require(
                bool(result.written_receipts),
                "publish must retain at least one controlled receipt",
            )
            receipt = _verified_cli_receipt(result.written_receipts[-1])
            receipt_marker_path = _controlled_receipt_marker_path(receipt.path)
            print(
                "CRATES_IO_PUBLICATION_RUN_PASS "
                f"version={PRODUCT_VERSION} status={result.receipt['status']} "
                f"receipt_path={receipt_marker_path} "
                f"receipt_sha256={receipt.sha256} "
                f"upload_attempts={len(result.upload_attempts)}"
            )
    except (CratesIoPublicationError, PublicationReceiptIOError):
        print(
            "error: publication output could not be safely finalized",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
