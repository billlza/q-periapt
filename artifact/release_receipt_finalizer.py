#!/usr/bin/env python3
"""Finalize domain publication leaves into one complete results successor.

Domain producers own evidence collection and receipt construction.  This
module owns only the cross-domain transaction: pin the current results bytes,
validate complete input leaves, apply the two permitted selector/receipt
mutations, validate the pure composite transition, and publish a separate
no-replace results candidate.
"""

from __future__ import annotations

import argparse
import copy
import dataclasses
import hashlib
import os
import pathlib
import re
import stat
import sys
from collections.abc import Sequence
from typing import Any, Never

import apple_stable_publication
import apple_publication_contract as apple_contract
import crates_io_publication
import crates_io_publication_contract as crates_contract
import platform_stable_publication
import platform_stable_publication_contract as platform_contract
from evidence_io import EvidenceIOError, parse_strict_json_bytes, read_regular_snapshot
from git_provenance import (
    GitProvenanceError,
    inspect_worktree,
    require_direct_results_only_child,
    require_results_only_descendant,
    run_git_bytes,
    run_git_text,
)
from proof_manifest import ProofManifestError, validate_declared_currentness
from publication_receipt_io import (
    PRIVATE_FILE_MODE,
    PUBLIC_FILE_MODE,
    PublicationReceiptIOError,
    create_private_transaction_json,
    read_fixed_json_snapshot,
)
from release_publication_contract import (
    PUBLICATION_STATE_PENDING,
    PUBLICATION_STATE_SOURCE,
    PUBLICATION_STATE_VERIFIED,
    ReleasePublicationContractError,
    publication_state,
    stable_source_identity,
    validate_release_publication_transition,
    validate_release_publications,
    validate_stable_source_currentness,
)


REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parent.parent
RESULTS_PATH = REPOSITORY_ROOT / "artifact" / "results.json"
RESULTS_CANDIDATE_ROOT = (
    REPOSITORY_ROOT / "target" / "release-publication-results"
)
RESULTS_CANDIDATE_NAME = "results.json"
MAX_RESULTS_BYTES = 16 * 1024 * 1024
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


class ReleaseReceiptFinalizerError(ValueError):
    """A full receipt or cross-domain results transition is invalid."""


@dataclasses.dataclass(frozen=True, slots=True)
class CommittedResults:
    manifest: dict[str, Any]
    sha256: str
    commit: str


def _fail(message: str) -> Never:
    raise ReleaseReceiptFinalizerError(message)


def _require(condition: bool, message: str) -> None:
    if not condition:
        _fail(message)


def _object(value: object, label: str) -> dict[str, Any]:
    _require(
        isinstance(value, dict)
        and all(isinstance(key, str) for key in value),
        f"{label} must be a JSON object with string keys",
    )
    return value


def _json_equal(left: object, right: object) -> bool:
    """Compare JSON values without accepting Python bool/int aliasing."""

    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(
            _json_equal(left[key], right[key]) for key in left
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _json_equal(left_item, right_item)
            for left_item, right_item in zip(left, right, strict=True)
        )
    return left == right


def _owned_results_metadata(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != PUBLIC_FILE_MODE
        or metadata.st_nlink != 1
    ):
        raise EvidenceIOError("current results manifest metadata differs")


def load_current_results(expected_sha256: str) -> CommittedResults:
    """Load results only when the worktree and HEAD blob are byte-identical."""

    _require(
        isinstance(expected_sha256, str)
        and HEX_64.fullmatch(expected_sha256) is not None,
        "expected current results SHA-256 is malformed",
    )
    try:
        snapshot = read_regular_snapshot(
            RESULTS_PATH,
            maximum=MAX_RESULTS_BYTES,
            label="current results manifest",
            validate_metadata=_owned_results_metadata,
        )
        value = parse_strict_json_bytes(
            snapshot.data,
            label="current results manifest",
        )
    except EvidenceIOError as exc:
        raise ReleaseReceiptFinalizerError(
            "cannot safely read current results manifest"
        ) from exc
    _require(
        snapshot.sha256 == expected_sha256,
        "current results manifest differs from its startup SHA-256 pin",
    )
    try:
        inspection = inspect_worktree(REPOSITORY_ROOT)
        head_bytes = run_git_bytes(
            REPOSITORY_ROOT,
            ["show", f"{inspection.commit}:artifact/results.json"],
        )
    except GitProvenanceError as exc:
        raise ReleaseReceiptFinalizerError(
            "cannot establish committed results provenance"
        ) from exc
    _require(
        not inspection.dirty,
        "release results finalization requires a clean committed checkout",
    )
    _require(
        head_bytes == snapshot.data,
        "current results bytes differ from HEAD:artifact/results.json",
    )
    manifest = _object(value, "current results manifest")
    try:
        validate_declared_currentness(manifest)
        validate_stable_source_currentness(manifest)
        validate_release_publications(manifest)
    except (ProofManifestError, ReleasePublicationContractError) as exc:
        raise ReleaseReceiptFinalizerError(str(exc)) from exc
    return CommittedResults(
        manifest=manifest,
        sha256=snapshot.sha256,
        commit=inspection.commit,
    )


def _load_apple_receipt(path: pathlib.Path) -> dict[str, Any]:
    snapshot = read_fixed_json_snapshot(
        path,
        safe_root=(
            apple_stable_publication.APPLE_PUBLICATION_RECEIPT_ROOT
        ),
        expected_leaf=(
            apple_stable_publication.APPLE_PUBLICATION_RECEIPT_NAME
        ),
        label="Apple 0.1.5 stable publication receipt input",
        parent_depth=1,
        maximum=apple_stable_publication.MAX_REMOTE_RECEIPT_BYTES,
        file_mode=PRIVATE_FILE_MODE,
    )
    receipt = snapshot.value
    try:
        apple_contract.validate_apple_publications(
            {
                "release_publications": {
                    apple_contract.APPLE_V0_1_5_PUBLICATION_KEY: receipt
                }
            }
        )
    except apple_contract.ApplePublicationContractError as exc:
        raise ReleaseReceiptFinalizerError(str(exc)) from exc
    return receipt


def _load_platform_receipt(path: pathlib.Path) -> dict[str, Any]:
    snapshot = read_fixed_json_snapshot(
        path,
        safe_root=platform_stable_publication.PLATFORM_PUBLICATION_RECEIPT_ROOT,
        expected_leaf=platform_stable_publication.RECEIPT_NAME,
        label="platform 0.1.5 stable publication receipt input",
        parent_depth=1,
        maximum=platform_stable_publication.MAX_PRIVATE_JSON_BYTES,
        file_mode=PRIVATE_FILE_MODE,
    )
    receipt = snapshot.value
    try:
        platform_contract.validate_v0_1_5_publication_receipt(receipt)
    except platform_contract.PlatformV015PublicationContractError as exc:
        raise ReleaseReceiptFinalizerError(str(exc)) from exc
    return receipt


def _load_crates_receipt(path: pathlib.Path) -> dict[str, Any]:
    snapshot = read_fixed_json_snapshot(
        path,
        safe_root=crates_io_publication.CRATES_IO_PUBLICATION_RECEIPT_ROOT,
        expected_leaf=crates_io_publication.CRATES_IO_PUBLICATION_RECEIPT_NAME,
        label="crates.io 0.1.5 stable publication receipt input",
        parent_depth=1,
        maximum=crates_io_publication.MAX_RECEIPT_BYTES,
        file_mode=PRIVATE_FILE_MODE,
    )
    receipt = snapshot.value
    try:
        crates_contract.validate_crates_io_publication_receipt(receipt)
    except crates_contract.CratesIoPublicationContractError as exc:
        raise ReleaseReceiptFinalizerError(str(exc)) from exc
    _require(
        receipt.get("status")
        == crates_contract.PUBLICATION_STATUS_PUBLISHED_VERIFIED,
        "crates.io aggregate receipt is not fully published and verified",
    )
    return receipt


def _verify_stable_source_git_binding(
    manifest: dict[str, Any], *, current_commit: str
) -> None:
    identity = stable_source_identity(manifest)
    if identity is None:
        return
    try:
        require_direct_results_only_child(
            REPOSITORY_ROOT,
            identity.source_parent_commit,
            identity.tag_commit,
        )
        require_results_only_descendant(
            REPOSITORY_ROOT,
            identity.tag_commit,
            current_commit,
        )
        observed_tree = run_git_text(
            REPOSITORY_ROOT,
            ["rev-parse", "--verify", f"{identity.tag_commit}^{{tree}}"],
        )
    except GitProvenanceError as exc:
        raise ReleaseReceiptFinalizerError(
            "stable publication Git source binding is invalid"
        ) from exc
    _require(
        observed_tree == identity.tag_tree,
        "stable publication tag tree differs from Git",
    )


def _assert_only_allowed_mutations(
    previous: dict[str, Any],
    current: dict[str, Any],
    *,
    previous_state: str,
    current_state: str,
) -> None:
    """Prove construction changed only the exact coordinated cohort fields."""

    allowed_top_level = {"release_publications"}
    if current_state == PUBLICATION_STATE_VERIFIED:
        allowed_top_level.add("swift_xcframework")
    _require(
        previous.keys() == current.keys(),
        "results finalization cannot add or remove top-level sections",
    )
    for key in previous:
        if key not in allowed_top_level:
            _require(
                _json_equal(previous[key], current[key]),
                f"results finalization changed forbidden top-level section {key!r}",
            )

    previous_publications = _object(
        previous.get("release_publications"),
        "previous release_publications",
    )
    current_publications = _object(
        current.get("release_publications"),
        "current release_publications",
    )
    mutable_publication_keys = {
        apple_contract.APPLE_V0_1_5_PUBLICATION_KEY,
        platform_contract.PLATFORM_V0_1_5_PUBLICATION_KEY,
    }
    if current_state == PUBLICATION_STATE_VERIFIED:
        mutable_publication_keys.add(crates_contract.CRATES_IO_PUBLICATION_KEY)
    for key in set(previous_publications) | set(current_publications):
        if key not in mutable_publication_keys:
            _require(
                key in previous_publications
                and key in current_publications
                and _json_equal(
                    previous_publications[key], current_publications[key]
                ),
                f"results finalization changed unprovided publication {key!r}",
            )

    if current_state == PUBLICATION_STATE_VERIFIED:
        previous_swift = _object(
            previous.get("swift_xcframework"),
            "previous swift_xcframework",
        )
        current_swift = _object(
            current.get("swift_xcframework"),
            "current swift_xcframework",
        )
        _require(
            previous_swift.keys() == current_swift.keys(),
            "Apple selector update changed swift_xcframework fields",
        )
        for key in previous_swift:
            if key not in {"active_publication_key", "distribution"}:
                _require(
                    _json_equal(previous_swift[key], current_swift[key]),
                    f"Apple selector update changed forbidden swift field {key!r}",
                )
    else:
        _require(
            _json_equal(
                previous.get("swift_xcframework"),
                current.get("swift_xcframework"),
            ),
            "pending stable cohort changed the active Apple selector",
        )
    _require(
        (previous_state, current_state)
        in {
            (PUBLICATION_STATE_SOURCE, PUBLICATION_STATE_PENDING),
            (PUBLICATION_STATE_PENDING, PUBLICATION_STATE_VERIFIED),
            (PUBLICATION_STATE_VERIFIED, PUBLICATION_STATE_VERIFIED),
        },
        "results finalization did not follow the coordinated cohort state machine",
    )


def assemble_next_results(
    expected_results_sha256: str,
    *,
    apple_receipt_path: pathlib.Path | None,
    platform_receipt_path: pathlib.Path | None,
    crates_receipt_path: pathlib.Path | None,
) -> tuple[dict[str, Any], CommittedResults]:
    """Apply exactly the next complete stable cohort to committed results."""

    committed = load_current_results(expected_results_sha256)
    previous = committed.manifest
    previous_state = publication_state(previous)
    if previous_state == PUBLICATION_STATE_SOURCE:
        if (
            apple_receipt_path is None
            or platform_receipt_path is None
            or crates_receipt_path is not None
        ):
            _fail(
                "pending finalization requires exactly Apple and platform receipts"
            )
    else:
        if (
            apple_receipt_path is None
            or platform_receipt_path is None
            or crates_receipt_path is None
        ):
            _fail(
                "verified finalization requires Apple, platform, and crates.io receipts"
            )
    apple_receipt = _load_apple_receipt(apple_receipt_path)
    platform_receipt = _load_platform_receipt(platform_receipt_path)
    crates_receipt = (
        _load_crates_receipt(crates_receipt_path)
        if crates_receipt_path is not None
        else None
    )
    current = copy.deepcopy(previous)
    publications = _object(
        current.get("release_publications"),
        "release_publications",
    )
    publications[apple_contract.APPLE_V0_1_5_PUBLICATION_KEY] = copy.deepcopy(
        apple_receipt
    )
    publications[platform_contract.PLATFORM_V0_1_5_PUBLICATION_KEY] = copy.deepcopy(
        platform_receipt
    )
    if crates_receipt is not None:
        publications[crates_contract.CRATES_IO_PUBLICATION_KEY] = copy.deepcopy(
            crates_receipt
        )
    if previous_state == PUBLICATION_STATE_PENDING:
        swift = _object(current.get("swift_xcframework"), "swift_xcframework")
        swift["active_publication_key"] = (
            apple_contract.APPLE_V0_1_5_PUBLICATION_KEY
        )
        swift["distribution"] = copy.deepcopy(apple_receipt["distribution"])
    try:
        validate_declared_currentness(current)
        validate_release_publications(current)
        validate_release_publication_transition(previous, current)
    except (ProofManifestError, ReleasePublicationContractError) as exc:
        raise ReleaseReceiptFinalizerError(str(exc)) from exc
    current_state = publication_state(current)
    _assert_only_allowed_mutations(
        previous,
        current,
        previous_state=previous_state,
        current_state=current_state,
    )
    _verify_stable_source_git_binding(
        current,
        current_commit=committed.commit,
    )
    return current, committed


def finalize_results(
    expected_results_sha256: str,
    *,
    apple_receipt_path: pathlib.Path | None,
    platform_receipt_path: pathlib.Path | None,
    crates_receipt_path: pathlib.Path | None,
) -> tuple[pathlib.Path, str, str, str]:
    """Publish one changed complete results candidate without replacement."""

    current, previous = assemble_next_results(
        expected_results_sha256,
        apple_receipt_path=apple_receipt_path,
        platform_receipt_path=platform_receipt_path,
        crates_receipt_path=crates_receipt_path,
    )
    _require(
        not _json_equal(previous.manifest, current),
        "provided receipts already match current results; use read-only verify",
    )
    path, digest = create_private_transaction_json(
        safe_root=RESULTS_CANDIDATE_ROOT,
        transaction_prefix="transaction.",
        expected_leaf=RESULTS_CANDIDATE_NAME,
        value=current,
        label="release publication results candidate",
        maximum=MAX_RESULTS_BYTES,
    )
    return path, digest, previous.commit, previous.sha256


def verify_existing_receipts(
    expected_results_sha256: str,
    *,
    apple_receipt_path: pathlib.Path | None,
    platform_receipt_path: pathlib.Path | None,
    crates_receipt_path: pathlib.Path | None,
) -> str:
    """Read-only confirm that provided leaves are already selected exactly."""

    committed = load_current_results(expected_results_sha256)
    current = committed.manifest
    state = publication_state(current)
    _require(
        state in {PUBLICATION_STATE_PENDING, PUBLICATION_STATE_VERIFIED},
        "current results contains no stable publication cohort",
    )
    _require(
        apple_receipt_path is not None and platform_receipt_path is not None,
        "stable cohort verification requires Apple and platform receipts",
    )
    apple_receipt = _load_apple_receipt(apple_receipt_path)
    platform_receipt = _load_platform_receipt(platform_receipt_path)
    publications = _object(current.get("release_publications"), "release_publications")
    _require(
        _json_equal(
            publications.get(apple_contract.APPLE_V0_1_5_PUBLICATION_KEY),
            apple_receipt,
        )
        and _json_equal(
            publications.get(platform_contract.PLATFORM_V0_1_5_PUBLICATION_KEY),
            platform_receipt,
        ),
        "provided domain receipts differ from current results",
    )
    if state == PUBLICATION_STATE_VERIFIED:
        _require(
            crates_receipt_path is not None,
            "verified cohort verification requires the crates.io receipt",
        )
        crates_receipt = _load_crates_receipt(crates_receipt_path)
        _require(
            _json_equal(
                publications.get(crates_contract.CRATES_IO_PUBLICATION_KEY),
                crates_receipt,
            ),
            "provided crates.io receipt differs from current results",
        )
    else:
        _require(
            crates_receipt_path is None,
            "pending cohort cannot be verified with a crates.io receipt",
        )
    _verify_stable_source_git_binding(current, current_commit=committed.commit)
    return committed.sha256


def _load_results_at_commit(
    commit: str,
    *,
    expected_sha256: str,
    label: str,
) -> dict[str, Any]:
    _require(COMMIT_RE.fullmatch(commit) is not None, f"{label} commit is malformed")
    _require(
        HEX_64.fullmatch(expected_sha256) is not None,
        f"{label} SHA-256 is malformed",
    )
    try:
        data = run_git_bytes(
            REPOSITORY_ROOT,
            ["show", f"{commit}:artifact/results.json"],
        )
        value = parse_strict_json_bytes(data, label=label)
    except (GitProvenanceError, EvidenceIOError) as exc:
        raise ReleaseReceiptFinalizerError(f"cannot load {label}") from exc
    _require(0 < len(data) <= MAX_RESULTS_BYTES, f"{label} size is outside bounds")
    _require(
        hashlib.sha256(data).hexdigest() == expected_sha256,
        f"{label} differs from its expected SHA-256",
    )
    manifest = _object(value, label)
    try:
        validate_declared_currentness(manifest)
        validate_release_publications(manifest)
    except (ProofManifestError, ReleasePublicationContractError) as exc:
        raise ReleaseReceiptFinalizerError(f"{label} is not current") from exc
    return manifest


def verify_installed_results(
    expected_results_sha256: str,
    *,
    expected_parent_commit: str,
    expected_parent_results_sha256: str,
) -> tuple[str, str]:
    """Verify one committed results-only cohort transition after installation."""

    current = load_current_results(expected_results_sha256)
    try:
        require_direct_results_only_child(
            REPOSITORY_ROOT,
            expected_parent_commit,
            current.commit,
        )
    except GitProvenanceError as exc:
        raise ReleaseReceiptFinalizerError(
            "installed publication results commit is not the direct results-only child"
        ) from exc
    previous = _load_results_at_commit(
        expected_parent_commit,
        expected_sha256=expected_parent_results_sha256,
        label="parent publication results",
    )
    try:
        validate_release_publication_transition(previous, current.manifest)
    except ReleasePublicationContractError as exc:
        raise ReleaseReceiptFinalizerError(
            "installed publication transition is invalid"
        ) from exc
    previous_state = publication_state(previous)
    current_state = publication_state(current.manifest)
    _assert_only_allowed_mutations(
        previous,
        current.manifest,
        previous_state=previous_state,
        current_state=current_state,
    )
    _verify_stable_source_git_binding(
        current.manifest,
        current_commit=current.commit,
    )
    return current.commit, current_state


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("finalize", "verify"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("expected_results_sha256")
        subparser.add_argument("--apple-receipt", type=pathlib.Path)
        subparser.add_argument("--platform-receipt", type=pathlib.Path)
        subparser.add_argument("--crates-receipt", type=pathlib.Path)
    installed = subparsers.add_parser("verify-installed")
    installed.add_argument("expected_results_sha256")
    installed.add_argument("expected_parent_commit")
    installed.add_argument("expected_parent_results_sha256")
    return parser


def _relative_output(path: pathlib.Path) -> str:
    try:
        return path.relative_to(REPOSITORY_ROOT).as_posix()
    except ValueError as exc:
        raise ReleaseReceiptFinalizerError(
            "results candidate output escaped the repository"
        ) from exc


def run(args: argparse.Namespace) -> None:
    if args.command == "verify-installed":
        commit, state = verify_installed_results(
            args.expected_results_sha256,
            expected_parent_commit=args.expected_parent_commit,
            expected_parent_results_sha256=(
                args.expected_parent_results_sha256
            ),
        )
        print(
            "RELEASE_PUBLICATION_RESULTS_INSTALLED_VERIFY_PASS "
            f"commit={commit} state={state}"
        )
        return
    if args.command == "verify":
        digest = verify_existing_receipts(
            args.expected_results_sha256,
            apple_receipt_path=args.apple_receipt,
            platform_receipt_path=args.platform_receipt,
            crates_receipt_path=args.crates_receipt,
        )
        print(f"RELEASE_PUBLICATION_RESULTS_VERIFY_PASS sha256={digest}")
        return
    path, digest, parent_commit, parent_sha256 = finalize_results(
        args.expected_results_sha256,
        apple_receipt_path=args.apple_receipt,
        platform_receipt_path=args.platform_receipt,
        crates_receipt_path=args.crates_receipt,
    )
    print(
        "RELEASE_PUBLICATION_RESULTS_CANDIDATE_PASS "
        f"path={_relative_output(path)} sha256={digest} "
        f"parent_commit={parent_commit} parent_sha256={parent_sha256}"
    )


def main() -> int:
    try:
        run(_parser().parse_args())
    except (
        ReleaseReceiptFinalizerError,
        PublicationReceiptIOError,
        OSError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
