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
import os
import pathlib
import re
import stat
import sys
from collections.abc import Sequence
from typing import Any, Never

import apple_alpha3_publication
import apple_publication_contract as apple_contract
import platform_alpha3_publication
import platform_alpha3_publication_contract as platform_contract
from evidence_io import EvidenceIOError, parse_strict_json_bytes, read_regular_snapshot
from proof_manifest import ProofManifestError, validate_declared_currentness
from publication_receipt_io import (
    PRIVATE_FILE_MODE,
    PUBLIC_FILE_MODE,
    PublicationReceiptIOError,
    create_private_transaction_json,
    read_fixed_json_snapshot,
)
from release_publication_contract import (
    ReleasePublicationContractError,
    validate_release_publication_transition,
    validate_release_publications,
)


REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parent.parent
RESULTS_PATH = REPOSITORY_ROOT / "artifact" / "results.json"
RESULTS_CANDIDATE_ROOT = (
    REPOSITORY_ROOT / "target" / "release-publication-results"
)
RESULTS_CANDIDATE_NAME = "results.json"
MAX_RESULTS_BYTES = 16 * 1024 * 1024
HEX_64 = re.compile(r"^[0-9a-f]{64}$")


class ReleaseReceiptFinalizerError(ValueError):
    """A full receipt or cross-domain results transition is invalid."""


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


def load_current_results(expected_sha256: str) -> tuple[dict[str, Any], str]:
    """Load the fixed current results manifest under an exact startup pin."""

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
    manifest = _object(value, "current results manifest")
    try:
        validate_declared_currentness(manifest)
        validate_release_publications(manifest)
    except (ProofManifestError, ReleasePublicationContractError) as exc:
        raise ReleaseReceiptFinalizerError(str(exc)) from exc
    return manifest, snapshot.sha256


def _load_apple_receipt(path: pathlib.Path) -> dict[str, Any]:
    snapshot = read_fixed_json_snapshot(
        path,
        safe_root=(
            apple_alpha3_publication.APPLE_PUBLICATION_RECEIPT_ROOT
        ),
        expected_leaf=(
            apple_alpha3_publication.APPLE_PUBLICATION_RECEIPT_NAME
        ),
        label="Apple alpha.3 publication receipt input",
        parent_depth=1,
        maximum=apple_alpha3_publication.MAX_REMOTE_RECEIPT_BYTES,
        file_mode=PRIVATE_FILE_MODE,
    )
    receipt = snapshot.value
    try:
        apple_contract.validate_apple_publications(
            {
                "release_publications": {
                    apple_contract.APPLE_ALPHA3_R1_PUBLICATION_KEY: receipt
                }
            }
        )
    except apple_contract.ApplePublicationContractError as exc:
        raise ReleaseReceiptFinalizerError(str(exc)) from exc
    return receipt


def _load_platform_receipt(path: pathlib.Path) -> dict[str, Any]:
    snapshot = read_fixed_json_snapshot(
        path,
        safe_root=platform_alpha3_publication.PLATFORM_PUBLICATION_RECEIPT_ROOT,
        expected_leaf=platform_alpha3_publication.RECEIPT_NAME,
        label="platform alpha.3 publication receipt input",
        parent_depth=1,
        maximum=platform_alpha3_publication.MAX_PRIVATE_JSON_BYTES,
        file_mode=PRIVATE_FILE_MODE,
    )
    receipt = snapshot.value
    try:
        platform_contract.validate_alpha3_publication_receipt(receipt)
    except platform_contract.PlatformAlpha3PublicationContractError as exc:
        raise ReleaseReceiptFinalizerError(str(exc)) from exc
    return receipt


def _assert_only_allowed_mutations(
    previous: dict[str, Any],
    current: dict[str, Any],
    *,
    apple_supplied: bool,
    platform_supplied: bool,
) -> None:
    """Prove construction changed only provided leaves and the Apple selector."""

    allowed_top_level = {"release_publications"}
    if apple_supplied:
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
    mutable_publication_keys: set[str] = set()
    if apple_supplied:
        mutable_publication_keys.add(
            apple_contract.APPLE_ALPHA3_R1_PUBLICATION_KEY
        )
    if platform_supplied:
        mutable_publication_keys.add(
            platform_contract.PLATFORM_ALPHA3_PUBLICATION_KEY
        )
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

    if apple_supplied:
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
            if key != "distribution":
                _require(
                    _json_equal(previous_swift[key], current_swift[key]),
                    f"Apple selector update changed forbidden swift field {key!r}",
                )


def assemble_next_results(
    expected_results_sha256: str,
    *,
    apple_receipt_path: pathlib.Path | None,
    platform_receipt_path: pathlib.Path | None,
) -> tuple[dict[str, Any], str]:
    """Apply one or two complete domain leaves to the pinned current results."""

    _require(
        apple_receipt_path is not None or platform_receipt_path is not None,
        "results finalization requires at least one full domain receipt",
    )
    previous, previous_sha256 = load_current_results(expected_results_sha256)
    apple_receipt = (
        _load_apple_receipt(apple_receipt_path)
        if apple_receipt_path is not None
        else None
    )
    platform_receipt = (
        _load_platform_receipt(platform_receipt_path)
        if platform_receipt_path is not None
        else None
    )
    current = copy.deepcopy(previous)
    publications = _object(
        current.get("release_publications"),
        "release_publications",
    )
    if apple_receipt is not None:
        publications[apple_contract.APPLE_ALPHA3_R1_PUBLICATION_KEY] = copy.deepcopy(
            apple_receipt
        )
        swift = _object(current.get("swift_xcframework"), "swift_xcframework")
        swift["distribution"] = copy.deepcopy(apple_receipt["distribution"])
    if platform_receipt is not None:
        publications[platform_contract.PLATFORM_ALPHA3_PUBLICATION_KEY] = copy.deepcopy(
            platform_receipt
        )

    _assert_only_allowed_mutations(
        previous,
        current,
        apple_supplied=apple_receipt is not None,
        platform_supplied=platform_receipt is not None,
    )
    try:
        validate_declared_currentness(current)
        validate_release_publications(current)
        validate_release_publication_transition(previous, current)
    except (ProofManifestError, ReleasePublicationContractError) as exc:
        raise ReleaseReceiptFinalizerError(str(exc)) from exc
    return current, previous_sha256


def finalize_results(
    expected_results_sha256: str,
    *,
    apple_receipt_path: pathlib.Path | None,
    platform_receipt_path: pathlib.Path | None,
) -> tuple[pathlib.Path, str]:
    """Publish one changed complete results candidate without replacement."""

    current, _previous_sha256 = assemble_next_results(
        expected_results_sha256,
        apple_receipt_path=apple_receipt_path,
        platform_receipt_path=platform_receipt_path,
    )
    previous, _ = load_current_results(expected_results_sha256)
    _require(
        not _json_equal(previous, current),
        "provided receipts already match current results; use read-only verify",
    )
    return create_private_transaction_json(
        safe_root=RESULTS_CANDIDATE_ROOT,
        transaction_prefix="transaction.",
        expected_leaf=RESULTS_CANDIDATE_NAME,
        value=current,
        label="release publication results candidate",
        maximum=MAX_RESULTS_BYTES,
    )


def verify_existing_receipts(
    expected_results_sha256: str,
    *,
    apple_receipt_path: pathlib.Path | None,
    platform_receipt_path: pathlib.Path | None,
) -> str:
    """Read-only confirm that provided leaves are already selected exactly."""

    assembled, previous_sha256 = assemble_next_results(
        expected_results_sha256,
        apple_receipt_path=apple_receipt_path,
        platform_receipt_path=platform_receipt_path,
    )
    previous, _ = load_current_results(expected_results_sha256)
    _require(
        _json_equal(previous, assembled),
        "provided receipts would advance current results; use finalize",
    )
    return previous_sha256


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("finalize", "verify"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("expected_results_sha256")
        subparser.add_argument("--apple-receipt", type=pathlib.Path)
        subparser.add_argument("--platform-receipt", type=pathlib.Path)
    return parser


def _relative_output(path: pathlib.Path) -> str:
    try:
        return path.relative_to(REPOSITORY_ROOT).as_posix()
    except ValueError as exc:
        raise ReleaseReceiptFinalizerError(
            "results candidate output escaped the repository"
        ) from exc


def run(args: argparse.Namespace) -> None:
    if args.command == "verify":
        digest = verify_existing_receipts(
            args.expected_results_sha256,
            apple_receipt_path=args.apple_receipt,
            platform_receipt_path=args.platform_receipt,
        )
        print(f"RELEASE_PUBLICATION_RESULTS_VERIFY_PASS sha256={digest}")
        return
    path, digest = finalize_results(
        args.expected_results_sha256,
        apple_receipt_path=args.apple_receipt,
        platform_receipt_path=args.platform_receipt,
    )
    print(
        "RELEASE_PUBLICATION_RESULTS_CANDIDATE_PASS "
        f"path={_relative_output(path)} sha256={digest}"
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
