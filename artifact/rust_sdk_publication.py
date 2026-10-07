#!/usr/bin/env python3
"""Prepare, observe or publish the exact source-bound 0.2.0 Rust SDK cohort.

Package production remains in rust_sdk_profile. Uploads, persistent locking,
intent/outcome journals and unknown-outcome recovery use crates_io_publication.
The SDK receipt has its own schema and namespace; legacy receipts stay separate.
"""
from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from collections.abc import Mapping, Sequence

import crates_io_publication as transaction
import crates_io_uploader_build as uploader
import rust_sdk_profile as sdk
from crates_io_publication_contract import (
    CratesIoPublicationContractError, parse_utc_timestamp, validate_publication_crates,
)
from evidence_io import FileSnapshot, parse_strict_json_bytes, read_regular_snapshot
from git_provenance import run_git_text
from publication_receipt_io import PublicationReceiptCommittedError, canonical_json_bytes

RELEASE = transaction.PublicationRelease.SDK_V0_2_0
RECEIPT_KIND = "qperiapt.sdk_crates_io_publication_receipt"
RECEIPT_BOUNDARY = (
    "Q-Periapt 0.2.0 ABI 2 Rust package publication. The selected clean source, "
    "package report and exact archives remain bound throughout the transaction. "
    "Published crates form a dependency-safe prefix and require matching "
    "non-yanked checksums from both the official API and sparse index. Upload "
    "success or an unknown outcome alone is not a published observation."
)
RECEIPT_ROOT = sdk.ROOT / "target/qperiapt-sdk-020-publication-receipts"
JOURNAL_ROOT = sdk.ROOT / "target/qperiapt-sdk-020-publication-journal"
TOPOLOGY = (
    ("q-periapt-mlkem-native-sys", ()),
    ("q-periapt-core", ()),
    ("q-periapt-kem", ("q-periapt-core",)),
    ("q-periapt-sig", ("q-periapt-core",)),
    ("q-periapt-backends", ("q-periapt-mlkem-native-sys", "q-periapt-core", "q-periapt-sig")),
    ("q-periapt-policy", ("q-periapt-core", "q-periapt-sig")),
    ("q-periapt-sdk", ("q-periapt-core", "q-periapt-kem", "q-periapt-backends", "q-periapt-policy")),
    ("q-periapt-host-store", ("q-periapt-core", "q-periapt-backends", "q-periapt-policy", "q-periapt-sdk")),
    ("q-periapt-rustls", ("q-periapt-core", "q-periapt-kem", "q-periapt-backends", "q-periapt-policy", "q-periapt-sdk")),
    ("q-periapt-ffi", ("q-periapt-core", "q-periapt-kem", "q-periapt-backends", "q-periapt-policy",
                      "q-periapt-sdk", "q-periapt-host-store", "q-periapt-rustls")),
    ("q-periapt-wasm", ("q-periapt-core", "q-periapt-kem", "q-periapt-backends", "q-periapt-policy")),
    ("q-periapt-cli", ("q-periapt-core", "q-periapt-sig", "q-periapt-backends", "q-periapt-policy", "q-periapt-rustls")),
)
if sdk.VERSION != RELEASE.value or tuple(name for name, _ in TOPOLOGY) != sdk.COHORT:
    raise RuntimeError("SDK publication order differs from package production")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CratesIoPublicationContractError(message)


def object_with_keys(value: object, keys: set[str], label: str) -> dict:
    require(isinstance(value, dict) and set(value) == keys, f"{label} keys differ")
    return value


def digest(value: object, length: int, label: str) -> str:
    require(isinstance(value, str) and re.fullmatch(rf"[0-9a-f]{{{length}}}", value) is not None,
            f"{label} is malformed")
    return value


def receipt_header() -> dict[str, object]:
    return {"boundary": RECEIPT_BOUNDARY, "kind": RECEIPT_KIND, "schema_version": 1,
            "identity": {"abi_version": 2, "product_version": sdk.VERSION,
                         "publication_key": "crates_io_v0_2_0", "registry": transaction.CRATES_IO_REGISTRY}}


def validate_receipt(value: object) -> None:
    receipt = object_with_keys(value, {"boundary", "kind", "schema_version", "identity", "observation", "crates", "status"},
                               "SDK publication receipt")
    header = receipt_header()
    require(type(receipt["schema_version"]) is int and all(receipt[key] == expected for key, expected in header.items()),
            "SDK publication receipt identity differs")
    identity = object_with_keys(receipt["identity"], {"abi_version", "product_version", "publication_key", "registry"},
                               "SDK publication identity")
    require(type(identity["abi_version"]) is int, "SDK publication ABI type differs")
    observation = object_with_keys(receipt["observation"], {"source", "package_contract", "observed_at"}, "SDK observation")
    source = object_with_keys(observation["source"], {"commit", "tree", "source_inputs_sha256"}, "SDK source")
    digest(source["commit"], 40, "SDK source commit")
    digest(source["tree"], 40, "SDK source tree")
    digest(source["source_inputs_sha256"], 64, "SDK source inputs digest")
    package = object_with_keys(observation["package_contract"], {"completed_at", "report_sha256", "source_commit"}, "SDK package contract")
    require(package["source_commit"] == source["commit"], "SDK package report source differs")
    digest(package["report_sha256"], 64, "SDK package report digest")
    completed = parse_utc_timestamp(package["completed_at"], "SDK package completion")
    observed = parse_utc_timestamp(observation["observed_at"], "SDK registry observation")
    require(completed <= observed, "SDK package completion postdates registry observation")
    validate_publication_crates(receipt["crates"], topology=TOPOLOGY, product_version=sdk.VERSION,
                                package_completed_at=completed, observed_at=observed, aggregate_status=receipt["status"])


def validate_current_source(report: Mapping, expected_commit: str) -> dict[str, str]:
    """Require the selected clean producer source, including every recorded input."""
    digest(expected_commit, 40, "selected SDK source commit")
    require(report.get("base_commit") == expected_commit, "SDK package report commit differs from selection")
    current, dirty = sdk.inspect_package_source(sdk.ROOT, allow_dirty=False)
    require(current == expected_commit and dirty is False, "SDK publication requires the exact clean producer commit")
    inputs = sdk.source_identity()
    require(report.get("source_inputs") == inputs, "SDK package report inputs differ from the current source")
    tree = run_git_text(sdk.ROOT, ["rev-parse", "--verify", "HEAD^{tree}"])
    digest(tree, 40, "SDK source tree")
    return {"commit": current, "tree": tree,
            "source_inputs_sha256": hashlib.sha256(canonical_json_bytes(inputs)).hexdigest()}


@dataclasses.dataclass(frozen=True, slots=True)
class SdkPublicationEvidence:
    report_snapshot: FileSnapshot
    source_commit: str
    source_tree: str
    source_inputs_sha256: str
    completed_at: str
    crates: tuple[transaction.LocalCrate, ...]

    @property
    def release(self) -> transaction.PublicationRelease:
        return RELEASE

    @property
    def handoff_manifest_sha256(self) -> str:
        # The common journal binds the selected package input digest. The SDK
        # format is a package report; it never masquerades as a legacy transcript.
        return self.report_snapshot.sha256

    def source_document(self) -> dict[str, str]:
        return {"commit": self.source_commit, "tree": self.source_tree, "source_inputs_sha256": self.source_inputs_sha256}

    def package_contract_document(self) -> dict[str, str]:
        return {"completed_at": self.completed_at, "report_sha256": self.report_snapshot.sha256, "source_commit": self.source_commit}

    def receipt_header(self) -> dict[str, object]:
        return receipt_header()

    def validate_receipt(self, value: object) -> None:
        validate_receipt(value)

    def resample(self) -> None:
        current = read_regular_snapshot(self.report_snapshot.path, maximum=uploader.MAX_INPUT_BYTES, label="SDK package report")
        require(current.data == self.report_snapshot.data, "SDK package report changed during publication")
        report = parse_strict_json_bytes(current.data, label="SDK package report")
        require(validate_current_source(report, self.source_commit) == self.source_document(),
                "SDK publication source changed")
        for crate in self.crates:
            observed = read_regular_snapshot(crate.path, maximum=sdk.MAX_ARCHIVE, label=f"{crate.name} archive")
            require((observed.size, observed.sha256, observed.data) == (crate.size, crate.sha256, crate.payload),
                    f"SDK archive changed during publication: {crate.name}")


def load_evidence(report_path: Path, report_sha256: str, source_commit: str) -> SdkPublicationEvidence:
    digest(report_sha256, 64, "selected SDK report digest")
    snapshot = read_regular_snapshot(report_path, maximum=uploader.MAX_INPUT_BYTES, label="SDK package report")
    require(snapshot.sha256 == report_sha256, "SDK package report digest differs from selection")
    report = parse_strict_json_bytes(snapshot.data, label="SDK package report")
    require(isinstance(report, Mapping), "SDK package report is not an object")
    crate_dir = report_path.parent / "crates"
    contracts, version, _ = uploader.build_contracts(report, crate_dir, profile=sdk.PROFILE)
    require(version == sdk.VERSION, "SDK publication version differs")
    completed_at = report.get("completed_at")
    parse_utc_timestamp(completed_at, "SDK package completion (regenerate reports without this field)")
    source = validate_current_source(report, source_commit)
    crates = []
    for name, dependencies in TOPOLOGY:
        contract = contracts[name]
        metadata = parse_strict_json_bytes(contract["metadata_json"].encode(), label="SDK registry metadata")
        observed_dependencies = {d["name"] for d in metadata["deps"] if d["kind"] != "dev" and d["name"] in sdk.COHORT}
        require(observed_dependencies == set(dependencies), f"SDK publication topology differs: {name}")
        archive = read_regular_snapshot(crate_dir / f"{name}-{sdk.VERSION}.crate", maximum=sdk.MAX_ARCHIVE, label=f"{name} archive")
        require((archive.size, archive.sha256) == (contract["size"], contract["sha256"]), f"SDK archive changed while loading: {name}")
        crates.append(transaction.LocalCrate(name=name, version=sdk.VERSION, dependencies=dependencies,
                      path=archive.path, size=archive.size, sha256=archive.sha256, payload=archive.data))
    evidence = SdkPublicationEvidence(snapshot, source["commit"], source["tree"], source["source_inputs_sha256"], completed_at, tuple(crates))
    evidence.resample()
    return evidence


def _written_receipts(items: Sequence[transaction.WrittenReceipt]) -> list[dict[str, str]]:
    return [{"path": str(item.path), "sha256": item.sha256} for item in items]


def main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("dry-run", "verify", "publish"))
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--report-sha256", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--previous-receipt", type=Path)
    parser.add_argument("--state-root", type=Path)
    parser.add_argument("--uploader-command", type=Path)
    parser.add_argument("--execute-real-upload", action="store_true")
    parser.add_argument("--acknowledge-irreversible-publish", action="store_true")
    parser.add_argument("--retry-unknown-intent")
    parser.add_argument("--http-connect-proxy")
    args = parser.parse_args(argv)
    try:
        lock = runner = credentials = acknowledgement = None
        receipt_root, journal_root = RECEIPT_ROOT, JOURNAL_ROOT
        if args.mode == "publish":
            require(args.execute_real_upload and args.acknowledge_irreversible_publish,
                    "SDK publish requires both explicit irreversible-upload acknowledgements")
            state_root = transaction._expected_publication_state_root(RELEASE)
            command = state_root / transaction.CRATES_IO_PUBLICATION_UPLOADER_NAME
            require(args.state_root == state_root and args.uploader_command == command,
                    "SDK publish paths must confirm the fixed account publication namespace")
            lock = transaction.production_lock_factory(state_root, release=RELEASE)
            runner = transaction.production_upload_runner(command, state_root=state_root, release=RELEASE,
                                                          http_connect_proxy=args.http_connect_proxy)
            receipt_root, journal_root = state_root / "receipts", state_root / "journal"
            credentials = lambda: os.environ.get("CARGO_REGISTRY_TOKEN", "")
            acknowledgement = RELEASE.acknowledgement
        else:
            require(not (args.execute_real_upload or args.acknowledge_irreversible_publish
                         or args.state_root or args.uploader_command or args.http_connect_proxy),
                    "SDK read-only modes cannot select upload authority")
        evidence = load_evidence(args.report.absolute(), args.report_sha256, args.source_commit)
        previous = None if args.previous_receipt is None else transaction.load_previous_receipt(
            args.previous_receipt.absolute(), safe_root=receipt_root, release=RELEASE, validator=validate_receipt)
        result = transaction.run_prepared_publication_transaction(
            evidence, mode=args.mode, previous_receipt=previous, retry_unknown_intent_sha256=args.retry_unknown_intent,
            receipt_root=receipt_root, journal_root=journal_root, execute_real_upload=args.execute_real_upload,
            irreversible_acknowledgement=acknowledgement, credential_provider=credentials, lock_factory=lock,
            upload_runner=runner,
        )
    except transaction.CratesIoUploadOutcomeUnknownError as error:
        print(json.dumps({"status": "upload_outcome_unknown", "crate": error.crate_name,
                          "receipts": _written_receipts(error.written_receipts)}))
        return 2
    except PublicationReceiptCommittedError as error:
        print(json.dumps({"status": "local_receipt_commit_uncertain", "path": str(error.path) if error.path is not None else None}))
        return 2
    except (OSError, ValueError, RuntimeError) as error:
        print(f"error: SDK publication: {transaction._safe_cli_error_message(error)}", file=sys.stderr)
        return 1
    print(json.dumps({"mode": result.mode, "profile": sdk.PROFILE, "source_commit": evidence.source_commit,
                      "package_report_sha256": evidence.handoff_manifest_sha256,
                      "planned_crates": result.planned_crates, "upload_attempts": result.upload_attempts,
                      "status": result.receipt["status"] if result.receipt is not None else "local_inputs_verified",
                      "receipts": _written_receipts(result.written_receipts)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
