#!/usr/bin/env python3
"""Admit the 0.2.0 cohort into the existing journaled GitHub transaction.

No alternate upload, retry or reconciliation implementation lives here. This
adapter owns only the version-specific source/evidence admission and staging.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import secrets
import time
from collections.abc import Sequence

import continuity_release_manifest as manifest
import github_release_observation as github
import sdk_github_publication_contract as contract
import stable_github_publication as transaction
from evidence_io import consume_regular_snapshot_at, parse_strict_json_bytes, read_regular_snapshot
from git_provenance import run_git_bytes, run_git_text
from publication_receipt_io import (
    PrivateDirectoryHandle, canonical_json_bytes, create_private_direct_child_handle,
    normalize_safe_root, verify_exact_directory_inventory_at, verify_private_directory_handle_identity,
    write_private_bytes_noreplace_at, write_private_json_noreplace_at,
)


def _committed_bytes(root: Path, commit: str, path: str, *, maximum: int) -> bytes:
    manifest.relative_path(path)
    entry = run_git_bytes(root, ["ls-tree", "-z", commit, "--", path])
    parts = entry.removesuffix(b"\0").split(b"\t")
    manifest.require(len(parts) == 2 and parts[1] == path.encode(), "committed evidence leaf is absent")
    mode, kind, oid = parts[0].split()
    manifest.require(mode == b"100644" and kind == b"blob", "committed evidence is not a regular data file")
    digest = oid.decode("ascii")
    manifest.digest(digest, 40, "committed evidence Git object")
    size = int(run_git_text(root, ["cat-file", "-s", digest]))
    manifest.require(0 < size <= maximum, "committed evidence exceeds its byte bound")
    payload = run_git_bytes(root, ["cat-file", "blob", digest])
    manifest.require(len(payload) == size, "committed evidence size changed")
    return payload


def _committed_reference(root: Path, commit: str, reference: dict, *, maximum: int) -> bytes:
    ref = manifest.file_ref(reference, maximum=maximum)
    payload = _committed_bytes(root, commit, ref["path"], maximum=maximum)
    manifest.require(len(payload) == ref["bytes"] and hashlib.sha256(payload).hexdigest() == ref["sha256"],
                     "committed release input differs from its admission pin")
    return payload


def _json(raw: bytes, label: str):
    return parse_strict_json_bytes(raw, label=label)


def _require_evidence_child(root: Path, source: str, commit: str) -> None:
    manifest.require(run_git_text(root, ["rev-list", "--parents", "-n", "1", commit]).split()
                     == [commit, source], "release evidence must be a direct child of its qualified source")
    raw = run_git_bytes(root, ["diff", "--no-renames", "--name-status", "-z", source, commit, "--"])
    fields = raw.removesuffix(b"\0").split(b"\0")
    manifest.require(4 <= len(fields) <= 2048 and len(fields) % 2 == 0,
                     "release evidence commit has an empty or oversized change inventory")
    paths = []
    for change, path in zip(fields[::2], fields[1::2], strict=True):
        decoded = path.decode("utf-8", errors="strict")
        manifest.relative_path(decoded)
        manifest.require(change == b"A" and decoded.startswith(contract.EVIDENCE_PREFIX),
                         "release evidence commit changes qualified source or existing evidence")
        paths.append(decoded)
    manifest.require({contract.ADMISSION_PATH, contract.MANIFEST_PATH} <= set(paths),
                     "release evidence commit omits admission or package manifest")


def read_committed_admission(expected_sha256: str, *, repository_root: Path | None = None) -> tuple[dict, str, str]:
    root = transaction._selected_repository_root(repository_root)
    manifest.digest(expected_sha256, 64, "selected SDK admission")
    commit = run_git_text(root, ["rev-parse", "--verify", "HEAD^{commit}"])
    tree = run_git_text(root, ["rev-parse", "--verify", "HEAD^{tree}"])
    manifest.require(run_git_bytes(root, ["status", "--porcelain=v1", "-z", "--untracked-files=all"]) == b"",
                     "publication checkout is not clean")
    raw = _committed_bytes(root, commit, contract.ADMISSION_PATH, maximum=contract.MAX_ADMISSION_BYTES)
    manifest.require(hashlib.sha256(raw).hexdigest() == expected_sha256, "selected SDK admission digest differs")
    admission = contract.parse_admission(_json(raw, "SDK admission"))
    manifest.require(raw == canonical_json_bytes(admission), "SDK admission is not canonical JSON")
    source = admission["source"]
    _require_evidence_child(root, source["commit"], commit)
    manifest.require(run_git_text(root, ["rev-parse", "--verify", f"{source['commit']}^{{tree}}"])
                     == source["tree"], "qualified source tree differs")
    selected = _json(_committed_reference(root, commit, admission["manifest"], maximum=manifest.MAX_MANIFEST),
                     "committed release manifest")
    manifest.require(type(selected) is dict and selected.get("source") == source
                     and selected.get("stage") == "release", "committed package manifest source or stage differs")
    for role, ref in admission["qualifications"].items():
        record = contract.parse_qualification(_json(_committed_reference(
            root, commit, ref, maximum=manifest.MAX_ASSESSMENT), role), role=role, source=source)
        for original in record["records"]:
            _committed_reference(root, commit, original, maximum=manifest.MAX_ASSESSMENT)
    # The source tree and all original records retain their identities even
    # though the annotated release tags point to the later evidence-only tree.
    return admission, commit, tree


def build_plan(expected_admission_sha256: str, *, repository_root: Path | None = None) -> transaction.SdkPublicationPlan:
    root = transaction._selected_repository_root(repository_root)
    admission, commit, tree = read_committed_admission(expected_admission_sha256, repository_root=root)
    releases = []
    for index, domain in enumerate(("apple", "platform")):
        tag = contract.TAGS[index]
        title, body = contract.RELEASE_TEXT[domain]
        latest = domain == "apple"
        assets = tuple(transaction.AssetPlan(name=row["name"], size=row["file"]["bytes"],
                       sha256=row["file"]["sha256"], content_type=contract.content_type(row["name"]),
                       staging_leaf=f"{domain}--{row['name']}") for row in admission["assets"][domain])
        releases.append(transaction.ReleasePlan(
            domain=domain, tag=tag, tag_object=transaction._local_tag_object(tag, commit, tree, repository_root=root),
            title=title, body=body, make_latest=latest, assets=assets,
            create_request=transaction._request_plan(f"create-{domain}.json", transaction._create_request_bytes(
                tag=tag, title=title, body=body, make_latest=latest, tag_commit=commit)),
            publish_request=transaction._request_plan(f"publish-{domain}.json", transaction._publish_request_bytes(
                tag=tag, title=title, body=body, make_latest=latest, tag_commit=commit)),
        ))
    plan = transaction.SdkPublicationPlan(
        source_commit=admission["source"]["commit"], source_tree=admission["source"]["tree"],
        tag_commit=commit, tag_tree=tree, admission_sha256=expected_admission_sha256,
        github_cli_sha256=github.select_github_cli(profile="sdk-020").sha256,
        releases=(releases[0], releases[1]),
    )
    manifest.require(transaction.parse_plan(plan.document()) == plan, "SDK plan is not canonical")
    return plan


def validate_local_admission(plan: transaction.SdkPublicationPlan, *, repository_root: Path | None = None) -> None:
    manifest.require(build_plan(plan.admission_sha256, repository_root=repository_root) == plan,
                     "SDK source, evidence, tag or tool authority changed after preparation")


def _bind_input_metadata(root: Path, admission: dict, *, repository_root: Path, evidence_commit: str) -> None:
    """Bind every non-archive manifest input to its committed source/evidence."""
    inputs = manifest.Inputs(root)
    selected = inputs.json(admission["manifest"], maximum=manifest.MAX_MANIFEST)
    references = [admission["manifest"], selected["spec_lock"]]
    lock = inputs.json(selected["spec_lock"])
    references.extend(lock["normative_files"].values())
    references.extend(lock["supporting_files"])
    references.append(lock["compiled_descriptor"])
    references.extend(row["contract"] for row in selected["interfaces"].values())
    for package in selected["packages"]:
        references.append(package["metadata"])
        if package["workspace"] is not None:
            references.append(package["workspace"])
        references.extend(package["assessments"])
    for ref in references:
        _committed_reference(repository_root, evidence_commit, ref, maximum=manifest.MAX_ASSESSMENT)
        inputs.read(ref, maximum=manifest.MAX_ASSESSMENT, binary=True)
    inputs.unchanged()


def _ensure_account_lock(*, repository_root: Path) -> None:
    # All versions acquire the existing account lane. A new machine may not
    # have its original lock yet; create only that empty private lock, never a
    # fabricated 0.1.5 plan, intent, outcome or publication receipt.
    root, created = transaction.ensure_state_root_for_prepare(repository_root=repository_root)
    with transaction.publication_lock(root, allow_create=created is not None,
                                      created_root_identity=created, repository_root=repository_root):
        pass


def prepare(expected_admission_sha256: str, *, input_root: Path, repository_root: Path | None = None):
    root = transaction._selected_repository_root(repository_root)

    def build_inputs():
        plan = build_plan(expected_admission_sha256, repository_root=root)
        admission, _commit, _tree = read_committed_admission(expected_admission_sha256, repository_root=root)
        contract.verify_admission_inputs(input_root, admission)
        _bind_input_metadata(input_root, admission, repository_root=root, evidence_commit=plan.tag_commit)

        def stage_assets(staging: PrivateDirectoryHandle) -> None:
            for release in plan.releases:
                for asset, row in zip(release.assets, admission["assets"][release.domain], strict=True):
                    snapshot = read_regular_snapshot(input_root / row["file"]["path"],
                        maximum=contract.MAX_ASSET_BYTES, label=f"SDK selected asset {asset.name}")
                    manifest.require((snapshot.size, snapshot.sha256) == (asset.size, asset.sha256),
                                     "SDK asset bytes changed after qualification")
                    transaction._stage_bytes(staging, asset.staging_leaf, snapshot.data,
                        expected_sha256=asset.sha256, allow_existing=True, label=f"SDK asset {asset.name}")

        return plan, stage_assets

    _ensure_account_lock(repository_root=root)
    return transaction.prepare_transaction(expected_admission_sha256, profile=contract.PROFILE,
        build_inputs=build_inputs, repository_root=root)


def _release_policy(plan, release, remote) -> github.ReleasePolicy:
    url = "https://github.com/" + transaction.REPOSITORY
    return github.ReleasePolicy(repository=transaction.REPOSITORY, repository_url=url,
        release_url=f"{url}/releases/tag/{release.tag}", download_prefix=f"{url}/releases/download/",
        api_asset_prefix=f"https://api.github.com/repos/{transaction.REPOSITORY}/releases/assets/",
        tag_subject_uri=f"pkg:github/{transaction.REPOSITORY}@{release.tag}",
        tag=release.tag, tag_commit=plan.tag_commit, tag_object=release.tag_object,
        asset_names=tuple(asset.name for asset in release.assets), expected_prerelease=False,
        expected_release_id=remote.release_id,
        expected_sha256={asset.name: asset.sha256 for asset in release.assets},
        expected_content_types={asset.name: asset.content_type for asset in release.assets},
        require_asset_order=False)


def verify_published_assets(*, verification_root: Path, repository_root: Path | None = None,
                            source_environment=None) -> tuple[dict, Path]:
    """Verify both immutable attestations and freshly download every asset.

    A failed observation retains its unique directory without a completion
    receipt. No publisher action is performed here; all network calls are reads.
    """
    root = transaction._selected_repository_root(repository_root)
    safe = normalize_safe_root(verification_root, label="SDK publication verification")
    state = transaction.expected_state_root(contract.PROFILE)
    environment = github.github_cli_environment(os.environ if source_environment is None else source_environment)
    tool = github.select_github_cli(profile="sdk-020")
    deadline = time.monotonic() + 3600

    def remaining():
        seconds = deadline - time.monotonic()
        manifest.require(seconds > 0, "SDK public verification deadline exhausted")
        return min(300, max(1, math.ceil(seconds)))

    with transaction.publication_lock(state, allow_create=False, repository_root=root) as lock:
        plan = transaction._load_prepared_plan(state)
        manifest.require(isinstance(plan, transaction.SdkPublicationPlan), "SDK verification selected a legacy plan")
        transaction.verify_local_plan(state, plan, repository_root=root)
        handle = PrivateDirectoryHandle(path=state, descriptor=lock.primary.root_descriptor,
            parent_descriptor=-1, name=state.name, device=lock.primary.root_device,
            inode=lock.primary.root_inode, mode=0o700)
        with transaction._open_journal(handle) as journal:
            cursor = transaction.load_journal(journal, plan, recover_residues=False)
            before = transaction.observe_remote_transaction(plan, source_environment=source_environment)
            observed = transaction._ensure_cursor_matches_remote(plan, cursor, before)
            manifest.require(cursor.trailing_intent is None and cursor.applied_count == plan.action_count
                             and observed.index == plan.action_count, "SDK publication is not complete")
        with create_private_direct_child_handle(safe_root=safe,
                direct_child_name="observation." + secrets.token_hex(16),
                label="SDK fresh public verification") as output:
            releases = []
            leaves = set()
            for release, remote in zip(plan.releases, before.releases.releases, strict=True):
                manifest.require(remote is not None and remote.immutable and not remote.draft,
                                 "SDK release is not immutable and public")
                raw = github.capture_github_cli(tool, ["release", "verify", release.tag, "--repo",
                    transaction.REPOSITORY, "--format", "json"], timeout_seconds=remaining(),
                    maximum_bytes=4 * 1024 * 1024, environment=environment, label="SDK release attestation")
                attestation = github.parse_release_verification(raw,
                    policy=_release_policy(plan, release, remote), release_id=remote.release_id,
                    published_at=remote.published_at, label="SDK release attestation")
                raw_leaf = release.domain + "--release-verification.json"
                write_private_bytes_noreplace_at(output.descriptor, raw_leaf, raw,
                    maximum=4 * 1024 * 1024, label="SDK raw release verification")
                leaves.add(raw_leaf)
                downloads = []
                for asset in release.assets:
                    leaf = asset.staging_leaf
                    github.write_github_cli_stdout_at(tool, ["release", "download", release.tag,
                        "--repo", transaction.REPOSITORY, "--pattern", asset.name, "--output", "-"],
                        output_directory_fd=output.descriptor, output_name=leaf,
                        timeout_seconds=remaining(), maximum_bytes=asset.size,
                        environment=environment, label=f"SDK fresh download {asset.name}")
                    found = consume_regular_snapshot_at(output.descriptor, leaf,
                        display_path=output.path / leaf, maximum=asset.size, label="SDK public asset")
                    manifest.require((found.size, found.sha256) == (asset.size, asset.sha256),
                                     "fresh public asset differs from the admitted bytes")
                    leaves.add(leaf)
                    downloads.append({"name": asset.name, "file": leaf, "bytes": found.size, "sha256": found.sha256})
                releases.append({"tag": release.tag, "release_id": remote.release_id,
                    "published_at": remote.published_at, "attestation": attestation.projection(include_verified_at=True),
                    "raw_verification": {"path": raw_leaf, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()},
                    "assets": downloads})
            after = transaction.observe_remote_transaction(plan, source_environment=source_environment)
            manifest.require(before == after, "SDK release authority changed during fresh public verification")
            transaction.verify_local_plan(state, plan, repository_root=root)
            transaction._verify_publication_lock(lock)
            verify_private_directory_handle_identity(output, label="SDK public verification directory")
            verify_exact_directory_inventory_at(output.descriptor, frozenset(leaves), label="SDK fresh downloads")
            for release in releases:
                retained = [{"file": release["raw_verification"]["path"],
                             "bytes": release["raw_verification"]["bytes"],
                             "sha256": release["raw_verification"]["sha256"]}, *release["assets"]]
                for item in retained:
                    found = consume_regular_snapshot_at(output.descriptor, item["file"],
                        display_path=output.path / item["file"], maximum=item["bytes"],
                        label="SDK retained public verification input")
                    manifest.require((found.size, found.sha256) == (item["bytes"], item["sha256"]),
                                     "retained public verification input changed before completion")
            receipt = {"schema_version": 1, "kind": "qperiapt.sdk_github_publication_verification",
                "completed": True, "plan_sha256": plan.sha256(), "admission_sha256": plan.admission_sha256,
                "source": {"commit": plan.source_commit, "tree": plan.source_tree},
                "tag_commit": plan.tag_commit, "tag_tree": plan.tag_tree,
                "cli_sha256": tool.sha256, "releases": releases,
                "remote_observation_sha256": hashlib.sha256(before.canonical()).hexdigest(),
                "scope": "Immutable release signatures and exact fresh download bytes; consumer qualification remains separately bound."}
            write_private_json_noreplace_at(output.descriptor, "PUBLICATION_VERIFICATION.json", receipt,
                maximum=contract.MAX_ADMISSION_BYTES, label="SDK completed public verification")
            return receipt, output.path


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("prepare", "status", "publish", "verify"))
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--admission-sha256")
    parser.add_argument("--input-root", type=Path)
    parser.add_argument("--verification-root", type=Path)
    parser.add_argument("--plan-sha256")
    parser.add_argument("--execute-real-github-mutation", action="store_true")
    parser.add_argument("--draft-barrier-ack")
    parser.add_argument("--publication-order-ack")
    args = parser.parse_args(argv)
    root = args.repository_root
    state = transaction.expected_state_root(contract.PROFILE)
    if args.operation == "prepare":
        parser_required = args.admission_sha256 is not None and args.input_root is not None
        if not parser_required:
            parser.error("prepare requires --admission-sha256 and --input-root")
        plan = prepare(args.admission_sha256, input_root=args.input_root, repository_root=root)
        print(json.dumps({"plan_sha256": plan.sha256(), "admission_sha256": plan.admission_sha256,
                          "actions": plan.action_count, "publication_performed": False}, sort_keys=True))
    elif args.operation == "publish":
        status = transaction.publish_plan(execute_real_github_mutation=args.execute_real_github_mutation,
            expected_plan_sha256=args.plan_sha256, expected_admission_sha256=args.admission_sha256,
            draft_barrier_ack=args.draft_barrier_ack, publication_order_ack=args.publication_order_ack,
            state_root=state, profile=contract.PROFILE, repository_root=root)
        transaction._emit_status("sdk_github_publication", status)
    elif args.operation == "verify":
        if args.verification_root is None:
            parser.error("verify requires --verification-root")
        receipt, path = verify_published_assets(verification_root=args.verification_root, repository_root=root)
        print(json.dumps({"receipt": str(path / "PUBLICATION_VERIFICATION.json"),
                          "plan_sha256": receipt["plan_sha256"], "completed": True}, sort_keys=True))
    else:
        transaction._emit_status("sdk_github_publication", transaction.status_plan(state_root=state, repository_root=root))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
