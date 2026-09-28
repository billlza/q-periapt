"""Exact-byte SDK uploader preparation; no registry request is made."""
from __future__ import annotations

import copy
import gzip
import hashlib
import importlib.util
import io
import json
import pathlib
import sys
import tarfile
import tempfile
import unittest
from importlib.machinery import SourceFileLoader
from unittest import mock

import crates_io_uploader_build as build
import rust_sdk_profile as sdk
from evidence_io import EvidenceIOError
from publication_receipt_io import PublicationReceiptIOError
from test_crates_io_uploader_build import _write_cohort

TEMPLATE = pathlib.Path(build.__file__).with_name("crates_io_uploader_template.py.in")
SOURCE = "a" * 40


def write_candidate(root: pathlib.Path, overrides: dict | None = None) -> dict:
    crates = root / "crates"
    crates.mkdir(exist_ok=True)
    records = {}
    for name in sdk.COHORT:
        extra = (overrides or {}).get(name, "")
        manifest = (f'[package]\nname = "{name}"\nversion = "{sdk.VERSION}"\n'
                    'description = "Synthetic archive fixture"\nlicense = "MIT"\n'
                    'readme = "README.md"\n' + extra).encode()
        files = {"Cargo.toml": manifest, "Cargo.toml.orig": manifest, "Cargo.lock": b"version = 4\n",
                 "README.md": b"Synthetic fixture.\n",
                 ".cargo_vcs_info.json": json.dumps({"git": {"sha1": SOURCE}}).encode()}
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as archive:
            for relative, data in sorted(files.items()):
                member = tarfile.TarInfo(f"{name}-{sdk.VERSION}/{relative}")
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        data = gzip.compress(stream.getvalue(), mtime=0)
        leaf = f"{name}-{sdk.VERSION}.crate"
        (crates / leaf).write_bytes(data)
        records[name] = {"file": leaf, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                         "members": len(files), "files": sorted(files)}
    return {"schema_version": 1, "profile": sdk.PROFILE, "version": sdk.VERSION,
            "native_abi_major": 2, "base_commit": SOURCE, "crates": records,
            "git_dirty": False, "diagnostic_only": False, "publication_performed": False,
            "release_claim_eligible": False, "sources_unchanged": True, "cargo_home_isolated": True,
            "cargo": "cargo 1.96.1 (fixture 2026-01-01)"}


class SdkUploaderTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name).resolve()
        self.report = write_candidate(self.root)
        self.manifest = self.root / "RUST_SDK_PACKAGE.json"
        self.output = self.root / "uploader"

    def prepare(self, *, expected_digest=None, **options):
        data = (json.dumps(self.report) + "\n").encode()
        self.manifest.write_bytes(data)
        return build.build(self.manifest, TEMPLATE, self.output, crate_dir=None, cargo_version="1.96.1",
                           profile=sdk.PROFILE, input_sha256=expected_digest or hashlib.sha256(data).hexdigest(),
                           **options)

    def test_twelve_crates_load_in_real_generated_uploader(self):
        self.report = write_candidate(self.root, {
            "q-periapt-sdk": '[dependencies]\nq-periapt-core = "=0.2.0"\n',
            "q-periapt-host-store": '[dependencies]\nq-periapt-sdk = "=0.2.0"\n',
            "q-periapt-rustls": '[dependencies]\nq-periapt-sdk = "=0.2.0"\n',
            "q-periapt-ffi": '[dependencies]\nq-periapt-host-store = "=0.2.0"\nq-periapt-rustls = "=0.2.0"\n',
        })
        summary = self.prepare()
        loader = SourceFileLoader("sdk_uploader_under_test", str(self.output))
        module = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
        sys.modules[loader.name] = module
        try:
            loader.exec_module(module)
        finally:
            sys.modules.pop(loader.name, None)
        self.assertEqual(summary["crates"], 12)
        self.assertEqual(summary["dependency_count"], 5)
        self.assertEqual(module.PRODUCT_VERSION, "0.2.0")
        self.assertEqual(module.FIXED_HANDOFF_MANIFEST_SHA256, hashlib.sha256(self.manifest.read_bytes()).hexdigest())
        self.assertEqual(set(module.COHORT_CONTRACTS), set(sdk.COHORT))
        for name, contract in module.COHORT_CONTRACTS.items():
            self.assertEqual(contract.sha256, self.report["crates"][name]["sha256"])
            self.assertEqual(contract.size, self.report["crates"][name]["bytes"])
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.output.stat().st_nlink, 1)

    def test_profiles_do_not_auto_select_each_other(self):
        self.manifest.write_text(json.dumps(self.report))
        with self.assertRaisesRegex(build.UploaderBuildError, "not a rust package handoff"):
            build.build(self.manifest, TEMPLATE, self.output, crate_dir=None, cargo_version="1.96.1")
        legacy = _write_cohort(self.root)
        with self.assertRaisesRegex(build.UploaderBuildError, "SDK package report identity"):
            build.build(legacy, TEMPLATE, self.output, crate_dir=None, cargo_version="1.96.1",
                        profile=sdk.PROFILE, input_sha256=hashlib.sha256(legacy.read_bytes()).hexdigest())

    def test_report_requires_explicit_matching_digest(self):
        self.manifest.write_text(json.dumps(self.report))
        with self.assertRaisesRegex(build.UploaderBuildError, "explicitly pinned"):
            build.build(self.manifest, TEMPLATE, self.output, crate_dir=None, cargo_version="1.96.1", profile=sdk.PROFILE)
        with self.assertRaisesRegex(build.UploaderBuildError, "SHA-256 differs"):
            self.prepare(expected_digest="0" * 64)
        self.assertFalse(self.output.exists())

    def test_dirty_incomplete_mixed_identity_reports_are_rejected(self):
        original = copy.deepcopy(self.report)
        for key, value in (("git_dirty", True), ("diagnostic_only", True), ("sources_unchanged", False),
                           ("cargo_home_isolated", False), ("publication_performed", True),
                           ("release_claim_eligible", True), ("native_abi_major", 3),
                           ("schema_version", True), ("version", "0.2.0-alpha.1"),
                           ("profile", "sdk-alpha1"), ("base_commit", "not-a-commit")):
            self.report = copy.deepcopy(original)
            self.report[key] = value
            with self.subTest(key=key), self.assertRaises(build.UploaderBuildError):
                self.prepare()
        self.assertFalse(self.output.exists())

    def test_missing_and_private_crates_are_rejected(self):
        original = copy.deepcopy(self.report)
        for name in ("q-periapt-sdk", "q-periapt-host-store"):
            self.report = copy.deepcopy(original)
            del self.report["crates"][name]
            with self.subTest(name=name), self.assertRaisesRegex(build.UploaderBuildError, "cohort differs"):
                self.prepare()
        self.report = copy.deepcopy(original)
        self.report["crates"]["q-periapt-policy-agent"] = self.report["crates"]["q-periapt-sdk"]
        with self.assertRaisesRegex(build.UploaderBuildError, "cohort differs"):
            self.prepare()

    def test_dependency_pins_and_production_order_are_enforced(self):
        for table in ("dependencies", "build-dependencies", 'target.\'cfg(unix)\'.dependencies'):
            self.report = write_candidate(self.root, {"q-periapt-core":
                f'[{table}]\nq-periapt-sdk = {{ version = "=0.2.0", optional = true }}\n'
                '[features]\nextra = ["dep:q-periapt-sdk"]\n'})
            with self.subTest(table=table), self.assertRaisesRegex(build.UploaderBuildError, "not earlier"):
                self.prepare()
        for dependency, version in (("q-periapt-core", "^0.2.0"), ("q-periapt-core", "=0.1.5"),
                                    ("q-periapt-policy-agent", "=0.2.0")):
            self.report = write_candidate(self.root, {"q-periapt-sdk":
                f'[dev-dependencies]\n{dependency} = "{version}"\n'})
            with self.subTest(dependency=dependency, version=version), self.assertRaisesRegex(build.UploaderBuildError, "internal dependency"):
                self.prepare()

    def test_dev_dependency_does_not_invert_publication_order(self):
        self.report = write_candidate(self.root, {"q-periapt-core": '[dev-dependencies]\nq-periapt-sdk = "=0.2.0"\n'})
        self.assertEqual(self.prepare()["dependency_count"], 1)

    def test_archive_inventory_source_and_cargo_are_bound(self):
        original = copy.deepcopy(self.report)
        for mutate in (
            lambda report: report["crates"]["q-periapt-sdk"].update(members=0),
            lambda report: report["crates"]["q-periapt-sdk"].update(files=["Cargo.toml"]),
            lambda report: report.update(base_commit="b" * 40),
            lambda report: report.update(cargo="cargo 1.85.0 (fixture 2026-01-01)"),
        ):
            self.report = copy.deepcopy(original)
            mutate(self.report)
            with self.assertRaises(build.UploaderBuildError):
                self.prepare()
        self.assertFalse(self.output.exists())

    def test_archive_bytes_and_regular_file_identity_are_required(self):
        path = self.root / "crates" / self.report["crates"]["q-periapt-sdk"]["file"]
        original = path.read_bytes()
        path.write_bytes(original + b"changed")
        with self.assertRaisesRegex(build.UploaderBuildError, "differ from the handoff"):
            self.prepare()
        path.unlink()
        target = self.root / "linked.crate"
        target.write_bytes(original)
        path.symlink_to(target)
        with self.assertRaises(EvidenceIOError):
            self.prepare()
        self.assertFalse(self.output.exists())

    def test_duplicate_legacy_entries_are_not_silently_collapsed(self):
        legacy = _write_cohort(self.root)
        document = json.loads(legacy.read_text())
        document["crates"].append(copy.deepcopy(document["crates"][0]))
        with self.assertRaisesRegex(build.UploaderBuildError, "duplicate crate"):
            build.build_contracts(document, self.root)

    def test_moving_input_is_rejected_before_output_is_exposed(self):
        real = build.evidence_io.read_regular_snapshot
        mutated = False
        def snapshot(path, **kwargs):
            nonlocal mutated
            if path == TEMPLATE and not mutated:
                record = self.report["crates"]["q-periapt-sdk"]
                (self.root / "crates" / record["file"]).write_bytes(b"changed after metadata reconstruction")
                mutated = True
            return real(path, **kwargs)
        with mock.patch.object(build.evidence_io, "read_regular_snapshot", side_effect=snapshot):
            with self.assertRaisesRegex(build.UploaderBuildError, "archive changed"):
                self.prepare()
        self.assertFalse(self.output.exists())

    def test_existing_output_and_unrelated_staging_file_are_preserved(self):
        self.output.write_bytes(b"existing release input")
        staging = self.output.with_name(self.output.name + ".materializing")
        staging.write_bytes(b"another process owns this")
        with self.assertRaises(PublicationReceiptIOError):
            self.prepare()
        self.assertEqual(self.output.read_bytes(), b"existing release input")
        self.assertEqual(staging.read_bytes(), b"another process owns this")
        self.assertEqual(list(self.root.glob(".uploader.*")), [])

    def test_output_directory_must_be_private_and_not_a_symlink(self):
        self.root.chmod(0o755)
        with self.assertRaises(PublicationReceiptIOError):
            self.prepare()
        self.assertFalse(self.output.exists())
        self.root.chmod(0o700)
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        self.output = alias / "uploader"
        with self.assertRaises(PublicationReceiptIOError):
            self.prepare()
        self.assertFalse((self.root / "uploader").exists())

    def test_directory_replacement_cannot_redirect_output_after_admission(self):
        admitted = self.root / "output"
        admitted.mkdir(mode=0o700)
        displaced = self.root / "displaced-output"
        self.output = admitted / "uploader"
        real = build.write_private_bytes_noreplace_at
        def replace_directory(directory, leaf, payload, **kwargs):
            admitted.rename(displaced)
            admitted.mkdir(mode=0o700)
            return real(directory, leaf, payload, **kwargs)
        with mock.patch.object(build, "write_private_bytes_noreplace_at", side_effect=replace_directory):
            with self.assertRaisesRegex(build.UploaderBuildError, "directory changed"):
                self.prepare()
        self.assertFalse(self.output.exists())
        self.assertTrue((displaced / "uploader").is_file())

    def test_replaced_bytes_are_not_given_executable_permission(self):
        real = build.write_private_bytes_noreplace_at
        def change_bytes(directory, leaf, payload, **kwargs):
            digest = real(directory, leaf, payload, **kwargs)
            self.output.write_bytes(b"different file contents")
            return digest
        with mock.patch.object(build, "write_private_bytes_noreplace_at", side_effect=change_bytes):
            with self.assertRaisesRegex(build.UploaderBuildError, "before executable mode"):
                self.prepare()
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
