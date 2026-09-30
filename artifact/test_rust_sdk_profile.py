"""Alpha cohort/normalized archive controls, independent of live crypto tests."""
import copy
import gzip
import io
import hashlib
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import rust_sdk_profile as sdk
import rust_sdk_msrv as msrv
from rust_publish_contract import RUST_PUBLISHABLE_CRATES


def metadata():
    packages = []
    for name in (*sdk.COHORT, *sorted(sdk.PRIVATE)):
        packages.append({"id": name, "name": name, "version": sdk.VERSION,
            "publish": [] if name in sdk.PRIVATE else ["crates-io"],
            "license": "Apache-2.0 OR MIT", "repository": "https://example.invalid/repo",
            "homepage": "https://example.invalid/repo", "readme": "README.md", "dependencies": []})
    return {"workspace_members": [p["id"] for p in packages], "packages": packages}


def archive(extra=(), *, trailing=b"", name="q-periapt-sdk", manifest=None):
    if manifest is None:
        manifest = f'[package]\nname="{name}"\nversion="{sdk.VERSION}"\n'.encode()
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as out:
        for path, content, kind in [
            ("Cargo.toml", manifest, tarfile.REGTYPE),
            ("Cargo.toml.orig", b"fixture manifest", tarfile.REGTYPE),
            ("Cargo.lock", b"version = 4\n", tarfile.REGTYPE),
            ("README.md", b"fixture README", tarfile.REGTYPE), *extra,
        ]:
            entry = tarfile.TarInfo(f"{name}-{sdk.VERSION}/{path}")
            entry.type = kind
            entry.size = len(content)
            if kind == tarfile.SYMTYPE:
                entry.linkname = "/etc/passwd"
            out.addfile(entry, io.BytesIO(content))
    return gzip.compress(stream.getvalue() + trailing)


class RustSDKProfileTests(unittest.TestCase):
    def test_exact_alpha_cohort_does_not_replace_frozen_publication_cohort(self):
        self.assertEqual(len(sdk.classify(metadata())), 18)
        self.assertEqual(len(sdk.COHORT), 12)
        self.assertEqual(len(RUST_PUBLISHABLE_CRATES), 10)
        self.assertNotIn("q-periapt-sdk", RUST_PUBLISHABLE_CRATES)
        self.assertNotIn("q-periapt-host-store", RUST_PUBLISHABLE_CRATES)

    def test_workspace_metadata_and_publication_scope_fail_closed(self):
        original = metadata()
        for key, value in (("version", "0.1.5"), ("publish", []), ("homepage", None), ("license", "unknown")):
            changed = copy.deepcopy(original)
            changed["packages"][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                sdk.classify(changed)
        changed = copy.deepcopy(original)
        changed["packages"][-1]["publish"] = None
        with self.assertRaisesRegex(ValueError, "must remain private"):
            sdk.classify(changed)
        with self.assertRaisesRegex(ValueError, "classification differs"):
            sdk.classify({"packages": original["packages"][:-1], "workspace_members": original["workspace_members"]})

    def test_optional_and_target_dependencies_also_constrain_publication_order(self):
        original = metadata()
        for dependency in (
            {"name": "q-periapt-core", "req": "^0.2.0", "kind": None},
            {"name": "q-periapt-policy-agent", "req": "=0.2.0", "kind": None},
            {"name": "q-periapt-ffi", "req": "=0.2.0", "kind": None, "optional": True},
        ):
            changed = copy.deepcopy(original)
            changed["packages"][0]["dependencies"] = [dependency]
            with self.subTest(dependency=dependency), self.assertRaises(ValueError):
                sdk.classify(changed)
        changed = copy.deepcopy(original)
        changed["packages"][0]["dependencies"] = [{"name": "q-periapt-ffi", "req": "=0.2.0", "kind": "dev"}]
        sdk.classify(changed)  # Dev cycles do not define registry upload order.

    def test_archive_closed_tree_and_integrity_boundaries(self):
        self.assertEqual(len(sdk.archive_files(archive(), "q-periapt-sdk")), 4)
        for path, content, kind in (
            ("../escape", b"x", tarfile.REGTYPE),
            ("link", b"", tarfile.SYMTYPE),
            ("README.md", b"duplicate", tarfile.REGTYPE),
            ("readme.md", b"collision", tarfile.REGTYPE),
        ):
            with self.subTest(path=path), self.assertRaises(ValueError):
                sdk.archive_files(archive([(path, content, kind)]), "q-periapt-sdk")
        with self.assertRaisesRegex(ValueError, "unparsed trailing"):
            sdk.archive_files(archive(trailing=b"unexpected"), "q-periapt-sdk")
        with self.assertRaisesRegex(ValueError, "root differs"):
            sdk.archive_files(archive(), "q-periapt-core")
        with self.assertRaisesRegex(ValueError, "source package list"):
            sdk.validate_archive(archive(), "q-periapt-sdk", {}, {"Cargo.toml"})

    def test_external_lock_identity_requires_exact_registry_and_checksums(self):
        good = ('version = 4\n[[package]]\nname = "dep"\nversion = "1.0.0"\n'
                'source = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "' + "a" * 64 + '"\n')
        self.assertEqual(len(sdk.external_lock(good.encode())), 1)
        for bad in (good.replace("registry+", "git+"), good.replace("a" * 64, "short"),
                    good + good.split("version = 4\n", 1)[1]):
            with self.assertRaisesRegex(ValueError, "identity/source/checksum"):
                sdk.external_lock(bad.encode())

    def test_zero_exit_audit_diagnostics_cannot_claim_complete_registry_checks(self):
        report = {"database": {"last-commit": "c" * 40},
            "settings": {"ignore": [], "target_arch": [], "target_os": [], "severity": None,
                         "informational_warnings": ["unmaintained", "unsound", "notice"]},
            "vulnerabilities": {"found": False, "count": 0}, "warnings": {},
            "lockfile": {"dependency-count": 1}}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); lock = root / "Cargo.lock"
            lock.write_text('version = 4\n[[package]]\nname = "fixture"\nversion = "1.0.0"\n')
            diagnostics = b"error: couldn't check if the package is yanked: not found: No such crate in crates.io index: arbitrary\n"
            def zero_exit(argv, prefix, cwd, *, environment):
                prefix.with_suffix(".stderr").write_bytes(diagnostics)
                return json.dumps(report).encode()
            with patch.object(sdk, "command", side_effect=zero_exit), \
                 patch.object(sdk, "validate_rustsec_advisory_database", return_value="c" * 40):
                with self.assertRaisesRegex(ValueError, "audit.*diagnostics"):
                    sdk.audit_lockfile(lock, root, "audit", {}, fetch=True)
                diagnostics = b""
                result = sdk.audit_lockfile(lock, root, "audit", {}, fetch=True)
                self.assertEqual(result["packages"], 1)

    def test_audit_filters_and_incomplete_lock_coverage_are_rejected(self):
        report = {"settings": {"ignore": [], "target_arch": [], "target_os": [], "severity": None,
            "informational_warnings": ["unmaintained", "unsound", "notice"]},
            "vulnerabilities": {"found": False, "count": 0}, "warnings": {}, "lockfile": {"dependency-count": 3}}
        sdk.validate_audit_report(report, 3)
        for key, value in (("ignore", ["RUSTSEC-0000-0000"]), ("target_arch", ["aarch64"]),
                           ("target_os", ["macos"]), ("severity", "high"), ("informational_warnings", [])):
            changed = copy.deepcopy(report); changed["settings"][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "filtered"):
                sdk.validate_audit_report(changed, 3)
        with self.assertRaisesRegex(ValueError, "coverage"):
            sdk.validate_audit_report(report, 4)
        changed = copy.deepcopy(report); changed["warnings"]["notice"] = ["finding"]
        with self.assertRaisesRegex(ValueError, "not clean"):
            sdk.validate_audit_report(changed, 3)

    def test_post_consumer_check_rejects_extra_and_changed_source_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary); output = folder / "output"; consumer = folder / "consumer"
            (output / "crates").mkdir(parents=True)
            records = {}
            for name in sdk.CONSUMER_CRATES:
                path = output / "crates" / f"{name}.crate"; path.write_bytes(archive(name=name))
                files = sdk.archive_files(path.read_bytes(), name)
                records[name] = {"file": path.name, "sha256": sdk.snapshot(path).sha256, "files": list(files)}
                destination = consumer / "packages" / f"{name}-{sdk.VERSION}"; destination.mkdir(parents=True)
                for relative, content in files.items(): (destination / relative).write_bytes(content)
            sdk.verify_consumed_sources(consumer, output, records)
            package = consumer / "packages" / f"{sdk.CONSUMER_CRATES[0]}-{sdk.VERSION}"
            unexpected = package / "unexpected.rs"; unexpected.write_bytes(b"new source")
            with self.assertRaisesRegex(ValueError, "source changed"):
                sdk.verify_consumed_sources(consumer, output, records)
            unexpected.unlink()
            (package / "README.md").write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "source changed"):
                sdk.verify_consumed_sources(consumer, output, records)

    def test_no_fetch_null_commit_requires_a_checked_unchanged_database(self):
        current, previous = "a" * 40, "b" * 40
        sdk.validate_audit_database_identity(current, current, None)
        sdk.validate_audit_database_identity(None, current, current)
        for reported, before in ((None, None), (None, previous), (previous, current)):
            with self.assertRaisesRegex(ValueError, "database identity"):
                sdk.validate_audit_database_identity(reported, current, before)

    def test_recorded_extraction_checks_archive_pin_inventory_and_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); output = root / "producer"
            (output / "crates").mkdir(parents=True)
            records = {}
            for name in sdk.CONSUMER_CRATES:
                path = output / "crates" / f"{name}-{sdk.VERSION}.crate"
                path.write_bytes(archive(name=name))
                records[name] = {"file": path.name, "sha256": sdk.snapshot(path).sha256,
                                 "files": list(sdk.archive_files(path.read_bytes(), name))}
            consumer = root / "accepted"; consumer.mkdir()
            (consumer / "Cargo.toml").write_text('[package]\nname="consumer"\nversion="0.0.0"\n')
            sdk.extract_recorded_crates(consumer, output, records)
            sdk.verify_consumed_sources(consumer, output, records)
            first = sdk.CONSUMER_CRATES[0]
            for index, (key, value) in enumerate((("file", "../wrong.crate"),
                                                 ("sha256", "f" * 64), ("files", ["Cargo.toml"]))):
                altered = copy.deepcopy(records); altered[first][key] = value
                with self.subTest(key=key), self.assertRaises(ValueError):
                    sdk.extract_recorded_crates(root / f"rejected-{index}", output, altered)
            wrong = output / "crates" / records[first]["file"]
            wrong.write_bytes(archive(name=first, manifest=b'[package]\nname="other"\nversion="0.2.0"\n'))
            records[first]["sha256"] = sdk.snapshot(wrong).sha256
            with self.assertRaisesRegex(ValueError, "identity differs"):
                sdk.extract_recorded_crates(root / "rejected-identity", output, records)

    def test_public_fixtures_and_policy_inputs_are_copied_without_overwriting(self):
        with tempfile.TemporaryDirectory() as temporary:
            consumer = Path(temporary) / "consumer"
            sdk.prepare_consumer_fixture(consumer)
            for name in ("client.der", "client.key.der", "server.der", "server.key.der"):
                self.assertEqual((consumer / "fixtures" / name).read_bytes(),
                                 (sdk.ROOT / sdk.FIXTURE / "fixtures" / name).read_bytes())
            for name in ("policy.toml", "revoke.toml", "enable.toml", "signature.bin", "root.bin"):
                self.assertGreater((consumer / "fixtures" / name).stat().st_size, 0)
            original = (consumer / "Cargo.toml").read_bytes()
            with self.assertRaises(FileExistsError):
                sdk.prepare_consumer_fixture(consumer)
            self.assertEqual((consumer / "Cargo.toml").read_bytes(), original)

    def test_public_consumer_requires_execution_of_every_test_without_ignores(self):
        lines = [f"test tests::{name} ... ok" for name in sorted(sdk.CONSUMER_TESTS)]
        summary = "test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.10s"
        good = "\n".join([*lines, summary])
        sdk.verify_consumer_tests(good.encode())
        for bad in ("", good.replace(lines[0], ""), good + "\n" + lines[0],
                    good.replace("0 ignored", "1 ignored"), good.replace("0 filtered out", "1 filtered out"),
                    good.replace(lines[0], lines[0].replace("... ok", "... ignored"))):
            with self.subTest(output=bad), self.assertRaisesRegex(ValueError, "all four"):
                sdk.verify_consumer_tests(bad.encode())

    def test_msrv_admission_requires_pinned_completed_current_alpha_cohort(self):
        good = {"schema_version": 1, "sources_unchanged": True, "version": sdk.VERSION,
                "profile": sdk.PROFILE, "native_abi_major": 2, "crates": dict.fromkeys(sdk.COHORT, {}),
                "source_inputs": {"rust_workspace_sha256": "a" * 64}}
        data = json.dumps(good).encode(); digest = hashlib.sha256(data).hexdigest()
        msrv.validate_report(data, digest, digest, "a" * 64)
        duplicate = data.replace(b"{", b'{"sources_unchanged":false,', 1)
        duplicate_digest = hashlib.sha256(duplicate).hexdigest()
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            msrv.validate_report(duplicate, duplicate_digest, duplicate_digest, "a" * 64)
        for expected, actual, current in (("b" * 64, digest, "a" * 64), (digest, "b" * 64, "a" * 64),
                                          (digest, digest, "b" * 64), (digest, digest, "")):
            with self.assertRaises(ValueError):
                msrv.validate_report(data, expected, actual, current)
        for key, value in (("schema_version", True), ("sources_unchanged", False), ("version", "0.1.5"),
                           ("native_abi_major", 3), ("profile", "abi2-legacy"), ("crates", {})):
            changed = copy.deepcopy(good); changed[key] = value
            data = json.dumps(changed).encode(); digest = hashlib.sha256(data).hexdigest()
            with self.subTest(key=key), self.assertRaises(ValueError):
                msrv.validate_report(data, digest, digest, "a" * 64)


if __name__ == "__main__":
    unittest.main()
