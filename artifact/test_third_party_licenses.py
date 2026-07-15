from __future__ import annotations

import json
import pathlib
import tempfile
import unittest
from unittest import mock

import third_party_licenses


class ThirdPartyLicenseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name) / "repo"
        self.package_root = pathlib.Path(self.temporary.name) / "package"
        self.root.mkdir()
        self.package_root.mkdir()
        (self.root / "Cargo.lock").write_text("version = 4\n", encoding="utf-8")
        self.dependency_root = pathlib.Path(self.temporary.name) / "registry" / "dep-1.2.3"
        self.dependency_root.mkdir(parents=True)
        (self.dependency_root / "Cargo.toml").write_text(
            '[package]\nname = "dep"\nversion = "1.2.3"\n',
            encoding="utf-8",
        )
        (self.dependency_root / "LICENSE-MIT").write_text(
            "MIT license text\n", encoding="utf-8"
        )
        self.source = "registry+https://github.com/rust-lang/crates.io-index"
        self.checksum = "a" * 64

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def metadata(self, *, kind: str | None = None) -> dict:
        return {
            "packages": [
                {
                    "id": "ffi-id",
                    "name": "q-periapt-ffi",
                    "version": "0.1.0-alpha.2",
                    "source": None,
                    "manifest_path": str(self.root / "crates/ffi/Cargo.toml"),
                },
                {
                    "id": "dep-id",
                    "name": "dep",
                    "version": "1.2.3",
                    "source": self.source,
                    "license": "MIT",
                    "license_file": None,
                    "manifest_path": str(self.dependency_root / "Cargo.toml"),
                },
            ],
            "resolve": {
                "nodes": [
                    {
                        "id": "ffi-id",
                        "deps": [
                            {
                                "pkg": "dep-id",
                                "dep_kinds": [{"kind": kind, "target": None}],
                            }
                        ],
                    },
                    {"id": "dep-id", "deps": []},
                ]
            },
        }

    def collect(self, metadata: dict | None = None) -> dict:
        with (
            mock.patch.object(
                third_party_licenses,
                "_cargo_metadata",
                return_value=metadata or self.metadata(),
            ),
            mock.patch.object(
                third_party_licenses,
                "_lock_checksums",
                return_value={("dep", "1.2.3", self.source): self.checksum},
            ),
        ):
            return third_party_licenses.collect(
                self.root,
                self.package_root,
                "x86_64-unknown-linux-gnu",
            )

    def test_collect_and_verify_exact_production_license_tree(self) -> None:
        first = self.collect()
        self.assertEqual(["dep"], [item["name"] for item in first["packages"]])
        inventory_path = (
            self.package_root / third_party_licenses.INVENTORY_RELATIVE
        )
        parsed = json.loads(inventory_path.read_text(encoding="utf-8"))
        self.assertEqual(first, parsed)
        self.assertEqual(
            "MIT license text\n",
            (
                self.package_root
                / "THIRD_PARTY/rust/dep-1.2.3/LICENSE-MIT"
            ).read_text(encoding="utf-8"),
        )
        verified = third_party_licenses.verify(
            self.package_root,
            expected_target="x86_64-unknown-linux-gnu",
        )
        self.assertEqual(first, verified)

    def test_dev_only_dependency_is_not_treated_as_shipped(self) -> None:
        with self.assertRaisesRegex(
            third_party_licenses.ThirdPartyLicenseError,
            "no external packages",
        ):
            self.collect(self.metadata(kind="dev"))

    def test_missing_or_escaping_license_fails_closed(self) -> None:
        (self.dependency_root / "LICENSE-MIT").unlink()
        with self.assertRaisesRegex(
            third_party_licenses.ThirdPartyLicenseError,
            "no distributable license text",
        ):
            self.collect()

        outside = pathlib.Path(self.temporary.name) / "outside-license"
        outside.write_text("outside\n", encoding="utf-8")
        metadata = self.metadata()
        metadata["packages"][1]["license_file"] = str(outside)
        with self.assertRaisesRegex(
            third_party_licenses.ThirdPartyLicenseError,
            "escapes package root",
        ):
            self.collect(metadata)

    def test_tampering_extra_files_and_symlinks_fail_closed(self) -> None:
        self.collect()
        license_path = self.package_root / "THIRD_PARTY/rust/dep-1.2.3/LICENSE-MIT"
        license_path.write_text("changed\n", encoding="utf-8")
        with self.assertRaisesRegex(
            third_party_licenses.ThirdPartyLicenseError,
            "bytes differ",
        ):
            third_party_licenses.verify(self.package_root)

        license_path.write_text("MIT license text\n", encoding="utf-8")
        extra = self.package_root / "THIRD_PARTY/rust/extra"
        extra.write_text("extra\n", encoding="utf-8")
        with self.assertRaisesRegex(
            third_party_licenses.ThirdPartyLicenseError,
            "file set differs",
        ):
            third_party_licenses.verify(self.package_root)

        extra.unlink()
        link = self.package_root / "THIRD_PARTY/rust/link"
        try:
            link.symlink_to(license_path)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        with self.assertRaisesRegex(
            third_party_licenses.ThirdPartyLicenseError,
            "contains symlink",
        ):
            third_party_licenses.verify(self.package_root)

    def test_inventory_target_and_canonical_bytes_are_enforced(self) -> None:
        self.collect()
        with self.assertRaisesRegex(
            third_party_licenses.ThirdPartyLicenseError,
            "target differs",
        ):
            third_party_licenses.verify(
                self.package_root,
                expected_target="aarch64-unknown-linux-gnu",
            )

        inventory_path = self.package_root / third_party_licenses.INVENTORY_RELATIVE
        document = json.loads(inventory_path.read_text(encoding="utf-8"))
        inventory_path.write_text(json.dumps(document), encoding="utf-8")
        with self.assertRaisesRegex(
            third_party_licenses.ThirdPartyLicenseError,
            "not canonical JSON",
        ):
            third_party_licenses.verify(self.package_root)

    def test_cargo_metadata_rejects_duplicate_keys_and_non_finite_numbers(self) -> None:
        malformed_documents = (
            (
                b'{"packages":[],"packages":[],"resolve":{"nodes":[]}}',
                "duplicate JSON key",
            ),
            (
                b'{"packages":[],"resolve":{"nodes":[]},"value":NaN}',
                "non-finite JSON number",
            ),
        )
        for stdout, message in malformed_documents:
            with (
                self.subTest(message=message),
                mock.patch.object(
                    third_party_licenses.shutil,
                    "which",
                    return_value="/usr/bin/cargo",
                ),
                mock.patch.object(
                    third_party_licenses.subprocess,
                    "run",
                    return_value=mock.Mock(stdout=stdout, stderr=b""),
                ),
                self.assertRaisesRegex(
                    third_party_licenses.ThirdPartyLicenseError,
                    message,
                ),
            ):
                third_party_licenses._cargo_metadata(
                    self.root,
                    "x86_64-unknown-linux-gnu",
                )

    def test_cargo_metadata_failure_never_discloses_stderr_or_credentials(self) -> None:
        private_registry = (
            b"failed to fetch https://private-user:private-password@registry.example/"
            b"index?token=secret-token"
        )
        failure = third_party_licenses.subprocess.CalledProcessError(
            101,
            ["cargo", "metadata"],
            stderr=private_registry,
        )
        with (
            mock.patch.object(
                third_party_licenses.shutil,
                "which",
                return_value="/usr/bin/cargo",
            ),
            mock.patch.object(
                third_party_licenses.subprocess,
                "run",
                side_effect=failure,
            ) as run,
            self.assertRaises(third_party_licenses.ThirdPartyLicenseError) as raised,
        ):
            third_party_licenses._cargo_metadata(
                self.root,
                "x86_64-unknown-linux-gnu",
            )
        self.assertEqual(
            "cargo metadata failed with exit code 101",
            str(raised.exception),
        )
        self.assertNotIn("private-password", str(raised.exception))
        self.assertNotIn("secret-token", str(raised.exception))
        self.assertIs(run.call_args.kwargs["stderr"], third_party_licenses.subprocess.DEVNULL)

        with (
            mock.patch.object(
                third_party_licenses.shutil,
                "which",
                return_value="/usr/bin/cargo",
            ),
            mock.patch.object(
                third_party_licenses.subprocess,
                "run",
                side_effect=OSError("/private/registry/credential-path"),
            ),
            self.assertRaisesRegex(
                third_party_licenses.ThirdPartyLicenseError,
                "^cannot execute cargo metadata$",
            ),
        ):
            third_party_licenses._cargo_metadata(
                self.root,
                "x86_64-unknown-linux-gnu",
            )

    def test_collect_and_verify_enforce_total_license_file_count(self) -> None:
        self.assertEqual(third_party_licenses.MAX_LICENSE_FILES, 1024)
        (self.dependency_root / "NOTICE").write_text(
            "dependency notice\n",
            encoding="utf-8",
        )
        with (
            mock.patch.object(third_party_licenses, "MAX_LICENSE_FILES", 1),
            self.assertRaisesRegex(
                third_party_licenses.ThirdPartyLicenseError,
                "license file count exceeds limit",
            ),
        ):
            self.collect()

        self.collect()
        with (
            mock.patch.object(third_party_licenses, "MAX_LICENSE_FILES", 1),
            self.assertRaisesRegex(
                third_party_licenses.ThirdPartyLicenseError,
                "license file count exceeds limit",
            ),
        ):
            third_party_licenses.verify(self.package_root)

    def test_collect_and_verify_enforce_total_license_bytes(self) -> None:
        self.assertEqual(
            third_party_licenses.MAX_TOTAL_LICENSE_BYTES,
            64 * 1024 * 1024,
        )
        maximum = len(b"MIT license text\n") - 1
        with (
            mock.patch.object(
                third_party_licenses,
                "MAX_TOTAL_LICENSE_BYTES",
                maximum,
            ),
            self.assertRaisesRegex(
                third_party_licenses.ThirdPartyLicenseError,
                "license text total exceeds limit",
            ),
        ):
            self.collect()

        self.collect()
        with (
            mock.patch.object(
                third_party_licenses,
                "MAX_TOTAL_LICENSE_BYTES",
                maximum,
            ),
            self.assertRaisesRegex(
                third_party_licenses.ThirdPartyLicenseError,
                "license text total exceeds limit",
            ),
        ):
            third_party_licenses.verify(self.package_root)


if __name__ == "__main__":
    unittest.main()
