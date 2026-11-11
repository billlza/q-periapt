from __future__ import annotations

import contextlib
import copy
import io
import json
import os
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
                    "version": "0.1.5",
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

    def union_metadata(self) -> dict[str, dict]:
        """Non-nested production closures: no one ABI can represent the AAR."""
        targets = ("aarch64-linux-android", "x86_64-linux-android",
                   "armv7-linux-androideabi", "i686-linux-android")
        extra_packages = []
        lock = [f'version = 4\n[[package]]\nname = "dep"\nversion = "1.2.3"\n'
                f'source = "{self.source}"\nchecksum = "{self.checksum}"\n']
        for name, version, digest in (("cpufeatures", "0.2.17", "b"),
                                      ("x86-only", "2.0.0", "c"),
                                      ("dev-only", "1.0.0", "d")):
            directory = self.dependency_root.parent / f"{name}-{version}"
            directory.mkdir()
            (directory / "Cargo.toml").write_text(
                f'[package]\nname = "{name}"\nversion = "{version}"\n', encoding="utf-8")
            (directory / "LICENSE").write_text(f"Synthetic {name} license\n", encoding="utf-8")
            extra_packages.append({"id": name, "name": name, "version": version,
                "source": self.source, "license": "MIT", "license_file": None,
                "manifest_path": str(directory / "Cargo.toml")})
            lock.append(f'[[package]]\nname = "{name}"\nversion = "{version}"\n'
                        f'source = "{self.source}"\nchecksum = "{digest * 64}"\n')
        (self.root / "Cargo.lock").write_text("".join(lock), encoding="utf-8")
        result = {}
        for target in targets:
            metadata = self.metadata()
            metadata["packages"].extend(copy.deepcopy(extra_packages))
            nodes = metadata["resolve"]["nodes"]
            nodes.extend({"id": item["id"], "deps": []} for item in extra_packages)
            nodes[0]["deps"].append({"pkg": "dev-only", "dep_kinds": [{"kind": "dev", "target": None}]})
            selected = {"aarch64-linux-android": "cpufeatures", "x86_64-linux-android": "x86-only"}.get(target)
            if selected:
                nodes[0]["deps"].append({"pkg": selected, "dep_kinds": [{"kind": None, "target": None}]})
            result[target] = metadata
        return result

    def test_multi_target_generation_ships_exact_union_and_retains_each_closure(self) -> None:
        metadata = self.union_metadata()
        inventory = third_party_licenses.collect_union(self.root, self.package_root,
            tuple(metadata), resolved_metadata=metadata)
        self.assertEqual(inventory["schema_version"], 2)
        self.assertEqual(inventory["targets"], sorted(metadata))
        self.assertEqual([p["name"] for p in inventory["packages"]], ["cpufeatures", "dep", "x86-only"])
        for target, names in (("aarch64-linux-android", ["cpufeatures", "dep"]),
                              ("x86_64-linux-android", ["dep", "x86-only"]),
                              ("armv7-linux-androideabi", ["dep"]),
                              ("i686-linux-android", ["dep"])):
            self.assertEqual([item[0] for item in inventory["target_packages"][target]], names)
        self.assertEqual((self.package_root / "THIRD_PARTY/rust/cpufeatures-0.2.17/LICENSE").read_bytes(),
                         b"Synthetic cpufeatures license\n")
        self.assertEqual(len(list((self.package_root / "THIRD_PARTY/rust").rglob("LICENSE*"))), 3)
        self.assertEqual(inventory, third_party_licenses.verify(self.package_root, expected_targets=tuple(metadata)))

    def test_multi_target_cli_is_order_independent_and_resolves_every_target(self) -> None:
        metadata = self.union_metadata()
        first = None
        for index, targets in enumerate((tuple(metadata), tuple(reversed(metadata)))):
            destination = self.package_root / str(index)
            destination.mkdir()
            arguments = [argument for target in targets for argument in ("--target", target)]
            with mock.patch.object(third_party_licenses, "_cargo_metadata",
                    side_effect=lambda root, target: metadata[target]) as cargo, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(third_party_licenses.main(["create", "--root", str(self.root),
                    "--package-root", str(destination), *arguments]), 0)
            self.assertEqual([call.args[1] for call in cargo.call_args_list], sorted(metadata))
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(third_party_licenses.main(["verify", "--package-root", str(destination),
                    *[argument for target in targets for argument in ("--expected-target", target)]]), 0)
            current = (destination / third_party_licenses.INVENTORY_RELATIVE).read_bytes()
            if first is None:
                first = current
            else:
                self.assertEqual(current, first)

    def test_multi_target_missing_arch_specific_license_or_lock_entry_fails_before_publication(self) -> None:
        metadata = self.union_metadata()
        path = self.dependency_root.parent / "cpufeatures-0.2.17/LICENSE"
        data = path.read_bytes()
        path.unlink()
        with self.assertRaisesRegex(third_party_licenses.ThirdPartyLicenseError, "no distributable license text"):
            third_party_licenses.collect_union(self.root, self.package_root, tuple(metadata), resolved_metadata=metadata)
        self.assertFalse((self.package_root / "THIRD_PARTY").exists())
        path.write_bytes(data)
        lock = self.root / "Cargo.lock"
        lock.write_text(lock.read_text().replace('name = "cpufeatures"', 'name = "unrelated"'), encoding="utf-8")
        with self.assertRaisesRegex(third_party_licenses.ThirdPartyLicenseError, "absent from Cargo.lock"):
            third_party_licenses.collect_union(self.root, self.package_root, tuple(metadata), resolved_metadata=metadata)
        self.assertFalse((self.package_root / "THIRD_PARTY").exists())

    def test_multi_target_conflicting_shared_license_evidence_fails_closed(self) -> None:
        metadata = self.union_metadata()
        metadata["x86_64-linux-android"]["packages"][1]["license"] = "BSD-3-Clause"
        with self.assertRaisesRegex(third_party_licenses.ThirdPartyLicenseError, "differs between targets"):
            third_party_licenses.collect_union(self.root, self.package_root, tuple(metadata), resolved_metadata=metadata)
        self.assertFalse((self.package_root / "THIRD_PARTY").exists())

    def test_multi_target_verifier_rejects_omitted_target_and_arch_specific_package(self) -> None:
        metadata = self.union_metadata()
        inventory = third_party_licenses.collect_union(self.root, self.package_root,
            tuple(metadata), resolved_metadata=metadata)
        path = self.package_root / third_party_licenses.INVENTORY_RELATIVE
        for mutation, message in (("target", "target set differs"),
                                  ("closure", "target closure set differs"),
                                  ("package", "missing from union"),
                                  ("duplicate", "duplicate or unsorted"),
                                  ("unselected", "unselected package")):
            changed = copy.deepcopy(inventory)
            if mutation == "target":
                changed["targets"].remove("aarch64-linux-android")
            elif mutation == "closure":
                del changed["target_packages"]["aarch64-linux-android"]
            elif mutation == "package":
                changed["packages"] = [item for item in changed["packages"] if item["name"] != "cpufeatures"]
            elif mutation == "duplicate":
                rows = changed["target_packages"]["aarch64-linux-android"]
                rows.insert(0, rows[0])
            else:
                changed["target_packages"]["aarch64-linux-android"] = [
                    row for row in changed["target_packages"]["aarch64-linux-android"] if row[0] != "cpufeatures"]
            path.write_bytes(third_party_licenses.canonical_json(changed))
            with self.subTest(mutation=mutation), self.assertRaisesRegex(third_party_licenses.ThirdPartyLicenseError, message):
                third_party_licenses.verify(self.package_root, expected_targets=tuple(metadata))
        path.write_bytes(third_party_licenses.canonical_json(inventory))
        (self.package_root / "THIRD_PARTY/rust/cpufeatures-0.2.17/LICENSE").write_bytes(b"changed\n")
        with self.assertRaisesRegex(third_party_licenses.ThirdPartyLicenseError, "bytes differ"):
            third_party_licenses.verify(self.package_root, expected_targets=tuple(metadata))

    def test_multi_target_union_limits_apply_after_deduplicating_shared_packages(self) -> None:
        metadata = self.union_metadata()
        with mock.patch.object(third_party_licenses, "MAX_LICENSE_FILES", 2), \
                self.assertRaisesRegex(third_party_licenses.ThirdPartyLicenseError, "package count exceeds limit"):
            third_party_licenses.collect_union(self.root, self.package_root, tuple(metadata), resolved_metadata=metadata)
        self.assertFalse((self.package_root / "THIRD_PARTY").exists())

        common = len((self.dependency_root / "LICENSE-MIT").read_bytes())
        arm = len((self.dependency_root.parent / "cpufeatures-0.2.17/LICENSE").read_bytes())
        x86 = len((self.dependency_root.parent / "x86-only-2.0.0/LICENSE").read_bytes())
        with mock.patch.object(third_party_licenses, "MAX_TOTAL_LICENSE_BYTES", common + max(arm, x86)), \
                self.assertRaisesRegex(third_party_licenses.ThirdPartyLicenseError, "license text total exceeds limit"):
            third_party_licenses.collect_union(self.root, self.package_root, tuple(metadata), resolved_metadata=metadata)
        self.assertFalse((self.package_root / "THIRD_PARTY").exists())

    def test_multi_target_schema_and_single_target_admission_remain_explicit(self) -> None:
        metadata = self.union_metadata()
        inventory = third_party_licenses.collect_union(self.root, self.package_root,
            tuple(metadata), resolved_metadata=metadata)
        with self.assertRaisesRegex(third_party_licenses.ThirdPartyLicenseError, "requires expected_targets"):
            third_party_licenses.verify(self.package_root, expected_target="x86_64-linux-android")
        path = self.package_root / third_party_licenses.INVENTORY_RELATIVE
        for schema in (2.0, True):
            path.write_bytes(third_party_licenses.canonical_json(dict(inventory, schema_version=schema)))
            with self.subTest(schema=schema), self.assertRaisesRegex(third_party_licenses.ThirdPartyLicenseError, "schema differs"):
                third_party_licenses.verify(self.package_root, expected_targets=tuple(metadata))

    def test_multi_target_requires_distinct_targets_and_exact_resolution_inputs(self) -> None:
        metadata = self.union_metadata()
        with self.assertRaisesRegex(third_party_licenses.ThirdPartyLicenseError, "targets are duplicate"):
            third_party_licenses.collect_union(self.root, self.package_root,
                ("aarch64-linux-android", "aarch64-linux-android"), resolved_metadata=metadata)
        with self.assertRaisesRegex(third_party_licenses.ThirdPartyLicenseError, "metadata target set differs"):
            third_party_licenses.collect_union(self.root, self.package_root,
                tuple(metadata), resolved_metadata={"aarch64-linux-android": metadata["aarch64-linux-android"]})
        self.collect()
        with self.assertRaisesRegex(third_party_licenses.ThirdPartyLicenseError, "does not cover multiple targets"):
            third_party_licenses.verify(self.package_root, expected_targets=tuple(metadata))

    def test_installed_continuity_resolution_keeps_the_exact_lock_and_licenses(self) -> None:
        metadata = self.metadata()
        metadata["packages"][0]["name"] = "q-periapt-continuity-c-consumer"
        (self.root / "Cargo.lock").write_text(
            f'version = 4\n[[package]]\nname = "dep"\nversion = "1.2.3"\n'
            f'source = "{self.source}"\nchecksum = "{self.checksum}"\n', encoding="utf-8")
        with mock.patch.object(third_party_licenses, "_cargo_metadata", side_effect=AssertionError("global Cargo used")):
            collected = third_party_licenses.collect(self.root, self.package_root, "aarch64-apple-darwin",
                root_package="q-periapt-continuity-c-consumer", resolved_metadata=metadata)
        self.assertEqual(collected["packages"][0]["checksum"], self.checksum)
        self.assertEqual(collected, third_party_licenses.verify(self.package_root,
            expected_target="aarch64-apple-darwin", root_package="q-periapt-continuity-c-consumer"))
        other = self.package_root.parent / "missing-lock"
        other.mkdir()
        lock = self.root / "Cargo.lock"
        lock.write_text(lock.read_text(encoding="utf-8").replace('name = "dep"', 'name = "other"'), encoding="utf-8")
        with self.assertRaisesRegex(third_party_licenses.ThirdPartyLicenseError, "absent from Cargo.lock"):
            third_party_licenses.collect(self.root, other, "aarch64-apple-darwin",
                root_package="q-periapt-continuity-c-consumer", resolved_metadata=metadata)

    def test_maintenance_license_root_uses_the_supplied_build_resolution(self) -> None:
        metadata = self.metadata()
        metadata["packages"][0]["name"] = "q-periapt-cli"
        (self.root / "Cargo.lock").write_text(
            f'version = 4\n[[package]]\nname = "dep"\nversion = "1.2.3"\n'
            f'source = "{self.source}"\nchecksum = "{self.checksum}"\n', encoding="utf-8")
        with mock.patch.object(third_party_licenses, "_cargo_metadata", side_effect=AssertionError("global Cargo used")):
            collected = third_party_licenses.collect(self.root, self.package_root, "aarch64-apple-darwin",
                root_package="q-periapt-cli", resolved_metadata=metadata)
        self.assertEqual(collected["root_package"], "q-periapt-cli")
        self.assertEqual(collected, third_party_licenses.verify(self.package_root,
            expected_target="aarch64-apple-darwin", root_package="q-periapt-cli"))
        with self.assertRaisesRegex(third_party_licenses.ThirdPartyLicenseError, "root package differs"):
            third_party_licenses.verify(self.package_root, expected_target="aarch64-apple-darwin")

    def test_reference_service_license_root_keeps_source_package_identity(self) -> None:
        metadata = self.metadata()
        metadata["packages"][0].update(name="q-periapt-continuity-reference-app", version="0.0.0")
        (self.root / "Cargo.lock").write_text(
            f'version = 4\n[[package]]\nname = "dep"\nversion = "1.2.3"\n'
            f'source = "{self.source}"\nchecksum = "{self.checksum}"\n', encoding="utf-8")
        collected = third_party_licenses.collect(self.root, self.package_root, "x86_64-unknown-linux-gnu",
            root_package="q-periapt-continuity-reference-app", resolved_metadata=metadata)
        self.assertEqual(collected, third_party_licenses.verify(self.package_root,
            expected_target="x86_64-unknown-linux-gnu", root_package="q-periapt-continuity-reference-app"))

    def test_explicit_notice_input_preserves_registry_identity_and_rejects_unselected_package(self) -> None:
        metadata = self.metadata()
        (self.dependency_root / "LICENSE-MIT").unlink()
        notice = self.root / "LICENSE-UPSTREAM"
        notice.write_bytes(b"Explicit synthetic upstream notice.\n")
        with mock.patch.object(third_party_licenses, "_lock_checksums",
                return_value={("dep", "1.2.3", self.source): self.checksum}):
            with self.assertRaisesRegex(third_party_licenses.ThirdPartyLicenseError, "selected production dependency"):
                third_party_licenses.collect(self.root, self.package_root, "x86_64-unknown-linux-gnu",
                    resolved_metadata=metadata, supplemental_licenses={("unselected", "1.2.3"): (notice,)})
            collected = third_party_licenses.collect(self.root, self.package_root, "x86_64-unknown-linux-gnu",
                resolved_metadata=metadata, supplemental_licenses={("dep", "1.2.3"): (notice,)})
        self.assertEqual(collected["packages"][0]["source"], self.source)
        self.assertEqual(collected["packages"][0]["checksum"], self.checksum)
        self.assertEqual(collected, third_party_licenses.verify(self.package_root, expected_target="x86_64-unknown-linux-gnu"))

    def test_dev_only_dependency_is_not_treated_as_shipped(self) -> None:
        with self.assertRaisesRegex(
            third_party_licenses.ThirdPartyLicenseError,
            "no external packages",
        ):
            self.collect(self.metadata(kind="dev"))

    def test_wasm_root_is_explicit_and_does_not_change_native_default(self) -> None:
        metadata = self.metadata()
        metadata["packages"][0]["name"] = "q-periapt-sdk-wasm"
        with (
            mock.patch.object(third_party_licenses, "_cargo_metadata", return_value=metadata),
            mock.patch.object(third_party_licenses, "_lock_checksums",
                              return_value={("dep", "1.2.3", self.source): self.checksum}),
        ):
            inventory = third_party_licenses.collect(self.root, self.package_root,
                "wasm32-unknown-unknown", root_package="q-periapt-sdk-wasm")
        self.assertEqual(inventory["root_package"], "q-periapt-sdk-wasm")
        self.assertEqual(inventory, third_party_licenses.verify(self.package_root,
            expected_target="wasm32-unknown-unknown", root_package="q-periapt-sdk-wasm"))
        with self.assertRaisesRegex(ValueError, "root package differs"):
            third_party_licenses.verify(self.package_root)
        with self.assertRaisesRegex(ValueError, "unsupported license root"):
            third_party_licenses._production_dependency_ids(metadata, "unknown")

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

    def _metadata_launcher(self, directory: pathlib.Path, name: str, selection: str) -> pathlib.Path:
        directory.mkdir(parents=True, exist_ok=True)
        if os.name == "nt":
            launcher = directory / (name + ".cmd")
            source = '@echo off\necho {"selected":"' + selection + '","program":"%~n0"}\n'
        else:
            launcher = directory / name
            source = (
                '#!/bin/sh\nprintf \'{"selected":"' + selection
                + '","program":"%s"}\\n\' "${0##*/}"\n'
            )
        launcher.write_text(source, encoding="utf-8")
        launcher.chmod(0o700)
        return launcher

    def test_cargo_metadata_keeps_relative_path_selection_across_cwd_change(self) -> None:
        caller = pathlib.Path(self.temporary.name) / "caller"
        self._metadata_launcher(caller / "bin", "cargo", "caller")
        self._metadata_launcher(self.root / "bin", "cargo", "checkout")
        with (
            contextlib.chdir(caller),
            mock.patch.dict(os.environ, {"PATH": "bin", "PATHEXT": ".CMD"}),
        ):
            observed = third_party_licenses._cargo_metadata(
                self.root, "x86_64-unknown-linux-gnu"
            )
        self.assertEqual(observed, {"selected": "caller", "program": "cargo"})

    def test_cargo_metadata_preserves_multicall_symlink_name(self) -> None:
        caller = pathlib.Path(self.temporary.name) / "caller"
        multicall = self._metadata_launcher(caller / "bin", "rustup", "caller")
        cargo = multicall.with_name("cargo" + multicall.suffix)
        cargo.symlink_to(multicall.name)
        with (
            contextlib.chdir(caller),
            mock.patch.dict(os.environ, {"PATH": "bin", "PATHEXT": ".CMD"}),
        ):
            observed = third_party_licenses._cargo_metadata(
                self.root, "x86_64-unknown-linux-gnu"
            )
        self.assertEqual(observed, {"selected": "caller", "program": "cargo"})

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
