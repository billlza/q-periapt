"""Bind formal archive identities to real manifests, consumers and lock graphs."""
from __future__ import annotations

import copy
import gzip
import io
from pathlib import Path
import re
import tarfile
import tomllib
import unittest

import continuity_apple_package as apple
import continuity_c_abi as c_abi
import continuity_kotlin_consumer as kotlin
import continuity_package as package
import rust_sdk_profile as sdk

ROOT = Path(__file__).resolve().parents[1]
ALIAS = "q-periapt-continuity-identity-candidate"
DEPENDENTS = (
    "crates/q-periapt-sdk-wasm/Cargo.toml",
    "bindings/c/ContinuityPackageConsumer/Cargo.toml",
    "bindings/rust/ContinuityPackageConsumer/Cargo.toml",
    "research/continuity-reference-app/Cargo.toml",
    "research/continuity-openssl-peer/native/Cargo.toml",
)
LOCKS = ("Cargo.lock", "research/continuity-identity-candidate/Cargo.lock",
         "research/continuity-reference-app/Cargo.lock",
         "research/continuity-openssl-peer/native/Cargo.lock")


def read_toml(path):
    return tomllib.loads(path.read_text())


def crate(files):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in sorted(files.items()):
            row = tarfile.TarInfo(f"{package.NAME}-{package.VERSION}/{name}")
            row.size = len(data)
            archive.addfile(row, io.BytesIO(data))
    return gzip.compress(stream.getvalue())


class ContinuityPackageIdentityTests(unittest.TestCase):
    def test_formal_source_archive_keeps_the_existing_library_and_registry_boundary(self):
        manifest = read_toml(package.CANDIDATE / "Cargo.toml")
        package.validate_package_identity(manifest)
        self.assertEqual(manifest["workspace"]["members"], ["."])
        self.assertNotIn(package.NAME, sdk.COHORT)
        for change in (
            {"name": ALIAS}, {"version": "0.0.0"}, {"publish": True},
            {"metadata": {"qperiapt": {"distribution": "registry", "product-version": "0.2.0"}}},
        ):
            altered = copy.deepcopy(manifest)
            altered["package"].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                package.validate_package_identity(altered)
        for change in ({"name": "q_periapt_continuity"}, {"crate-type": ["rlib"]}):
            altered = copy.deepcopy(manifest)
            altered["lib"].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                package.validate_package_identity(altered)

    def test_every_direct_consumer_resolves_the_formal_name_with_an_exact_version(self):
        for relative in DEPENDENTS:
            manifest = read_toml(ROOT / relative)
            edges = []
            for section in (manifest, *manifest.get("target", {}).values()):
                for kind in ("dependencies", "dev-dependencies", "build-dependencies"):
                    for alias, dependency in section.get(kind, {}).items():
                        if alias == ALIAS or (isinstance(dependency, dict)
                                              and dependency.get("package") == package.NAME):
                            edges.append((alias, dependency))
            with self.subTest(consumer=relative):
                self.assertEqual(len(edges), 1)
                alias, dependency = edges[0]
                self.assertEqual(alias, ALIAS)
                self.assertEqual(dependency["package"], package.NAME)
                self.assertEqual(dependency["version"], "=" + package.VERSION)
                if "path" in dependency:
                    self.assertEqual((ROOT / relative).parent.joinpath(dependency["path"]).resolve(),
                                     package.CANDIDATE)

    def test_all_committed_engine_locks_use_one_formal_package_identity(self):
        for relative in LOCKS:
            rows = read_toml(ROOT / relative)["package"]
            with self.subTest(lock=relative):
                self.assertFalse(any(row["name"] == ALIAS for row in rows))
                engine, = [row for row in rows if row["name"] == package.NAME]
                self.assertEqual(engine["version"], package.VERSION)
                self.assertNotIn("source", engine)
                self.assertNotIn("checksum", engine)
                for row in rows:
                    for dependency in row.get("dependencies", []):
                        self.assertNotEqual(dependency.split()[0], ALIAS)
                    if row["name"] != package.NAME:
                        continue
                    for dependency in row.get("dependencies", []):
                        if dependency.startswith("q-periapt-"):
                            target, = [item for item in rows if item["name"] == dependency.split()[0]]
                            self.assertEqual(target["version"], sdk.VERSION)

    def test_normalized_archive_binds_library_metadata_and_rejects_checkout_edges(self):
        original = (package.CANDIDATE / "Cargo.toml").read_bytes()
        normalized = re.sub(rb', path = "[^"]+"', b"", original)
        names = ("Cargo.lock", "README.md", "LICENSE", "LICENSE-APACHE", "LICENSE-MIT", "tests/owned_connection.rs",
                 "tests/owned_connection/roster_renewal.rs", "tests/owned_connection/enrollment.rs",
                 "tests/owned_connection/replacement.rs")
        files = {name: (package.CANDIDATE / name).read_bytes() for name in names}
        files.update({"Cargo.toml": normalized, "Cargo.toml.orig": original})
        self.assertEqual(package.validate_candidate(crate(files), set(files)), files)
        changes = (
            normalized.replace(package.LIBRARY.encode(), b"q_periapt_continuity"),
            normalized.replace(b'publish = false', b'publish = true'),
            normalized.replace(b'cargo-source-archive', b'crates-io'),
            normalized.replace(b'q-periapt-core = { version = "=0.2.0" }',
                               b'q-periapt-core = { version = "=0.2.0", path = "../../checkout" }'),
        )
        for altered in changes:
            self.assertNotEqual(altered, normalized)
            with self.subTest(manifest=altered[:100]), self.assertRaises(ValueError):
                package.validate_candidate(crate(dict(files, **{"Cargo.toml": altered})), set(files))

    def test_documented_public_alias_and_archive_sdk_closure_match_actual_packages(self):
        document = (ROOT / "docs/continuity/SOURCE_DISTRIBUTION_0_2.md").read_text()
        blocks = re.findall(r"```toml\n(.*?)\n```", document, re.S)
        self.assertEqual(len(blocks), 2)
        dependency = tomllib.loads(blocks[0])["dependencies"]["continuity"]
        self.assertEqual(dependency["package"], package.NAME)
        self.assertEqual(dependency["version"], "=" + package.VERSION)
        self.assertEqual(dependency["path"], f"packages/{package.NAME}-{package.VERSION}")
        patches = tomllib.loads(blocks[1])["patch"]["crates-io"]
        self.assertEqual(set(patches), set(sdk.CONSUMER_CRATES))
        for name, patch in patches.items():
            self.assertEqual(patch, {"path": f"packages/{name}-{sdk.VERSION}"})

    def test_adapter_versions_keep_the_separate_owner_abi_and_existing_exports(self):
        owner = c_abi.load(ROOT / "bindings/c/ContinuityPackageConsumer")
        self.assertEqual(len(owner["functions"]), 158)
        self.assertEqual(len(owner["records"]), 70)
        self.assertEqual(len(owner["constants"]), 112)
        self.assertEqual(apple.VERSION, package.VERSION)
        self.assertEqual(apple.ARCHIVE, f"{apple.NAME}-Apple-{package.VERSION}.zip")
        contract = kotlin.maven_contract()
        self.assertEqual(contract.coordinate, "dev.qperiapt:q-periapt-continuity-kotlin:0.2.0")
        self.assertEqual(contract.manifest_extensions, (("QPeriapt-Continuity-ABI", "qpc-owner/1"),))
        producer = (ROOT / "bindings/kotlin/ContinuityPackageConsumer/build.gradle.kts").read_text()
        consumer = (ROOT / "bindings/kotlin/ContinuityPackageConsumer/consumer/build.gradle.kts").read_text()
        self.assertIn(f'version = "{contract.version}"', producer)
        self.assertIn(f'implementation("{contract.coordinate}")', consumer)


if __name__ == "__main__":
    unittest.main()
