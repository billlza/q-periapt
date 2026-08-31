#!/usr/bin/env python3
"""Derivation tests for crates_io_registry_metadata.

The golden cases rebuild a ``.crate`` from a real crate's committed normalized
``Cargo.toml`` and ``README`` and assert the derivation reproduces cargo's own
registry metadata byte-for-byte. The synthetic cases exercise every derivation
branch (dependency kinds and order, requirement normalization, optional and
default-features handling, feature tables, README presence, scalar fields, and
the refusals for unmodeled manifest constructs)."""

from __future__ import annotations

import gzip
import io
import json
import pathlib
import tarfile
import unittest

import crates_io_registry_metadata as registry

FIXTURES = pathlib.Path(__file__).resolve().parent / "testdata" / "crates_io_uploader"


def build_crate(members: dict[str, bytes], *, root: str = "pkg-0.0.0") -> bytes:
    """Pack members (path -> bytes, relative to a crate root dir) into a .crate."""

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for relative, payload in members.items():
            info = tarfile.TarInfo(f"{root}/{relative}")
            info.size = len(payload)
            info.mtime = 0
            tar.addfile(info, io.BytesIO(payload))
    return gzip.compress(buffer.getvalue(), mtime=0)


def crate_from_manifest(manifest: str, *, readme: str | None = None,
                        readme_name: str = "README.md") -> bytes:
    members = {"Cargo.toml": manifest.encode("utf-8")}
    if readme is not None:
        members[readme_name] = readme.encode("utf-8")
    return build_crate(members)


class GoldenReproductionTests(unittest.TestCase):
    """Reproduce shipped cargo metadata for real crates from committed inputs."""

    def _assert_golden(self, name: str) -> None:
        manifest = (FIXTURES / f"{name}.cargo.toml").read_bytes()
        readme = (FIXTURES / f"{name}.readme.md").read_bytes()
        expected = (FIXTURES / f"{name}.metadata.json").read_text(encoding="utf-8")
        crate = build_crate({
            "Cargo.toml": manifest,
            "README.md": readme,
        }, root=f"{name}-0.1.4")
        metadata = registry.registry_metadata(crate)
        self.assertEqual(registry.serialize_metadata(metadata), expected)

    def test_cli_golden_no_dependencies(self) -> None:
        self._assert_golden("q-periapt-cli")

    def test_wasm_golden_internal_dependencies(self) -> None:
        self._assert_golden("q-periapt-wasm")

    def test_golden_metadata_matches_strict_json(self) -> None:
        # The committed golden must itself be exactly what serialize produces
        # when re-parsed, i.e. compact and key-stable.
        for name in ("q-periapt-cli", "q-periapt-wasm"):
            text = (FIXTURES / f"{name}.metadata.json").read_text(encoding="utf-8")
            reparsed = json.loads(text)
            self.assertEqual(
                json.dumps(reparsed, separators=(",", ":"), ensure_ascii=False),
                text,
            )


class DependencyDerivationTests(unittest.TestCase):
    def _deps(self, manifest: str) -> list[dict]:
        return registry.registry_metadata(crate_from_manifest(manifest))["deps"]

    def test_dependency_table_order_and_kinds(self) -> None:
        manifest = (
            '[package]\nname = "d"\nversion = "1.0.0"\n\n'
            '[dependencies]\nserde = "1"\naaa = "2"\n\n'
            '[dev-dependencies]\nproptest = "1"\n\n'
            '[build-dependencies]\ncc = "1"\n'
        )
        deps = self._deps(manifest)
        self.assertEqual(
            [(d["name"], d["kind"]) for d in deps],
            [("serde", "normal"), ("aaa", "normal"),
             ("proptest", "dev"), ("cc", "build")],
        )

    def test_target_specific_dependencies_carry_cfg(self) -> None:
        manifest = (
            '[package]\nname = "d"\nversion = "1.0.0"\n\n'
            '[dependencies]\nbase = "1"\n\n'
            '[target."cfg(unix)".dependencies]\nnix = "0.27"\n'
        )
        deps = self._deps(manifest)
        self.assertEqual(deps[0]["target"], None)
        self.assertEqual((deps[1]["name"], deps[1]["target"], deps[1]["kind"]),
                         ("nix", 'cfg(unix)', "normal"))

    def test_requirement_normalization(self) -> None:
        manifest = (
            '[package]\nname = "d"\nversion = "1.0.0"\n\n'
            '[dependencies]\n'
            'bare = "0.6"\n'
            'exact = { version = "=1.2.3" }\n'
            'caret = { version = "^0.4.1" }\n'
        )
        reqs = {d["name"]: d["version_req"] for d in self._deps(manifest)}
        self.assertEqual(reqs, {"bare": "^0.6", "exact": "=1.2.3", "caret": "^0.4.1"})

    def test_optional_and_default_features(self) -> None:
        manifest = (
            '[package]\nname = "d"\nversion = "1.0.0"\n\n'
            '[dependencies]\n'
            'opt = { version = "1", optional = true, default-features = false, '
            'features = ["a", "b"] }\n\n'
            # opt is referenced via dep: so Cargo creates no implicit feature.
            '[features]\nuse-opt = ["dep:opt"]\n'
        )
        dep = self._deps(manifest)[0]
        self.assertEqual(
            (dep["optional"], dep["default_features"], dep["features"]),
            (True, False, ["a", "b"]),
        )
        self.assertEqual(list(dep), list(registry._DEP_FIELD_ORDER))

    def test_unreferenced_optional_dependency_is_refused(self) -> None:
        # An optional dep not referenced via dep: would need Cargo's implicit
        # feature, which this module does not reproduce -> refuse fail-closed.
        manifest = (
            '[package]\nname = "d"\nversion = "1.0.0"\n\n'
            '[dependencies]\nopt = { version = "1", optional = true }\n'
        )
        with self.assertRaisesRegex(
            registry.RegistryMetadataError, "implicit feature"
        ):
            registry.registry_metadata(crate_from_manifest(manifest))

    def test_no_dependencies_is_empty_list(self) -> None:
        manifest = '[package]\nname = "d"\nversion = "1.0.0"\n'
        self.assertEqual(self._deps(manifest), [])


class RefusalTests(unittest.TestCase):
    def _expect_refusal(self, manifest: str, pattern: str) -> None:
        with self.assertRaisesRegex(registry.RegistryMetadataError, pattern):
            registry.registry_metadata(crate_from_manifest(manifest))

    def test_renamed_dependency_is_refused(self) -> None:
        manifest = (
            '[package]\nname = "d"\nversion = "1.0.0"\n\n'
            '[dependencies]\nalias = { version = "1", package = "real" }\n'
        )
        self._expect_refusal(manifest, "renamed")

    def test_alternate_registry_is_refused(self) -> None:
        manifest = (
            '[package]\nname = "d"\nversion = "1.0.0"\n\n'
            '[dependencies]\nx = { version = "1", registry = "other" }\n'
        )
        self._expect_refusal(manifest, "alternate registry")

    def test_git_source_is_refused(self) -> None:
        manifest = (
            '[package]\nname = "d"\nversion = "1.0.0"\n\n'
            '[dependencies]\nx = { version = "1", git = "https://example/x" }\n'
        )
        self._expect_refusal(manifest, "git/path source")

    def test_path_source_is_refused(self) -> None:
        manifest = (
            '[package]\nname = "d"\nversion = "1.0.0"\n\n'
            '[dependencies]\nx = { version = "1", path = "../x" }\n'
        )
        self._expect_refusal(manifest, "git/path source")

    def test_registry_index_is_refused(self) -> None:
        manifest = (
            '[package]\nname = "d"\nversion = "1.0.0"\n\n'
            '[dependencies]\nx = { version = "1", registry-index = "https://r" }\n'
        )
        self._expect_refusal(manifest, "alternate registry")

    def test_wildcard_requirement_is_refused(self) -> None:
        manifest = (
            '[package]\nname = "d"\nversion = "1.0.0"\n\n'
            '[dependencies]\nx = "1.*"\n'
        )
        self._expect_refusal(manifest, "does not reproduce")

    def test_spaced_range_requirement_is_refused(self) -> None:
        manifest = (
            '[package]\nname = "d"\nversion = "1.0.0"\n\n'
            '[dependencies]\nx = ">= 1.2, < 1.5"\n'
        )
        self._expect_refusal(manifest, "does not")

    def test_missing_cargo_toml_member_is_refused(self) -> None:
        crate = build_crate({"NOTCARGO.toml": b"junk"})
        with self.assertRaisesRegex(registry.RegistryMetadataError, "no Cargo.toml"):
            registry.registry_metadata(crate)

    def test_invalid_toml_is_refused(self) -> None:
        self._expect_refusal("this is = = not toml\n", "not valid TOML")

    def test_non_utf8_readme_is_refused(self) -> None:
        manifest = '[package]\nname = "d"\nversion = "1.0.0"\nreadme = "README.md"\n'
        crate = build_crate({
            "Cargo.toml": manifest.encode("utf-8"),
            "README.md": b"\xff\xfe not utf-8",
        })
        with self.assertRaisesRegex(registry.RegistryMetadataError, "not valid UTF-8"):
            registry.registry_metadata(crate)

    def test_missing_requirement_is_refused(self) -> None:
        manifest = (
            '[package]\nname = "d"\nversion = "1.0.0"\n\n'
            '[dependencies]\nx = { optional = true }\n'
        )
        self._expect_refusal(manifest, "no version requirement")

    def test_missing_package_table_is_refused(self) -> None:
        self._expect_refusal('[dependencies]\nx = "1"\n', "no .package.")

    def test_missing_readme_file_is_refused(self) -> None:
        manifest = (
            '[package]\nname = "d"\nversion = "1.0.0"\nreadme = "README.md"\n'
        )
        # no README member packed
        with self.assertRaisesRegex(registry.RegistryMetadataError, "readme"):
            registry.registry_metadata(build_crate(
                {"Cargo.toml": manifest.encode("utf-8")}))


class ScalarFieldTests(unittest.TestCase):
    def test_scalars_and_readme_and_field_order(self) -> None:
        manifest = (
            '[package]\nname = "scalar-crate"\nversion = "2.3.4"\n'
            'authors = ["李子昂 <a@example.com>"]\n'
            'description = "d"\nhomepage = "https://h"\nrepository = "https://r"\n'
            'documentation = "https://d"\nkeywords = ["k1", "k2"]\n'
            'categories = ["c"]\nlicense = "MIT"\nrust-version = "1.85"\n'
            'links = "foo"\nreadme = "README.md"\n\n'
            '[badges]\n'
        )
        metadata = registry.registry_metadata(
            crate_from_manifest(manifest, readme="# Title\n"))
        self.assertEqual(tuple(metadata), registry._METADATA_FIELD_ORDER)
        self.assertEqual(metadata["name"], "scalar-crate")
        self.assertEqual(metadata["vers"], "2.3.4")
        self.assertEqual(metadata["authors"], ["李子昂 <a@example.com>"])
        self.assertEqual(metadata["readme"], "# Title\n")
        self.assertEqual(metadata["readme_file"], "README.md")
        self.assertEqual(metadata["keywords"], ["k1", "k2"])
        self.assertEqual(metadata["links"], "foo")
        self.assertEqual(metadata["rust_version"], "1.85")

    def test_absent_scalars_are_none_and_empty(self) -> None:
        manifest = '[package]\nname = "bare"\nversion = "0.1.0"\n'
        metadata = registry.registry_metadata(crate_from_manifest(manifest))
        self.assertIsNone(metadata["description"])
        self.assertIsNone(metadata["readme"])
        self.assertIsNone(metadata["readme_file"])
        self.assertIsNone(metadata["links"])
        self.assertEqual(metadata["authors"], [])
        self.assertEqual(metadata["keywords"], [])
        self.assertEqual(metadata["badges"], {})
        self.assertEqual(metadata["features"], {})

    def test_serialize_is_compact_and_utf8(self) -> None:
        manifest = (
            '[package]\nname = "u"\nversion = "0.1.0"\n'
            'authors = ["Ünïcode <u@example.com>"]\n'
        )
        text = registry.serialize_metadata(
            registry.registry_metadata(crate_from_manifest(manifest)))
        self.assertNotIn(", ", text)
        self.assertNotIn(": ", text)
        self.assertIn("Ünïcode", text)  # ensure_ascii=False


if __name__ == "__main__":
    unittest.main()
