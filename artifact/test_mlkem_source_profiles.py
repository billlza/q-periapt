#!/usr/bin/env python3
"""Separate historical TCB identity from the opt-in SDK 0.2.0 source candidate."""

from __future__ import annotations

import json
import pathlib
import tomllib
import unittest

from rust_publish_contract import (
    RustPublishContractError,
    validate_mlkem_native_manifest_features,
    validate_packaged_mlkem_native_source_contract,
)

ROOT = pathlib.Path(__file__).resolve().parent.parent
SYS_CRATE = ROOT / "crates/q-periapt-mlkem-native-sys"
SDK_VERSION = "0.2.0"


class MlKemSourceProfilesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.current = {"build.rs": (SYS_CRATE / "build.rs").read_bytes()}
        cls.current.update({
            path.relative_to(SYS_CRATE).as_posix(): path.read_bytes()
            for path in (SYS_CRATE / "src").rglob("*") if path.is_file()
        })
        fixture = json.loads(
            (ROOT / "artifact/fixtures/mlkem-native-sys-v0.1.5-sources.json")
            .read_text(encoding="utf-8")
        )
        cls.legacy = {
            name: source.encode("utf-8") for name, source in fixture["files"].items()
        }

    def test_each_source_version_accepts_only_its_own_complete_bytes(self) -> None:
        for version, sources in (("0.1.5", self.legacy), (SDK_VERSION, self.current)):
            with self.subTest(version=version):
                validate_packaged_mlkem_native_source_contract(
                    sources, package_version=version,
                )
                other = self.current if version == "0.1.5" else self.legacy
                with self.assertRaises(RustPublishContractError):
                    validate_packaged_mlkem_native_source_contract(
                        other, package_version=version,
                    )

    def test_unknown_profiles_do_not_inherit_sdk_or_historical_trust(self) -> None:
        for version in ("0.2.1", "0.2.0-alpha.1", "0.2.0-alpha.2", "0.1.6", "", None, 2):
            with self.subTest(version=version):
                with self.assertRaisesRegex(RustPublishContractError, "unsupported"):
                    validate_packaged_mlkem_native_source_contract(
                        self.current, package_version=version,
                    )

    def test_every_sdk_source_byte_is_closed_including_tests_and_cpu_guard(self) -> None:
        self.assertEqual(len(self.current), 16)
        for name in self.current:
            with self.subTest(file=name):
                mutation = dict(self.current)
                mutation[name] += b"\n"
                with self.assertRaisesRegex(RustPublishContractError, "source bytes differ"):
                    validate_packaged_mlkem_native_source_contract(
                        mutation, package_version=SDK_VERSION,
                    )
                del mutation[name]
                with self.assertRaisesRegex(RustPublishContractError, "source.*set differs"):
                    validate_packaged_mlkem_native_source_contract(
                        mutation, package_version=SDK_VERSION,
                    )

    def test_extra_sources_shadow_headers_and_non_bytes_are_rejected(self) -> None:
        for name, data in (
            ("src/extra.c", b""),
            ("src/mlkem_native.h", b""),
            ("src/injected.S", b""),
            ("build_extra.rs", b""),
            ("src/x86_cpu.rs", "not bytes"),
        ):
            with self.subTest(file=name):
                mutation = {**self.current, name: data}
                with self.assertRaises(RustPublishContractError):
                    validate_packaged_mlkem_native_source_contract(
                        mutation, package_version=SDK_VERSION,
                    )

    def test_removing_an_isa_requirement_is_not_an_accepted_candidate(self) -> None:
        mutation = dict(self.current)
        original = mutation["src/x86_cpu.rs"]
        changed = original.replace(b"AVX2 | (1 << 8)", b"AVX2", 1)
        self.assertNotEqual(original, changed)
        mutation["src/x86_cpu.rs"] = changed
        with self.assertRaisesRegex(RustPublishContractError, "source bytes differ"):
            validate_packaged_mlkem_native_source_contract(
                mutation, package_version=SDK_VERSION,
            )

    def test_candidate_feature_cannot_become_default_or_gain_an_alias(self) -> None:
        manifest = tomllib.loads((SYS_CRATE / "Cargo.toml").read_text())
        features = manifest["features"]
        validate_mlkem_native_manifest_features(features, package_version=SDK_VERSION)
        validate_mlkem_native_manifest_features({}, package_version="0.1.5")
        for mutation in (
            {},
            {**features, "default": ["linux-x86_64-avx2"]},
            {**features, "native": ["linux-x86_64-avx2"]},
            {"linux-x86_64-avx2": ["other/feature"]},
            {"linux-x86_64-avx2": False},
        ):
            with self.subTest(features=mutation):
                with self.assertRaisesRegex(RustPublishContractError, "feature table"):
                    validate_mlkem_native_manifest_features(mutation, package_version=SDK_VERSION)
        with self.assertRaisesRegex(RustPublishContractError, "feature table"):
            validate_mlkem_native_manifest_features(features, package_version="0.1.5")

    def test_workspace_members_and_internal_pins_move_as_one_alpha(self) -> None:
        workspace = tomllib.loads((ROOT / "Cargo.toml").read_text())
        self.assertEqual(workspace["workspace"]["package"]["version"], SDK_VERSION)
        for member in workspace["workspace"]["members"]:
            manifest = tomllib.loads((ROOT / member / "Cargo.toml").read_text())
            with self.subTest(member=member):
                self.assertEqual(manifest["package"]["version"], {"workspace": True})
                sections = [manifest, *manifest.get("target", {}).values()]
                for section in sections:
                    for key in ("dependencies", "dev-dependencies", "build-dependencies"):
                        for name, dependency in section.get(key, {}).items():
                            if name.startswith("q-periapt-"):
                                self.assertEqual(dependency["version"], "=" + SDK_VERSION)
        lock = tomllib.loads((ROOT / "Cargo.lock").read_text())
        versions = {
            package["version"] for package in lock["package"]
            if package["name"].startswith("q-periapt-")
        }
        self.assertEqual(versions, {SDK_VERSION})


if __name__ == "__main__":
    unittest.main()
