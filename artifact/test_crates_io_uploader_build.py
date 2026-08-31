#!/usr/bin/env python3
"""Tests for crates_io_uploader_build and the uploader template.

A synthetic ten-crate cohort (the canonical publishable names, tiny manifests) is
materialized through the committed template, and the result is checked the way
the uploader's own loader checks it: schema, digests, uniform version, dependency
count, and dependency kinds -- plus mode-0700 output, absent placeholders, the
materialization guard, and byte-for-byte determinism. Binding failures (bytes
that disagree with the handoff, an incomplete cohort, non-uniform versions) must
be refused."""

from __future__ import annotations

import ast
import base64
import gzip
import hashlib
import importlib.util
import io
import json
import lzma
import os
import pathlib
import re
import stat
import sys
import tarfile
import tempfile
import unittest
from importlib.machinery import SourceFileLoader

import crates_io_uploader_build as build
import crates_io_registry_metadata as registry
from rust_publish_contract import RUST_PUBLISHABLE_CRATES

ARTIFACT = pathlib.Path(__file__).resolve().parent
TEMPLATE = ARTIFACT / "crates_io_uploader_template.py.in"
VERSION = "9.9.9"

# One crate carries a dependency so the cohort's dependency count is non-zero.
_DEP_CRATE = "q-periapt-core"


def _manifest(name: str, version: str) -> str:
    manifest = f'[package]\nname = "{name}"\nversion = "{version}"\n'
    manifest += 'description = "synthetic"\nlicense = "MIT"\nreadme = "README.md"\n'
    if name == _DEP_CRATE:
        manifest += '\n[dependencies]\nserde = "1"\n'
    return manifest


def _crate_bytes(name: str, version: str) -> bytes:
    buffer = io.BytesIO()
    # Uncompressed tar with a fixed mtime, then gzip with mtime=0, so the bytes
    # (and thus the sha256) are deterministic across runs.
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for relative, payload in (
            ("Cargo.toml", _manifest(name, version).encode("utf-8")),
            ("README.md", f"# {name}\n".encode("utf-8")),
        ):
            info = tarfile.TarInfo(f"{name}-{version}/{relative}")
            info.size = len(payload)
            info.mtime = 0
            tar.addfile(info, io.BytesIO(payload))
    return gzip.compress(buffer.getvalue(), mtime=0)


def _write_cohort(directory: pathlib.Path, *, break_sha: str | None = None,
                  drop: str | None = None,
                  handoff_version_override: dict | None = None,
                  packaged_version_override: dict | None = None,
                  kind: str | None = None) -> pathlib.Path:
    """Write a synthetic cohort + handoff.

    ``handoff_version_override`` changes only the handoff entry's version (the
    packaged crate keeps VERSION), exercising the handoff/packaged binding.
    ``packaged_version_override`` changes the packaged crate's manifest version
    AND its matching handoff entry, so binding still passes but packaged versions
    disagree across the cohort.
    """

    crates = []
    for name in RUST_PUBLISHABLE_CRATES:
        if name == drop:
            continue
        packaged_version = (packaged_version_override or {}).get(name, VERSION)
        payload = _crate_bytes(name, packaged_version)
        crate_file = f"{name}-{packaged_version}.crate"
        (directory / crate_file).write_bytes(payload)
        sha = hashlib.sha256(payload).hexdigest()
        if break_sha == name:
            sha = "0" * 64
        handoff_version = (handoff_version_override or {}).get(name, packaged_version)
        crates.append({
            "name": name,
            "version": handoff_version,
            "crate_file": crate_file,
            "crate_sha256": sha,
            "crate_size": len(payload),
        })
    handoff = {"kind": kind if kind is not None else build.HANDOFF_KIND,
               "crates": crates}
    handoff_path = directory / "rust-package-handoff.json"
    handoff_path.write_text(json.dumps(handoff), encoding="utf-8")
    return handoff_path


def _decode_contracts(text: str) -> dict:
    blob = "".join(re.findall(
        r'"([^"]*)"',
        re.search(r'_FIXED_CONTRACT_B85 = \((.*?)\)\n', text, re.S).group(1)))
    return json.loads(lzma.decompress(base64.b85decode(blob)).decode("utf-8"))


def _const(text: str, name: str) -> str:
    return re.search(rf'{name} = "([^"]*)"', text).group(1)


class TemplateIntegrityTests(unittest.TestCase):
    def test_template_is_valid_python_with_placeholders_and_guard(self) -> None:
        text = TEMPLATE.read_text(encoding="utf-8")
        ast.parse(text)  # must remain syntactically valid
        for placeholder in ("@PRODUCT_VERSION@", "@CARGO_VERSION@",
                            "@HANDOFF_SHA256@", "@CONTRACT_XZ_SHA256@",
                            "@CONTRACT_B85@"):
            self.assertIn(placeholder, text)
        self.assertIn('if "@" in PRODUCT_VERSION:', text)
        self.assertIn("_FIXED_DEPENDENCY_COUNT = -1", text)
        self.assertTrue(text.startswith("#!"))  # shebang on line 1


class GeneratorTests(unittest.TestCase):
    def _materialize(self, directory: pathlib.Path, **kwargs) -> tuple[pathlib.Path, dict]:
        handoff = _write_cohort(directory, **kwargs)
        output = directory / "qperiapt-crates-io-uploader"
        summary = build.build(
            handoff, TEMPLATE, output,
            crate_dir=directory, cargo_version="1.99.0")
        return output, summary

    def test_materialized_uploader_structure(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = pathlib.Path(raw)
            output, summary = self._materialize(directory)
            text = output.read_text(encoding="utf-8")

            # mode 0700, single-link regular file (coordinator requires this)
            info = output.lstat()
            self.assertTrue(stat.S_ISREG(info.st_mode))
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o700)
            self.assertEqual(info.st_nlink, 1)

            ast.parse(text)  # valid python
            self.assertEqual(_const(text, "PRODUCT_VERSION"), VERSION)
            self.assertEqual(_const(text, "USER_AGENT"),
                             f"qperiapt-crates-io-uploader/{VERSION}")
            self.assertEqual(_const(text, "FIXED_CARGO_VERSION"), "1.99.0")
            self.assertIn('if "@" in PRODUCT_VERSION:', text)
            # every template placeholder is filled
            for placeholder in re.findall(r'@[A-Z0-9_]+@', TEMPLATE.read_text()):
                self.assertNotIn(placeholder, text)
            self.assertEqual(summary["product_version"], VERSION)
            self.assertEqual(summary["dependency_count"], 1)  # one serde dep

    def test_embedded_contracts_pass_loader_equivalent_checks(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = pathlib.Path(raw)
            output, summary = self._materialize(directory)
            text = output.read_text(encoding="utf-8")

            document = _decode_contracts(text)
            xz_sha = _const(text, "_FIXED_CONTRACT_XZ_SHA256")
            identities_block = re.search(
                r'EXPECTED_CRATE_IDENTITIES = MappingProxyType\(\n(    \{.*?\n    \})\n\)',
                text, re.S).group(1)
            identities = ast.literal_eval(identities_block)
            dep_count_declared = int(re.search(
                r'_FIXED_DEPENDENCY_COUNT = (\d+)', text).group(1))

            # cohort + schema + digests, mirroring the uploader's _load_fixed_contracts
            self.assertEqual(set(document), set(RUST_PUBLISHABLE_CRATES))
            self.assertEqual(set(identities), set(RUST_PUBLISHABLE_CRATES))
            total_deps = 0
            for name, record in document.items():
                self.assertEqual(set(record),
                                 {"metadata_json", "metadata_sha256", "sha256", "size"})
                self.assertEqual(identities[name], (record["size"], record["sha256"]))
                self.assertEqual(
                    hashlib.sha256(record["metadata_json"].encode()).hexdigest(),
                    record["metadata_sha256"])
                metadata = json.loads(record["metadata_json"])
                self.assertEqual(metadata["name"], name)
                self.assertEqual(metadata["vers"], VERSION)
                for dependency in metadata["deps"]:
                    self.assertIn(dependency["kind"], {"normal", "build", "dev"})
                total_deps += len(metadata["deps"])
            self.assertEqual(total_deps, dep_count_declared)
            self.assertEqual(total_deps, summary["dependency_count"])

            # xz digest binds the embedded blob
            blob = "".join(re.findall(
                r'"([^"]*)"',
                re.search(r'_FIXED_CONTRACT_B85 = \((.*?)\)\n', text, re.S).group(1)))
            self.assertEqual(
                hashlib.sha256(base64.b85decode(blob)).hexdigest(), xz_sha)

    def test_materialized_uploader_real_loader_accepts_it(self) -> None:
        # Import the materialized uploader so its OWN _load_fixed_contracts runs
        # (at module import COHORT_CONTRACTS = _load_fixed_contracts()), rather
        # than re-implementing the loader's checks. No upload code runs on import.
        with tempfile.TemporaryDirectory() as raw:
            directory = pathlib.Path(raw)
            output, summary = self._materialize(directory)
            loader = SourceFileLoader("materialized_uploader_under_test", str(output))
            spec = importlib.util.spec_from_loader(loader.name, loader)
            module = importlib.util.module_from_spec(spec)
            # dataclasses (with `from __future__ import annotations`) resolves the
            # class module via sys.modules, so register before executing.
            sys.modules[loader.name] = module
            try:
                loader.exec_module(module)
            finally:
                sys.modules.pop(loader.name, None)

            self.assertEqual(module.PRODUCT_VERSION, VERSION)
            self.assertEqual(set(module.COHORT_CONTRACTS), set(RUST_PUBLISHABLE_CRATES))
            total = sum(len(json.loads(contract.metadata_json)["deps"])
                        for contract in module.COHORT_CONTRACTS.values())
            self.assertEqual(total, summary["dependency_count"])

    def test_deterministic_output(self) -> None:
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            first, _ = self._materialize(pathlib.Path(a))
            second, _ = self._materialize(pathlib.Path(b))
            self.assertEqual(first.read_text(), second.read_text())

    def test_handoff_sha_binds_output(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = pathlib.Path(raw)
            output, _ = self._materialize(directory)
            handoff_bytes = (directory / "rust-package-handoff.json").read_bytes()
            expected = hashlib.sha256(handoff_bytes).hexdigest()
            self.assertIn(expected, output.read_text())


class VersionSafetyTests(unittest.TestCase):
    """A version token is embedded into a Python string literal; unsafe tokens
    (that could break out of the literal) must be refused before emission."""

    def test_unsafe_product_version_is_refused(self) -> None:
        template = TEMPLATE.read_text(encoding="utf-8")
        with self.assertRaisesRegex(build.UploaderBuildError, "safe version token"):
            build.materialize(
                template, {}, product_version='1.0";import os#',
                dependency_count=0, cargo_version="1.0.0", handoff_sha256="0" * 64)

    def test_unsafe_cargo_version_is_refused(self) -> None:
        template = TEMPLATE.read_text(encoding="utf-8")
        with self.assertRaisesRegex(build.UploaderBuildError, "safe version token"):
            build.materialize(
                template, {}, product_version="1.0.0",
                dependency_count=0, cargo_version='x"\n', handoff_sha256="0" * 64)


class BindingFailureTests(unittest.TestCase):
    def _expect(self, pattern: str, **kwargs) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = pathlib.Path(raw)
            handoff = _write_cohort(directory, **kwargs)
            with self.assertRaisesRegex(build.UploaderBuildError, pattern):
                build.build(handoff, TEMPLATE, directory / "out",
                            crate_dir=directory, cargo_version="1.0.0")

    def test_crate_bytes_must_match_handoff(self) -> None:
        self._expect("differ from the handoff", break_sha="q-periapt-kem")

    def test_cohort_must_be_complete(self) -> None:
        self._expect("cohort differs", drop="q-periapt-cli")

    def test_handoff_version_must_match_packaged(self) -> None:
        # One handoff entry disagrees with its packaged crate's version.
        self._expect("handoff version differs",
                     handoff_version_override={"q-periapt-sig": "0.0.1"})

    def test_packaged_versions_must_be_uniform(self) -> None:
        # One crate is packaged (and pinned in the handoff) at a different
        # version, so the packaged manifests disagree across the cohort.
        self._expect("not uniform",
                     packaged_version_override={"q-periapt-sig": "8.8.8"})

    def test_wrong_handoff_kind_is_refused(self) -> None:
        self._expect("not a rust package handoff", kind="something.else")

    def test_missing_packaged_crate_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = pathlib.Path(raw)
            handoff = _write_cohort(directory)
            (directory / f"q-periapt-cli-{VERSION}.crate").unlink()
            with self.assertRaisesRegex(build.UploaderBuildError, "packaged crate is missing"):
                build.build(handoff, TEMPLATE, directory / "out",
                            crate_dir=directory, cargo_version="1.0.0")

    def test_empty_or_non_object_handoff_is_refused(self) -> None:
        for payload, pattern in (
            (b'{"kind": "qperiapt.rust_package_handoff", "crates": []}', "no crates"),
            (b'"a string, not an object"', "not a JSON object"),
        ):
            with tempfile.TemporaryDirectory() as raw:
                directory = pathlib.Path(raw)
                handoff = directory / "rust-package-handoff.json"
                handoff.write_bytes(payload)
                with self.assertRaisesRegex(build.UploaderBuildError, pattern):
                    build.build(handoff, TEMPLATE, directory / "out",
                                crate_dir=directory, cargo_version="1.0.0")

    def test_traversal_crate_file_is_refused(self) -> None:
        # A handoff crate_file with a path component (external data) must not be
        # allowed to steer the read outside crate_dir.
        with tempfile.TemporaryDirectory() as raw:
            directory = pathlib.Path(raw)
            handoff = _write_cohort(directory)
            tampered = json.loads(handoff.read_text())
            tampered["crates"][0]["crate_file"] = "../escape.crate"
            handoff.write_text(json.dumps(tampered))
            with self.assertRaisesRegex(build.UploaderBuildError, "bare filename"):
                build.build(handoff, TEMPLATE, directory / "out",
                            crate_dir=directory, cargo_version="1.0.0")


if __name__ == "__main__":
    unittest.main()
