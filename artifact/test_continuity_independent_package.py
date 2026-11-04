"""Installed graph rejection controls; synthetic metadata is not runtime evidence."""
import copy
import os
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest

import continuity_independent_package as installed


LOCK = b'version = 4\n[[package]]\nname = "getrandom"\nversion = "0.4.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "' + b'a' * 64 + b'"\n'


def metadata(root):
    rows = [{"id": name, "name": name, "version": version, "source": None,
             "manifest_path": str(root / "packages" / f"{name}-{version}" / "Cargo.toml")}
            for name, version in installed.VERSIONS.items()]
    rows += [{"id": installed.NAME, "name": installed.NAME, "source": None,
              "manifest_path": str(root / "Cargo.toml")},
             {"id": "random", "name": "getrandom", "version": "0.4.0",
              "source": "registry+https://github.com/rust-lang/crates.io-index"}]
    return {"packages": rows, "resolve": {"root": installed.NAME},
            "workspace_members": [installed.NAME], "workspace_default_members": [installed.NAME]}


class IndependentPackageTests(unittest.TestCase):
    def test_selected_clippy_does_not_execute_cache_or_path_proxies(self):
        # Synthetic process-routing control; actual compiler/runtime evidence is
        # produced by the installed counterpart, never by these tiny programs.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            toolchain, cache = root / "selected", root / "cache"
            for directory in (toolchain / "bin", cache / "bin"):
                directory.mkdir(parents=True)
            for name in ("cargo-clippy", "clippy-driver"):
                path = toolchain / "bin" / name
                path.write_text("#!/bin/sh\nset -eu\nprintf '%s\\n' '"
                                + installed.CLIPPY_VERSION + "'\n")
                path.chmod(0o700)
                proxy = cache / "bin" / name
                proxy.write_text("#!/bin/sh\nset -eu\nprintf invoked > \"$PROXY_MARKER\"\nexit 91\n")
                proxy.chmod(0o700)
            environment = {"PATH": str(cache / "bin") + os.pathsep + "/usr/bin:/bin",
                           "CARGO_HOME": str(cache), "PROXY_MARKER": str(root / "proxy-invoked")}
            calls = []
            def run(argv, label):
                calls.append((argv, label))
                result = subprocess.run(argv, env=environment, stdin=subprocess.DEVNULL,
                                        capture_output=True, timeout=5, check=True)
                self.assertEqual(result.stderr, b"")
                return result.stdout
            command, versions = installed.qualified_clippy(toolchain, run)
            self.assertEqual(command, [str(toolchain / "bin/cargo-clippy"), "clippy"])
            self.assertEqual(versions, {"frontend": installed.CLIPPY_VERSION, "driver": installed.CLIPPY_VERSION})
            self.assertEqual([argv for argv, _ in calls], [command + ["--version"],
                              [str(toolchain / "bin/clippy-driver"), "--version"]])
            self.assertFalse((root / "proxy-invoked").exists())

    def test_each_clippy_version_must_match_the_selected_compiler(self):
        correct = (installed.CLIPPY_VERSION + "\n").encode()
        for changed in (b"clippy 0.1.99 (58cf8f9c35 2026-10-13)\n", b"", correct + correct):
            for label in ("clippy-version", "clippy-driver-version"):
                with self.subTest(version=changed, label=label), self.assertRaisesRegex(ValueError, "Clippy compiler differs"):
                    installed.qualified_clippy(Path("/selected"),
                        lambda argv, current: changed if current == label else correct)

    def test_partial_or_malformed_ci_selection_cannot_fall_back_to_source_build(self):
        self.assertFalse(installed.validate_sdk_selection("", ""))
        self.assertTrue(installed.validate_sdk_selection("39129232908", "a" * 64))
        for run, digest in [("39129232908", ""), ("", "a" * 64), ("0", "a" * 64),
                            ("../run", "a" * 64), ("39129232908", "A" * 64), (True, "a" * 64)]:
            with self.subTest(run=run, digest=digest), self.assertRaises(ValueError):
                installed.validate_sdk_selection(run, digest)

    def test_complete_counterpart_setup_retains_lock_and_refuses_existing_state(self):
        with tempfile.TemporaryDirectory() as temp:
            consumer = Path(temp) / "counterpart"
            original = installed.prepare_counterpart(consumer)
            self.assertEqual(original, (installed.SOURCE / "Cargo.lock").read_bytes())
            self.assertEqual((consumer / "Cargo.lock").read_bytes(), original)
            for path in installed.native_files():
                if path.name != "Cargo.toml":
                    self.assertEqual((consumer / path.relative_to(installed.SOURCE)).read_bytes(), path.read_bytes())
            generated = tomllib.loads((consumer / "Cargo.toml").read_text())
            self.assertTrue(generated["workspace"]["exclude"])
            with self.assertRaisesRegex(ValueError, "must be fresh"):
                installed.prepare_counterpart(consumer)
            self.assertEqual((consumer / "Cargo.lock").read_bytes(), original)

    def test_archive_edges_preserve_source_build_and_lint_settings(self):
        original = (installed.SOURCE / "Cargo.toml").read_bytes()
        before = tomllib.loads(original.decode())
        after = tomllib.loads(installed.installed_manifest(original).decode())
        for field in ("package", "profile", "lints"):
            self.assertEqual(after[field], before[field])
        for name in ("getrandom", "zeroize", "tempfile"):
            self.assertEqual(after["dependencies"][name], before["dependencies"][name])
        expected = {f"packages/{name}-{version}" for name, version in installed.VERSIONS.items()}
        self.assertEqual(set(after["workspace"]["exclude"]), expected)
        self.assertTrue(all("*" not in name for name in after["workspace"]["exclude"]))
        self.assertNotIn("q-periapt-rustls", after["patch"]["crates-io"])
        for name, value in after["dependencies"].items():
            if name.startswith("q-periapt"):
                self.assertEqual(value, {"version": "=" + installed.VERSIONS[name],
                                        "path": f"packages/{name}-{installed.VERSIONS[name]}"})

    def test_new_dependency_features_or_workspace_cannot_be_silently_dropped(self):
        original = (installed.SOURCE / "Cargo.toml").read_bytes()
        changes = [original.replace(b'[workspace]', b'[workspace]\nmembers = ["elsewhere"]'),
                   original.replace(b'{ path = "../../continuity-identity-candidate" }',
                                    b'{ path = "../../continuity-identity-candidate", features = ["connection-tls"] }'),
                   original.replace(b'publish = false', b'publish = true'),
                   original + b'\n[patch.crates-io]\nother = { path = "elsewhere" }\n']
        for changed in changes:
            with self.subTest(changed=changed[-100:]), self.assertRaises(ValueError):
                installed.installed_manifest(changed)

    def test_exact_graph_and_original_lock(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            result = installed.verify_graph(metadata(root), root, LOCK, LOCK)
            self.assertEqual(result["product_crates"], 9)
            self.assertEqual(result["external_packages"], 1)
            # Equal external packages are insufficient: the original lock bytes
            # also bind the standalone local package graph and resolver state.
            with self.assertRaisesRegex(ValueError, "original lockfile"):
                installed.verify_graph(metadata(root), root, LOCK + b'\n', LOCK)

    def test_checkout_sources_mixed_versions_and_implicit_members_are_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve(); original = metadata(root)
            variants = []
            value = copy.deepcopy(original); value["packages"][0]["manifest_path"] = str(root / "checkout/Cargo.toml"); variants.append(value)
            value = copy.deepcopy(original); value["packages"][0]["version"] = "0.1.0"; variants.append(value)
            value = copy.deepcopy(original); value["workspace_members"].append(installed.package.NAME); variants.append(value)
            value = copy.deepcopy(original); value["workspace_default_members"] = [installed.package.NAME]; variants.append(value)
            value = copy.deepcopy(original); value["resolve"]["root"] = installed.package.NAME; value["workspace_members"] = value["workspace_default_members"] = [installed.package.NAME]; variants.append(value)
            value = copy.deepcopy(original); value["packages"][-1]["source"] = None; variants.append(value)
            value = copy.deepcopy(original); value["packages"].append(copy.deepcopy(value["packages"][0])); variants.append(value)
            for value in variants:
                with self.subTest(value=value), self.assertRaises(ValueError):
                    installed.verify_graph(value, root, LOCK, LOCK)

    def test_external_dependency_checksum_changes_are_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            with self.assertRaisesRegex(ValueError, "external dependency"):
                installed.verify_graph(metadata(root), root, LOCK.replace(b'a' * 64, b'b' * 64), LOCK)


if __name__ == "__main__":
    unittest.main()
