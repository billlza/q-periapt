from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import codeql_consumer_context as context
import rust_sdk_profile as sdk


class ConsumerContextTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()

    def owned_tree(self):
        parent = self.root / "owned"
        parent.mkdir()
        file = parent / "input"
        file.write_bytes(b"original")
        alias = parent / "alias"
        alias.symlink_to(self.root / "source")
        objects = {"owned": context.identity(parent), "owned/input": context.identity(file),
                   "owned/alias": context.identity(alias)}
        patch = mock.patch.object(context, "allowed_paths", return_value=set(objects))
        patch.start()
        self.addCleanup(patch.stop)
        return objects, parent, file, alias

    def test_owned_context_removes_only_its_objects(self):
        owned, parent, _, _ = self.owned_tree()
        context.remove_owned(self.root, owned)
        self.assertFalse(parent.exists())

    def test_modified_file_prevents_all_cleanup(self):
        owned, parent, file, alias = self.owned_tree()
        file.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "analysis input changed"):
            context.remove_owned(self.root, owned)
        self.assertTrue(parent.exists())
        self.assertTrue(alias.is_symlink())
        self.assertEqual(b"changed", file.read_bytes())

    def test_replaced_alias_and_unknown_child_are_preserved(self):
        owned, _, file, alias = self.owned_tree()
        alias.unlink()
        alias.symlink_to(self.root / "other")
        with self.assertRaises(ValueError):
            context.remove_owned(self.root, owned)
        self.assertTrue(file.exists())
        owned["owned/alias"] = context.identity(alias)
        unknown = file.with_name("unowned")
        unknown.write_bytes(b"keep")
        with self.assertRaisesRegex(ValueError, "unowned file"):
            context.remove_owned(self.root, owned)
        self.assertEqual(b"keep", unknown.read_bytes())

    def test_unexpected_receipt_path_cannot_be_deleted(self):
        path = self.root / "unrelated"
        path.write_bytes(b"keep")
        with mock.patch.object(context, "allowed_paths", return_value=set()):
            with self.assertRaisesRegex(ValueError, "unexpected temporary input"):
                context.remove_owned(self.root, {"unrelated": context.identity(path)})
        self.assertEqual(b"keep", path.read_bytes())

    def test_registry_wrong_checkout_and_missing_targets_fail(self):
        original = {"name": "consumer", "targets": [{"name": "test", "src_path": "/source/test.rs"}]}
        provider = {"name": "q-periapt-core", "source": None,
                    "manifest_path": "/source/Cargo.toml", "version": "0.2.0"}
        selected = {"q-periapt-core": (Path("/source/Cargo.toml"), "0.2.0")}
        context.check_metadata({"packages": [original, provider]}, original, selected)
        for replacement in ({"source": "registry"}, {"manifest_path": "/stale/Cargo.toml"},
                            {"version": "0.1.5"}, {"name": "q-periapt-other"}):
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                context.check_metadata({"packages": [original, dict(provider, **replacement)]}, original, selected)
        with self.assertRaisesRegex(ValueError, "target paths or attributes"):
            context.check_metadata({"packages": [dict(original, targets=[]), provider]}, original, selected)
        with self.assertRaisesRegex(ValueError, "missing analysis provider"):
            context.check_metadata({"packages": [original]}, original, selected)

    def test_lock_identity_includes_source_version_and_checksum(self):
        template = '[[package]]\nname="dependency"\nversion="1"\nsource="registry"\nchecksum="aaa"\n'
        expected = context.external_packages(template.encode())
        for old, new in (("aaa", "bbb"), ('version="1"', 'version="2"'), ("registry", "other")):
            self.assertNotEqual(expected, context.external_packages(template.replace(old, new).encode()))

    def test_public_fixture_bytes_equal_the_packaging_vectors(self):
        actual = sdk.policy_fixture_inputs()
        self.assertEqual(7, len(actual))
        for vector, stem in zip(sdk.POLICIES, ("policy", "revoke", "enable")):
            source = json.loads((sdk.ROOT / "bindings" / vector).read_text())
            self.assertEqual(source["policy_toml"].encode(), actual[stem + ".toml"])
            name = "signature.bin" if stem == "policy" else stem + "-signature.bin"
            self.assertEqual(bytes.fromhex(source["signature"]), actual[name])
            if stem == "policy":
                self.assertEqual(bytes.fromhex(source["verification_key"]), actual["root.bin"])

    def test_provider_inventory_stays_on_current_source(self):
        for label, count in (("continuity-c", 10), ("sdk-rust", 9)):
            selected = context.providers(context.ROOT, label)
            self.assertEqual(count, len(selected))
            self.assertTrue(all(path.is_relative_to(context.ROOT) for path, _ in selected.values()))

    def test_preexisting_input_is_preserved_before_running_cargo(self):
        file = self.root / "already-present"
        file.write_bytes(b"keep")
        output = self.root / "receipts"
        with mock.patch.object(context, "git_commit", return_value="a" * 40), \
             mock.patch.object(context, "run_git_bytes", return_value=b""), \
             mock.patch.object(context, "allowed_paths", return_value={"already-present"}), \
             mock.patch.object(sdk, "command") as cargo:
            with self.assertRaisesRegex(ValueError, "input already exists"):
                context.prepare(self.root, output, ["1.98.1"])
        cargo.assert_not_called()
        self.assertEqual(b"keep", file.read_bytes())
        state = json.loads((output / "STATE.json").read_text())
        self.assertFalse(state["prepared"])
        self.assertTrue(state["cleanup_completed"])

    def test_workflow_runs_profile_preparation_before_queries_and_publication(self):
        source = (context.ROOT / ".github/workflows/codeql.yml").read_text()
        prepare = source.index("codeql_rust_profile.py prepare")
        analyze = source.index("codeql_rust_profile.py analyze")
        publication = source.index("codeql_rust_publication.py")
        self.assertLess(prepare, analyze)
        self.assertLess(analyze, publication)
        self.assertIn("needs: rust", source)
        self.assertNotIn("continue-on-error", source)


if __name__ == "__main__":
    unittest.main()
