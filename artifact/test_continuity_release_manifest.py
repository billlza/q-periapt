"""Identity checks cannot promote or mix real package and specification inputs."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import continuity_contract
import continuity_release_manifest as manifest


class ContinuityReleaseManifestTests(unittest.TestCase):
    """All temporary packages/assessments are synthetic unit fixtures."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.source = {"commit": hashlib.sha1(b"unit-fixture-commit").hexdigest(),
                       "tree": hashlib.sha1(b"unit-fixture-tree").hexdigest()}
        self.budgets = json.loads(continuity_contract.BUDGETS.read_text())
        self.sdk_abi = {"schema": 1, "kind": "qperiapt.c_abi_contract",
                        "package": {"semver": "0.2.0", "abi_major": 2},
                        "abi": {"major": 2, "exports": [
                            {"name": "q_periapt_abi_version", "declaration": "uint32_t q_periapt_abi_version(void);"}]}}
        self.owner_abi = {"schema_version": 1, "abi": "qpc-owner/1", "package_version": "0.0.0",
                          "frozen_product_contract": False,
                          "declarations": ["int32_t qpc_owner_v1_open ( uint64_t * out ) ;"]}
        self.interfaces = {
            "sdk_c": {"abi": 2, "package_version": "0.2.0", "contract": self.json_file("abi/sdk.json", self.sdk_abi),
                      "exports": ["q_periapt_abi_version"]},
            "continuity_c": {"abi": "qpc-owner/1", "package_version": "0.0.0",
                             "contract": self.json_file("abi/owner.json", self.owner_abi), "exports": ["qpc_owner_v1_open"]},
        }
        self.workspace = self.file("Cargo.toml", b'[workspace.package]\nversion = "0.2.0"\n')
        core = self.cargo("core", "sdk", "q-periapt-core", "0.2.0")
        sdk = self.cargo("sdk", "sdk", "q-periapt-sdk", "0.2.0", dependencies=[core], inherited=True)
        engine = self.cargo("engine", "engine", "q-periapt-continuity-identity-candidate", "0.0.0", dependencies=[sdk])
        normative = {role: self.file(f"spec/{role}.md", f"Synthetic {role} contract.\n".encode())
                     for role in manifest.NORMATIVE_ROLES if role != "budgets"}
        normative["budgets"] = self.json_file("spec/budgets.json", self.budgets)
        self.lock = {"schema_version": 1, "kind": manifest.LOCK_KIND, "stage": "candidate", "product_version": "0.2.0",
                     "frozen_product_contract": False, "normative_files": normative, "supporting_files": [],
                     "compiled_descriptor": None, "package_graph_sha256": "", "interfaces_sha256": ""}
        self.document = {"schema_version": 1, "kind": manifest.MANIFEST_KIND, "stage": "candidate",
                         "product_version": "0.2.0", "source": self.source, "spec_lock": None,
                         "packages": [core, sdk, engine], "interfaces": self.interfaces,
                         "release_claim_eligible": False, "publication_performed": False}
        self.save()

    def file(self, path: str, data: bytes) -> dict:
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        return {"path": path, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}

    def json_file(self, path: str, value: object) -> dict:
        return self.file(path, manifest.canonical_json_bytes(value))

    def cargo(self, identifier: str, role: str, name: str, version: str,
              *, dependencies: list[dict] | None = None, inherited: bool = False) -> dict:
        dependencies = dependencies or []
        text = f'[package]\nname = "{name}"\n'
        text += 'version.workspace = true\n' if inherited else f'version = "{version}"\n'
        text += "[dependencies]\n"
        text += "".join(f'{row["name"]} = "={row["version"]}"\n' for row in dependencies)
        return {"id": identifier, "role": role, "name": name, "version": version, "format": "cargo",
                "metadata": self.file(f"packages/{identifier}/Cargo.toml", text.encode()),
                "workspace": self.workspace if inherited else None, "dependencies": [row["id"] for row in dependencies],
                "interfaces": [], "artifacts": [], "assessments": []}

    def save(self) -> str:
        self.lock["package_graph_sha256"] = manifest.package_graph_digest(self.document["packages"])
        self.lock["interfaces_sha256"] = manifest.canonical_digest(self.document["interfaces"])
        self.document["spec_lock"] = self.json_file("SPEC_LOCK.json", self.lock)
        self.selected = self.json_file("MANIFEST.json", self.document)
        return self.selected["sha256"]

    def verify(self, **overrides):
        arguments = {"expected_sha256": self.selected["sha256"], "source_commit": self.source["commit"],
                     "source_tree": self.source["tree"], "stage": self.document["stage"]}
        arguments.update(overrides)
        return manifest.verify_manifest(self.root, "MANIFEST.json", **arguments)

    def release_fixture(self):
        """Construct a complete synthetic identity graph, never product proof."""
        self.document["stage"] = self.lock["stage"] = "release"
        self.lock["frozen_product_contract"] = True
        self.budgets["frozen_product_contract"] = True
        self.lock["normative_files"]["budgets"] = self.json_file("spec/budgets.json", self.budgets)
        self.lock["compiled_descriptor"] = self.json_file("compiled/descriptor.json", self.budgets)
        self.owner_abi.update(package_version="0.2.0", frozen_product_contract=True)
        self.interfaces["continuity_c"].update(package_version="0.2.0", contract=self.json_file("abi/owner.json", self.owner_abi))
        packages = [self.cargo(name, "sdk", name, "0.2.0") for name in manifest.COHORT]
        sdk = next(row for row in packages if row["name"] == "q-periapt-sdk")
        engine = self.cargo("engine", "engine", "q-periapt-continuity", "0.2.0", dependencies=[sdk])
        packages.append(engine)
        for role in ("native", "swift", "kotlin", "android", "browser", "service"):
            row = {"id": role, "role": role, "name": "q-periapt-" + role, "version": "0.2.0",
                   "format": "npm" if role == "browser" else "distribution", "metadata": None,
                   "workspace": None, "dependencies": ["engine"], "interfaces": ["continuity_c"] if role == "native" else [],
                   "artifacts": [], "assessments": []}
            if role == "browser":
                bridge = self.cargo("browser-bridge", "browser", "q-periapt-sdk-wasm", "0.2.0", dependencies=[engine])
                packages.append(bridge)
                row["name"] = bridge["name"]
                row["dependencies"] = [bridge["id"]]
            packages.append(row)
        for row in packages:
            row["artifacts"] = [self.file(f"artifacts/{row['id']}.bin", f"Synthetic artifact {row['id']}.\n".encode())]
            row["assessments"] = [self.json_file(f"assessments/{row['id']}.json",
                                  {"kind": "unit.synthetic_package_report", "completed": True,
                                   "source_commit": self.source["commit"], "scope": "synthetic fixture, not qualification"})]
            if row["format"] == "distribution":
                row["metadata"] = self.json_file(f"packages/{row['id']}.json", {
                    "schema_version": 1, "kind": "qperiapt.continuity_distribution_identity",
                    "name": row["name"], "version": row["version"], "source": self.source,
                    "dependencies": row["dependencies"], "interfaces": row["interfaces"], "artifacts": row["artifacts"]})
            elif row["format"] == "npm":
                row["metadata"] = self.json_file("packages/browser/package.json",
                    {"name": row["name"], "version": row["version"], "exports": {"./web": "./web/index.js"}})
        self.document["packages"] = packages
        self.save()

    def test_valid_candidate_is_an_inventory_without_release_or_compilation_claim(self):
        result = self.verify()
        self.assertTrue(result["completed"])
        self.assertFalse(result["compiled_descriptor_matched"])
        self.assertFalse(result["release_claim_eligible"])
        self.assertFalse(result["publication_performed"])
        self.assertEqual(result["exports"], {"sdk_c": 1, "continuity_c": 1})
        self.assertIn("android", result["missing_release_roles"])
        self.assertNotIn("sources_unchanged", result)
        self.assertIs(self.budgets["frozen_product_contract"], False)

    def test_independent_manifest_source_and_stage_selections_are_required(self):
        for arguments, message in (({"expected_sha256": "0" * 64}, "manifest digest"),
                                   ({"source_commit": "0" * 40}, "source differs"),
                                   ({"source_tree": "0" * 40}, "source differs"),
                                   ({"stage": "release"}, "selected stage")):
            with self.subTest(arguments=arguments), self.assertRaisesRegex(ValueError, message):
                self.verify(**arguments)

    def test_status_booleans_cannot_authorize_publication(self):
        for field in ("release_claim_eligible", "publication_performed"):
            for value in (True, 0, "false", None):
                with self.subTest(field=field, value=value):
                    self.document[field] = value
                    self.save()
                    with self.assertRaisesRegex(ValueError, "cannot authorize release"):
                        self.verify()
                    self.document[field] = False

    def test_changing_release_labels_does_not_promote_candidate_budgets(self):
        self.document["stage"] = self.lock["stage"] = "release"
        self.lock["frozen_product_contract"] = True
        self.save()
        with self.assertRaisesRegex(ValueError, "descriptor freeze state"):
            self.verify()

    def test_candidate_lock_cannot_claim_a_freeze(self):
        self.lock["frozen_product_contract"] = True
        self.save()
        with self.assertRaisesRegex(ValueError, "lock identity or freeze"):
            self.verify()

    def test_wrong_package_identity_is_rejected_even_when_graph_is_relocked(self):
        self.document["packages"][-1]["version"] = "0.2.0"
        self.save()
        with self.assertRaisesRegex(ValueError, "Cargo package identity"):
            self.verify()

    def test_cargo_alias_and_target_dependency_are_checked_by_actual_package_name(self):
        row = self.document["packages"][-1]
        text = ('[package]\nname = "q-periapt-continuity-identity-candidate"\nversion = "0.0.0"\n'
                '[dependencies]\ncompat = { package = "q-periapt-sdk", version = "=0.2.0" }\n'
                '[target.\'cfg(unix)\'.dependencies]\nq-periapt-core = { version = "=0.2.0", optional = true }\n')
        row["metadata"] = self.file(row["metadata"]["path"], text.encode())
        row["dependencies"] = ["core", "sdk"]
        self.save()
        self.assertTrue(self.verify()["completed"])
        row["metadata"] = self.file(row["metadata"]["path"], text.replace('version = "=0.2.0", optional', 'version = "=0.1.5", optional').encode())
        self.save()
        with self.assertRaisesRegex(ValueError, "Cargo dependency version"):
            self.verify()

    def test_missing_internal_cargo_dependency_and_graph_edge_are_not_externalized(self):
        row = self.document["packages"][-1]
        original = (self.root / row["metadata"]["path"]).read_bytes()
        row["metadata"] = self.file(row["metadata"]["path"], original + b'q-periapt-sig = "=0.2.0"\n')
        self.save()
        with self.assertRaisesRegex(ValueError, "dependency missing from package graph"):
            self.verify()
        row["metadata"] = self.file(row["metadata"]["path"], original)
        row["dependencies"] = []
        self.save()
        with self.assertRaisesRegex(ValueError, "Cargo dependency graph"):
            self.verify()

    def test_cargo_local_dependency_must_name_the_selected_metadata_directory(self):
        row = self.document["packages"][-1]
        original = (self.root / row["metadata"]["path"]).read_text()
        for path, accepted in (("../sdk", True), ("../core", False), ("../../../outside", False)):
            text = original.replace('q-periapt-sdk = "=0.2.0"',
                                    f'q-periapt-sdk = {{ version = "=0.2.0", path = "{path}" }}')
            row["metadata"] = self.file(row["metadata"]["path"], text.encode())
            self.save()
            with self.subTest(path=path):
                if accepted:
                    self.assertTrue(self.verify()["completed"])
                else:
                    with self.assertRaisesRegex(ValueError, "dependency path"):
                        self.verify()

    def test_cargo_workspace_dependency_path_is_relative_to_pinned_workspace(self):
        row = self.document["packages"][-1]
        text = ('[package]\nname = "q-periapt-continuity-identity-candidate"\nversion = "0.0.0"\n'
                '[dependencies]\nq-periapt-sdk = { workspace = true, features = ["extra"], optional = true }\n')
        row["metadata"] = self.file(row["metadata"]["path"], text.encode())
        for path, accepted in (("packages/sdk", True), ("../sdk", False)):
            workspace = self.file("Cargo.toml", ('[workspace.package]\nversion = "0.2.0"\n'
                '[workspace.dependencies]\nq-periapt-sdk = { version = "=0.2.0", path = "' + path + '" }\n').encode())
            for package in self.document["packages"]:
                if package["workspace"] is not None or package is row:
                    package["workspace"] = workspace
            self.save()
            with self.subTest(path=path):
                if accepted:
                    self.assertTrue(self.verify()["completed"])
                else:
                    with self.assertRaisesRegex(ValueError, "dependency path"):
                        self.verify()

    def test_cargo_inherited_dependency_cannot_hide_a_member_identity_override(self):
        row = self.document["packages"][-1]
        workspace = self.file("Cargo.toml", b'[workspace.package]\nversion = "0.2.0"\n'
                              b'[workspace.dependencies]\nq-periapt-sdk = "=0.2.0"\n')
        for package in self.document["packages"]:
            if package["workspace"] is not None or package is row:
                package["workspace"] = workspace
        for override in ('version = "=0.1.5"', 'path = "../core"', 'package = "q-periapt-core"'):
            text = ('[package]\nname = "q-periapt-continuity-identity-candidate"\nversion = "0.0.0"\n'
                    '[dependencies]\nq-periapt-sdk = { workspace = true, ' + override + ' }\n')
            row["metadata"] = self.file(row["metadata"]["path"], text.encode())
            self.save()
            with self.subTest(override=override), self.assertRaisesRegex(ValueError, "inherited dependency overrides"):
                self.verify()

    def test_unrelated_workspace_cannot_supply_an_inherited_version(self):
        self.document["packages"][1]["workspace"] = self.file("unrelated/Cargo.toml", b'[workspace.package]\nversion = "0.2.0"\n')
        self.save()
        with self.assertRaisesRegex(ValueError, "selected Cargo workspace"):
            self.verify()

    def test_forward_or_cyclic_dependencies_are_rejected(self):
        self.document["packages"][1]["dependencies"] = ["engine"]
        self.save()
        with self.assertRaisesRegex(ValueError, "cyclic or out of build order"):
            self.verify()

    def test_cargo_and_npm_browser_packages_can_share_their_actual_name(self):
        engine = self.document["packages"][-1]
        bridge = self.cargo("browser-engine", "browser", "q-periapt-sdk-wasm", "0.2.0", dependencies=[engine])
        package = {"id": "browser", "role": "browser", "name": "q-periapt-sdk-wasm", "version": "0.2.0",
                   "format": "npm", "metadata": self.json_file("packages/browser/package.json", {
                       "name": "q-periapt-sdk-wasm", "version": "0.2.0", "exports": {"./web": "./web/index.js"}}),
                   "workspace": None, "dependencies": ["browser-engine"], "interfaces": [],
                   "artifacts": [], "assessments": []}
        self.document["packages"].extend([bridge, package])
        self.save()
        self.assertEqual(self.verify()["packages"], 5)
        duplicate = copy.deepcopy(package)
        duplicate["id"] = "browser-duplicate"
        self.document["packages"].append(duplicate)
        self.save()
        with self.assertRaisesRegex(ValueError, "ecosystem/name identity is duplicated"):
            self.verify()

    def add_browser(self, identifier: str = "browser", name: str = "q-periapt-sdk-wasm") -> dict:
        engine = next(row for row in self.document["packages"] if row["role"] == "engine")
        bridge = self.cargo(identifier + "-bridge", "browser", name, "0.2.0", dependencies=[engine])
        row = {"id": identifier, "role": "browser", "name": name, "version": "0.2.0", "format": "npm",
               "metadata": self.json_file(f"packages/{identifier}/package.json", {
                   "name": name, "version": "0.2.0", "exports": {"./web": "./web/index.js"}}),
               "workspace": None, "dependencies": [bridge["id"]], "interfaces": [], "artifacts": [], "assessments": []}
        self.document["packages"].extend([bridge, row])
        return row

    def test_npm_internal_edges_match_actual_package_definition(self):
        helper = self.add_browser("helper", "q-periapt-web-helper")
        row = self.add_browser()
        metadata = json.loads((self.root / row["metadata"]["path"]).read_text())
        metadata["dependencies"] = {helper["name"]: "0.2.0"}
        row["metadata"] = self.json_file(row["metadata"]["path"], metadata)
        self.save()
        with self.assertRaisesRegex(ValueError, "npm dependency graph"):
            self.verify()
        row["dependencies"].append(helper["id"])
        self.save()
        self.assertTrue(self.verify()["completed"])
        metadata["dependencies"][helper["name"]] = "0.1.5"
        row["metadata"] = self.json_file(row["metadata"]["path"], metadata)
        self.save()
        with self.assertRaisesRegex(ValueError, "npm dependency version"):
            self.verify()
        metadata["optionalDependencies"] = {helper["name"]: "0.2.0"}
        row["metadata"] = self.json_file(row["metadata"]["path"], metadata)
        self.save()
        self.assertTrue(self.verify()["completed"])

    def test_npm_alias_and_local_path_cannot_redirect_selected_package(self):
        helper = self.add_browser("helper", "q-periapt-web-helper")
        row = self.add_browser()
        metadata = json.loads((self.root / row["metadata"]["path"]).read_text())
        row["dependencies"].append(helper["id"])
        for dependency in ({"compat": "npm:q-periapt-web-helper@0.2.0"},
                           {helper["name"]: "file:../helper"}, {"compat": "file:../helper"}):
            metadata["dependencies"] = dependency
            row["metadata"] = self.json_file(row["metadata"]["path"], metadata)
            self.save()
            self.assertTrue(self.verify()["completed"])
        metadata["dependencies"] = {helper["name"]: "file:../core"}
        row["metadata"] = self.json_file(row["metadata"]["path"], metadata)
        self.save()
        with self.assertRaisesRegex(ValueError, "npm dependency path"):
            self.verify()

    def test_npm_graph_cannot_add_unobserved_edges_or_use_a_null_web_export(self):
        row = self.add_browser()
        row["dependencies"].append("engine")
        self.save()
        with self.assertRaisesRegex(ValueError, "npm dependency graph"):
            self.verify()
        row["dependencies"].remove("engine")
        metadata = json.loads((self.root / row["metadata"]["path"]).read_text())
        metadata["exports"]["./web"] = None
        row["metadata"] = self.json_file(row["metadata"]["path"], metadata)
        self.save()
        with self.assertRaisesRegex(ValueError, "browser /web export"):
            self.verify()

    def test_cargo_dependency_cannot_resolve_to_npm_namesake(self):
        engine = self.document["packages"][-1]
        sdk = self.document["packages"].pop(1)
        npm = {"id": "sdk", "role": "browser", "name": sdk["name"], "version": sdk["version"],
               "format": "npm", "metadata": self.json_file("packages/namesake/package.json", {
                   "name": sdk["name"], "version": sdk["version"], "exports": {"./web": "./web/index.js"}}),
               "workspace": None, "dependencies": [], "interfaces": [], "artifacts": [], "assessments": []}
        self.document["packages"].insert(1, npm)
        # A normal Cargo consumer may depend on the earlier node by ID, but
        # actual Cargo resolution still must find a Cargo package, not npm.
        engine["role"] = "service"
        additional_engine = self.cargo("other-engine", "engine", "q-periapt-continuity", "0.0.0")
        self.document["packages"].append(additional_engine)
        self.save()
        with self.assertRaisesRegex(ValueError, "Cargo dependency missing from package graph"):
            self.verify()

    def test_cargo_nodes_cannot_stand_in_for_foreign_distribution_surfaces(self):
        for role in ("native", "swift", "kotlin", "android"):
            self.document["packages"][0]["role"] = role
            self.save()
            with self.subTest(role=role), self.assertRaisesRegex(ValueError, "actual surface format"):
                self.verify()

    def test_release_browser_cargo_bridge_does_not_replace_npm_surface(self):
        self.release_fixture()
        previous = next(row for row in self.document["packages"] if row["role"] == "browser" and row["format"] == "npm")
        self.document["packages"].remove(previous)
        self.save()
        with self.assertRaisesRegex(ValueError, "actual npm package"):
            self.verify()

    def test_interface_namespaces_and_exports_cannot_be_mixed(self):
        original = copy.deepcopy(self.document["interfaces"])
        for field, value, message in (("abi", 2, "ABI namespace"),
                                       ("exports", ["q_periapt_abi_version"], "export inventory"),
                                       ("exports", [], "nonempty and sorted")):
            self.document["interfaces"] = copy.deepcopy(original)
            self.document["interfaces"]["continuity_c"][field] = value
            self.save()
            with self.subTest(field=field, value=value), self.assertRaisesRegex(ValueError, message):
                self.verify()

    def test_lock_hashes_are_checked_without_silently_regenerating_them(self):
        for field in ("package_graph_sha256", "interfaces_sha256"):
            self.save()
            changed = copy.deepcopy(self.lock)
            changed[field] = "0" * 64
            self.document["spec_lock"] = self.json_file("SPEC_LOCK.json", changed)
            self.selected = self.json_file("MANIFEST.json", self.document)
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "differ[s]? from the specification lock"):
                self.verify()

    def test_missing_normative_file_and_changed_bytes_are_rejected(self):
        ref = self.lock["normative_files"]["wire"]
        original = (self.root / ref["path"]).read_bytes()
        (self.root / ref["path"]).unlink()
        with self.assertRaises(ValueError):
            self.verify()
        self.file(ref["path"], original + b"unreviewed change")
        with self.assertRaisesRegex(ValueError, "file bytes or digest differ"):
            self.verify()

    def test_declared_artifact_must_exist_and_match_even_for_a_candidate(self):
        ref = self.file("artifacts/engine.crate", b"synthetic archive fixture")
        self.document["packages"][-1]["artifacts"] = [ref]
        self.save()
        self.assertEqual(self.verify()["artifacts"], 1)
        (self.root / ref["path"]).unlink()
        with self.assertRaises(ValueError):
            self.verify()
        self.file(ref["path"], b"a different archive fixture")
        with self.assertRaisesRegex(ValueError, "file bytes or digest differ"):
            self.verify()

    def test_duplicate_json_keys_and_noncanonical_paths_are_rejected(self):
        content = manifest.canonical_json_bytes(self.document)
        content = b'{"stage":"release",' + content.lstrip()[1:]
        self.selected = self.file("MANIFEST.json", content)
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            self.verify()
        for path in ("../outside", "/absolute", "spec/./wire.md", "spec\\wire.md"):
            self.lock["normative_files"]["wire"]["path"] = path
            self.save()
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "canonical relative path"):
                self.verify()

    def test_symlinked_input_is_rejected(self):
        path = self.root / self.lock["normative_files"]["wire"]["path"]
        original = path.with_name("original-wire.md")
        path.rename(original)
        try:
            path.symlink_to(original.name)
        except (OSError, NotImplementedError) as error:
            self.skipTest(f"symlinks unavailable: {error}")
        with self.assertRaises(ValueError):
            self.verify()

    def test_mid_verification_input_change_is_not_a_completed_inventory(self):
        original = manifest._packages

        def change_after_packages(*args, **kwargs):
            result = original(*args, **kwargs)
            self.file(self.lock["normative_files"]["wire"]["path"], b"changed after the first read")
            return result

        with patch.object(manifest, "_packages", side_effect=change_after_packages), \
                self.assertRaisesRegex(ValueError, "file bytes or digest differ"):
            self.verify()

    def test_compiled_descriptor_requires_separate_exact_bytes(self):
        self.lock["compiled_descriptor"] = self.lock["normative_files"]["budgets"]
        self.save()
        with self.assertRaisesRegex(ValueError, "separate retained output"):
            self.verify()
        self.lock["compiled_descriptor"] = self.json_file("compiled/descriptor.json", self.budgets)
        self.save()
        self.assertTrue(self.verify()["compiled_descriptor_matched"])
        altered = copy.deepcopy(self.budgets)
        altered["maximums"]["plaintext_bytes"] += 1
        self.lock["compiled_descriptor"] = self.json_file("compiled/descriptor.json", altered)
        self.save()
        with self.assertRaisesRegex(ValueError, "compiled descriptor differs"):
            self.verify()

    def test_complete_release_identity_still_does_not_authorize_release(self):
        self.release_fixture()
        result = self.verify()
        self.assertTrue(result["completed"])
        self.assertTrue(result["compiled_descriptor_matched"])
        self.assertEqual(result["missing_release_roles"], [])
        self.assertFalse(result["release_claim_eligible"])
        self.assertFalse(result["publication_performed"])

    def test_release_requires_all_selected_artifacts_and_completed_assessments(self):
        self.release_fixture()
        row = self.document["packages"][0]
        original = row["artifacts"]
        row["artifacts"] = []
        self.save()
        with self.assertRaisesRegex(ValueError, "package artifacts is missing"):
            self.verify()
        row["artifacts"] = original
        row["assessments"] = [self.json_file("assessments/incomplete.json", {"kind": "unit.incomplete", "completed": False})]
        self.save()
        with self.assertRaisesRegex(ValueError, "incomplete assessment"):
            self.verify()

    def test_release_rejects_incomplete_surface_and_unfrozen_abi(self):
        self.release_fixture()
        service = self.document["packages"].pop()
        self.save()
        with self.assertRaisesRegex(ValueError, "omits an agreed surface"):
            self.verify()
        self.document["packages"].append(service)
        self.owner_abi["frozen_product_contract"] = False
        self.interfaces["continuity_c"]["contract"] = self.json_file("abi/owner.json", self.owner_abi)
        self.save()
        with self.assertRaisesRegex(ValueError, "identity or freeze state"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
