"""Source/capsule binding and failure controls for the explicit projection plan."""

from __future__ import annotations

from contextlib import contextmanager, ExitStack
import copy
import gzip
import hashlib
import io
import json
import os
import stat
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

import codeql_summary_control as control
import codeql_summary_plan as capsule
import codeql_summary_projection as projection
from evidence_io import EvidenceIOError
from test_codeql_summary_control import COMPILED_HASHES, FULL_SUMMARY, QUERY_HASHES, valid_report
from test_codeql_summary_plan import candidate_report


ORIGINAL = b"one\nread\nthree\nfour\nfive\n"
PROJECTED = b"one\ntarget\nkept full\nthree\nfour\nelse\nfive\n"
PATCH = ("--- a/" + projection.PATCH_PATH + "\n+++ b/" + projection.PATCH_PATH + "\n"
         "@@ -1,3 +1,4 @@\n one\n-read\n+target\n+kept full\n three\n"
         "@@ -4,2 +5,3 @@\n four\n+else\n five\n").encode()
OTHER_DEPENDENCY = "codeql/dataflow/2.1.15/codeql/Other.qll"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_identity(data):
    return {"bytes": len(data), "sha256": digest(data)}


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


@contextmanager
def pack_case():
    """Use the real frozen capsule with small, explicitly synthetic source inputs."""
    with tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
        root = Path(folder).resolve()
        pack, evidence = root / "pack", root / "evidence"
        (pack / ".codeql/precompiled").mkdir(parents=True)
        evidence.mkdir()
        value = copy.deepcopy(projection.manifest())
        query_hashes, compiled = {}, {}
        for name in QUERY_HASHES:
            source, plan = ("source: " + name + "\n").encode(), ("bundled: " + name + "\n").encode()
            write(pack / name, source)
            write((pack / name).with_suffix(".qlx"), plan)
            query_hashes[name], compiled[name] = digest(source), digest(plan)
        original_plan = (pack / projection.PLAN_PATH).read_bytes()
        query_manifest = root / "queries.json"
        query_manifest.write_text(json.dumps({"codeql_version": "2.27.2", "query_pack": "0.1.44",
                                              "queries": query_hashes}))
        value["query_manifest_sha256"] = digest(query_manifest.read_bytes())
        value["query_source_sha256"] = query_hashes[FULL_SUMMARY]
        value["bundled_plan_sha256"] = digest(original_plan)
        value["bundled_compiled_inventory_sha256"] = projection.canonical_sha(compiled)
        compiled[FULL_SUMMARY] = projection.PLAN_SHA256
        value["compiled_inventory_sha256"] = projection.canonical_sha(compiled)
        support_name = "queries/summary/Stats.qll"
        support = b"synthetic unchanged support\n"
        write(pack / support_name, support)
        value["query_pack_support_files"] = {support_name: file_identity(support)}
        original = {projection.DEPENDENCY_PATH: file_identity(ORIGINAL),
                    OTHER_DEPENDENCY: file_identity(b"unchanged dependency\n")}
        candidate = {**original, projection.DEPENDENCY_PATH: file_identity(PROJECTED)}
        libraries = pack / ".codeql/libraries"
        write(libraries / projection.DEPENDENCY_PATH, ORIGINAL)
        write(libraries / OTHER_DEPENDENCY, b"unchanged dependency\n")
        vendor_patch = root / "vendor.patch"
        vendor_patch.write_bytes(PATCH)
        value["vendor_patch"].update(file_identity(PATCH), upstream=original[projection.DEPENDENCY_PATH],
                                     effective=candidate[projection.DEPENDENCY_PATH])
        inventories = {"original": original, "candidate": candidate}
        raw = json.dumps(inventories, sort_keys=True).encode()
        dependencies = root / "dependencies.json.gz"
        dependencies.write_bytes(gzip.compress(raw, mtime=0))
        value["dependency_inventory"].update(file_identity(dependencies.read_bytes()), expanded_bytes=len(raw),
                                             file_count=2, upstream_inventory_sha256=projection.canonical_sha(original),
                                             effective_inventory_sha256=projection.canonical_sha(candidate))
        fixed_capsule = root / "capsule.zip"
        fixed_capsule.write_bytes(projection.CAPSULE.read_bytes())
        for name, replacement in (("manifest", None), ("QUERY_MANIFEST", query_manifest), ("PATCH", vendor_patch),
                                  ("DEPENDENCIES", dependencies), ("CAPSULE", fixed_capsule)):
            stack.enter_context(patch.object(projection, name, return_value=value) if name == "manifest"
                                else patch.object(projection, name, replacement))
        yield SimpleNamespace(root=root, pack=pack, evidence=evidence, value=value, libraries=libraries,
                              vendor=libraries / projection.DEPENDENCY_PATH, patch=vendor_patch,
                              dependencies=dependencies, inventories=inventories, capsule=fixed_capsule,
                              original_plan=original_plan, support=pack / support_name,
                              stage=next(name for name in value["files"] if name != projection.PLAN_PATH))


def projection_report(profile):
    report = valid_report(profile)
    report["summary_plan_mode"] = "projection"
    report["summary_plan"] = projection.expected_identity()
    report["summary_plan_after"] = projection.expected_identity()
    report["compiled_query_hashes"][FULL_SUMMARY] = projection.PLAN_SHA256
    command = control.query_command(Path("/tool/codeql"), Path("/case/database"), Path("/case"), profile, "projection")
    report["query_command"] = command
    report["evaluation"]["command"] = command
    report["observations"].update(
        precompiled_query_loads=[str((Path("/tool/qlpacks/codeql/rust-queries/0.1.44") / name).with_suffix(".qlx"))
                                 for name in QUERY_HASHES], query_compilations=0)
    return report


class FixedProjectionInputsTests(unittest.TestCase):
    def test_frozen_inputs_bind_one_vendor_change_and_original_38_plans(self):
        value = projection.manifest()
        inventory, vendor_patch, _ = projection.source_inputs(value)
        self.assertEqual(digest(projection.CAPSULE.read_bytes()),
                         "d90df7ba37cc05bfa7f603f74e9758b9dd0d791920b9e67b42d66414196dcbdf")
        self.assertEqual(digest(vendor_patch), "737949e5e1c26a7cae8e8049f7f96b8fd0a041c4d3e0b1e1c6c4bdaaf803c75a")
        self.assertEqual(len(inventory["original"]), 1175)
        self.assertEqual({name for name in inventory["original"]
                          if inventory["original"][name] != inventory["candidate"][name]}, {projection.DEPENDENCY_PATH})
        self.assertEqual(value["compiler_inputs_digest"], "0ee092250be1b05f03b994a868d639cc")
        self.assertEqual(value["query_source_sha256"], QUERY_HASHES[FULL_SUMMARY])
        self.assertEqual(len(value["query_pack_support_files"]), 9)
        compiled = {**COMPILED_HASHES, FULL_SUMMARY: projection.PLAN_SHA256}
        self.assertEqual(projection.canonical_sha(compiled), projection.COMPILED_INVENTORY_SHA256)
        self.assertNotEqual(projection.COMPILED_INVENTORY_SHA256, capsule.COMPILED_INVENTORY_SHA256)

    def test_mutated_manifest_cannot_choose_a_different_patch_or_inventory(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / projection.MANIFEST.name
            value = projection.manifest()
            value["vendor_patch"]["sha256"] = "0" * 64
            path.write_text(json.dumps(value))
            with patch.object(projection, "MANIFEST", path), self.assertRaisesRegex(capsule.PlanError, "manifest digest"):
                projection.manifest()

    def test_fixed_capsule_header_requires_projection_key_and_exact_15_stages(self):
        value = projection.manifest()
        with zipfile.ZipFile(projection.CAPSULE) as archive:
            data = archive.read(projection.PLAN_PATH)
        capsule.admit_header(data, value["files"], compiler_inputs_digest=projection.COMPILER_INPUTS_DIGEST)
        with self.assertRaisesRegex(capsule.PlanError, "compiler input key"):
            capsule.admit_header(data, value["files"])
        changed = data.replace(projection.COMPILER_INPUTS_DIGEST.encode(), capsule.COMPILER_INPUTS_DIGEST.encode())
        with self.assertRaisesRegex(capsule.PlanError, "compiler input key"):
            capsule.admit_header(changed, value["files"], compiler_inputs_digest=projection.COMPILER_INPUTS_DIGEST)
        stage = next(name for name in value["files"] if name != projection.PLAN_PATH)
        changed = data.replace(("- filename: " + Path(stage).name + "\n").encode(), b"")
        with self.assertRaisesRegex(capsule.PlanError, "stage closure"):
            capsule.admit_header(changed, value["files"], compiler_inputs_digest=projection.COMPILER_INPUTS_DIGEST)


class ExactVendorPatchTests(unittest.TestCase):
    def test_multiple_hunks_apply_at_exact_original_and_result_coordinates(self):
        self.assertEqual(projection.apply_vendor_patch(ORIGINAL, PATCH), PROJECTED)

    def test_no_fuzz_second_file_or_ambiguous_hunk_is_accepted(self):
        variants = {
            "changed_preimage": (ORIGINAL.replace(b"read", b"wrong"), PATCH),
            "wrong_original_position": (ORIGINAL, PATCH.replace(b"@@ -1,3", b"@@ -2,3")),
            "wrong_result_position": (ORIGINAL, PATCH.replace(b"+5,3 @@", b"+4,3 @@")),
            "wrong_line_count": (ORIGINAL, PATCH.replace(b"@@ -1,3", b"@@ -1,4")),
            "second_file": (ORIGINAL, PATCH + b"--- a/other\n+++ b/other\n"),
            "wrong_file": (ORIGINAL, PATCH.replace(b"internal/DataFlowImpl", b"internal/Other")),
            "overlapping_hunk": (ORIGINAL, PATCH + PATCH.split(b"@@ -1,3", 1)[0] + b"@@ -1,3 +1,4 @@\n"),
            "unconsumed_suffix": (ORIGINAL, PATCH + b"unexpected\n"),
            "no_hunks": (ORIGINAL, b"".join(PATCH.splitlines(keepends=True)[:2])),
        }
        for name, (source, vendor_patch) in variants.items():
            with self.subTest(name=name), self.assertRaises(capsule.PlanError):
                projection.apply_vendor_patch(source, vendor_patch)


class ProjectionInstallationTests(unittest.TestCase):
    def assert_rejected_before_pack_mutation(self, case):
        before = (case.pack / projection.PLAN_PATH).read_bytes()
        with self.assertRaises((capsule.PlanError, EvidenceIOError, OSError)):
            projection.install(case.pack, case.evidence)
        self.assertEqual((case.pack / projection.PLAN_PATH).read_bytes(), before)
        self.assertEqual(list(case.evidence.iterdir()), [])

    def test_real_capsule_is_installed_with_actual_embedded_patch_and_retained_inputs(self):
        with pack_case() as case:
            original_queries = {name: (case.pack / name).read_bytes() for name in QUERY_HASHES}
            other_plans = {name: (case.pack / name).with_suffix(".qlx").read_bytes()
                           for name in QUERY_HASHES if name != FULL_SUMMARY}
            identity = projection.install(case.pack, case.evidence)
            self.assertEqual(identity, projection.validate(case.pack))
            self.assertEqual(case.vendor.read_bytes(), PROJECTED)
            self.assertEqual((case.evidence / "SUMMARY_PLAN_VENDOR_ORIGINAL.qll").read_bytes(), ORIGINAL)
            self.assertEqual((case.evidence / "SUMMARY_PLAN_VENDOR_PATCH.patch").read_bytes(), PATCH)
            self.assertEqual((case.evidence / "SUMMARY_PLAN_DEPENDENCIES.json.gz").read_bytes(), case.dependencies.read_bytes())
            self.assertEqual((case.evidence / "SUMMARY_PLAN_ORIGINAL.qlx").read_bytes(), case.original_plan)
            self.assertEqual(json.loads((case.evidence / "SUMMARY_PLAN.json").read_bytes()), identity)
            self.assertEqual({name: (case.pack / name).read_bytes() for name in QUERY_HASHES}, original_queries)
            self.assertEqual({name: (case.pack / name).with_suffix(".qlx").read_bytes() for name in other_plans}, other_plans)
            self.assertFalse(list(case.pack.rglob("*.projection-incoming")))

    def test_changed_source_query_support_or_other_compiled_plan_is_rejected(self):
        for name in ("vendor", "dependency", "root_query", "other_query", "other_qlx", "support"):
            with self.subTest(name=name), pack_case() as case:
                other = next(query for query in QUERY_HASHES if query != FULL_SUMMARY)
                path = {"vendor": case.vendor, "dependency": case.libraries / OTHER_DEPENDENCY,
                        "root_query": case.pack / FULL_SUMMARY, "other_query": case.pack / other,
                        "other_qlx": (case.pack / other).with_suffix(".qlx"), "support": case.support}[name]
                path.write_bytes(b"changed\n")
                self.assert_rejected_before_pack_mutation(case)

    def test_inventory_rejects_missing_extra_empty_directory_link_and_special_file(self):
        for mutation in ("missing", "extra", "empty_directory", "file_link", "directory_link", "fifo"):
            with self.subTest(mutation=mutation), pack_case() as case:
                path = case.libraries / OTHER_DEPENDENCY
                if mutation == "missing":
                    path.unlink()
                elif mutation == "extra":
                    path.with_name("extra.qll").write_bytes(b"extra")
                elif mutation == "empty_directory":
                    path.with_name("extra").mkdir()
                elif mutation == "file_link":
                    outside = case.root / "same-dependency"
                    path.rename(outside)
                    path.symlink_to(outside)
                elif mutation == "directory_link":
                    outside = case.root / "same-libraries"
                    case.libraries.rename(outside)
                    case.libraries.symlink_to(outside, target_is_directory=True)
                else:
                    path.unlink()
                    os.mkfifo(path)
                self.assert_rejected_before_pack_mutation(case)

    def test_patch_inventory_and_capsule_tampering_are_rejected_before_any_write(self):
        for name in ("patch", "dependencies", "capsule"):
            with self.subTest(name=name), pack_case() as case:
                path = getattr(case, name)
                data = bytearray(path.read_bytes())
                data[-1] ^= 1
                path.write_bytes(data)
                self.assert_rejected_before_pack_mutation(case)

    def test_self_consistent_second_vendor_change_cannot_expand_the_patch_scope(self):
        with pack_case() as case:
            case.inventories["candidate"][OTHER_DEPENDENCY] = file_identity(b"second change")
            raw = json.dumps(case.inventories).encode()
            case.dependencies.write_bytes(gzip.compress(raw, mtime=0))
            case.value["dependency_inventory"].update(file_identity(case.dependencies.read_bytes()),
                expanded_bytes=len(raw), effective_inventory_sha256=projection.canonical_sha(case.inventories["candidate"]))
            self.assert_rejected_before_pack_mutation(case)

    def test_patched_result_must_equal_the_pinned_effective_source(self):
        with pack_case() as case:
            changed = PATCH.replace(b"+target\n", b"+another\n")
            case.patch.write_bytes(changed)
            case.value["vendor_patch"].update(file_identity(changed))
            self.assert_rejected_before_pack_mutation(case)

    def test_capsule_census_type_member_hash_and_header_are_independently_checked(self):
        for mutation in ("missing", "extra", "duplicate", "symlink", "member_hash", "old_compiler_key"):
            with self.subTest(mutation=mutation), pack_case() as case:
                with zipfile.ZipFile(case.capsule) as archive:
                    members = [(item, archive.read(item)) for item in archive.infolist()]
                if mutation == "missing":
                    members.pop(0)
                elif mutation == "extra":
                    item = zipfile.ZipInfo(".codeql/precompiled/extra.bytes.qlx")
                    item.external_attr = (stat.S_IFREG | 0o400) << 16
                    members.append((item, b"extra"))
                elif mutation == "duplicate":
                    members.append(members[0])
                elif mutation == "symlink":
                    members[0][0].external_attr = (stat.S_IFLNK | 0o777) << 16
                elif mutation == "member_hash":
                    item, data = members[0]
                    members[0] = (item, b"X" + data[1:])
                else:
                    for index, (item, data) in enumerate(members):
                        if item.filename == projection.PLAN_PATH:
                            changed = data.replace(projection.COMPILER_INPUTS_DIGEST.encode(), capsule.COMPILER_INPUTS_DIGEST.encode())
                            members[index] = (item, changed)
                            case.value["files"][item.filename] = file_identity(changed)
                output = io.BytesIO()
                with zipfile.ZipFile(output, "w") as archive:
                    with self.assertWarns(UserWarning) if mutation == "duplicate" else ExitStack():
                        for item, data in members:
                            archive.writestr(item, data)
                raw = output.getvalue()
                case.capsule.write_bytes(raw)
                case.value.update(capsule_bytes=len(raw), capsule_sha256=digest(raw))
                self.assert_rejected_before_pack_mutation(case)

    def test_stage_collision_or_symlinked_stage_parent_is_rejected(self):
        for mutation in ("stage_exists", "stage_parent_link", "pending_source", "pending_plan"):
            with self.subTest(mutation=mutation), pack_case() as case:
                if mutation == "stage_exists":
                    (case.pack / case.stage).write_bytes(b"existing")
                elif mutation == "stage_parent_link":
                    parent = case.pack / ".codeql/precompiled"
                    parent.rmdir()
                    outside = case.root / "stages"
                    outside.mkdir()
                    parent.symlink_to(outside, target_is_directory=True)
                elif mutation == "pending_source":
                    case.vendor.with_name(".DataFlowImpl.qll.projection-incoming").write_bytes(b"existing")
                else:
                    (case.pack / projection.PLAN_PATH).with_name(".SummaryStats.qlx.projection-incoming").write_bytes(b"existing")
                self.assert_rejected_before_pack_mutation(case)

    def test_partial_write_failure_cannot_commit_plan_or_vendor_source(self):
        with pack_case() as case:
            real_write = capsule.write_exclusive
            def fail_stage(path, data):
                if path.parent.name == "precompiled":
                    raise OSError("injected disk write failure")
                real_write(path, data)
            with patch.object(capsule, "write_exclusive", side_effect=fail_stage), self.assertRaises(OSError):
                projection.install(case.pack, case.evidence)
            self.assertEqual((case.pack / projection.PLAN_PATH).read_bytes(), case.original_plan)
            self.assertEqual(case.vendor.read_bytes(), ORIGINAL)
            self.assertFalse((case.evidence / "SUMMARY_PLAN.json").exists())
            with self.assertRaises(capsule.PlanError):
                projection.install(case.pack, case.root / "retry-evidence")

    def test_postcheck_rejects_dependency_query_plan_support_and_stage_mutation(self):
        for mutation in ("vendor", "dependency", "extra_dependency", "query", "other_plan", "support",
                         "missing_stage", "changed_stage", "linked_stage", "patched_twice"):
            with self.subTest(mutation=mutation), pack_case() as case:
                projection.install(case.pack, case.evidence)
                other = next(name for name in QUERY_HASHES if name != FULL_SUMMARY)
                if mutation == "patched_twice":
                    with self.assertRaises(capsule.PlanError):
                        projection.install(case.pack, case.evidence)
                    continue
                stage = case.pack / case.stage
                if mutation == "missing_stage":
                    stage.unlink()
                elif mutation == "linked_stage":
                    outside = case.root / "same-stage"
                    stage.rename(outside)
                    stage.symlink_to(outside)
                else:
                    path = {"vendor": case.vendor, "dependency": case.libraries / OTHER_DEPENDENCY,
                            "extra_dependency": case.libraries / "extra.qll", "query": case.pack / other,
                            "other_plan": (case.pack / other).with_suffix(".qlx"), "support": case.support,
                            "changed_stage": stage}[mutation]
                    if path.exists():
                        path.unlink()
                    path.write_bytes(b"changed after evaluator\n")
                with self.assertRaises((capsule.PlanError, EvidenceIOError, OSError)):
                    projection.validate(case.pack)


class ProjectionComparisonTests(unittest.TestCase):
    def test_explicit_projection_preserves_all_39_and_retained_38_result_requirements(self):
        result = control.compare_reports(projection_report("heap-2048"), projection_report("heap-1536"), "projection")
        self.assertTrue(result["completed"])
        self.assertEqual(result["summary_plan_mode"], "projection")
        self.assertEqual(result["query_count"], 39)
        self.assertEqual(result["retained_result_count"], 38)
        self.assertFalse(result["production_default_validated"])

    def test_projection_uses_all_evaluator_option_but_remains_a_distinct_admission(self):
        args = (Path("/tool/codeql"), Path("/case/database"), Path("/case"), "heap-2048")
        self.assertEqual(control.query_command(*args, "projection"), control.query_command(*args, "all"))
        for wrong in ("project", "all,projection", ""):
            with self.subTest(wrong=wrong), self.assertRaises(control.ControlError):
                control.query_command(*args, wrong)
        for mode in ("none", "all"):
            with self.subTest(mode=mode), self.assertRaises(control.ControlError):
                control.compare_reports(projection_report("heap-2048"), projection_report("heap-1536"), mode)
        for report in (valid_report("heap-1536"), candidate_report("heap-1536")):
            with self.assertRaises(control.ControlError):
                control.compare_reports(projection_report("heap-2048"), report, "projection")

    def test_matching_forged_vendor_or_compiler_identities_in_both_arms_are_rejected(self):
        for field in ("vendor_patch", "dependency_inventory", "compiler_inputs_digest", "manifest_sha256", "files"):
            with self.subTest(field=field):
                reports = [projection_report("heap-2048"), projection_report("heap-1536")]
                for report in reports:
                    for key in ("summary_plan", "summary_plan_after"):
                        report[key][field] = "self-consistent forged identity"
                with self.assertRaises(control.ControlError):
                    control.compare_reports(*reports, "projection")

    def test_full_results_zero_compile_and_postcheck_are_required(self):
        for mutation in ("missing_summary", "partial_timeout", "retained_mismatch", "full_semantics",
                         "compiler_fallback", "missing_load", "missing_postcheck", "other_qlx"):
            with self.subTest(mutation=mutation):
                a, b = projection_report("heap-2048"), projection_report("heap-1536")
                if mutation == "missing_summary":
                    b["results"].pop(FULL_SUMMARY)
                elif mutation == "partial_timeout":
                    b["evaluation"].update(returncode=None, stopped="timeout")
                    b["completed"] = False
                elif mutation == "retained_mismatch":
                    name = next(iter(b["retained_results"]))
                    a["results"][name]["semantic_sha256"] = b["results"][name]["semantic_sha256"] = "f" * 64
                elif mutation == "full_semantics":
                    b["results"][FULL_SUMMARY]["semantic_sha256"] = "f" * 64
                elif mutation == "compiler_fallback":
                    b["observations"]["query_compilations"] = 1
                elif mutation == "missing_load":
                    b["observations"]["precompiled_query_loads"].pop()
                elif mutation == "missing_postcheck":
                    b.pop("summary_plan_after")
                else:
                    name = next(query for query in QUERY_HASHES if query != FULL_SUMMARY)
                    a["compiled_query_hashes"][name] = b["compiled_query_hashes"][name] = "f" * 64
                with self.assertRaises(control.ControlError):
                    control.compare_reports(a, b, "projection")

    def test_none_and_all_do_not_read_projection_assets(self):
        with patch.object(projection, "manifest", side_effect=AssertionError("projection must be explicit")):
            self.assertTrue(control.compare_reports(valid_report("heap-2048"), valid_report("heap-1536"))["completed"])
            self.assertTrue(control.compare_reports(candidate_report("heap-2048"), candidate_report("heap-1536"), "all")["completed"])

    def test_each_tool_field_and_query_manifest_remains_bound_to_the_selected_capsule(self):
        tool = valid_report("heap-2048")["tool_identity"]
        for plan in (capsule, projection):
            control.validate_plan_tool(plan, tool)
            for key in ("codeql_version", "query_pack", "tool_bundle_bytes", "tool_bundle_sha256", "query_manifest_sha256"):
                with self.subTest(mode=plan.__name__, key=key):
                    value = plan.manifest()
                    value[key] = "different admitted tool"
                    with patch.object(plan, "manifest", return_value=value), self.assertRaises(control.ControlError):
                        control.validate_plan_tool(plan, tool)

    def test_failed_projection_admission_never_starts_a_probe_or_evaluator(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            output = root / "case"
            queries = {name: Path("/unused/queries") / name for name in QUERY_HASHES}
            with patch.dict(os.environ, {"RUNNER_TEMP": str(root)}), \
                    patch.object(control, "prepare_database", return_value=(output / "database", {})), \
                    patch.object(control, "admit_tool", return_value=(queries, valid_report("heap-2048")["tool_identity"], QUERY_HASHES, COMPILED_HASHES, control.SOURCE_ALLOCATION)), \
                    patch.object(projection, "install", side_effect=capsule.PlanError("projection source mismatch")), \
                    patch.object(control, "jvm_probe") as probe, patch.object(control, "run_queries") as evaluate:
                with self.assertRaisesRegex(RuntimeError, "Retained SummaryStats control failed"):
                    control.evaluate(Path("/unused/codeql"), Path("/unused/bundle"), output, "heap-2048", "projection")
                probe.assert_not_called()
                evaluate.assert_not_called()
            report = json.loads((output / "evidence/RESULT.json").read_bytes())
            self.assertEqual(report["failure"], {"phase": "install_summary_plan", "type": "PlanError",
                                               "message": "projection source mismatch"})
            self.assertFalse(report["completed"])

    def test_changed_admitted_tool_is_rejected_before_install_probe_or_evaluator(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            output = root / "case"
            queries = {name: Path("/unused/queries") / name for name in QUERY_HASHES}
            tool = valid_report("heap-2048")["tool_identity"]
            tool["tool_bundle_sha256"] = "a" * 64
            with patch.dict(os.environ, {"RUNNER_TEMP": str(root)}), \
                    patch.object(control, "prepare_database", return_value=(output / "database", {})), \
                    patch.object(control, "admit_tool", return_value=(queries, tool, QUERY_HASHES, COMPILED_HASHES, control.SOURCE_ALLOCATION)), \
                    patch.object(projection, "install") as install, \
                    patch.object(control, "jvm_probe") as probe, patch.object(control, "run_queries") as evaluate:
                with self.assertRaises(RuntimeError):
                    control.evaluate(Path("/unused/codeql"), Path("/unused/bundle"), output, "heap-2048", "projection")
                install.assert_not_called()
                probe.assert_not_called()
                evaluate.assert_not_called()
            report = json.loads((output / "evidence/RESULT.json").read_bytes())
            self.assertEqual(report["failure"]["phase"], "install_summary_plan")
            self.assertIn("tool or query-manifest binding differs", report["failure"]["message"])

    def test_projection_postcheck_runs_after_evaluator_failure_without_replacing_it(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            output = root / "case"
            queries = {name: Path("/unused/queries") / name for name in QUERY_HASHES}
            compiled = {**COMPILED_HASHES, FULL_SUMMARY: projection.PLAN_SHA256}
            hashes = {str(path): QUERY_HASHES[name] for name, path in queries.items()}
            hashes.update({str(path.with_suffix(".qlx")): compiled[name] for name, path in queries.items()})
            real_sha = control.sha
            def lookup(path):
                return hashes[str(path)] if str(path) in hashes else real_sha(path)
            def failed_evaluator(command, evidence, environment, *, progress_queries=None):
                self.assertEqual(set(progress_queries), set(queries))
                control.write_json(evidence / "query.json", {"command": command, "returncode": None,
                    "stopped": "timeout", "cleanup_ambiguous": False, "seconds": 18001})
                raise RuntimeError("injected stopped evaluator")
            with patch.dict(os.environ, {"RUNNER_TEMP": str(root)}), \
                    patch.object(control, "prepare_database", return_value=(output / "database", {})), \
                    patch.object(control, "admit_tool", return_value=(queries, valid_report("heap-2048")["tool_identity"], QUERY_HASHES, COMPILED_HASHES, control.SOURCE_ALLOCATION)), \
                    patch.object(control, "sha", side_effect=lookup), \
                    patch.object(projection, "install", return_value=projection.expected_identity()), \
                    patch.object(projection, "validate", side_effect=capsule.PlanError("changed vendor source")) as postcheck, \
                    patch.object(control, "jvm_probe", return_value=valid_report("heap-2048")["jvm_admission"]), \
                    patch.object(control, "decode_retained_results", return_value={}), \
                    patch.object(control, "evaluator_observations", return_value={}), \
                    patch.object(control, "retain_partial_results", return_value={}), \
                    patch.object(control, "run_queries", side_effect=failed_evaluator):
                with self.assertRaisesRegex(RuntimeError, "Retained SummaryStats control failed"):
                    control.evaluate(Path("/unused/codeql"), Path("/unused/bundle"), output, "heap-2048", "projection")
                postcheck.assert_called_once()
            report = json.loads((output / "evidence/RESULT.json").read_bytes())
            self.assertEqual(report["failure"]["type"], "RuntimeError")
            self.assertEqual(report["failure"]["phase"], "evaluate")
            self.assertEqual(report["evaluation"]["stopped"], "timeout")
            self.assertEqual(report["summary_plan_after_failure"], {"type": "PlanError", "message": "changed vendor source"})
            self.assertFalse(report["completed"])


if __name__ == "__main__":
    unittest.main()
