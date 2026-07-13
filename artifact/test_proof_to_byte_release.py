#!/usr/bin/env python3

from __future__ import annotations

import copy
import hashlib
import importlib._bootstrap_external
import importlib.util
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from camera_ready_proof import EXPECTED_TOOLS
from git_provenance import WorktreeInspection, git_commit
import proof_to_byte_finalizer


ROOT = pathlib.Path(__file__).resolve().parents[1]
PROOF_SCRIPT = ROOT / "artifact" / "proof-to-byte.sh"
CAMERA_READY_SCRIPT = ROOT / "camera-ready-bare-metal.sh"
CAMERA_SANDBOX_SCRIPT = ROOT / "artifact" / "camera-ready-sandbox.sh"
ARTIFACT_GUIDE = ROOT / "ARTIFACT.md"
PAPER_SOURCE = ROOT / "paper" / "q-periapt.tex"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
RUST_PUBLISH_SCRIPT = ROOT / "artifact" / "rust-publish-dry-run.sh"
RUST_PUBLISH_CONTRACT = ROOT / "artifact" / "rust_publish_contract.py"
RUST_PUBLISH_CONTRACT_TESTS = ROOT / "artifact" / "test_rust_publish_contract.py"
FINALIZER_SCRIPT = ROOT / "artifact" / "proof_to_byte_finalizer.py"
XCODE27_GATE = ROOT / "artifact" / "apple-device-xcode27-gate.sh"
TEST_COMMIT = "a" * 40
TEST_SOURCE_SHA256 = "b" * 64
TEST_MANIFEST_SHA256 = "c" * 64
PINNED_CHECKOUT_ACTION = (
    "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0"
)
EXPECTED_CHECKOUT_STEP = (
    f"      - uses: {PINNED_CHECKOUT_ACTION}\n"
    "        with:\n"
    "          persist-credentials: false\n"
    "          fetch-depth: 0\n"
)
EXPECTED_CHECKOUT_PROVENANCE_STEP = (
    "      - name: Verify checkout provenance\n"
    "        env:\n"
    "          EXPECTED_COMMIT: ${{ github.sha }}\n"
    "        run: |\n"
    "          actual_commit=$(git rev-parse --verify 'HEAD^{commit}')\n"
    '          if [ "$actual_commit" != "$EXPECTED_COMMIT" ]; then\n'
    '            echo "checked-out HEAD $actual_commit does not match GitHub commit $EXPECTED_COMMIT" >&2\n'
    "            exit 1\n"
    "          fi\n"
)
EXPECTED_PROOF_TO_BYTE_STEP = (
    "      - name: Proof-to-byte manifest and canonical source binding\n"
    "        env:\n"
    "          QPERIAPT_EXPECTED_GIT_COMMIT: ${{ github.sha }}\n"
    "        run: QPERIAPT_SKIP_SMOKE=1 sh artifact/proof-to-byte.sh\n"
)
YAML_ALIAS = re.compile(
    r"(?m)(?:^|[ \t:\-\[,{}])\*[^\s\[\]{},]+"
)

CONTINUITY_PROOF_INPUTS = {
    "continuity_context_spec_sha256": "docs/continuity/LIFECYCLE_CONTEXT_V1.md",
    "continuity_context_model_sha256": "models/q-periapt-continuity-model/src/context.rs",
    "continuity_context_tests_sha256": "models/q-periapt-continuity-model/tests/context.rs",
    "continuity_context_vectors_sha256": "models/q-periapt-continuity-model/vectors/lifecycle-context-v1.json",
    "continuity_context_vector_emitter_sha256": "models/q-periapt-continuity-model/examples/continuity_context_vectors.rs",
    "continuity_context_verifier_sha256": "artifact/continuity_context.py",
    "continuity_context_verifier_tests_sha256": "artifact/test_continuity_context.py",
    "continuity_prekey_spec_sha256": "docs/continuity/PREKEY_SELECTION_V1.md",
    "continuity_prekey_codec_sha256": "models/q-periapt-continuity-model/src/codec.rs",
    "continuity_prekey_commitments_sha256": "models/q-periapt-continuity-model/src/commitments.rs",
    "continuity_prekey_model_sha256": "models/q-periapt-continuity-model/src/prekey.rs",
    "continuity_prekey_tests_sha256": "models/q-periapt-continuity-model/tests/prekey_selection.rs",
    "continuity_prekey_vectors_sha256": "models/q-periapt-continuity-model/vectors/prekey-selection-v1.json",
    "continuity_prekey_vector_emitter_sha256": "models/q-periapt-continuity-model/examples/prekey_selection_vectors.rs",
    "continuity_prekey_verifier_sha256": "artifact/prekey_selection.py",
    "continuity_prekey_verifier_tests_sha256": "artifact/test_prekey_selection.py",
    "continuity_model_manifest_sha256": "models/q-periapt-continuity-model/Cargo.toml",
    "continuity_model_lib_sha256": "models/q-periapt-continuity-model/src/lib.rs",
    "continuity_model_types_sha256": "models/q-periapt-continuity-model/src/types.rs",
    "continuity_model_state_machine_sha256": "models/q-periapt-continuity-model/src/model.rs",
    "continuity_model_lifecycle_tests_sha256": "models/q-periapt-continuity-model/tests/lifecycle.rs",
    "continuity_model_isolation_tests_sha256": "artifact/test_continuity_model_isolation.py",
    "continuity_effect_lifecycle_spec_sha256": "docs/continuity/G1_EFFECT_LIFECYCLE.md",
    "continuity_easycrypt_model_sha256": "formal/easycrypt/continuity/LifecycleContextV1.ec",
    "continuity_prekey_easycrypt_model_sha256": "formal/easycrypt/continuity/PrekeySelectionV1.ec",
    "continuity_easycrypt_makefile_sha256": "formal/easycrypt/continuity/Makefile",
}

HQC_CANDIDATE_PROOF_INPUTS = {
    "hqc_candidate_readme_sha256": "research/hqc-fips207-candidate/README.md",
    "hqc_candidate_manifest_sha256": "research/hqc-fips207-candidate/Cargo.toml",
    "hqc_candidate_lock_sha256": "research/hqc-fips207-candidate/Cargo.lock",
    "hqc_candidate_adapter_sha256": "research/hqc-fips207-candidate/src/lib.rs",
    "hqc_candidate_tests_sha256": "research/hqc-fips207-candidate/tests/adapter.rs",
    "hqc_candidate_verify_sha256": "research/hqc-fips207-candidate/scripts/verify.sh",
}


def extract_ci_check_job(workflow: str) -> str:
    check_match = re.search(
        r"(?ms)^  check:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)", workflow
    )
    if check_match is None:
        raise ValueError("CI workflow has no check job")
    return check_match.group("body")


def repository_head() -> str:
    commit = git_commit(ROOT)
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise AssertionError(f"repository HEAD is not a 40-character commit: {commit}")
    return commit


def validate_ci_check_checkout(check_job: str) -> None:
    if check_job.lower().count("actions/checkout@") != 1:
        raise ValueError("CI check job must contain exactly one checkout action")
    if YAML_ALIAS.search(check_job) is not None:
        raise ValueError("CI check job must not use YAML aliases")

    lines = check_job.splitlines(keepends=True)
    checkout_starts = [
        index
        for index, line in enumerate(lines)
        if line.lower().startswith("      - uses: actions/checkout@")
    ]
    if len(checkout_starts) != 1:
        raise ValueError("CI check job must contain one explicit checkout step")

    def step_end(start: int) -> int:
        end = start + 1
        while end < len(lines):
            line = lines[end]
            if line.startswith("      - ") or (
                line.strip() and len(line) - len(line.lstrip(" ")) <= 6
            ):
                break
            end += 1
        return end

    start = checkout_starts[0]
    checkout_end = step_end(start)
    checkout_step = "".join(lines[start:checkout_end])
    if checkout_step != EXPECTED_CHECKOUT_STEP:
        raise ValueError(
            "CI check checkout must use the pinned action and exact hardened settings"
        )
    provenance_end = step_end(checkout_end)
    provenance_step = "".join(lines[checkout_end:provenance_end])
    if provenance_step != EXPECTED_CHECKOUT_PROVENANCE_STEP:
        raise ValueError(
            "CI check job must verify checkout provenance immediately after checkout"
        )

    proof_starts = [
        index
        for index, line in enumerate(lines)
        if line
        == "      - name: Proof-to-byte manifest and canonical source binding\n"
    ]
    if len(proof_starts) != 1:
        raise ValueError("CI check job must contain one explicit proof-to-byte step")
    proof_start = proof_starts[0]
    proof_step = "".join(lines[proof_start : step_end(proof_start)])
    if proof_step != EXPECTED_PROOF_TO_BYTE_STEP:
        raise ValueError("CI proof-to-byte step differs from the audited fail-closed form")


def format_marker(*states: int) -> str:
    state = proof_to_byte_finalizer.AttestationState.from_values(
        [str(value) for value in states]
    )
    return proof_to_byte_finalizer.format_attestation_marker(
        state,
        proof_to_byte_finalizer.SourceSnapshot(
            commit=TEST_COMMIT,
            source_sha256=TEST_SOURCE_SHA256,
            manifest_sha256=TEST_MANIFEST_SHA256,
            dirty=state.source_tree_dirty,
        ),
    )


class BoundVerifierWiringTests(unittest.TestCase):
    def test_proof_to_byte_names_every_continuity_input(self) -> None:
        source = PROOF_SCRIPT.read_text(encoding="utf-8")
        manifest = json.loads((ROOT / "artifact" / "results.json").read_text(encoding="utf-8"))
        inputs = manifest["proof_to_byte_inputs"]
        for key, relative in CONTINUITY_PROOF_INPUTS.items():
            with self.subTest(key=key):
                self.assertIn(f'"{key}": "{relative}"', source)
                actual = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
                self.assertEqual(inputs.get(key), actual)

    def test_proof_to_byte_names_every_hqc_candidate_input(self) -> None:
        source = PROOF_SCRIPT.read_text(encoding="utf-8")
        manifest = json.loads((ROOT / "artifact" / "results.json").read_text(encoding="utf-8"))
        inputs = manifest["proof_to_byte_inputs"]
        for key, relative in HQC_CANDIDATE_PROOF_INPUTS.items():
            with self.subTest(key=key):
                self.assertIn(f'"{key}": "{relative}"', source)
                actual = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
                self.assertEqual(inputs.get(key), actual)

    def test_publish_contract_fences_research_and_mlkem_provider(self) -> None:
        source = RUST_PUBLISH_SCRIPT.read_text(encoding="utf-8")
        manifest = json.loads((ROOT / "artifact" / "results.json").read_text(encoding="utf-8"))
        expected_hash = hashlib.sha256(RUST_PUBLISH_SCRIPT.read_bytes()).hexdigest()
        expected_contract_hash = hashlib.sha256(
            RUST_PUBLISH_CONTRACT.read_bytes()
        ).hexdigest()
        expected_contract_tests_hash = hashlib.sha256(
            RUST_PUBLISH_CONTRACT_TESTS.read_bytes()
        ).hexdigest()
        for token in (
            "pqcrypto-hqc",
            "pqcrypto-internals",
            "pqcrypto-traits",
            "hqc-kem",
            "src/hqc.rs",
        ):
            with self.subTest(token=token):
                self.assertIn(token, source)
        self.assertIn("RUST_BACKENDS_NORMALIZED_MANIFEST_PASS", source)
        self.assertIn("RUST_BACKENDS_INSPECTION_PACKAGE_PASS", source)
        self.assertIn("cargo package $ALLOW_DIRTY_ARG --locked \\", source)
        self.assertNotIn("--no-verify", source)
        self.assertIn("qperiapt-package-inspection.XXXXXX", source)
        self.assertIn("publishable q-periapt-backends exposes retired hqc feature", source)
        self.assertIn(
            'python3 "$ROOT/crates/q-periapt-mlkem-native-sys/scripts/verify-vendor.py"',
            source,
        )
        self.assertIn("mlkem_reference_dependencies", source)
        self.assertIn("=0.2.3", source)
        self.assertIn("RUST_MLKEM_PROVIDER_FENCE_PASS", source)
        self.assertIn("resolved_mlkem_providers", source)
        self.assertIn('"src/build_support.rs"', source)
        self.assertIn("from rust_publish_contract import", source)
        self.assertIn("validate_mlkem_native_build_surface", source)
        self.assertEqual(
            manifest["proof_to_byte_inputs"].get("rust_publish_dry_run_script_sha256"),
            expected_hash,
        )
        self.assertEqual(
            manifest["proof_to_byte_inputs"].get("rust_publish_contract_sha256"),
            expected_contract_hash,
        )
        self.assertEqual(
            manifest["proof_to_byte_inputs"].get("rust_publish_contract_tests_sha256"),
            expected_contract_tests_hash,
        )

    def test_continuity_diagnostic_is_scoped_fail_closed_and_non_release(self) -> None:
        source = PROOF_SCRIPT.read_text(encoding="utf-8")
        cargo = "cargo test -p q-periapt-continuity-model --locked"
        python_tests = "sh artifact/python-run.sh -m unittest -v"
        vectors = "sh artifact/python-run.sh artifact/continuity_context.py verify"
        prekey_vectors = "sh artifact/python-run.sh artifact/prekey_selection.py verify"
        formal = "make -C formal/easycrypt/continuity check"
        marker = (
            "PROOF_TO_BYTE_CONTINUITY_MODEL_DIAGNOSTIC_PASS "
            "boundary=non_normative_not_release"
        )
        self.assertIn("QPERIAPT_RUN_CONTINUITY_DIAGNOSTIC", source)
        self.assertLess(source.index(cargo), source.index(python_tests))
        self.assertLess(source.index(python_tests), source.index(vectors))
        self.assertLess(source.index(vectors), source.index(prekey_vectors))
        self.assertLess(source.index(prekey_vectors), source.index(formal))
        self.assertLess(source.index(formal), source.index(marker))
        self.assertIn("artifact/test_prekey_selection.py", source)
        for command in (cargo, python_tests, vectors, prekey_vectors, formal):
            self.assertNotIn(command + " ||", source)
            self.assertNotIn(command + "; true", source)
        release_marker = FINALIZER_SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn("CONTINUITY", release_marker)
        self.assertNotIn("continuity", release_marker)
        self.assertNotIn("CONTINUITY_DIAGNOSTIC_PASSED", source)

    def test_publish_and_device_entrypoints_harden_before_first_python(self) -> None:
        source_line = '. "$ROOT/artifact/python-env.sh"'
        python_token = re.compile(r"(?<![A-Za-z0-9_])python3(?![A-Za-z0-9_])")
        entrypoints = []
        for path in sorted((ROOT / "artifact").glob("*.sh")):
            if path.name in {"python-env.sh", "python-run.sh"}:
                continue
            source = path.read_text(encoding="utf-8")
            if python_token.search(source):
                entrypoints.append(path)
        self.assertTrue(entrypoints, "no repository Python shell entrypoints discovered")
        for path in entrypoints:
            relative = path.relative_to(ROOT).as_posix()
            with self.subTest(entrypoint=relative):
                lines = path.read_text(encoding="utf-8").splitlines()
                executable_lines = [
                    (number, line)
                    for number, line in enumerate(lines, start=1)
                    if line.strip() and not line.lstrip().startswith("#")
                ]
                source_lines = [
                    number
                    for number, line in executable_lines
                    if line.strip() == source_line
                ]
                self.assertEqual(
                    len(source_lines),
                    1,
                    f"{relative} must source the hardened helper exactly once",
                )
                python_lines = [
                    number
                    for number, line in executable_lines
                    if python_token.search(line)
                ]
                self.assertTrue(python_lines, f"{relative} has no Python invocation to protect")
                self.assertLess(
                    source_lines[0],
                    python_lines[0],
                    f"{relative} invokes Python before sourcing the hardened helper",
                )

    def test_one_shot_runner_sources_helper_before_dispatch(self) -> None:
        source = (ROOT / "artifact" / "python-run.sh").read_text(encoding="utf-8")
        helper = source.index('. "$ROOT/artifact/python-env.sh"')
        dispatch = source.index('python3 "$@"')
        self.assertIn("set -eu", source)
        self.assertLess(helper, dispatch)

    def test_shell_has_no_post_verification_selected_proof_reopen(self) -> None:
        source = PROOF_SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn("manifest_selected_proof_binding", source)
        self.assertGreaterEqual(source.count('--results-manifest "$RESULTS_MANIFEST"'), 6)
        self.assertGreaterEqual(
            source.count(
                '--expected-results-manifest-sha256 "$RESULTS_MANIFEST_SHA256"'
            ),
            6,
        )
        finalizer = FINALIZER_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("PROOF_TO_BYTE_RESULTS_MANIFEST_STABLE_PASS", finalizer)

    def test_finalizer_is_a_named_proof_input(self) -> None:
        source = PROOF_SCRIPT.read_text(encoding="utf-8")
        manifest = json.loads((ROOT / "artifact" / "results.json").read_text(encoding="utf-8"))
        self.assertIn(
            '"proof_to_byte_finalizer_sha256": "artifact/proof_to_byte_finalizer.py"',
            source,
        )
        self.assertEqual(
            manifest["proof_to_byte_inputs"].get("proof_to_byte_finalizer_sha256"),
            hashlib.sha256(FINALIZER_SCRIPT.read_bytes()).hexdigest(),
        )

    def test_finalizer_freezes_before_domains_and_rechecks_after_them(self) -> None:
        source = PROOF_SCRIPT.read_text(encoding="utf-8")
        preflight = source.index("# Normalize every active caller-controlled option")
        freeze = source.index("proof_to_byte_finalizer.py freeze")
        first_domain = source.index('test -f "$CAMERA_READY_TRANSCRIPT"')
        last_domain = source.index('test -f "$PERFORMANCE_PROOF"')
        finalize = source.index("proof_to_byte_finalizer.py finalize")
        self.assertLess(preflight, freeze)
        self.assertLess(freeze, first_domain)
        self.assertLess(last_domain, finalize)
        self.assertIn('--expected-git-commit "$EXPECTED_GIT_COMMIT"', source)
        self.assertIn('--expected-git-commit "$FROZEN_GIT_COMMIT"', source)
        self.assertIn('--expected-source-sha256 "$FROZEN_SOURCE_TREE_SHA256"', source)

    def test_xcode27_capture_does_not_self_promote_unselected_proof(self) -> None:
        source = XCODE27_GATE.read_text(encoding="utf-8")
        self.assertNotIn("artifact/proof-to-byte.sh", source)
        self.assertIn("APPLE_DEVICE_XCODE27_CAPTURE_PASS", source)
        self.assertIn("promotion=pending", source)

    def test_domain_verifiers_emit_manifest_bound_marker(self) -> None:
        apple = (ROOT / "artifact" / "apple_device_proof.py").read_text(
            encoding="utf-8"
        )
        performance = (ROOT / "artifact" / "performance_gate.py").read_text(
            encoding="utf-8"
        )
        android = (ROOT / "artifact" / "android_device_proof.py").read_text(
            encoding="utf-8"
        )
        marker = "PROOF_TO_BYTE_SELECTED_PROOF_MANIFEST_PASS"
        self.assertIn(marker, apple)
        self.assertIn(marker, performance)
        self.assertIn(marker, android)
        self.assertIn('binding="apple_device"', apple)
        self.assertIn('binding="apple_matrix"', apple)
        self.assertIn('binding="performance"', performance)
        self.assertIn('binding="android_runtime"', android)

    def test_release_policy_cannot_be_selected_by_evidence_or_environment(self) -> None:
        matrix_script = (ROOT / "artifact" / "apple-device-matrix.sh").read_text(
            encoding="utf-8"
        )
        apple = (ROOT / "artifact" / "apple_device_proof.py").read_text(
            encoding="utf-8"
        )
        performance = (ROOT / "artifact" / "performance_gate.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("QPERIAPT_REQUIRED_DEVICE_TYPES was removed", matrix_script)
        self.assertNotIn('add_argument("--required-device-types"', apple)
        self.assertNotIn('add_argument("--budget"', performance)
        self.assertIn(
            'PRODUCTION_BUDGET_RELATIVE = pathlib.PurePosixPath("artifact/performance-budgets.json")',
            performance,
        )

    def test_release_dirty_state_uses_hardened_git_provenance(self) -> None:
        finalizer = FINALIZER_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("from git_provenance import (", finalizer)
        self.assertIn("inspect_worktree", finalizer)
        self.assertNotIn("git status --porcelain", finalizer)
        for relative in (
            "artifact/apple-device-smoke.sh",
            "artifact/apple-device-matrix.sh",
            "artifact/android-device-smoke.sh",
        ):
            source = (ROOT / relative).read_text(encoding="utf-8")
            self.assertIn("from git_provenance import source_tree_dirty", source)
            self.assertNotIn("git status --porcelain", source)

    def test_release_entrypoint_does_not_execute_forged_timestamp_pyc(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            artifact = root / "artifact"
            artifact.mkdir()
            for name in (
                "proof-to-byte.sh",
                "proof_manifest.py",
                "evidence_io.py",
                "python-env.sh",
                "python_bootstrap.py",
            ):
                shutil.copy2(ROOT / "artifact" / name, artifact / name)
            (artifact / "results.json").write_text("{}\n", encoding="utf-8")

            trusted_source = artifact / "proof_manifest.py"
            source_stat = trusted_source.stat()
            sentinel = root / "malicious-pyc-executed"
            malicious_source = (
                "import hashlib\n"
                "import os\n"
                "import pathlib\n"
                "pathlib.Path(os.environ['QPERIAPT_TEST_PYC_SENTINEL']).write_text("
                "'executed', encoding='utf-8')\n"
                "class _File:\n"
                "    sha256 = '0' * 64\n"
                "class _Snapshot:\n"
                "    file = _File()\n"
                "def load_results_manifest_snapshot(*args, **kwargs):\n"
                "    return _Snapshot()\n"
            )
            malicious_code = compile(
                malicious_source,
                str(trusted_source),
                "exec",
            )
            # Compute the ordinary adjacent cache location explicitly.  This
            # test itself may be running through the hardened launcher, whose
            # private sys.pycache_prefix must not redirect the planted control.
            cache_path = (
                trusted_source.parent
                / "__pycache__"
                / f"{trusted_source.stem}.{sys.implementation.cache_tag}.pyc"
            )
            cache_path.parent.mkdir()
            cache_path.write_bytes(
                importlib._bootstrap_external._code_to_timestamp_pyc(
                    malicious_code,
                    int(source_stat.st_mtime),
                    source_stat.st_size,
                )
            )

            environment = os.environ.copy()
            environment["PYTHONPATH"] = str(artifact)
            environment["QPERIAPT_TEST_PYC_SENTINEL"] = str(sentinel)
            environment["GITHUB_SHA"] = TEST_COMMIT
            environment.pop("PYTHONPYCACHEPREFIX", None)
            control = subprocess.run(
                [sys.executable, "-c", "import proof_manifest"],
                cwd=root,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(control.returncode, 0, control.stderr)
            self.assertTrue(sentinel.is_file(), "forged pyc control did not execute")
            sentinel.unlink()

            environment["QPERIAPT_SKIP_SMOKE"] = "invalid"
            guarded = subprocess.run(
                ["sh", str(artifact / "proof-to-byte.sh")],
                cwd=root,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(guarded.returncode, 2, guarded.stderr)
            self.assertIn("QPERIAPT_SKIP_SMOKE must be 0 or 1", guarded.stderr)
            self.assertFalse(
                sentinel.exists(),
                "release entrypoint executed a forged ignored timestamp pyc",
            )

    def test_release_entrypoint_ignores_hostile_python_startup_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            artifact = root / "artifact"
            artifact.mkdir()
            for name in (
                "proof-to-byte.sh",
                "proof_manifest.py",
                "evidence_io.py",
                "python-env.sh",
                "python_bootstrap.py",
            ):
                shutil.copy2(ROOT / "artifact" / name, artifact / name)
            (artifact / "results.json").write_text("{}\n", encoding="utf-8")

            user_base = root / "hostile-user-base"
            clean_python_environment = {
                name: value
                for name, value in os.environ.items()
                if not name.startswith("PYTHON")
            }
            clean_python_environment["PYTHONUSERBASE"] = str(user_base)
            site_query = subprocess.run(
                [sys.executable, "-c", "import site; print(site.getusersitepackages())"],
                cwd=root,
                env=clean_python_environment,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(site_query.returncode, 0, site_query.stderr)
            user_site = pathlib.Path(site_query.stdout.strip())
            self.assertTrue(user_site.is_absolute())
            self.assertTrue(user_site.is_relative_to(user_base))
            user_site.mkdir(parents=True)
            pth_sentinel = root / "hostile-pth-executed"
            (user_site / "hostile.pth").write_text(
                "import os, pathlib; pathlib.Path(os.environ["
                "'QPERIAPT_TEST_PTH_SENTINEL']).write_text('executed', encoding='utf-8')\n",
                encoding="utf-8",
            )

            python_path = root / "hostile-python-path"
            python_path.mkdir()
            path_sentinel = root / "hostile-pythonpath-executed"
            (python_path / "sitecustomize.py").write_text(
                "import os\n"
                "import pathlib\n"
                "pathlib.Path(os.environ['QPERIAPT_TEST_PATH_SENTINEL']).write_text("
                "'executed', encoding='utf-8')\n",
                encoding="utf-8",
            )
            bootstrap_sentinel = root / "hostile-bootstrap-executed"
            hostile_bootstrap = root / "hostile-bootstrap.py"
            hostile_bootstrap.write_text(
                "import os\n"
                "import pathlib\n"
                "pathlib.Path(os.environ['QPERIAPT_TEST_BOOTSTRAP_SENTINEL']).write_text("
                "'executed', encoding='utf-8')\n",
                encoding="utf-8",
            )

            control_environment = clean_python_environment.copy()
            control_environment["PYTHONUSERBASE"] = str(user_base)
            control_environment["QPERIAPT_TEST_PTH_SENTINEL"] = str(pth_sentinel)
            pth_control = subprocess.run(
                [sys.executable, "-c", "pass"],
                cwd=root,
                env=control_environment,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(pth_control.returncode, 0, pth_control.stderr)
            self.assertTrue(pth_sentinel.is_file(), "hostile .pth control did not execute")
            pth_sentinel.unlink()

            control_environment = clean_python_environment.copy()
            control_environment.pop("PYTHONUSERBASE", None)
            control_environment["PYTHONPATH"] = str(python_path)
            control_environment["QPERIAPT_TEST_PATH_SENTINEL"] = str(path_sentinel)
            path_control = subprocess.run(
                [sys.executable, "-c", "pass"],
                cwd=root,
                env=control_environment,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(path_control.returncode, 0, path_control.stderr)
            self.assertTrue(
                path_sentinel.is_file(), "hostile PYTHONPATH control did not execute"
            )
            path_sentinel.unlink()

            hostile_python_home = root / "nonexistent-python-home"
            control_environment = clean_python_environment.copy()
            control_environment["PYTHONHOME"] = str(hostile_python_home)
            home_control = subprocess.run(
                [sys.executable, "-c", "pass"],
                cwd=root,
                env=control_environment,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(
                home_control.returncode,
                0,
                "hostile PYTHONHOME control unexpectedly had no effect",
            )

            guarded_environment = clean_python_environment.copy()
            guarded_environment.update(
                {
                    "PYTHONUSERBASE": str(user_base),
                    "PYTHONPATH": str(python_path),
                    "PYTHONHOME": str(hostile_python_home),
                    "QPERIAPT_TEST_PTH_SENTINEL": str(pth_sentinel),
                    "QPERIAPT_TEST_PATH_SENTINEL": str(path_sentinel),
                    "QPERIAPT_TEST_BOOTSTRAP_SENTINEL": str(bootstrap_sentinel),
                    "QPERIAPT_PYTHON_ENV_INITIALIZED": "1",
                    "QPERIAPT_PYTHON_BOOTSTRAP": str(hostile_bootstrap),
                    "QPERIAPT_SKIP_SMOKE": "invalid",
                    "GITHUB_SHA": TEST_COMMIT,
                }
            )
            guarded = subprocess.run(
                ["sh", str(artifact / "proof-to-byte.sh")],
                cwd=root,
                env=guarded_environment,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(guarded.returncode, 2, guarded.stderr)
            self.assertIn("QPERIAPT_SKIP_SMOKE must be 0 or 1", guarded.stderr)
            self.assertFalse(pth_sentinel.exists(), "release entrypoint executed hostile .pth")
            self.assertFalse(
                path_sentinel.exists(), "release entrypoint executed hostile PYTHONPATH"
            )
            self.assertFalse(
                bootstrap_sentinel.exists(),
                "release entrypoint trusted a caller-selected Python bootstrap",
            )


class ProofToByteReleaseMarkerTests(unittest.TestCase):
    def test_every_boolean_flag_fails_before_provenance_and_markers(self) -> None:
        flags = (
            "QPERIAPT_SKIP_SMOKE",
            "QPERIAPT_REQUIRE_FORMAL",
            "QPERIAPT_RUN_CONTINUITY_DIAGNOSTIC",
            "QPERIAPT_REQUIRE_APPLE_DEVICE",
            "QPERIAPT_REQUIRE_APPLE_DEVICE_MATRIX",
            "QPERIAPT_REQUIRE_ANDROID_RUNTIME",
            "QPERIAPT_REQUIRE_PERFORMANCE",
            "QPERIAPT_REQUIRE_CAMERA_READY",
            "QPERIAPT_REQUIRE_DEPENDENCY_AUDIT",
            "QPERIAPT_ALLOW_DIRTY_APPLE_DEVICE_PROOF",
            "QPERIAPT_ALLOW_DIRTY_ANDROID_RUNTIME_PROOF",
            "QPERIAPT_ALLOW_DIRTY_PERFORMANCE_PROOF",
        )
        for flag in flags:
            with self.subTest(flag=flag):
                environment = {
                    name: value
                    for name, value in os.environ.items()
                    if not name.startswith("QPERIAPT_")
                }
                environment.update(
                    {
                        flag: "yes",
                        "QPERIAPT_EXPECTED_GIT_COMMIT": repository_head(),
                        "GITHUB_SHA": TEST_COMMIT,
                    }
                )
                result = subprocess.run(
                    ["sh", str(PROOF_SCRIPT)],
                    cwd=ROOT,
                    text=True,
                    capture_output=True,
                    check=False,
                    env=environment,
                )
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn(f"{flag} must be 0 or 1", result.stderr)
                self.assertEqual(result.stdout, "")

    def test_active_configuration_preflight_fails_before_proof_markers(self) -> None:
        outside = ROOT / "artifact" / "results.json"
        cases = (
            (
                "apple modes are mutually exclusive",
                {
                    "QPERIAPT_REQUIRE_APPLE_DEVICE": "1",
                    "QPERIAPT_REQUIRE_APPLE_DEVICE_MATRIX": "1",
                },
                "are mutually exclusive",
            ),
            (
                "camera bundle is required",
                {"QPERIAPT_REQUIRE_CAMERA_READY": "1"},
                "QPERIAPT_CAMERA_READY_BUNDLE must explicitly name",
            ),
            (
                "camera max age is numeric",
                {
                    "QPERIAPT_REQUIRE_CAMERA_READY": "1",
                    "QPERIAPT_CAMERA_READY_BUNDLE": str(ROOT / "target" / "bundle"),
                    "QPERIAPT_CAMERA_READY_MAX_AGE_SECONDS": "tomorrow",
                },
                "QPERIAPT_CAMERA_READY_MAX_AGE_SECONDS must be an ASCII base-10 integer",
            ),
            (
                "camera freshness is fixed",
                {
                    "QPERIAPT_REQUIRE_CAMERA_READY": "1",
                    "QPERIAPT_CAMERA_READY_BUNDLE": str(ROOT / "target" / "bundle"),
                    "QPERIAPT_CAMERA_READY_MAX_AGE_SECONDS": "2",
                },
                "fixes camera-ready freshness to 86400 seconds",
            ),
            (
                "apple result directory is contained",
                {
                    "QPERIAPT_REQUIRE_APPLE_DEVICE": "1",
                    "QPERIAPT_DEVICE_RESULT_DIR": str(ROOT / "target"),
                },
                "QPERIAPT_DEVICE_RESULT_DIR must be under",
            ),
            (
                "apple prefix is canonical",
                {
                    "QPERIAPT_REQUIRE_APPLE_DEVICE": "1",
                    "QPERIAPT_DEVICE_ARTIFACT_PREFIX": "../ipad",
                },
                "invalid QPERIAPT_DEVICE_ARTIFACT_PREFIX",
            ),
            (
                "apple prefix cannot be explicitly empty",
                {
                    "QPERIAPT_REQUIRE_APPLE_DEVICE": "1",
                    "QPERIAPT_DEVICE_ARTIFACT_PREFIX": "",
                },
                "invalid QPERIAPT_DEVICE_ARTIFACT_PREFIX",
            ),
            (
                "apple device type is recognized",
                {
                    "QPERIAPT_REQUIRE_APPLE_DEVICE": "1",
                    "QPERIAPT_EXPECT_DEVICE_TYPE": "Mac",
                },
                "invalid QPERIAPT_EXPECT_DEVICE_TYPE",
            ),
            (
                "apple max age is bounded",
                {
                    "QPERIAPT_REQUIRE_APPLE_DEVICE": "1",
                    "QPERIAPT_DEVICE_PROOF_MAX_AGE_SECONDS": "0",
                },
                "QPERIAPT_DEVICE_PROOF_MAX_AGE_SECONDS must be an ASCII base-10 integer",
            ),
            (
                "apple release freshness is fixed",
                {
                    "QPERIAPT_REQUIRE_APPLE_DEVICE": "1",
                    "QPERIAPT_DEVICE_PROOF_MAX_AGE_SECONDS": "2",
                },
                "fixes Apple proof freshness to 86400 seconds",
            ),
            (
                "matrix proof is contained",
                {
                    "QPERIAPT_REQUIRE_APPLE_DEVICE_MATRIX": "1",
                    "QPERIAPT_DEVICE_MATRIX_PROOF": str(outside),
                },
                "QPERIAPT_DEVICE_MATRIX_PROOF must be under",
            ),
            (
                "android proof is contained",
                {
                    "QPERIAPT_REQUIRE_ANDROID_RUNTIME": "1",
                    "QPERIAPT_ANDROID_DEVICE_PROOF": str(outside),
                },
                "QPERIAPT_ANDROID_DEVICE_PROOF must be under",
            ),
            (
                "android device kind is recognized",
                {
                    "QPERIAPT_REQUIRE_ANDROID_RUNTIME": "1",
                    "QPERIAPT_ANDROID_EXPECT_DEVICE_KIND": "tablet",
                },
                "invalid QPERIAPT_ANDROID_EXPECT_DEVICE_KIND",
            ),
            (
                "android max age is bounded",
                {
                    "QPERIAPT_REQUIRE_ANDROID_RUNTIME": "1",
                    "QPERIAPT_ANDROID_PROOF_MAX_AGE_SECONDS": "604801",
                },
                "QPERIAPT_ANDROID_PROOF_MAX_AGE_SECONDS must be an ASCII base-10 integer",
            ),
            (
                "performance proof is contained",
                {
                    "QPERIAPT_REQUIRE_PERFORMANCE": "1",
                    "QPERIAPT_PERFORMANCE_PROOF": str(outside),
                },
                "QPERIAPT_PERFORMANCE_PROOF must be under",
            ),
            (
                "performance max age is numeric",
                {
                    "QPERIAPT_REQUIRE_PERFORMANCE": "1",
                    "QPERIAPT_PERFORMANCE_PROOF_MAX_AGE_SECONDS": "1.5",
                },
                "QPERIAPT_PERFORMANCE_PROOF_MAX_AGE_SECONDS must be an ASCII base-10 integer",
            ),
            (
                "performance release freshness is fixed",
                {
                    "QPERIAPT_REQUIRE_PERFORMANCE": "1",
                    "QPERIAPT_PERFORMANCE_PROOF_MAX_AGE_SECONDS": "2",
                },
                "fixes performance proof freshness to 86400 seconds",
            ),
            (
                "later active gate fails before any gate starts",
                {
                    "QPERIAPT_REQUIRE_APPLE_DEVICE": "1",
                    "QPERIAPT_REQUIRE_PERFORMANCE": "1",
                    "QPERIAPT_PERFORMANCE_PROOF_MAX_AGE_SECONDS": "2",
                },
                "fixes performance proof freshness to 86400 seconds",
            ),
            (
                "freshness rejects non-ASCII digits",
                {
                    "QPERIAPT_REQUIRE_PERFORMANCE": "1",
                    "QPERIAPT_PERFORMANCE_PROOF_MAX_AGE_SECONDS": "１２",
                },
                "QPERIAPT_PERFORMANCE_PROOF_MAX_AGE_SECONDS must be an ASCII base-10 integer",
            ),
            (
                "freshness error is bounded",
                {
                    "QPERIAPT_REQUIRE_PERFORMANCE": "1",
                    "QPERIAPT_PERFORMANCE_PROOF_MAX_AGE_SECONDS": "9" * 10_000,
                },
                "QPERIAPT_PERFORMANCE_PROOF_MAX_AGE_SECONDS must be an ASCII base-10 integer",
            ),
        )
        for label, overrides, expected_error in cases:
            with self.subTest(label=label):
                environment = {
                    name: value
                    for name, value in os.environ.items()
                    if not name.startswith("QPERIAPT_")
                }
                environment.update(
                    {
                        "QPERIAPT_SKIP_SMOKE": "1",
                        "QPERIAPT_EXPECTED_GIT_COMMIT": repository_head(),
                        "GITHUB_SHA": TEST_COMMIT,
                        **overrides,
                    }
                )
                result = subprocess.run(
                    ["sh", str(PROOF_SCRIPT)],
                    cwd=ROOT,
                    text=True,
                    capture_output=True,
                    check=False,
                    env=environment,
                )
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn(expected_error, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertNotIn("Traceback", result.stderr)
                self.assertLess(len(result.stderr), 1024)

        with (
            tempfile.TemporaryDirectory(
                dir=ROOT / "artifact" / "device-runs"
            ) as device_temporary,
            tempfile.TemporaryDirectory(dir=ROOT / "target") as target_temporary,
        ):
            device_loop = pathlib.Path(device_temporary) / "loop"
            performance_loop = pathlib.Path(target_temporary) / "loop"
            device_loop.symlink_to(device_loop)
            performance_loop.symlink_to(performance_loop)
            loop_cases = (
                (
                    {
                        "QPERIAPT_REQUIRE_APPLE_DEVICE": "1",
                        "QPERIAPT_DEVICE_RESULT_DIR": str(device_loop),
                    },
                    "QPERIAPT_DEVICE_RESULT_DIR",
                ),
                (
                    {
                        "QPERIAPT_REQUIRE_PERFORMANCE": "1",
                        "QPERIAPT_PERFORMANCE_PROOF": str(performance_loop),
                    },
                    "QPERIAPT_PERFORMANCE_PROOF",
                ),
            )
            for overrides, expected_error in loop_cases:
                with self.subTest(symlink_loop=expected_error):
                    environment = {
                        name: value
                        for name, value in os.environ.items()
                        if not name.startswith("QPERIAPT_")
                    }
                    environment.update(
                        {
                            "QPERIAPT_SKIP_SMOKE": "1",
                            "QPERIAPT_EXPECTED_GIT_COMMIT": repository_head(),
                            "GITHUB_SHA": TEST_COMMIT,
                            **overrides,
                        }
                    )
                    result = subprocess.run(
                        ["sh", str(PROOF_SCRIPT)],
                        cwd=ROOT,
                        text=True,
                        capture_output=True,
                        check=False,
                        env=environment,
                    )
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn(expected_error, result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertNotIn("Traceback", result.stderr)

    def test_required_tools_are_checked_before_proof_markers(self) -> None:
        environment = {
            name: value
            for name, value in os.environ.items()
            if not name.startswith("QPERIAPT_")
        }
        environment.update(
            {
                "HOME": "",
                "PATH": "/nonexistent",
                "QPERIAPT_SKIP_SMOKE": "1",
                "QPERIAPT_REQUIRE_FORMAL": "1",
                "QPERIAPT_EXPECTED_GIT_COMMIT": repository_head(),
                "GITHUB_SHA": TEST_COMMIT,
            }
        )
        result = subprocess.run(
            ["/bin/sh", str(PROOF_SCRIPT)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            env=environment,
        )
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("required tool not found: make", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_preflight_errors_escape_caller_controlled_values(self) -> None:
        hostile_value = "invalid\n::warning::injected\x1b[31m"
        cases = (
            {
                "QPERIAPT_REQUIRE_PERFORMANCE": "1",
                "QPERIAPT_PERFORMANCE_PROOF_MAX_AGE_SECONDS": hostile_value,
            },
            {
                "QPERIAPT_REQUIRE_APPLE_DEVICE": "1",
                "QPERIAPT_DEVICE_ARTIFACT_PREFIX": hostile_value,
            },
            {
                "QPERIAPT_REQUIRE_APPLE_DEVICE": "1",
                "QPERIAPT_EXPECT_DEVICE_TYPE": hostile_value,
            },
            {
                "QPERIAPT_REQUIRE_ANDROID_RUNTIME": "1",
                "QPERIAPT_ANDROID_EXPECT_DEVICE_KIND": hostile_value,
            },
        )
        for overrides in cases:
            with self.subTest(overrides=overrides):
                environment = {
                    name: value
                    for name, value in os.environ.items()
                    if not name.startswith("QPERIAPT_")
                }
                environment.update(
                    {
                        "QPERIAPT_SKIP_SMOKE": "1",
                        "QPERIAPT_EXPECTED_GIT_COMMIT": repository_head(),
                        "GITHUB_SHA": TEST_COMMIT,
                        **overrides,
                    }
                )
                result = subprocess.run(
                    ["sh", str(PROOF_SCRIPT)],
                    cwd=ROOT,
                    text=True,
                    capture_output=True,
                    check=False,
                    env=environment,
                )
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertNotIn("\n::warning::injected", result.stderr)
                self.assertNotIn("\x1b", result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                self.assertLess(len(result.stderr), 1024)

        path_cases = (
            (
                {
                    "QPERIAPT_REQUIRE_CAMERA_READY": "1",
                    "QPERIAPT_CAMERA_READY_BUNDLE": str(ROOT / "target" / "bundle"),
                    "QPERIAPT_CAMERA_READY_TRANSCRIPT": "",
                },
                "QPERIAPT_CAMERA_READY_TRANSCRIPT",
            ),
            (
                {
                    "QPERIAPT_REQUIRE_CAMERA_READY": "1",
                    "QPERIAPT_CAMERA_READY_BUNDLE": "",
                },
                "QPERIAPT_CAMERA_READY_BUNDLE",
            ),
            (
                {
                    "QPERIAPT_REQUIRE_APPLE_DEVICE": "1",
                    "QPERIAPT_DEVICE_RESULT_DIR": "",
                },
                "QPERIAPT_DEVICE_RESULT_DIR",
            ),
            (
                {
                    "QPERIAPT_REQUIRE_APPLE_DEVICE_MATRIX": "1",
                    "QPERIAPT_DEVICE_MATRIX_PROOF": "",
                },
                "QPERIAPT_DEVICE_MATRIX_PROOF",
            ),
            (
                {
                    "QPERIAPT_REQUIRE_ANDROID_RUNTIME": "1",
                    "QPERIAPT_ANDROID_DEVICE_PROOF": "",
                },
                "QPERIAPT_ANDROID_DEVICE_PROOF",
            ),
            (
                {
                    "QPERIAPT_REQUIRE_PERFORMANCE": "1",
                    "QPERIAPT_PERFORMANCE_PROOF": "",
                },
                "QPERIAPT_PERFORMANCE_PROOF",
            ),
        )
        hostile_paths = (
            "invalid\n::warning::injected\x1b[31m",
            "invalid\N{RIGHT-TO-LEFT OVERRIDE}path",
            "x" * 10_000,
        )
        for template, expected_label in path_cases:
            for hostile_path in hostile_paths:
                with self.subTest(path=expected_label, hostile_path=hostile_path):
                    overrides = {
                        name: hostile_path if value == "" else value
                        for name, value in template.items()
                    }
                    environment = {
                        name: value
                        for name, value in os.environ.items()
                        if not name.startswith("QPERIAPT_")
                    }
                    environment.update(
                        {
                            "QPERIAPT_SKIP_SMOKE": "1",
                            "QPERIAPT_EXPECTED_GIT_COMMIT": repository_head(),
                            "GITHUB_SHA": TEST_COMMIT,
                            **overrides,
                        }
                    )
                    result = subprocess.run(
                        ["sh", str(PROOF_SCRIPT)],
                        cwd=ROOT,
                        text=True,
                        capture_output=True,
                        check=False,
                        env=environment,
                    )
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertIn(
                        f"{expected_label} must be a non-empty printable path of at most 4095 filesystem bytes",
                        result.stderr,
                    )
                    self.assertNotIn("\n::warning::injected", result.stderr)
                    self.assertNotIn("\x1b", result.stderr)
                    self.assertNotIn("\N{RIGHT-TO-LEFT OVERRIDE}", result.stderr)
                    self.assertNotIn("Traceback", result.stderr)
                    self.assertLess(len(result.stderr), 1024)

        empty_path_cases = (
            (
                {
                    "QPERIAPT_REQUIRE_CAMERA_READY": "1",
                    "QPERIAPT_CAMERA_READY_BUNDLE": str(ROOT / "target" / "bundle"),
                    "QPERIAPT_CAMERA_READY_TRANSCRIPT": "",
                },
                "QPERIAPT_CAMERA_READY_TRANSCRIPT",
            ),
            (
                {
                    "QPERIAPT_REQUIRE_APPLE_DEVICE": "1",
                    "QPERIAPT_DEVICE_RESULT_DIR": "",
                },
                "QPERIAPT_DEVICE_RESULT_DIR",
            ),
            (
                {
                    "QPERIAPT_REQUIRE_APPLE_DEVICE_MATRIX": "1",
                    "QPERIAPT_DEVICE_MATRIX_PROOF": "",
                },
                "QPERIAPT_DEVICE_MATRIX_PROOF",
            ),
            (
                {
                    "QPERIAPT_REQUIRE_ANDROID_RUNTIME": "1",
                    "QPERIAPT_ANDROID_DEVICE_PROOF": "",
                },
                "QPERIAPT_ANDROID_DEVICE_PROOF",
            ),
            (
                {
                    "QPERIAPT_REQUIRE_PERFORMANCE": "1",
                    "QPERIAPT_PERFORMANCE_PROOF": "",
                },
                "QPERIAPT_PERFORMANCE_PROOF",
            ),
        )
        for overrides, expected_label in empty_path_cases:
            with self.subTest(empty_path=expected_label):
                environment = {
                    name: value
                    for name, value in os.environ.items()
                    if not name.startswith("QPERIAPT_")
                }
                environment.update(
                    {
                        "QPERIAPT_SKIP_SMOKE": "1",
                        "QPERIAPT_EXPECTED_GIT_COMMIT": repository_head(),
                        "GITHUB_SHA": TEST_COMMIT,
                        **overrides,
                    }
                )
                result = subprocess.run(
                    ["sh", str(PROOF_SCRIPT)],
                    cwd=ROOT,
                    text=True,
                    capture_output=True,
                    check=False,
                    env=environment,
                )
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertIn(
                    f"{expected_label} must be a non-empty printable path of at most 4095 filesystem bytes",
                    result.stderr,
                )
                self.assertNotIn("PROOF_TO_BYTE_", result.stdout)

    def test_clean_complete_state_requires_real_dependency_audit_pass(self) -> None:
        marker = format_marker(1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0)
        self.assertEqual(
            marker,
            "PROOF_TO_BYTE_APPLE_LOCAL_CANDIDATE_PASS camera_ready_bundle=not_required"
            f" commit={TEST_COMMIT} source_sha256={TEST_SOURCE_SHA256}"
            f" manifest_sha256={TEST_MANIFEST_SHA256}",
        )

    def test_required_camera_bundle_is_part_of_release_state(self) -> None:
        missing = format_marker(1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0)
        self.assertIn("PROOF_TO_BYTE_RUN_FINISHED", missing)
        self.assertIn("camera_ready_bundle=0", missing)
        verified = format_marker(1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0)
        self.assertEqual(
            verified,
            "PROOF_TO_BYTE_APPLE_LOCAL_CANDIDATE_PASS camera_ready_bundle=verified"
            f" commit={TEST_COMMIT} source_sha256={TEST_SOURCE_SHA256}"
            f" manifest_sha256={TEST_MANIFEST_SHA256}",
        )

    def test_missing_audit_is_scoped_summary_even_if_environment_claims_pass(self) -> None:
        with mock.patch.dict(os.environ, {"DEPENDENCY_AUDIT_PASSED": "1"}):
            marker = format_marker(1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0)
        self.assertIn("PROOF_TO_BYTE_RUN_FINISHED", marker)
        self.assertIn("dependency_audit=0", marker)
        self.assertNotIn("PROOF_TO_BYTE_APPLE_LOCAL_CANDIDATE_PASS", marker)

    def test_finalizer_never_claims_distribution_release(self) -> None:
        source = FINALIZER_SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn("PROOF_TO_BYTE_APPLE_RELEASE_PASS", source)

    def test_dirty_source_tree_cannot_emit_release_pass(self) -> None:
        marker = format_marker(1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0)
        self.assertEqual(
            marker,
            "PROOF_TO_BYTE_RELEASE_NOT_ATTESTED reason=dirty_source_tree"
            f" commit={TEST_COMMIT} source_sha256={TEST_SOURCE_SHA256}"
            f" manifest_sha256={TEST_MANIFEST_SHA256}",
        )

    def test_allow_dirty_proof_override_cannot_emit_release_pass(self) -> None:
        for apple_override, performance_override in ((1, 0), (0, 1)):
            with self.subTest(
                apple_override=apple_override,
                performance_override=performance_override,
            ):
                marker = format_marker(
                    1,
                    1,
                    0,
                    1,
                    0,
                    1,
                    0,
                    0,
                    1,
                    0,
                    apple_override,
                    performance_override,
                )
                self.assertEqual(
                    marker,
                    "PROOF_TO_BYTE_RELEASE_NOT_ATTESTED reason=diagnostic_proof_override"
                    f" commit={TEST_COMMIT} source_sha256={TEST_SOURCE_SHA256}"
                    f" manifest_sha256={TEST_MANIFEST_SHA256}",
                )

    def test_invalid_marker_state_fails_closed(self) -> None:
        with self.assertRaisesRegex(
            proof_to_byte_finalizer.FinalizerError,
            "release attestation state must be 0 or 1",
        ):
            format_marker(1, 1, 0, 1, 0, 1, 2, 0, 1, 0, 0, 0)

    def test_format_cli_is_not_exposed(self) -> None:
        result = subprocess.run(
            [
                "sh",
                str(ROOT / "artifact" / "python-run.sh"),
                str(FINALIZER_SCRIPT),
                "format",
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("invalid choice: 'format'", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_finalizer_rejects_clean_commit_transition(self) -> None:
        first = "1" * 40
        second = "2" * 40
        inspection = WorktreeInspection(commit=second, dirty=False, reasons=())
        with (
            mock.patch.object(
                proof_to_byte_finalizer,
                "git_commit",
                side_effect=[first, second],
            ),
            mock.patch.object(
                proof_to_byte_finalizer,
                "validate_release_metadata",
                return_value=(TEST_COMMIT, "e" * 64),
            ),
            mock.patch.object(
                proof_to_byte_finalizer,
                "verify_claim_ledger",
                return_value=TEST_SOURCE_SHA256,
            ),
            mock.patch.object(
                proof_to_byte_finalizer,
                "inspect_worktree",
                return_value=inspection,
            ),
        ):
            with self.assertRaisesRegex(
                proof_to_byte_finalizer.FinalizerError,
                "Git commit changed while finalizing",
            ):
                proof_to_byte_finalizer.capture_source_snapshot(
                    ROOT,
                    ROOT / "artifact" / "claim-ledger.json",
                    ROOT / "artifact" / "results.json",
                    TEST_MANIFEST_SHA256,
                )

    def test_finalizer_rejects_digest_or_dirty_state_transition(self) -> None:
        inspection = WorktreeInspection(commit=TEST_COMMIT, dirty=True, reasons=("changed",))
        with (
            mock.patch.object(
                proof_to_byte_finalizer,
                "git_commit",
                side_effect=[TEST_COMMIT, TEST_COMMIT],
            ),
            mock.patch.object(
                proof_to_byte_finalizer,
                "validate_release_metadata",
                return_value=(TEST_COMMIT, "e" * 64),
            ),
            mock.patch.object(
                proof_to_byte_finalizer,
                "verify_claim_ledger",
                side_effect=[TEST_SOURCE_SHA256, "d" * 64],
            ),
            mock.patch.object(
                proof_to_byte_finalizer,
                "inspect_worktree",
                return_value=inspection,
            ),
        ):
            with self.assertRaisesRegex(
                proof_to_byte_finalizer.FinalizerError,
                "canonical source digest changed",
            ):
                proof_to_byte_finalizer.capture_source_snapshot(
                    ROOT,
                    ROOT / "artifact" / "claim-ledger.json",
                    ROOT / "artifact" / "results.json",
                    TEST_MANIFEST_SHA256,
                )

        with (
            mock.patch.object(
                proof_to_byte_finalizer,
                "git_commit",
                side_effect=[TEST_COMMIT, TEST_COMMIT],
            ),
            mock.patch.object(
                proof_to_byte_finalizer,
                "validate_release_metadata",
                return_value=(TEST_COMMIT, "e" * 64),
            ),
            mock.patch.object(
                proof_to_byte_finalizer,
                "verify_claim_ledger",
                return_value=TEST_SOURCE_SHA256,
            ),
            mock.patch.object(
                proof_to_byte_finalizer,
                "inspect_worktree",
                return_value=inspection,
            ),
        ):
            with self.assertRaisesRegex(
                proof_to_byte_finalizer.FinalizerError,
                "source dirty state changed",
            ):
                proof_to_byte_finalizer.capture_source_snapshot(
                    ROOT,
                    ROOT / "artifact" / "claim-ledger.json",
                    ROOT / "artifact" / "results.json",
                    TEST_MANIFEST_SHA256,
                    expected_commit=TEST_COMMIT,
                    expected_source_sha256=TEST_SOURCE_SHA256,
                    expected_dirty=False,
                )

    def test_release_metadata_binds_snapshot_commit_and_footprint_csv(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            paper = root / "paper"
            paper.mkdir()
            footprint = paper / "footprint.csv"
            footprint.write_text(
                "# generated footprint\n"
                "host,rustc,artifact,bytes,kib\n"
                "Darwin 27.0.0 arm64,1.96.0,c-abi-cdylib-stripped,683800,667.8\n"
                "Darwin 27.0.0 arm64,1.96.0,wasm-lean-default,100034,97.7\n"
                "Darwin 27.0.0 arm64,1.96.0,wasm-signed-policy,340625,332.6\n",
                encoding="utf-8",
            )
            expected, footprint_sha256 = proof_to_byte_finalizer._load_footprint_csv(
                footprint
            )
            self.assertEqual(expected["platform"], "Darwin 27.0.0 arm64, rustc 1.96.0")
            self.assertEqual(
                expected["c_abi_cdylib_stripped"],
                {"bytes": 683800, "kib": 667.8},
            )
            document = {
                "provenance": {"snapshot_commit": TEST_COMMIT},
                "footprint_bytes": expected,
            }
            manifest_snapshot = mock.Mock(value=document)
            with (
                mock.patch.object(
                    proof_to_byte_finalizer,
                    "load_results_manifest_snapshot",
                    return_value=manifest_snapshot,
                ),
                mock.patch.object(
                    proof_to_byte_finalizer,
                    "require_commit_or_evidence_successor",
                ) as require_successor,
            ):
                self.assertEqual(
                    proof_to_byte_finalizer.validate_release_metadata(
                        root,
                        root / "artifact" / "results.json",
                        TEST_MANIFEST_SHA256,
                    ),
                    (TEST_COMMIT, footprint_sha256),
                )
                require_successor.assert_called_once_with(root, TEST_COMMIT)

                document["footprint_bytes"] = dict(expected)
                document["footprint_bytes"]["wasm_lean_default"] = {
                    "bytes": 100035,
                    "kib": 97.7,
                }
                with self.assertRaisesRegex(
                    proof_to_byte_finalizer.FinalizerError,
                    "footprint_bytes differs",
                ):
                    proof_to_byte_finalizer.validate_release_metadata(
                        root,
                        root / "artifact" / "results.json",
                        TEST_MANIFEST_SHA256,
                    )

    def test_footprint_csv_rejects_duplicate_and_inconsistent_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            footprint = pathlib.Path(temporary) / "footprint.csv"
            footprint.write_text(
                "host,rustc,artifact,bytes,kib\n"
                "host,1.96.0,c-abi-cdylib-stripped,1024,1.0\n"
                "host,1.96.0,wasm-lean-default,1024,1.0\n"
                "host,1.96.0,wasm-lean-default,1024,1.0\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                proof_to_byte_finalizer.FinalizerError,
                "unknown or duplicate artifact",
            ):
                proof_to_byte_finalizer._load_footprint_csv(footprint)

            footprint.write_text(
                "host,rustc,artifact,bytes,kib\n"
                "host,1.96.0,c-abi-cdylib-stripped,1024,1.0\n"
                "host,1.96.0,wasm-lean-default,1024,1.0\n"
                "other,1.96.0,wasm-signed-policy,1024,1.0\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                proof_to_byte_finalizer.FinalizerError,
                "share one host",
            ):
                proof_to_byte_finalizer._load_footprint_csv(footprint)

    def test_footprint_csv_numeric_failures_are_contextual_finalizer_errors(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            footprint = pathlib.Path(temporary) / "footprint.csv"
            trailing_rows = (
                "host,1.96.0,wasm-lean-default,1024,1.0\n"
                "host,1.96.0,wasm-signed-policy,1024,1.0\n"
            )
            cases = (
                (
                    "9" * 5000,
                    "1.0",
                    r"artifact 'c-abi-cdylib-stripped' field 'bytes' exceeds",
                ),
                (
                    "1024",
                    "1.1",
                    r"artifact 'c-abi-cdylib-stripped' field 'kib' differs from bytes",
                ),
            )
            for raw_bytes, raw_kib, message in cases:
                with self.subTest(message=message):
                    footprint.write_text(
                        "host,rustc,artifact,bytes,kib\n"
                        f"host,1.96.0,c-abi-cdylib-stripped,{raw_bytes},{raw_kib}\n"
                        + trailing_rows,
                        encoding="utf-8",
                    )
                    with self.assertRaisesRegex(
                        proof_to_byte_finalizer.FinalizerError,
                        message,
                    ):
                        proof_to_byte_finalizer._load_footprint_csv(footprint)

    def test_release_metadata_rejects_extra_fields_and_wrong_numeric_types(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            paper = root / "paper"
            paper.mkdir()
            footprint = paper / "footprint.csv"
            footprint.write_text(
                "host,rustc,artifact,bytes,kib\n"
                "host,1.96.0,c-abi-cdylib-stripped,1024,1.0\n"
                "host,1.96.0,wasm-lean-default,2048,2.0\n"
                "host,1.96.0,wasm-signed-policy,3072,3.0\n",
                encoding="utf-8",
            )
            expected, _ = proof_to_byte_finalizer._load_footprint_csv(footprint)
            document = {
                "provenance": {"snapshot_commit": TEST_COMMIT},
                "footprint_bytes": expected,
            }
            manifest_snapshot = mock.Mock(value=document)
            with (
                mock.patch.object(
                    proof_to_byte_finalizer,
                    "load_results_manifest_snapshot",
                    return_value=manifest_snapshot,
                ),
                mock.patch.object(
                    proof_to_byte_finalizer,
                    "require_commit_or_evidence_successor",
                ),
            ):
                invalid_cases = (
                    (
                        lambda value: value.update({"unexpected": {}}),
                        "footprint_bytes fields differ.*extra=\\['unexpected'\\]",
                    ),
                    (
                        lambda value: value["wasm_lean_default"].update(
                            {"unexpected": 0}
                        ),
                        "entry 'wasm_lean_default' fields differ.*unexpected",
                    ),
                    (
                        lambda value: value["wasm_lean_default"].update(
                            {"bytes": True}
                        ),
                        "entry 'wasm_lean_default' field 'bytes' must be an integer",
                    ),
                    (
                        lambda value: value["wasm_lean_default"].update({"kib": 2}),
                        "entry 'wasm_lean_default' field 'kib' must be a finite JSON float",
                    ),
                )
                for mutate, message in invalid_cases:
                    with self.subTest(message=message):
                        document["footprint_bytes"] = copy.deepcopy(expected)
                        mutate(document["footprint_bytes"])
                        with self.assertRaisesRegex(
                            proof_to_byte_finalizer.FinalizerError,
                            message,
                        ):
                            proof_to_byte_finalizer.validate_release_metadata(
                                root,
                                root / "artifact" / "results.json",
                                TEST_MANIFEST_SHA256,
                            )

    def test_audit_pass_state_is_set_only_after_warning_denied_command(self) -> None:
        source = PROOF_SCRIPT.read_text(encoding="utf-8")
        initial = source.index("DEPENDENCY_AUDIT_PASSED=0")
        command = source.index("cargo audit --deny warnings")
        passed = source.index("DEPENDENCY_AUDIT_PASSED=1")
        self.assertLess(initial, command)
        self.assertLess(command, passed)
        self.assertNotIn("cargo audit --deny warnings ||", source)
        self.assertNotIn("cargo audit --deny warnings; true", source)
        self.assertNotIn("--ignore", source)

    def test_ci_uses_warning_denied_audit_without_suppression(self) -> None:
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("- run: cargo audit --deny warnings", workflow)
        self.assertNotIn("cargo audit --deny warnings ||", workflow)
        self.assertNotIn("cargo audit --ignore", workflow)

    def test_ci_check_fetches_full_history_for_evidence_successors(self) -> None:
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")
        validate_ci_check_checkout(extract_ci_check_job(workflow))

    def test_ci_checkout_mutations_fail_closed(self) -> None:
        check_job = extract_ci_check_job(CI_WORKFLOW.read_text(encoding="utf-8"))
        mutations = {
            "unpinned action": check_job.replace(
                PINNED_CHECKOUT_ACTION,
                "actions/checkout@main",
                1,
            ),
            "ref override": check_job.replace(
                "          fetch-depth: 0\n",
                "          fetch-depth: 0\n          ref: deadbeef\n",
                1,
            ),
            "repository override": check_job.replace(
                "          fetch-depth: 0\n",
                "          fetch-depth: 0\n          repository: other/project\n",
                1,
            ),
            "duplicate with": check_job.replace(
                "          fetch-depth: 0\n",
                "          fetch-depth: 0\n        with:\n          ref: deadbeef\n",
                1,
            ),
            "missing provenance check": check_job.replace(
                EXPECTED_CHECKOUT_PROVENANCE_STEP,
                "",
                1,
            ),
            "non-blocking provenance check": check_job.replace(
                EXPECTED_CHECKOUT_PROVENANCE_STEP,
                EXPECTED_CHECKOUT_PROVENANCE_STEP
                + "        continue-on-error: true\n",
                1,
            ),
            "post-check provenance mutation": check_job.replace(
                EXPECTED_CHECKOUT_PROVENANCE_STEP,
                EXPECTED_CHECKOUT_PROVENANCE_STEP
                + "          git checkout --detach HEAD^\n",
                1,
            ),
            "non-blocking proof": check_job.replace(
                EXPECTED_PROOF_TO_BYTE_STEP,
                EXPECTED_PROOF_TO_BYTE_STEP + "        continue-on-error: true\n",
                1,
            ),
            "conditional proof": check_job.replace(
                EXPECTED_PROOF_TO_BYTE_STEP,
                EXPECTED_PROOF_TO_BYTE_STEP + "        if: failure()\n",
                1,
            ),
            "PR head instead of tested merge commit": check_job.replace(
                EXPECTED_PROOF_TO_BYTE_STEP,
                EXPECTED_PROOF_TO_BYTE_STEP.replace(
                    "${{ github.sha }}",
                    "${{ github.event.pull_request.head.sha }}",
                ),
                1,
            ),
            "numeric alias": check_job + "      - uses: *1\n",
            "hyphen alias": check_job + "      - uses: *-foo\n",
            "merge alias": check_job + "        <<: *checkout-settings\n",
            "second checkout": check_job
            + "      - uses: Actions/Checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0\n",
        }
        for label, mutation in mutations.items():
            with self.subTest(label=label):
                with self.assertRaises(ValueError):
                    validate_ci_check_checkout(mutation)

    def test_freeze_expected_commit_argument_is_optional_and_exact(self) -> None:
        arguments = [
            "freeze",
            "--root",
            str(ROOT),
            "--ledger",
            str(ROOT / "artifact" / "claim-ledger.json"),
            "--manifest",
            str(ROOT / "artifact" / "results.json"),
            "--expected-manifest-sha256",
            TEST_MANIFEST_SHA256,
        ]
        parser = proof_to_byte_finalizer.build_parser()
        self.assertIsNone(parser.parse_args(arguments).expected_git_commit)
        self.assertEqual(
            parser.parse_args(
                [*arguments, "--expected-git-commit", TEST_COMMIT]
            ).expected_git_commit,
            TEST_COMMIT,
        )
        snapshot = proof_to_byte_finalizer.SourceSnapshot(
            commit=TEST_COMMIT,
            source_sha256=TEST_SOURCE_SHA256,
            manifest_sha256=TEST_MANIFEST_SHA256,
            dirty=False,
        )
        for expected_commit, extra_arguments in (
            (None, ()),
            (TEST_COMMIT, ("--expected-git-commit", TEST_COMMIT)),
        ):
            with self.subTest(expected_commit=expected_commit):
                parsed = parser.parse_args([*arguments, *extra_arguments])
                with (
                    mock.patch.object(
                        proof_to_byte_finalizer,
                        "capture_source_snapshot",
                        return_value=snapshot,
                    ) as capture,
                    mock.patch("builtins.print") as output,
                ):
                    proof_to_byte_finalizer.run(parsed)
                capture.assert_called_once_with(
                    ROOT.resolve(),
                    (ROOT / "artifact" / "claim-ledger.json").resolve(),
                    (ROOT / "artifact" / "results.json").resolve(),
                    TEST_MANIFEST_SHA256,
                    expected_commit=expected_commit,
                )
                output.assert_called_once_with(
                    f"{TEST_COMMIT}:{TEST_SOURCE_SHA256}:0"
                )

    def test_proof_to_byte_validates_explicit_expected_commit(self) -> None:
        source = PROOF_SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn("GITHUB_SHA", source)

        def run_with_expected_commit(value: str) -> subprocess.CompletedProcess[str]:
            environment = {
                name: current
                for name, current in os.environ.items()
                if not name.startswith("QPERIAPT_")
            }
            environment.update(
                {
                    "QPERIAPT_SKIP_SMOKE": "1",
                    "QPERIAPT_EXPECTED_GIT_COMMIT": value,
                    "GITHUB_SHA": TEST_COMMIT,
                    "GIT_DIR": str(ROOT / "does-not-exist"),
                    "GIT_WORK_TREE": str(ROOT / "does-not-exist"),
                    "GIT_CONFIG_GLOBAL": str(ROOT / "does-not-exist"),
                    "GIT_NO_REPLACE_OBJECTS": "0",
                }
            )
            return subprocess.run(
                ["sh", str(PROOF_SCRIPT)],
                cwd=ROOT,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )

        for label, malformed in (
            ("short", "0" * 39),
            ("long", "0" * 41),
            ("uppercase", "A" * 40),
            ("non-hex", "g" * 40),
        ):
            with self.subTest(label=label):
                result = run_with_expected_commit(malformed)
                self.assertEqual(result.returncode, 2)
                self.assertIn("exactly 40 lowercase hexadecimal", result.stderr)
                self.assertNotIn("PROOF_TO_BYTE_", result.stdout)

        result = run_with_expected_commit("0" * 40)
        self.assertEqual(result.returncode, 2)
        self.assertIn(
            "checked-out Git commit does not match expected provenance",
            result.stderr,
        )
        self.assertIn(f"got {repository_head()}", result.stderr)
        self.assertNotIn("PROOF_TO_BYTE_", result.stdout)

        with tempfile.TemporaryDirectory() as temporary:
            alternate = pathlib.Path(temporary) / "alternate-repository"
            subprocess.run(
                ["/usr/bin/git", "init", "-q", str(alternate)],
                check=True,
                capture_output=True,
            )
            (alternate / "fixture.txt").write_text("alternate\n", encoding="utf-8")
            subprocess.run(
                ["/usr/bin/git", "-C", str(alternate), "add", "fixture.txt"],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [
                    "/usr/bin/git",
                    "-C",
                    str(alternate),
                    "-c",
                    "user.name=Proof Test",
                    "-c",
                    "user.email=proof@example.invalid",
                    "commit",
                    "-qm",
                    "alternate",
                ],
                check=True,
                capture_output=True,
            )
            alternate_head = git_commit(alternate)
            self.assertNotEqual(alternate_head, repository_head())
            environment = {
                name: value
                for name, value in os.environ.items()
                if not name.startswith("QPERIAPT_")
            }
            environment.update(
                {
                    "QPERIAPT_SKIP_SMOKE": "1",
                    "QPERIAPT_EXPECTED_GIT_COMMIT": alternate_head,
                    "GITHUB_SHA": TEST_COMMIT,
                    "GIT_DIR": str(alternate / ".git"),
                    "GIT_WORK_TREE": str(alternate),
                    "GIT_COMMON_DIR": str(alternate / ".git"),
                    "GIT_OBJECT_DIRECTORY": str(alternate / ".git" / "objects"),
                }
            )
            spoofed = subprocess.run(
                ["sh", str(PROOF_SCRIPT)],
                cwd=ROOT,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(spoofed.returncode, 2, spoofed.stderr)
            self.assertIn(f"got {repository_head()}", spoofed.stderr)
            self.assertIn(f"expected {alternate_head}", spoofed.stderr)
            self.assertEqual(spoofed.stdout, "")

    def test_ci_discovers_every_artifact_python_test(self) -> None:
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn(
            "sh artifact/python-run.sh -m unittest discover -s artifact -p 'test_*.py' -v",
            workflow,
        )
        self.assertNotIn("python3 -m unittest", workflow)

    def test_ci_repository_python_calls_use_one_shot_runner(self) -> None:
        workflows = sorted((ROOT / ".github" / "workflows").glob("*.y*ml"))
        self.assertTrue(workflows)
        direct_python = re.compile(r"(?<![A-Za-z0-9_])python3(?![A-Za-z0-9_])")
        repository_script = re.compile(r"artifact/[A-Za-z0-9_.-]+\.py(?:\s|$)")
        runner_calls = 0
        for workflow in workflows:
            for number, line in enumerate(
                workflow.read_text(encoding="utf-8").splitlines(), start=1
            ):
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                self.assertIsNone(
                    direct_python.search(line),
                    f"{workflow.relative_to(ROOT)}:{number} invokes Python directly",
                )
                if repository_script.search(line):
                    self.assertIn(
                        "sh artifact/python-run.sh",
                        line,
                        f"{workflow.relative_to(ROOT)}:{number} bypasses the one-shot runner",
                    )
                runner_calls += line.count("sh artifact/python-run.sh")
        self.assertGreaterEqual(runner_calls, 2)


class CameraReadyEvidenceGateTests(unittest.TestCase):
    def test_unconfirmed_host_fails_without_success_marker(self) -> None:
        environment = os.environ.copy()
        environment.pop("QPERIAPT_BARE_METAL_CONFIRMED", None)
        result = subprocess.run(
            ["sh", str(CAMERA_READY_SCRIPT)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            env=environment,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("CAMERA_READY_BARE_METAL_PASS", result.stdout)

    def test_script_has_no_skip_or_shellcheck_suppression_path(self) -> None:
        source = CAMERA_READY_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("set -eu", source)
        self.assertNotIn("SKIP:", source)
        self.assertNotIn("|| true", source)
        self.assertNotIn("shellcheck disable", source)
        self.assertEqual(source.count("CAMERA_READY_BARE_METAL_PASS"), 1)

    def test_documented_camera_ready_invocation_preserves_script_failure(self) -> None:
        script = CAMERA_READY_SCRIPT.read_text(encoding="utf-8")
        guide = ARTIFACT_GUIDE.read_text(encoding="utf-8")
        paper = PAPER_SOURCE.read_text(encoding="utf-8")
        for source in (script, guide):
            self.assertIn("QPERIAPT_BARE_METAL_CONFIRMED=1", source)
            self.assertIn("bash -o pipefail", source)
            self.assertNotIn("sudo -E", source)
            self.assertNotIn("sudo sh camera-ready-bare-metal.sh", source)
        self.assertIn(r"QPERIAPT\_BARE\_METAL\_CONFIRMED=1", paper)
        self.assertNotIn("sudo sh", paper)

    def test_privileged_state_has_narrow_ownership_checked_contract(self) -> None:
        source = CAMERA_READY_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("root process is the narrow host-state supervisor", source)
        self.assertIn("--clear-groups", source)
        self.assertIn("--no-new-privs", source)
        self.assertIn("--inh-caps=-all", source)
        self.assertIn("cgroup.kill", source)
        self.assertIn("QPERIAPT_FROZEN_LAUNCHER=1", source)
        self.assertIn("dedicated runner account must have a nologin/false shell", source)
        self.assertIn("source snapshot is not root-owned read-only", source)
        self.assertIn("cargo must be root-owned and not group/world writable", source)
        self.assertIn("/sys/devices/system/cpu/cpufreq/policy*/scaling_governor", source)
        self.assertNotIn("/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor", source)
        self.assertIn("NETEM_HANDLE=51ab:", source)
        self.assertIn('qdisc del dev lo root handle "$NETEM_HANDLE"', source)
        self.assertIn("refusing to delete non-identical state", source)
        self.assertIn("changed concurrently; refusing to overwrite it", source)
        self.assertIn("validate_sysctl_record", source)
        self.assertIn("validate_sysfs_record", source)
        self.assertIn('SYSFS_RECORDS=""', source)
        self.assertIn('SYSCTL_RECORDS=""', source)
        self.assertNotIn("governors.state", source)
        self.assertNotIn("sysctls.state", source)
        self.assertNotIn("docker run", source)
        self.assertIn("ct_mode=native", source)

    def test_root_launcher_and_early_cleanup_precede_runner_code(self) -> None:
        source = CAMERA_READY_SCRIPT.read_text(encoding="utf-8")
        launcher = source.index("QPERIAPT_FROZEN_LAUNCHER=1")
        early_trap = source.index("trap early_exit EXIT")
        work = source.index('WORK=$("$MKTEMP" -d "$WORK_ROOT/qperiapt-camera-ready.')
        runner = source.index("run_as_runner()")
        first_runner_call = source.index("FROZEN_SOURCE_TREE_SHA256=$(canonical_source_digest)")
        self.assertLess(launcher, early_trap)
        self.assertLess(early_trap, work)
        self.assertLess(work, runner)
        self.assertLess(runner, first_runner_call)
        self.assertIn("executed root-owned launcher does not match the clean Git archive", source)

    def test_runner_descendants_and_measurement_binaries_are_frozen(self) -> None:
        source = CAMERA_READY_SCRIPT.read_text(encoding="utf-8")
        self.assertIn('>"$run_group/cgroup.procs"', source)
        self.assertIn('>"$run_group/cgroup.kill"', source)
        self.assertIn("cgroup_has_processes", source)
        netem_copy = source.index('freeze_runner_binary "$BUILT_NETEM_BIN" "$BIN"')
        netem_run = source.index('"$TASKSET" -c "$PIN" "$BIN"')
        ct_copy = source.index(
            'freeze_runner_binary "$BUILT_CT_ROOT/ct_leaky_control" '
            '"$LEAKY_CONTROL_BIN"'
        )
        ct_run = source.index(
            'run_memcheck "$LEAKY_CONTROL_BIN" planted leaky-control'
        )
        self.assertLess(netem_copy, netem_run)
        self.assertLess(ct_copy, ct_run)
        self.assertIn('HOME="$VALIDATION_HOME"', source)
        self.assertIn('"$CHMOD" 0550 "$binary_target"', source)

    def test_runner_sandbox_is_bounded_locked_and_cleaned_before_work_removal(self) -> None:
        source = CAMERA_READY_SCRIPT.read_text(encoding="utf-8")
        sandbox = CAMERA_SANDBOX_SCRIPT.read_text(encoding="utf-8")
        lock = source.index('"$FLOCK" -n 9')
        process_scan = source.index('pathlib.Path("/proc").glob')
        restore_unmount = source.rindex("if ! cleanup_runner_fs; then")
        work_remove = source.index('if ! "$RM" -rf -- "$WORK"; then')
        self.assertLess(lock, process_scan)
        self.assertLess(restore_unmount, work_remove)
        self.assertIn("size=8589934592,nr_inodes=524288", source)
        self.assertIn('"$UNSHARE" --mount --ipc --net', source)
        self.assertIn('"$UNSHARE" --mount --ipc --', source)
        self.assertIn("run_as_measurement", source)
        self.assertIn("ro=recursive", sandbox)
        self.assertIn("writable mount escaped camera-ready sandbox", sandbox)
        self.assertIn("qperiapt-private-tmp", sandbox)

    def test_camera_gate_requires_raw_bundle_and_scoped_marker(self) -> None:
        source = PROOF_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("QPERIAPT_CAMERA_READY_BUNDLE", source)
        self.assertIn("must explicitly name the root-owned run-id bundle", source)
        self.assertNotIn(
            'QPERIAPT_CAMERA_READY_BUNDLE:-$ROOT/target/camera-ready/bundle', source
        )
        self.assertIn("camera_ready_proof.py verify", source)
        self.assertIn("--bundle", source)
        self.assertIn("--max-age-seconds", source)
        self.assertIn("PROOF_TO_BYTE_CAMERA_READY_CAPTURE_EVIDENCE_PASS", source)
        self.assertIn("producer_origin_not_independent_attestation", source)
        self.assertNotIn("PROOF_TO_BYTE_CAMERA_READY_PASS", source)

    def test_primary_transcript_freezes_source_toolchain_and_binaries(self) -> None:
        source = CAMERA_READY_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("camera-ready primary evidence requires a clean source tree", source)
        self.assertIn("build --frozen --release", source)
        self.assertIn('CARGO_TARGET_DIR="$RUNNER_ROOT/target-$build_lane"', source)
        self.assertIn("validate-cargo-seed", source)
        self.assertIn("run_as_builder", source)
        self.assertIn('"$UNSHARE" --net --', source)
        self.assertIn('>"$run_group/pids.max"', source)
        self.assertIn('>"$run_group/memory.max"', source)
        self.assertIn("archive --format=tar", source)
        self.assertIn("source-archive-sha256", source)
        self.assertIn("FROZEN_SOURCE_TREE_SHA256=$(canonical_source_digest)", source)
        self.assertIn("FINAL_SOURCE_TREE_SHA256=$(canonical_source_digest)", source)
        self.assertIn("camera-ready bundle", source)
        self.assertIn("netem-binary-sha256", source)
        self.assertIn("mlkem-ct-binary-sha256", source)
        self.assertIn("leaky-control-ct-binary-sha256", source)
        self.assertNotIn("hqc-ct-binary-sha256", source)
        proof_source = PROOF_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("camera_ready_sandbox_script_sha256", proof_source)

    def test_camera_harness_and_verifier_tool_sets_match(self) -> None:
        source = CAMERA_READY_SCRIPT.read_text(encoding="utf-8")
        recorded = set(re.findall(r'"([a-z0-9-]+)\|\$[A-Z0-9_]+"', source))
        self.assertEqual(recorded, EXPECTED_TOOLS)

    def test_success_marker_follows_complete_matrix_and_discriminator_assertions(self) -> None:
        source = CAMERA_READY_SCRIPT.read_text(encoding="utf-8")
        marker = source.index("CAMERA_READY_BARE_METAL_PASS")
        matrix_gate = source.index(
            '[ "$NETEM_RUNS" -eq "$EXPECTED_NETEM_RUNS" ]'
        )
        mlkem_gate = source.index('[ "$MLKEM_PROBE_ERRORS" -eq 0 ]')
        leaky_control_gate = source.index('[ "$LEAKY_CONTROL_ERRORS" -gt 0 ]')
        cleanup_gate = source.rindex("if ! restore; then")
        source_recheck = source.index(
            '[ "$FINAL_SOURCE_TREE_SHA256" = "$FROZEN_SOURCE_TREE_SHA256" ]'
        )
        binary_recheck = source.index(
            '[ "$(sha256_file "$LEAKY_CONTROL_BIN")" = '
            '"$LEAKY_CONTROL_BIN_SHA256" ]'
        )
        self.assertLess(matrix_gate, marker)
        self.assertLess(mlkem_gate, marker)
        self.assertLess(leaky_control_gate, marker)
        self.assertLess(binary_recheck, marker)
        self.assertLess(source_recheck, marker)
        self.assertLess(cleanup_gate, marker)


if __name__ == "__main__":
    unittest.main()
