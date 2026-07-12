import copy
import pathlib
import subprocess
import tempfile
import unittest

from continuity_context import (
    ContextVectorError,
    encode_input,
    load_json,
    render_vectors,
    verify_vectors,
)


ROOT = pathlib.Path(__file__).resolve().parents[1]
VECTORS = ROOT / "models/q-periapt-continuity-model/vectors/lifecycle-context-v1.json"


class ContinuityContextTests(unittest.TestCase):
    def setUp(self) -> None:
        self.document = load_json(VECTORS)

    def test_frozen_vectors_recompute_exactly(self) -> None:
        verify_vectors(self.document)

    def test_vector_loader_rejects_ambiguous_or_unsafe_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            invalid_documents = {
                "duplicate.json": '{"schema_version":1,"schema_version":1,"vectors":[]}',
                "nonfinite.json": '{"schema_version":NaN,"vectors":[]}',
                "array.json": "[]",
            }
            for filename, contents in invalid_documents.items():
                path = root / filename
                path.write_text(contents, encoding="utf-8")
                with self.subTest(filename=filename), self.assertRaises(ContextVectorError):
                    load_json(path)

            target = root / "target.json"
            target.write_text('{"schema_version":1,"vectors":[]}', encoding="utf-8")
            link = root / "link.json"
            link.symlink_to(target)
            with self.assertRaises(ContextVectorError):
                load_json(link)

    def test_rust_encoder_matches_the_independent_python_encoder(self) -> None:
        completed = subprocess.run(
            [
                "cargo",
                "run",
                "--quiet",
                "--locked",
                "-p",
                "q-periapt-continuity-model",
                "--example",
                "continuity_context_vectors",
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        emitted: dict[str, str] = {}
        for line in completed.stdout.splitlines():
            name, separator, value = line.partition("=")
            self.assertEqual(separator, "=", line)
            self.assertNotIn(name, emitted)
            emitted[name] = value

        expected: dict[str, str] = {}
        for vector in self.document["vectors"]:
            encoded = encode_input(vector["input"])
            name = vector["name"]
            expected[f"{name}.policy_bound_kctx"] = encoded["policy_bound_kctx"].hex()
            expected[f"{name}.digest_preimage"] = encoded["digest_preimage"].hex()
        self.assertEqual(emitted, expected)

    def test_expected_hash_mutation_fails_closed(self) -> None:
        mutated = copy.deepcopy(self.document)
        mutated["vectors"][0]["expected"]["body_sha256"] = "00" * 32
        with self.assertRaises(ContextVectorError):
            verify_vectors(mutated)

    def test_every_named_input_mutation_changes_expected_values(self) -> None:
        vector = self.document["vectors"][0]
        baseline = render_vectors(
            {"schema_version": 2, "vectors": [{"name": "baseline", "input": vector["input"]}]}
        )["vectors"][0]["expected"]
        mutations = []
        suite = copy.deepcopy(vector["input"])
        suite["suite_digest"] = "aa" * 32
        suite["prekey_selection"]["suite_digest"] = "aa" * 32
        mutations.append(("suite_digest", suite))
        identity_mode = copy.deepcopy(vector["input"])
        identity_mode["identity_mode"] = "deniable"
        mutations.append(("identity_mode", identity_mode))
        checkpoint = copy.deepcopy(vector["input"])
        checkpoint["directory_checkpoint_digest"] = "ac" * 32
        checkpoint["prekey_selection"]["directory_checkpoint_digest"] = "ac" * 32
        mutations.append(("directory_checkpoint_digest", checkpoint))
        manifest = copy.deepcopy(vector["input"])
        manifest["prekey_selection"]["signed_prekey_manifest_digest"] = "ad" * 32
        mutations.append(("signed_prekey_manifest_digest", manifest))
        selected = copy.deepcopy(vector["input"])
        selected["prekey_selection"]["classical"]["selected_prekey_id"] = "ae" * 32
        mutations.append(("classical.selected_prekey_id", selected))
        for field, candidate in mutations:
            rendered = render_vectors(
                {"schema_version": 2, "vectors": [{"name": field, "input": candidate}]}
            )["vectors"][0]["expected"]
            self.assertNotEqual(rendered, baseline, field)

    def test_stage_role_zero_and_unknown_enum_fail(self) -> None:
        baseline = self.document["vectors"][0]["input"]
        cases = []
        wrong_stage = copy.deepcopy(baseline)
        wrong_stage["authentication_stage"] = "peer_confirmed"
        cases.append(wrong_stage)
        same_party = copy.deepcopy(baseline)
        same_party["responder"] = copy.deepcopy(same_party["initiator"])
        cases.append(same_party)
        same_logical_device_new_epoch = copy.deepcopy(baseline)
        same_logical_device_new_epoch["responder"]["account_id"] = baseline[
            "initiator"
        ]["account_id"]
        same_logical_device_new_epoch["responder"]["device_id"] = baseline[
            "initiator"
        ]["device_id"]
        same_logical_device_new_epoch["responder"]["device_epoch"] = (
            baseline["initiator"]["device_epoch"] + 1
        )
        cases.append(same_logical_device_new_epoch)
        zero_suite = copy.deepcopy(baseline)
        zero_suite["suite_digest"] = "00" * 32
        cases.append(zero_suite)
        unknown_mode = copy.deepcopy(baseline)
        unknown_mode["prekey_selection"]["classical"]["mode"] = "automatic"
        cases.append(unknown_mode)
        reverse_direction = copy.deepcopy(baseline)
        reverse_direction["direction"] = "responder_to_initiator"
        cases.append(reverse_direction)
        for candidate in cases:
            with self.assertRaises(ContextVectorError):
                encode_input(candidate)

    def test_prekey_scope_grafting_fails_closed(self) -> None:
        baseline = self.document["vectors"][0]["input"]
        cases = []
        suite = copy.deepcopy(baseline)
        suite["prekey_selection"]["suite_digest"] = "aa" * 32
        cases.append(suite)
        responder = copy.deepcopy(baseline)
        responder["prekey_selection"]["responder"]["device_id"] = "ab" * 16
        cases.append(responder)
        checkpoint = copy.deepcopy(baseline)
        checkpoint["prekey_selection"]["directory_checkpoint_digest"] = "ac" * 32
        cases.append(checkpoint)
        for candidate in cases:
            with self.assertRaises(ContextVectorError):
                encode_input(candidate)

    def test_root_transition_pattern_and_overflow_fail(self) -> None:
        baseline = self.document["vectors"][1]["input"]
        zero_start = copy.deepcopy(baseline)
        for leg in ("root", "dh", "pq"):
            zero_start[f"prior_{leg}_epoch"] = 0
            zero_start[f"next_{leg}_epoch"] = 1
        self.assertEqual(len(encode_input(zero_start)["body"]), 626)

        terminal = copy.deepcopy(baseline)
        for leg in ("root", "dh", "pq"):
            terminal[f"prior_{leg}_epoch"] = (1 << 64) - 2
            terminal[f"next_{leg}_epoch"] = (1 << 64) - 1
        self.assertEqual(len(encode_input(terminal)["body"]), 626)

        unchanged_terminal = copy.deepcopy(baseline)
        unchanged_terminal["root_transition_kind"] = "dh"
        unchanged_terminal["prior_pq_epoch"] = (1 << 64) - 1
        unchanged_terminal["next_pq_epoch"] = (1 << 64) - 1
        self.assertEqual(len(encode_input(unchanged_terminal)["body"]), 626)

        skipped = copy.deepcopy(baseline)
        skipped["next_root_epoch"] += 1
        wrong_leg = copy.deepcopy(baseline)
        wrong_leg["next_pq_epoch"] += 1
        overflow = copy.deepcopy(baseline)
        overflow["prior_root_epoch"] = (1 << 64) - 1
        overflow["next_root_epoch"] = 0
        for candidate in (skipped, wrong_leg, overflow):
            with self.assertRaises(ContextVectorError):
                encode_input(candidate)


if __name__ == "__main__":
    unittest.main()
