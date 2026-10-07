import copy
import pathlib
import subprocess
import tempfile
import unittest

from prekey_selection import (
    PREKEY_SELECTION_ENCODED_LEN,
    PrekeyVectorError,
    decode_record,
    encode_input,
    load_json,
    render_vectors,
    verify_vectors,
)


ROOT = pathlib.Path(__file__).resolve().parents[1]
VECTORS = ROOT / "models/q-periapt-continuity-model/vectors/prekey-selection-v1.json"


class PrekeySelectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.document = load_json(VECTORS)

    def test_frozen_vectors_recompute_exactly(self) -> None:
        verify_vectors(self.document)
        self.assertEqual(
            [vector["expected"]["quality_code"] for vector in self.document["vectors"]],
            [1, 2, 3, 4],
        )

    def test_rust_encoder_matches_full_independent_python_bytes(self) -> None:
        completed = subprocess.run(
            [
                "cargo",
                "run",
                "--quiet",
                "--locked",
                "-p",
                "q-periapt-continuity-model",
                "--example",
                "prekey_selection_vectors",
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
            name = vector["name"]
            expected[f"{name}.record"] = vector["expected"]["record_hex"]
            expected[f"{name}.digest_preimage"] = vector["expected"]["digest_preimage_hex"]
        self.assertEqual(emitted, expected)

    def test_python_decoder_roundtrips_all_four_canonical_records(self) -> None:
        for vector in self.document["vectors"]:
            record = bytes.fromhex(vector["expected"]["record_hex"])
            decoded = decode_record(record)
            self.assertEqual(decoded, vector["input"])
            self.assertEqual(encode_input(decoded)["record"], record)

    def test_decoder_rejects_every_truncation_trailing_and_compensated_lengths(self) -> None:
        canonical = bytes.fromhex(self.document["vectors"][0]["expected"]["record_hex"])
        self.assertEqual(len(canonical), PREKEY_SELECTION_ENCODED_LEN)
        for length in range(len(canonical)):
            with self.subTest(length=length), self.assertRaises(PrekeyVectorError):
                decode_record(canonical[:length])
        with self.assertRaises(PrekeyVectorError) as trailing:
            decode_record(canonical + b"\x00")
        self.assertEqual(trailing.exception.code, "trailing_bytes")

        offsets: list[int] = []
        offset = 0
        for _ in range(16):
            offsets.append(offset)
            length = int.from_bytes(canonical[offset : offset + 8], "big")
            offset += 8 + length
        for offset in offsets:
            huge = bytearray(canonical)
            huge[offset : offset + 8] = ((1 << 64) - 1).to_bytes(8, "big")
            with self.assertRaises(PrekeyVectorError):
                decode_record(bytes(huge))

        compensated = bytearray(canonical)
        compensated[offsets[2] : offsets[2] + 8] = (33).to_bytes(8, "big")
        compensated[offsets[3] : offsets[3] + 8] = (31).to_bytes(8, "big")
        with self.assertRaises(PrekeyVectorError):
            decode_record(bytes(compensated))

    def test_input_schema_has_no_caller_supplied_derived_values(self) -> None:
        baseline = self.document["vectors"][0]["input"]
        for field, value in [
            ("prekey_quality", 1),
            ("prekey_selection_digest", "11" * 32),
        ]:
            candidate = copy.deepcopy(baseline)
            candidate[field] = value
            with self.subTest(field=field), self.assertRaises(PrekeyVectorError):
                encode_input(candidate)

    def test_invalid_modes_relations_zero_epochs_hex_and_bool_fail_closed(self) -> None:
        baseline = self.document["vectors"][0]["input"]
        candidates = []

        unknown_mode = copy.deepcopy(baseline)
        unknown_mode["classical"]["mode"] = "automatic"
        candidates.append(unknown_mode)

        invalid_classical_relation = copy.deepcopy(baseline)
        invalid_classical_relation["classical"]["selected_prekey_id"] = (
            invalid_classical_relation["classical"]["signed_prekey_id"]
        )
        candidates.append(invalid_classical_relation)

        invalid_pq_relation = copy.deepcopy(baseline)
        invalid_pq_relation["post_quantum"]["selected_prekey_id"] = invalid_pq_relation[
            "post_quantum"
        ]["last_resort_prekey_id"]
        candidates.append(invalid_pq_relation)

        zero_suite = copy.deepcopy(baseline)
        zero_suite["suite_digest"] = "00" * 32
        candidates.append(zero_suite)

        zero_epoch = copy.deepcopy(baseline)
        zero_epoch["bundle_epoch"] = 0
        candidates.append(zero_epoch)

        terminal_epoch = copy.deepcopy(baseline)
        terminal_epoch["responder"]["device_epoch"] = (1 << 64) - 1
        candidates.append(terminal_epoch)

        bool_epoch = copy.deepcopy(baseline)
        bool_epoch["bundle_epoch"] = True
        candidates.append(bool_epoch)

        uppercase = copy.deepcopy(baseline)
        uppercase["signed_prekey_manifest_digest"] = ("ab" * 32).upper()
        candidates.append(uppercase)

        for candidate in candidates:
            with self.assertRaises(PrekeyVectorError):
                encode_input(candidate)

    def test_named_field_mutations_change_record_and_digest(self) -> None:
        baseline = self.document["vectors"][0]["input"]
        baseline_encoded = encode_input(baseline)
        mutations = []

        for path in [
            ("suite_digest",),
            ("responder", "account_id"),
            ("responder", "device_id"),
            ("responder", "identity_credential_digest"),
            ("directory_checkpoint_digest",),
            ("signed_prekey_manifest_digest",),
            ("classical", "signed_prekey_id"),
            ("classical", "selected_prekey_id"),
            ("post_quantum", "last_resort_prekey_id"),
            ("post_quantum", "selected_prekey_id"),
        ]:
            candidate = copy.deepcopy(baseline)
            target = candidate
            for component in path[:-1]:
                target = target[component]
            target[path[-1]] = "aa" * (16 if path[-1] == "device_id" else 32)
            mutations.append(candidate)

        for path in [("responder", "device_epoch"), ("bundle_epoch",)]:
            candidate = copy.deepcopy(baseline)
            if len(path) == 2:
                candidate[path[0]][path[1]] += 1
            else:
                candidate[path[0]] += 1
            mutations.append(candidate)

        for candidate in mutations:
            encoded = encode_input(candidate)
            self.assertNotEqual(encoded["record"], baseline_encoded["record"])
            self.assertNotEqual(
                encoded["digest_preimage"], baseline_encoded["digest_preimage"]
            )

    def test_vector_loader_and_expected_mutations_fail_closed(self) -> None:
        mutated = copy.deepcopy(self.document)
        mutated["vectors"][0]["expected"]["record_sha256"] = "00" * 32
        with self.assertRaises(PrekeyVectorError):
            verify_vectors(mutated)

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
                with self.subTest(filename=filename), self.assertRaises(PrekeyVectorError):
                    load_json(path)

            target = root / "target.json"
            target.write_text('{"schema_version":1,"vectors":[]}', encoding="utf-8")
            link = root / "link.json"
            link.symlink_to(target)
            with self.assertRaises(PrekeyVectorError):
                load_json(link)

    def test_rendered_schema_rejects_unknown_document_version(self) -> None:
        with self.assertRaises(PrekeyVectorError):
            render_vectors({"schema_version": 2, "vectors": self.document["vectors"]})


if __name__ == "__main__":
    unittest.main()
