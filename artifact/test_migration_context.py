import copy
import hashlib
import pathlib
import struct
import tempfile
import unittest

from migration_context import (
    EXTERNALLY_ASSERTED_COMMITMENT_FIELDS,
    FIELD_SPECS,
    INPUT_KEYS,
    MAX_VECTOR_JSON_BYTES,
    MIGRATION_CONTEXT_ENCODED_LEN,
    MigrationContextError,
    decode_context,
    encode_input,
    expected_values,
    load_json,
    render_vectors,
    verify_vectors,
)


ROOT = pathlib.Path(__file__).resolve().parents[1]
VECTORS = ROOT / "models/q-periapt-migration/vectors/migration-context-v1.json"


def independent_encode(value: dict[str, object]) -> bytes:
    """Test-only encoder kept independent of the production codec helpers."""

    role_codes = {"initiator": b"\x01", "responder": b"\x02"}
    suite = int(value["selected_suite"])
    floor = int(value["security_floor"])
    suite_security_levels = {1: 3, 2: 5}
    if suite not in suite_security_levels or floor not in {1, 2, 3, 5}:
        raise ValueError("unknown suite or security floor")
    if suite_security_levels[suite] < floor:
        raise ValueError("selected suite is below the security floor")
    fields = (
        b"Q-PERIAPT-MIGRATION-CONTEXT/v1",
        b"\x00\x01",
        bytes.fromhex(str(value["protocol_id"])),
        role_codes[str(value["encapsulator_role"])],
        int(value["migration_epoch"]).to_bytes(8, "big"),
        bytes.fromhex(str(value["initiator_policy_digest"])),
        bytes.fromhex(str(value["responder_policy_digest"])),
        bytes.fromhex(str(value["capability_transcript_hash"])),
        bytes([suite]),
        bytes([floor]),
        bytes.fromhex(str(value["transition_state_hash"])),
        bytes.fromhex(str(value["pre_kem_transcript_hash"])),
    )
    return b"".join(struct.pack(">Q", len(field)) + field for field in fields)


def split_lp8(encoded: bytes) -> tuple[list[bytes], list[int], list[int]]:
    fields: list[bytes] = []
    prefix_offsets: list[int] = []
    body_offsets: list[int] = []
    offset = 0
    for _ in range(12):
        prefix_offsets.append(offset)
        length = struct.unpack(">Q", encoded[offset : offset + 8])[0]
        offset += 8
        body_offsets.append(offset)
        fields.append(encoded[offset : offset + length])
        offset += length
    if offset != len(encoded):
        raise AssertionError("test helper found non-canonical trailing bytes")
    return fields, prefix_offsets, body_offsets


class MigrationContextTests(unittest.TestCase):
    def setUp(self) -> None:
        self.document = load_json(VECTORS)
        self.baseline = self.document["vectors"][0]["input"]

    def test_frozen_vectors_recompute_exactly_and_cover_closed_codes(self) -> None:
        verify_vectors(self.document)
        self.assertEqual(len(self.document["vectors"]), 4)
        self.assertEqual(
            {vector["input"]["encapsulator_role"] for vector in self.document["vectors"]},
            {"initiator", "responder"},
        )
        self.assertEqual(
            {vector["input"]["selected_suite"] for vector in self.document["vectors"]},
            {1, 2},
        )
        self.assertEqual(
            {vector["input"]["security_floor"] for vector in self.document["vectors"]},
            {1, 2, 3, 5},
        )
        for vector in self.document["vectors"]:
            self.assertEqual(vector["expected"]["length"], MIGRATION_CONTEXT_ENCODED_LEN)
            self.assertEqual(len(vector["expected"]["encoded_hex"]), 630)

    def test_frozen_bytes_match_an_independent_reference_encoder(self) -> None:
        for vector in self.document["vectors"]:
            with self.subTest(name=vector["name"]):
                encoded = independent_encode(vector["input"])
                self.assertEqual(encoded.hex(), vector["expected"]["encoded_hex"])
                self.assertEqual(
                    hashlib.sha256(encoded).hexdigest(),
                    vector["expected"]["sha256"],
                )
                self.assertEqual(
                    hashlib.sha3_256(encoded).hexdigest(),
                    vector["expected"]["sha3_256"],
                )

    def test_decoder_roundtrips_every_frozen_context(self) -> None:
        for vector in self.document["vectors"]:
            with self.subTest(name=vector["name"]):
                encoded = bytes.fromhex(vector["expected"]["encoded_hex"])
                self.assertEqual(decode_context(encoded), vector["input"])
                self.assertEqual(encode_input(decode_context(encoded)), encoded)

    def test_lp8_field_order_lengths_and_epoch_endianness_are_exact(self) -> None:
        vector = self.document["vectors"][1]
        encoded = bytes.fromhex(vector["expected"]["encoded_hex"])
        fields, prefix_offsets, _ = split_lp8(encoded)
        self.assertEqual([len(field) for field in fields], [length for _, length in FIELD_SPECS])
        for field, prefix_offset in zip(fields, prefix_offsets, strict=True):
            self.assertEqual(
                encoded[prefix_offset : prefix_offset + 8],
                len(field).to_bytes(8, "big"),
            )
        self.assertEqual(fields[4], b"\x01\x02\x03\x04\x05\x06\x07\x08")
        self.assertEqual(fields[3], b"\x02")
        self.assertEqual(fields[8], b"\x02")
        self.assertEqual(fields[9], b"\x02")
        self.assertEqual(len(encoded), 315)

    def test_each_named_input_field_changes_only_its_lp8_body(self) -> None:
        baseline_encoded = encode_input(self.baseline)
        baseline_fields, _, _ = split_lp8(baseline_encoded)
        mutations = {
            "protocol_id": (2, "ff" * 16),
            "encapsulator_role": (3, "responder"),
            "migration_epoch": (4, 2),
            "initiator_policy_digest": (5, "a1" * 32),
            "responder_policy_digest": (6, "b2" * 32),
            "capability_transcript_hash": (7, "c3" * 32),
            "selected_suite": (8, 2),
            "security_floor": (9, 3),
            "transition_state_hash": (10, "d4" * 32),
            "pre_kem_transcript_hash": (11, "e5" * 32),
        }
        for field, (field_index, replacement) in mutations.items():
            candidate = copy.deepcopy(self.baseline)
            candidate[field] = replacement
            encoded = encode_input(candidate)
            mutated_fields, _, _ = split_lp8(encoded)
            changed = [
                index
                for index, (before, after) in enumerate(
                    zip(baseline_fields, mutated_fields, strict=True)
                )
                if before != after
            ]
            with self.subTest(field=field):
                self.assertEqual(changed, [field_index])
                self.assertNotEqual(encoded, baseline_encoded)
                self.assertNotEqual(
                    expected_values(encoded)["sha3_256"],
                    expected_values(baseline_encoded)["sha3_256"],
                )

    def test_role_and_policy_ownership_are_not_endpoint_relative(self) -> None:
        initiator_view = copy.deepcopy(self.baseline)
        responder_view = copy.deepcopy(self.baseline)
        self.assertEqual(encode_input(initiator_view), encode_input(responder_view))

        endpoint_relative = copy.deepcopy(self.baseline)
        endpoint_relative["local_policy_digest"] = endpoint_relative.pop(
            "initiator_policy_digest"
        )
        endpoint_relative["peer_policy_digest"] = endpoint_relative.pop(
            "responder_policy_digest"
        )
        with self.assertRaises(MigrationContextError) as error:
            encode_input(endpoint_relative)
        self.assertEqual(error.exception.code, "schema_keys")

        numeric_role = copy.deepcopy(self.baseline)
        numeric_role["encapsulator_role"] = 1
        with self.assertRaises(MigrationContextError):
            encode_input(numeric_role)

    def test_compatible_role_suite_floor_and_epoch_boundaries_encode(self) -> None:
        for role in ("initiator", "responder"):
            for suite in (1, 2):
                for floor in (1, 2, 3, 5):
                    for epoch in (1, (1 << 64) - 2):
                        candidate = copy.deepcopy(self.baseline)
                        candidate["encapsulator_role"] = role
                        candidate["selected_suite"] = suite
                        candidate["security_floor"] = floor
                        candidate["migration_epoch"] = epoch
                        with self.subTest(
                            role=role,
                            suite=suite,
                            floor=floor,
                            epoch=epoch,
                        ):
                            if suite == 1 and floor == 5:
                                with self.assertRaises(MigrationContextError) as error:
                                    encode_input(candidate)
                                self.assertEqual(error.exception.code, "suite_below_floor")
                            else:
                                self.assertEqual(len(encode_input(candidate)), 315)

    def test_commitment_fields_are_explicitly_external_assertions(self) -> None:
        self.assertEqual(
            EXTERNALLY_ASSERTED_COMMITMENT_FIELDS,
            {
                "initiator_policy_digest",
                "responder_policy_digest",
                "capability_transcript_hash",
                "transition_state_hash",
                "pre_kem_transcript_hash",
            },
        )
        suite_one_below_level_five = copy.deepcopy(self.baseline)
        suite_one_below_level_five["selected_suite"] = 1
        suite_one_below_level_five["security_floor"] = 5
        with self.assertRaises(MigrationContextError) as error:
            encode_input(suite_one_below_level_five)
        self.assertEqual(error.exception.code, "suite_below_floor")
        with self.assertRaises(ValueError):
            independent_encode(suite_one_below_level_five)

        suite_two_at_level_five = copy.deepcopy(suite_one_below_level_five)
        suite_two_at_level_five["selected_suite"] = 2
        self.assertEqual(len(encode_input(suite_two_at_level_five)), 315)

    def test_missing_unknown_and_legacy_transcript_fields_fail_closed(self) -> None:
        for field in sorted(INPUT_KEYS):
            candidate = copy.deepcopy(self.baseline)
            del candidate[field]
            with self.subTest(missing=field), self.assertRaises(MigrationContextError) as error:
                encode_input(candidate)
            self.assertEqual(error.exception.code, "schema_keys")

        unknown = copy.deepcopy(self.baseline)
        unknown["unexpected"] = 1
        with self.assertRaises(MigrationContextError):
            encode_input(unknown)

        circular_name = copy.deepcopy(self.baseline)
        circular_name["handshake_transcript_hash"] = circular_name.pop(
            "pre_kem_transcript_hash"
        )
        with self.assertRaises(MigrationContextError) as error:
            encode_input(circular_name)
        self.assertEqual(error.exception.code, "schema_keys")

    def test_all_zero_and_malformed_commitments_fail_closed(self) -> None:
        hex_fields = (
            ("protocol_id", 16),
            ("initiator_policy_digest", 32),
            ("responder_policy_digest", 32),
            ("capability_transcript_hash", 32),
            ("transition_state_hash", 32),
            ("pre_kem_transcript_hash", 32),
        )
        for field, length in hex_fields:
            candidate = copy.deepcopy(self.baseline)
            candidate[field] = "00" * length
            with self.subTest(zero=field), self.assertRaises(MigrationContextError) as error:
                encode_input(candidate)
            self.assertEqual(error.exception.code, "zero_field")

        malformed_values = ("0", "gg" * 16, "AA" * 16, 1, None)
        for value in malformed_values:
            candidate = copy.deepcopy(self.baseline)
            candidate["protocol_id"] = value
            with self.subTest(value=value), self.assertRaises(MigrationContextError):
                encode_input(candidate)

    def test_unknown_role_suite_floor_and_invalid_epochs_fail_closed(self) -> None:
        cases: list[dict[str, object]] = []
        for role in ("", "client", 1, None):
            candidate = copy.deepcopy(self.baseline)
            candidate["encapsulator_role"] = role
            cases.append(candidate)
        for suite in (0, 3, -1, True, "1", 1.0):
            candidate = copy.deepcopy(self.baseline)
            candidate["selected_suite"] = suite
            cases.append(candidate)
        for floor in (0, 4, 6, -1, True, "3", 3.0):
            candidate = copy.deepcopy(self.baseline)
            candidate["security_floor"] = floor
            cases.append(candidate)
        for epoch in (0, -1, (1 << 64) - 1, 1 << 64, True, "1", 1.0):
            candidate = copy.deepcopy(self.baseline)
            candidate["migration_epoch"] = epoch
            cases.append(candidate)
        for index, candidate in enumerate(cases):
            with self.subTest(index=index), self.assertRaises(MigrationContextError):
                encode_input(candidate)

    def test_decoder_rejects_truncation_trailing_and_corrupt_lp8_lengths(self) -> None:
        encoded = encode_input(self.baseline)
        _, prefix_offsets, _ = split_lp8(encoded)
        for length in range(len(encoded)):
            with self.subTest(truncation=length), self.assertRaises(MigrationContextError):
                decode_context(encoded[:length])
        with self.assertRaises(MigrationContextError) as trailing:
            decode_context(encoded + b"\x00")
        self.assertEqual(trailing.exception.code, "trailing_bytes")

        for prefix_offset in prefix_offsets:
            corrupted = bytearray(encoded)
            corrupted[prefix_offset : prefix_offset + 8] = ((1 << 64) - 1).to_bytes(
                8, "big"
            )
            with self.subTest(prefix=prefix_offset), self.assertRaises(
                MigrationContextError
            ):
                decode_context(bytes(corrupted))

        compensated = bytearray(encoded)
        compensated[prefix_offsets[2] : prefix_offsets[2] + 8] = (17).to_bytes(8, "big")
        compensated[prefix_offsets[3] : prefix_offsets[3] + 8] = (0).to_bytes(8, "big")
        with self.assertRaises(MigrationContextError):
            decode_context(bytes(compensated))

    def test_decoder_rejects_wrong_domain_schema_enum_epoch_and_zero_fields(self) -> None:
        encoded = encode_input(self.baseline)
        _, _, body_offsets = split_lp8(encoded)
        mutations = [
            (0, b"X" * 30),
            (1, b"\x00\x02"),
            (3, b"\x00"),
            (3, b"\x03"),
            (4, b"\x00" * 8),
            (4, b"\xff" * 8),
            (8, b"\x00"),
            (8, b"\x03"),
            (9, b"\x00"),
            (9, b"\x04"),
            (9, b"\x05"),
        ]
        mutations.extend(
            (field_index, b"\x00" * FIELD_SPECS[field_index][1])
            for field_index in (2, 5, 6, 7, 10, 11)
        )
        for field_index, replacement in mutations:
            corrupted = bytearray(encoded)
            start = body_offsets[field_index]
            corrupted[start : start + len(replacement)] = replacement
            with self.subTest(field=FIELD_SPECS[field_index][0]), self.assertRaises(
                MigrationContextError
            ):
                decode_context(bytes(corrupted))
        with self.assertRaises(MigrationContextError) as type_error:
            decode_context(bytearray(encoded))
        self.assertEqual(type_error.exception.code, "type_error")

    def test_vector_document_and_expected_schema_mutations_fail_closed(self) -> None:
        expected_mutations = []
        wrong_hash = copy.deepcopy(self.document)
        wrong_hash["vectors"][0]["expected"]["sha256"] = "00" * 32
        expected_mutations.append(wrong_hash)
        float_length = copy.deepcopy(self.document)
        float_length["vectors"][0]["expected"]["length"] = 315.0
        expected_mutations.append(float_length)
        uppercase = copy.deepcopy(self.document)
        uppercase["vectors"][0]["expected"]["sha3_256"] = uppercase["vectors"][0][
            "expected"
        ]["sha3_256"].upper()
        expected_mutations.append(uppercase)
        missing_expected = copy.deepcopy(self.document)
        del missing_expected["vectors"][0]["expected"]
        expected_mutations.append(missing_expected)
        unknown_expected = copy.deepcopy(self.document)
        unknown_expected["vectors"][0]["expected"]["extra"] = 1
        expected_mutations.append(unknown_expected)
        for index, document in enumerate(expected_mutations):
            with self.subTest(expected=index), self.assertRaises(MigrationContextError):
                verify_vectors(document)

        for schema_version in (2, True, "1"):
            candidate = copy.deepcopy(self.document)
            candidate["schema_version"] = schema_version
            with self.subTest(schema=schema_version), self.assertRaises(
                MigrationContextError
            ):
                render_vectors(candidate)

        duplicate = copy.deepcopy(self.document)
        duplicate["vectors"][1]["name"] = duplicate["vectors"][0]["name"]
        with self.assertRaises(MigrationContextError):
            render_vectors(duplicate)

        empty = {"schema_version": 1, "vectors": []}
        with self.assertRaises(MigrationContextError):
            render_vectors(empty)

        unknown_document = copy.deepcopy(self.document)
        unknown_document["extra"] = 1
        with self.assertRaises(MigrationContextError):
            render_vectors(unknown_document)

    def test_loader_rejects_ambiguous_malformed_oversized_and_symlink_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            invalid_documents = {
                "duplicate.json": b'{"schema_version":1,"schema_version":1,"vectors":[]}',
                "nan.json": b'{"schema_version":NaN,"vectors":[]}',
                "infinity.json": b'{"schema_version":Infinity,"vectors":[]}',
                "array.json": b"[]",
                "truncated.json": b'{"schema_version":1',
                "utf8.json": b'{"schema_version":1,"vectors":[]}\xff',
            }
            for filename, contents in invalid_documents.items():
                path = root / filename
                path.write_bytes(contents)
                with self.subTest(filename=filename), self.assertRaises(
                    MigrationContextError
                ):
                    load_json(path)

            oversized = root / "oversized.json"
            oversized.write_bytes(b" " * (MAX_VECTOR_JSON_BYTES + 1))
            with self.assertRaises(MigrationContextError):
                load_json(oversized)

            target = root / "target.json"
            target.write_text('{"schema_version":1,"vectors":[]}', encoding="utf-8")
            link = root / "link.json"
            link.symlink_to(target)
            with self.assertRaises(MigrationContextError):
                load_json(link)


if __name__ == "__main__":
    unittest.main()
