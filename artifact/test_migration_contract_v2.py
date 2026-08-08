#!/usr/bin/env python3

from __future__ import annotations

import copy
import hashlib
import json
import pathlib
import tempfile
import unittest

from migration_contract_v2 import (
    CONTEXT_DOMAIN,
    CONTEXT_ENCODED_LEN,
    CONTEXT_FIELD_WIDTHS,
    INPUT_KEYS,
    STATE_DOMAIN,
    STATE_FIELD_WIDTHS,
    MigrationContractV2Error,
    decode_lp8,
    load_vectors,
    render,
    verify_document,
)


ROOT = pathlib.Path(__file__).resolve().parents[1]
VECTORS = ROOT / "models/q-periapt-migration/vectors/migration-contract-v2.json"


class MigrationContractV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.document = load_vectors(VECTORS)
        self.inputs = self.document["inputs"]
        self.expected = self.document["expected"]

    def test_frozen_vector_recomputes_every_layer(self) -> None:
        verify_document(self.document)
        self.assertEqual(render(self.inputs), self.expected)
        for name in (
            "state_digest",
            "negotiation_digest",
            "pre_kem_digest",
            "context_digest",
            "post_kem_digest",
            "initiator_finished",
            "responder_finished",
            "accepted_key",
        ):
            with self.subTest(name=name):
                self.assertEqual(len(bytes.fromhex(self.expected[name])), 32)

    def test_state_and_context_have_exact_domains_widths_and_endianness(self) -> None:
        state_bytes = bytes.fromhex(self.expected["state_body_hex"])
        context_bytes = bytes.fromhex(self.expected["context_hex"])
        state = decode_lp8(state_bytes, STATE_FIELD_WIDTHS)
        context = decode_lp8(context_bytes, CONTEXT_FIELD_WIDTHS)
        self.assertEqual(state[0], STATE_DOMAIN)
        self.assertEqual(state[1], b"\x00\x01")
        self.assertEqual(state[2], (1).to_bytes(8, "big"))
        self.assertEqual(state[5], (1).to_bytes(8, "big"))
        self.assertEqual(context[0], CONTEXT_DOMAIN)
        self.assertEqual(context[1], b"\x00\x02")
        self.assertEqual(context[3], b"\x01")
        self.assertEqual(context[4], (1).to_bytes(8, "big"))
        self.assertEqual(len(context_bytes), CONTEXT_ENCODED_LEN)

    def test_every_state_and_context_truncation_and_trailing_byte_fails(self) -> None:
        records = (
            (bytes.fromhex(self.expected["state_body_hex"]), STATE_FIELD_WIDTHS),
            (bytes.fromhex(self.expected["context_hex"]), CONTEXT_FIELD_WIDTHS),
        )
        for encoded, widths in records:
            for length in range(len(encoded)):
                with self.subTest(record_len=len(encoded), truncation=length):
                    with self.assertRaises(MigrationContractV2Error):
                        decode_lp8(encoded[:length], widths)
            with self.assertRaises(MigrationContractV2Error) as error:
                decode_lp8(encoded + b"\x00", widths)
            self.assertEqual(error.exception.code, "trailing")

    def test_lp8_width_corruption_fails_closed(self) -> None:
        context = bytearray.fromhex(self.expected["context_hex"])
        context[:8] = (29).to_bytes(8, "big")
        with self.assertRaises(MigrationContractV2Error) as error:
            decode_lp8(bytes(context), CONTEXT_FIELD_WIDTHS)
        self.assertEqual(error.exception.code, "field_width")

    def test_input_and_expected_schemas_are_exact(self) -> None:
        self.assertEqual(set(self.inputs), INPUT_KEYS)
        missing = copy.deepcopy(self.document)
        missing["inputs"].pop("session_id_hex")
        with self.assertRaises(MigrationContractV2Error) as error:
            verify_document(missing)
        self.assertEqual(error.exception.code, "schema_keys")

        extra = copy.deepcopy(self.document)
        extra["expected"]["unbound"] = "00"
        with self.assertRaises(MigrationContractV2Error) as error:
            verify_document(extra)
        self.assertEqual(error.exception.code, "schema_keys")

    def test_frozen_expected_bytes_and_digests_cannot_drift(self) -> None:
        mutated = copy.deepcopy(self.document)
        original = mutated["expected"]["context_digest"]
        mutated["expected"]["context_digest"] = ("0" if original[0] != "0" else "1") + original[1:]
        with self.assertRaises(MigrationContractV2Error) as error:
            verify_document(mutated)
        self.assertEqual(error.exception.code, "expected_mismatch")

    def test_reflection_floor_suite_mode_and_secret_fail_closed(self) -> None:
        cases: tuple[tuple[str, object], ...] = (
            ("responder_role", 1),
            ("responder_identity_key_id_hex", self.inputs["initiator_identity_key_id_hex"]),
            ("responder_nonce_hex", self.inputs["initiator_nonce_hex"]),
            ("effective_floor", 5),
            ("initiator_offered_suite_bits", 0b100),
            ("component_mode", 2),
            ("shared_secret_length", 31),
        )
        for name, value in cases:
            candidate = copy.deepcopy(self.inputs)
            candidate[name] = value
            with self.subTest(name=name):
                    with self.assertRaises(MigrationContractV2Error):
                        render(candidate)

    def test_each_offer_floor_is_derived_from_authenticated_policy_and_state(self) -> None:
        for role in ("initiator", "responder"):
            candidate = copy.deepcopy(self.inputs)
            candidate[f"{role}_offer_floor"] = 1
            with self.subTest(role=role):
                with self.assertRaises(MigrationContractV2Error) as error:
                    render(candidate)
                self.assertEqual(error.exception.code, "offer_floor")

        stronger_policy = copy.deepcopy(self.inputs)
        stronger_policy["initiator_authenticated_policy_floor"] = 5
        stronger_policy["initiator_offer_floor"] = 5
        stronger_policy["effective_floor"] = 5
        with self.assertRaises(MigrationContractV2Error) as error:
            render(stronger_policy)
        self.assertEqual(error.exception.code, "below_floor")

    def test_receiver_key_selection_is_direction_bound(self) -> None:
        reverse = copy.deepcopy(self.inputs)
        reverse["encapsulator_role"] = 2
        rendered = render(reverse)
        self.assertNotEqual(rendered["pre_kem_hex"], self.expected["pre_kem_hex"])
        self.assertNotEqual(rendered["context_hex"], self.expected["context_hex"])
        self.assertNotEqual(rendered["accepted_key"], self.expected["accepted_key"])

    def test_role_separated_finished_values_are_distinct(self) -> None:
        self.assertNotEqual(
            self.expected["initiator_finished"], self.expected["responder_finished"]
        )
        post = bytes.fromhex(self.expected["post_kem_digest"])
        self.assertEqual(len(post), hashlib.sha3_256().digest_size)

    def test_duplicate_json_keys_are_rejected_by_evidence_loader(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "duplicate.json"
            path.write_text(
                '{"schema":"a","schema":"b","schema_version":1,'
                '"case":"x","inputs":{},"expected":{}}',
                encoding="utf-8",
            )
            with self.assertRaises(MigrationContractV2Error) as error:
                load_vectors(path)
            self.assertEqual(error.exception.code, "unsafe_json")

    def test_json_roundtrip_does_not_change_frozen_document(self) -> None:
        encoded = json.dumps(self.document, sort_keys=True, separators=(",", ":"))
        self.assertEqual(json.loads(encoded), self.document)


if __name__ == "__main__":
    unittest.main()
