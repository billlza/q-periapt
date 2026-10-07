#!/usr/bin/env python3
"""Independent byte renderer and verifier for Migration Contract V2 vectors."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys
from typing import Any

from evidence_io import EvidenceIOError, load_json_object_snapshot


VECTOR_SCHEMA = "q-periapt-migration-contract-v2-vectors"
VECTOR_SCHEMA_VERSION = 1
MAX_VECTOR_JSON_BYTES = 2 * 1024 * 1024

STATE_DOMAIN = b"Q-PERIAPT-MIGRATION-STATE/v1"
CAPABILITY_DOMAIN = b"Q-PERIAPT-MIGRATION-CAPABILITY-OFFER/v1"
KEY_SHARE_DOMAIN = b"Q-PERIAPT-MIGRATION-KEY-SHARE/v1"
NEGOTIATION_DOMAIN = b"Q-PERIAPT-MIGRATION-AUTHENTICATED-NEGOTIATION/v1"
PRE_KEM_DOMAIN = b"Q-PERIAPT-MIGRATION-PRE-KEM-TRANSCRIPT/v1"
CONTEXT_DOMAIN = b"Q-PERIAPT-MIGRATION-CONTEXT/v2"
POST_KEM_DOMAIN = b"Q-PERIAPT-MIGRATION-POST-KEM-TRANSCRIPT/v1"
FINISHED_DOMAIN = b"Q-PERIAPT-MIGRATION-FINISHED/v1"
ACCEPTED_KEY_DOMAIN = b"Q-PERIAPT-MIGRATION-ACCEPTED-KEY/v1"

STATE_SCHEMA_VERSION = 1
CAPABILITY_SCHEMA_VERSION = 1
TRANSCRIPT_SCHEMA_VERSION = 1
CONTEXT_SCHEMA_VERSION = 2
CONTEXT_ENCODED_LEN = 324

ROLES = frozenset({1, 2})
SUITES = frozenset({1, 2})
SUITE_LEVELS = {1: 3, 2: 5}
FLOORS = frozenset({1, 2, 3, 5})
COMPONENT_MODES = frozenset({1, 2})
KNOWN_SUITE_BITS = 0b11

ROOT_KEYS = {"schema", "schema_version", "case", "inputs", "expected"}
INPUT_KEYS = {
    "protocol_id_hex",
    "chain_id_hex",
    "global_generation",
    "migration_epoch",
    "previous_state_digest_hex",
    "authority_key_id_hex",
    "execution_state_hex",
    "state_minimum_pq_level",
    "component_mode",
    "state_allowed_suite_bits",
    "session_id_hex",
    "initiator_role",
    "responder_role",
    "initiator_identity_key_id_hex",
    "responder_identity_key_id_hex",
    "initiator_nonce_hex",
    "responder_nonce_hex",
    "initiator_policy_state_hex",
    "responder_policy_state_hex",
    "initiator_offered_suite_bits",
    "responder_offered_suite_bits",
    "initiator_authenticated_policy_floor",
    "responder_authenticated_policy_floor",
    "initiator_offer_floor",
    "responder_offer_floor",
    "effective_floor",
    "selected_suite",
    "encapsulator_role",
    "initiator_pq_key_fill",
    "initiator_pq_key_length",
    "initiator_traditional_key_fill",
    "initiator_traditional_key_length",
    "responder_pq_key_fill",
    "responder_pq_key_length",
    "responder_traditional_key_fill",
    "responder_traditional_key_length",
    "pq_ciphertext_fill",
    "pq_ciphertext_length",
    "traditional_ciphertext_fill",
    "traditional_ciphertext_length",
    "shared_secret_fill",
    "shared_secret_length",
}
EXPECTED_KEYS = {
    "state_body_hex",
    "state_digest",
    "initiator_offer_body_hex",
    "responder_offer_body_hex",
    "negotiation_digest",
    "pre_kem_hex",
    "pre_kem_digest",
    "context_hex",
    "context_digest",
    "post_kem_digest",
    "initiator_finished",
    "responder_finished",
    "accepted_key",
}

STATE_FIELD_WIDTHS = (28, 2, 8, 32, 16, 8, 32, 32, 36, 1, 1, 1)
CONTEXT_FIELD_WIDTHS = (30, 2, 16, 1, 8, 32, 32, 32, 1, 1, 32, 32, 1)


class MigrationContractV2Error(ValueError):
    """A V2 input, expected value, or canonical encoding is invalid."""

    def __init__(self, message: str, *, code: str, field: str | None = None):
        self.code = code
        self.field = field
        location = f" field={field}" if field is not None else ""
        super().__init__(f"{code}{location}: {message}")


def load_vectors(path: pathlib.Path) -> dict[str, Any]:
    """Load one immutable JSON object with duplicate-key and file-safety checks."""

    try:
        return load_json_object_snapshot(
            path,
            maximum=MAX_VECTOR_JSON_BYTES,
            label=f"Migration Contract V2 vectors {path}",
        ).value
    except EvidenceIOError as error:
        raise MigrationContractV2Error(
            f"cannot load {path}: {error}", code="unsafe_json"
        ) from error


def _exact_keys(value: dict[str, Any], expected: set[str], field: str) -> None:
    actual = set(value)
    if actual != expected:
        raise MigrationContractV2Error(
            f"keys differ: missing={sorted(expected - actual)} "
            f"extra={sorted(actual - expected)}",
            code="schema_keys",
            field=field,
        )


def _object(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise MigrationContractV2Error("must be an object", code="type", field=field)
    return value


def _integer(value: Any, minimum: int, maximum: int, field: str) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise MigrationContractV2Error(
            f"must be an integer in {minimum}..{maximum}",
            code="range",
            field=field,
        )
    return value


def _closed(value: Any, allowed: frozenset[int], field: str) -> int:
    if type(value) is not int or value not in allowed:
        raise MigrationContractV2Error(
            f"must be one of {sorted(allowed)}", code="unknown_enum", field=field
        )
    return value


def _hex(value: Any, length: int, field: str, *, zero_allowed: bool = False) -> bytes:
    if not isinstance(value, str) or value.lower() != value or len(value) != length * 2:
        raise MigrationContractV2Error(
            f"must be exactly {length} bytes of lowercase hex",
            code="hex_shape",
            field=field,
        )
    try:
        decoded = bytes.fromhex(value)
    except ValueError as error:
        raise MigrationContractV2Error("is not hex", code="invalid_hex", field=field) from error
    if len(decoded) != length or (not zero_allowed and not any(decoded)):
        raise MigrationContractV2Error(
            "has an invalid decoded length or reserved zero value",
            code="invalid_value",
            field=field,
        )
    return decoded


def _policy_state(value: Any, field: str) -> bytes:
    encoded = _hex(value, 36, field)
    if int.from_bytes(encoded[:4], "big") == 0 or not any(encoded[4:]):
        raise MigrationContractV2Error(
            "policy version and digest must be nonzero", code="invalid_policy", field=field
        )
    return encoded


def _suite_bits(value: Any, selected: int, field: str) -> int:
    bits = _integer(value, 1, 255, field)
    if bits & ~KNOWN_SUITE_BITS or bits & (1 << (selected - 1)) == 0:
        raise MigrationContractV2Error(
            "contains unknown bits or omits the selected suite",
            code="suite_set",
            field=field,
        )
    return bits


def _filled(fill: Any, length: Any, maximum: int, field: str) -> bytes:
    byte = _integer(fill, 0, 255, f"{field}_fill")
    extent = _integer(length, 1, maximum, f"{field}_length")
    return bytes([byte]) * extent


def lp8(value: bytes) -> bytes:
    """Encode one unsigned-64-bit big-endian length-prefixed field."""

    return len(value).to_bytes(8, "big") + value


def lp8_fields(*fields: bytes) -> bytes:
    """Encode a complete ordered LP8 tuple."""

    return b"".join(lp8(field) for field in fields)


def sha3(value: bytes) -> bytes:
    """Return SHA3-256 bytes."""

    return hashlib.sha3_256(value).digest()


def decode_lp8(encoded: bytes, widths: tuple[int, ...]) -> tuple[bytes, ...]:
    """Strictly decode a fixed-field LP8 record and reject trailing bytes."""

    if not isinstance(encoded, bytes):
        raise MigrationContractV2Error("record must be bytes", code="type")
    fields: list[bytes] = []
    offset = 0
    for index, width in enumerate(widths):
        if offset + 8 > len(encoded):
            raise MigrationContractV2Error(
                "truncated LP8 length", code="truncated", field=f"field[{index}]"
            )
        length = int.from_bytes(encoded[offset : offset + 8], "big")
        offset += 8
        end = offset + length
        if end > len(encoded):
            raise MigrationContractV2Error(
                "truncated LP8 value", code="truncated", field=f"field[{index}]"
            )
        field = encoded[offset:end]
        if len(field) != width:
            raise MigrationContractV2Error(
                f"expected {width} bytes, got {len(field)}",
                code="field_width",
                field=f"field[{index}]",
            )
        fields.append(field)
        offset = end
    if offset != len(encoded):
        raise MigrationContractV2Error("trailing bytes", code="trailing")
    return tuple(fields)


def render(inputs: dict[str, Any]) -> dict[str, str]:
    """Recompute every frozen V2 byte string and digest from structured inputs."""

    _exact_keys(inputs, INPUT_KEYS, "inputs")
    protocol = _hex(inputs["protocol_id_hex"], 16, "inputs.protocol_id_hex")
    chain = _hex(inputs["chain_id_hex"], 32, "inputs.chain_id_hex")
    generation = _integer(inputs["global_generation"], 1, (1 << 64) - 2, "inputs.global_generation")
    epoch = _integer(inputs["migration_epoch"], 1, (1 << 64) - 2, "inputs.migration_epoch")
    previous = _hex(
        inputs["previous_state_digest_hex"],
        32,
        "inputs.previous_state_digest_hex",
        zero_allowed=generation == 1,
    )
    authority = _hex(inputs["authority_key_id_hex"], 32, "inputs.authority_key_id_hex")
    execution = _policy_state(inputs["execution_state_hex"], "inputs.execution_state_hex")
    state_floor = _closed(inputs["state_minimum_pq_level"], FLOORS, "inputs.state_minimum_pq_level")
    mode = _closed(inputs["component_mode"], COMPONENT_MODES, "inputs.component_mode")
    selected = _closed(inputs["selected_suite"], SUITES, "inputs.selected_suite")
    if mode != 1:
        raise MigrationContractV2Error(
            "the frozen accepted ABI2 vector requires HybridRequired",
            code="abi2_incompatible_mode",
            field="inputs.component_mode",
        )
    if SUITE_LEVELS[selected] < state_floor:
        raise MigrationContractV2Error(
            "selected suite is below the state floor", code="below_floor", field="inputs.selected_suite"
        )
    state_suites = _suite_bits(inputs["state_allowed_suite_bits"], selected, "inputs.state_allowed_suite_bits")

    session = _hex(inputs["session_id_hex"], 32, "inputs.session_id_hex")
    initiator_role = _closed(inputs["initiator_role"], ROLES, "inputs.initiator_role")
    responder_role = _closed(inputs["responder_role"], ROLES, "inputs.responder_role")
    encapsulator_role = _closed(inputs["encapsulator_role"], ROLES, "inputs.encapsulator_role")
    if initiator_role != 1 or responder_role != 2:
        raise MigrationContractV2Error("roles are not canonical", code="role_order", field="inputs")
    initiator_id = _hex(
        inputs["initiator_identity_key_id_hex"], 32, "inputs.initiator_identity_key_id_hex"
    )
    responder_id = _hex(
        inputs["responder_identity_key_id_hex"], 32, "inputs.responder_identity_key_id_hex"
    )
    initiator_nonce = _hex(inputs["initiator_nonce_hex"], 32, "inputs.initiator_nonce_hex")
    responder_nonce = _hex(inputs["responder_nonce_hex"], 32, "inputs.responder_nonce_hex")
    if initiator_id == responder_id or initiator_nonce == responder_nonce:
        raise MigrationContractV2Error(
            "peer identities and nonces must differ", code="reflection", field="inputs"
        )

    initiator_policy = _policy_state(
        inputs["initiator_policy_state_hex"], "inputs.initiator_policy_state_hex"
    )
    responder_policy = _policy_state(
        inputs["responder_policy_state_hex"], "inputs.responder_policy_state_hex"
    )
    initiator_suites = _suite_bits(
        inputs["initiator_offered_suite_bits"], selected, "inputs.initiator_offered_suite_bits"
    )
    responder_suites = _suite_bits(
        inputs["responder_offered_suite_bits"], selected, "inputs.responder_offered_suite_bits"
    )
    initiator_policy_floor = _closed(
        inputs["initiator_authenticated_policy_floor"],
        FLOORS,
        "inputs.initiator_authenticated_policy_floor",
    )
    responder_policy_floor = _closed(
        inputs["responder_authenticated_policy_floor"],
        FLOORS,
        "inputs.responder_authenticated_policy_floor",
    )
    initiator_offer_floor = _closed(
        inputs["initiator_offer_floor"], FLOORS, "inputs.initiator_offer_floor"
    )
    responder_offer_floor = _closed(
        inputs["responder_offer_floor"], FLOORS, "inputs.responder_offer_floor"
    )
    if initiator_offer_floor != max(initiator_policy_floor, state_floor):
        raise MigrationContractV2Error(
            "initiator offer floor is not derived from authenticated policy and state",
            code="offer_floor",
            field="inputs.initiator_offer_floor",
        )
    if responder_offer_floor != max(responder_policy_floor, state_floor):
        raise MigrationContractV2Error(
            "responder offer floor is not derived from authenticated policy and state",
            code="offer_floor",
            field="inputs.responder_offer_floor",
        )
    effective_floor = _closed(inputs["effective_floor"], FLOORS, "inputs.effective_floor")
    if effective_floor != max(
        state_floor, initiator_policy_floor, responder_policy_floor
    ):
        raise MigrationContractV2Error(
            "effective floor is not the closed maximum", code="floor_join", field="inputs.effective_floor"
        )
    if SUITE_LEVELS[selected] < effective_floor:
        raise MigrationContractV2Error(
            "selected suite is below the effective floor", code="below_floor", field="inputs.selected_suite"
        )

    initiator_pq = _filled(
        inputs["initiator_pq_key_fill"], inputs["initiator_pq_key_length"], 4096, "initiator_pq_key"
    )
    initiator_traditional = _filled(
        inputs["initiator_traditional_key_fill"],
        inputs["initiator_traditional_key_length"],
        256,
        "initiator_traditional_key",
    )
    responder_pq = _filled(
        inputs["responder_pq_key_fill"], inputs["responder_pq_key_length"], 4096, "responder_pq_key"
    )
    responder_traditional = _filled(
        inputs["responder_traditional_key_fill"],
        inputs["responder_traditional_key_length"],
        256,
        "responder_traditional_key",
    )
    pq_ciphertext = _filled(
        inputs["pq_ciphertext_fill"], inputs["pq_ciphertext_length"], 4096, "pq_ciphertext"
    )
    traditional_ciphertext = _filled(
        inputs["traditional_ciphertext_fill"],
        inputs["traditional_ciphertext_length"],
        256,
        "traditional_ciphertext",
    )
    secret = _filled(
        inputs["shared_secret_fill"], inputs["shared_secret_length"], 32, "shared_secret"
    )
    if len(secret) != 32:
        raise MigrationContractV2Error(
            "shared secret must be exactly 32 bytes", code="secret_length", field="inputs.shared_secret_length"
        )

    state_body = lp8_fields(
        STATE_DOMAIN,
        STATE_SCHEMA_VERSION.to_bytes(2, "big"),
        generation.to_bytes(8, "big"),
        chain,
        protocol,
        epoch.to_bytes(8, "big"),
        previous,
        authority,
        execution,
        bytes([state_floor]),
        bytes([mode]),
        bytes([state_suites]),
    )
    state_digest = sha3(state_body)

    initiator_key_commitment = sha3(
        lp8_fields(KEY_SHARE_DOMAIN, initiator_pq, initiator_traditional)
    )
    responder_key_commitment = sha3(
        lp8_fields(KEY_SHARE_DOMAIN, responder_pq, responder_traditional)
    )

    def offer_body(
        role: int,
        sender: bytes,
        receiver: bytes,
        nonce: bytes,
        policy: bytes,
        suites: int,
        floor: int,
        key_commitment: bytes,
    ) -> bytes:
        return lp8_fields(
            CAPABILITY_DOMAIN,
            CAPABILITY_SCHEMA_VERSION.to_bytes(2, "big"),
            protocol,
            chain,
            session,
            bytes([role]),
            sender,
            receiver,
            nonce,
            policy,
            state_digest,
            generation.to_bytes(8, "big"),
            bytes([suites]),
            bytes([floor]),
            bytes([mode]),
            key_commitment,
        )

    initiator_offer = offer_body(
        initiator_role,
        initiator_id,
        responder_id,
        initiator_nonce,
        initiator_policy,
        initiator_suites,
        initiator_offer_floor,
        initiator_key_commitment,
    )
    responder_offer = offer_body(
        responder_role,
        responder_id,
        initiator_id,
        responder_nonce,
        responder_policy,
        responder_suites,
        responder_offer_floor,
        responder_key_commitment,
    )
    negotiation_digest = sha3(
        lp8_fields(
            NEGOTIATION_DOMAIN,
            initiator_offer,
            responder_offer,
            execution,
            bytes([selected]),
            bytes([effective_floor]),
            bytes([mode]),
        )
    )

    receiver_pq, receiver_traditional = (
        (responder_pq, responder_traditional)
        if encapsulator_role == 1
        else (initiator_pq, initiator_traditional)
    )
    pre_kem = lp8_fields(
        PRE_KEM_DOMAIN,
        TRANSCRIPT_SCHEMA_VERSION.to_bytes(2, "big"),
        protocol,
        session,
        negotiation_digest,
        state_digest,
        generation.to_bytes(8, "big"),
        epoch.to_bytes(8, "big"),
        execution,
        bytes([selected]),
        bytes([effective_floor]),
        bytes([mode]),
        bytes([encapsulator_role]),
        receiver_pq,
        receiver_traditional,
    )
    pre_kem_digest = sha3(pre_kem)

    context = lp8_fields(
        CONTEXT_DOMAIN,
        CONTEXT_SCHEMA_VERSION.to_bytes(2, "big"),
        protocol,
        bytes([encapsulator_role]),
        epoch.to_bytes(8, "big"),
        initiator_policy[4:],
        responder_policy[4:],
        negotiation_digest,
        bytes([selected]),
        bytes([effective_floor]),
        state_digest,
        pre_kem_digest,
        bytes([mode]),
    )
    if len(context) != CONTEXT_ENCODED_LEN:
        raise MigrationContractV2Error(
            "V2 context length invariant failed", code="internal_length"
        )
    context_digest = sha3(context)
    post_kem = lp8_fields(
        POST_KEM_DOMAIN,
        TRANSCRIPT_SCHEMA_VERSION.to_bytes(2, "big"),
        context,
        pq_ciphertext,
        traditional_ciphertext,
    )
    post_kem_digest = sha3(post_kem)

    initiator_finished = sha3(
        lp8_fields(FINISHED_DOMAIN, secret, bytes([1]), post_kem_digest)
    )
    responder_finished = sha3(
        lp8_fields(FINISHED_DOMAIN, secret, bytes([2]), post_kem_digest)
    )
    accepted_key = sha3(
        lp8_fields(
            ACCEPTED_KEY_DOMAIN,
            secret,
            post_kem_digest,
            initiator_finished,
            responder_finished,
        )
    )
    return {
        "state_body_hex": state_body.hex(),
        "state_digest": state_digest.hex(),
        "initiator_offer_body_hex": initiator_offer.hex(),
        "responder_offer_body_hex": responder_offer.hex(),
        "negotiation_digest": negotiation_digest.hex(),
        "pre_kem_hex": pre_kem.hex(),
        "pre_kem_digest": pre_kem_digest.hex(),
        "context_hex": context.hex(),
        "context_digest": context_digest.hex(),
        "post_kem_digest": post_kem_digest.hex(),
        "initiator_finished": initiator_finished.hex(),
        "responder_finished": responder_finished.hex(),
        "accepted_key": accepted_key.hex(),
    }


def verify_document(document: dict[str, Any]) -> None:
    """Fail unless the complete strict vector equals independent recomputation."""

    _exact_keys(document, ROOT_KEYS, "document")
    if document["schema"] != VECTOR_SCHEMA or document["schema_version"] != VECTOR_SCHEMA_VERSION:
        raise MigrationContractV2Error(
            "unsupported vector schema", code="unsupported_schema", field="document"
        )
    if not isinstance(document["case"], str) or not document["case"]:
        raise MigrationContractV2Error("case must be non-empty", code="type", field="case")
    inputs = _object(document["inputs"], "inputs")
    expected = _object(document["expected"], "expected")
    _exact_keys(expected, EXPECTED_KEYS, "expected")
    for key, value in expected.items():
        if not isinstance(value, str) or value.lower() != value or len(value) % 2:
            raise MigrationContractV2Error(
                "expected values must be lowercase even-length hex",
                code="expected_shape",
                field=f"expected.{key}",
            )
        try:
            bytes.fromhex(value)
        except ValueError as error:
            raise MigrationContractV2Error(
                "expected value is not hex", code="expected_shape", field=f"expected.{key}"
            ) from error
    rendered = render(inputs)
    if rendered != expected:
        mismatches = sorted(key for key in EXPECTED_KEYS if rendered[key] != expected[key])
        raise MigrationContractV2Error(
            f"frozen expected values differ: {mismatches}", code="expected_mismatch"
        )
    state = decode_lp8(bytes.fromhex(expected["state_body_hex"]), STATE_FIELD_WIDTHS)
    context = decode_lp8(bytes.fromhex(expected["context_hex"]), CONTEXT_FIELD_WIDTHS)
    if state[0] != STATE_DOMAIN or state[1] != b"\x00\x01":
        raise MigrationContractV2Error("state domain/schema mismatch", code="state_shape")
    if context[0] != CONTEXT_DOMAIN or context[1] != b"\x00\x02":
        raise MigrationContractV2Error("context domain/schema mismatch", code="context_shape")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("verify", "render"))
    parser.add_argument("--vectors", required=True, type=pathlib.Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    document = load_vectors(args.vectors)
    if args.command == "verify":
        verify_document(document)
        print("MIGRATION_CONTRACT_V2_VECTORS_PASS")
    else:
        inputs = _object(document.get("inputs"), "inputs")
        print(json.dumps(render(inputs), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except MigrationContractV2Error as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
