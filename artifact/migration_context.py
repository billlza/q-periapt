#!/usr/bin/env python3
"""Independent MigrationContextV1 codec and frozen-vector verifier."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import pathlib
import sys
from typing import Any

from evidence_io import EvidenceIOError, load_json_object_snapshot


MIGRATION_CONTEXT_DOMAIN = b"Q-PERIAPT-MIGRATION-CONTEXT/v1"
MIGRATION_CONTEXT_SCHEMA_VERSION = 1
VECTOR_SCHEMA_VERSION = 1
MIGRATION_CONTEXT_ENCODED_LEN = 315
MAX_VECTOR_JSON_BYTES = 1 << 20

ENCAPSULATOR_ROLES = {"initiator": 1, "responder": 2}
SELECTED_SUITES = frozenset({1, 2})
SECURITY_FLOORS = frozenset({1, 2, 3, 5})
SUITE_SECURITY_LEVELS = {1: 3, 2: 5}

# The codec commits these caller-supplied digests verbatim. Their authenticity,
# preimage construction, and (for the transcript) pre-KEM scope must be verified
# by the protocol layer before encoding; canonicalization cannot establish them.
EXTERNALLY_ASSERTED_COMMITMENT_FIELDS = frozenset(
    {
        "initiator_policy_digest",
        "responder_policy_digest",
        "capability_transcript_hash",
        "transition_state_hash",
        "pre_kem_transcript_hash",
    }
)

INPUT_KEYS = {
    "protocol_id",
    "encapsulator_role",
    "migration_epoch",
    "initiator_policy_digest",
    "responder_policy_digest",
    "capability_transcript_hash",
    "selected_suite",
    "security_floor",
    "transition_state_hash",
    "pre_kem_transcript_hash",
}

FIELD_SPECS = (
    ("domain", 30),
    ("schema_version", 2),
    ("protocol_id", 16),
    ("encapsulator_role", 1),
    ("migration_epoch", 8),
    ("initiator_policy_digest", 32),
    ("responder_policy_digest", 32),
    ("capability_transcript_hash", 32),
    ("selected_suite", 1),
    ("security_floor", 1),
    ("transition_state_hash", 32),
    ("pre_kem_transcript_hash", 32),
)

EXPECTED_KEYS = {"encoded_hex", "length", "sha256", "sha3_256"}


class MigrationContextError(ValueError):
    """A migration context, vector, or canonical encoding is invalid."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "invalid_input",
        field: str | None = None,
    ):
        self.code = code
        self.field = field
        location = f" field={field}" if field is not None else ""
        super().__init__(f"{code}{location}: {message}")


def load_json(path: pathlib.Path) -> dict[str, Any]:
    """Load one strict, immutable JSON-object snapshot."""

    try:
        return load_json_object_snapshot(
            path,
            maximum=MAX_VECTOR_JSON_BYTES,
            label=f"MigrationContextV1 vectors {path}",
        ).value
    except EvidenceIOError as error:
        raise MigrationContextError(
            f"cannot load {path}: {error}",
            code="unsafe_json",
        ) from error


def _object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise MigrationContextError("must be an object", field=name)
    return value


def _exact_keys(value: dict[str, Any], expected: set[str], name: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise MigrationContextError(
            f"keys differ: missing={missing} extra={extra}",
            code="schema_keys",
            field=name,
        )


def _hex(value: Any, length: int, name: str) -> bytes:
    if not isinstance(value, str) or len(value) != length * 2:
        raise MigrationContextError(
            f"must be exactly {length} bytes of lowercase hex",
            code="field_length",
            field=name,
        )
    if value.lower() != value:
        raise MigrationContextError(
            "must use lowercase hex",
            code="noncanonical_hex",
            field=name,
        )
    try:
        decoded = bytes.fromhex(value)
    except ValueError as error:
        raise MigrationContextError(
            "is not hex",
            code="invalid_hex",
            field=name,
        ) from error
    if len(decoded) != length:
        raise MigrationContextError(
            "decoded length differs",
            code="field_length",
            field=name,
        )
    if not any(decoded):
        raise MigrationContextError(
            "uses the reserved all-zero sentinel",
            code="zero_field",
            field=name,
        )
    return decoded


def _monotonic_u64(value: Any, name: str) -> int:
    if type(value) is not int or not 1 <= value < (1 << 64) - 1:
        raise MigrationContextError(
            "must be an integer in 1..2^64-2",
            code="monotonic_range",
            field=name,
        )
    return value


def _closed_code(value: Any, allowed: frozenset[int], name: str) -> int:
    if type(value) is not int or value not in allowed:
        raise MigrationContextError(
            f"must be one of {sorted(allowed)}",
            code="unknown_enum",
            field=name,
        )
    return value


def _encapsulator_role(value: Any, name: str) -> tuple[str, int]:
    if not isinstance(value, str) or value not in ENCAPSULATOR_ROLES:
        raise MigrationContextError(
            "must be initiator or responder",
            code="unknown_enum",
            field=name,
        )
    return value, ENCAPSULATOR_ROLES[value]


def lp8(value: bytes) -> bytes:
    """Encode one unsigned-64-bit big-endian length-prefixed field."""

    return len(value).to_bytes(8, "big") + value


def encode_input(value: dict[str, Any]) -> bytes:
    """Validate and encode one complete canonical MigrationContextV1 input."""

    _exact_keys(value, INPUT_KEYS, "input")
    _, role_code = _encapsulator_role(
        value["encapsulator_role"],
        "input.encapsulator_role",
    )
    migration_epoch = _monotonic_u64(
        value["migration_epoch"],
        "input.migration_epoch",
    )
    selected_suite = _closed_code(
        value["selected_suite"],
        SELECTED_SUITES,
        "input.selected_suite",
    )
    security_floor = _closed_code(
        value["security_floor"],
        SECURITY_FLOORS,
        "input.security_floor",
    )
    if SUITE_SECURITY_LEVELS[selected_suite] < security_floor:
        raise MigrationContextError(
            "selected suite security level is below the required floor",
            code="suite_below_floor",
            field="input.security_floor",
        )
    fields = (
        MIGRATION_CONTEXT_DOMAIN,
        MIGRATION_CONTEXT_SCHEMA_VERSION.to_bytes(2, "big"),
        _hex(value["protocol_id"], 16, "input.protocol_id"),
        bytes([role_code]),
        migration_epoch.to_bytes(8, "big"),
        _hex(
            value["initiator_policy_digest"],
            32,
            "input.initiator_policy_digest",
        ),
        _hex(
            value["responder_policy_digest"],
            32,
            "input.responder_policy_digest",
        ),
        _hex(
            value["capability_transcript_hash"],
            32,
            "input.capability_transcript_hash",
        ),
        bytes([selected_suite]),
        bytes([security_floor]),
        _hex(
            value["transition_state_hash"],
            32,
            "input.transition_state_hash",
        ),
        _hex(
            value["pre_kem_transcript_hash"],
            32,
            "input.pre_kem_transcript_hash",
        ),
    )
    encoded = b"".join(lp8(field) for field in fields)
    if len(fields) != len(FIELD_SPECS) or len(encoded) != MIGRATION_CONTEXT_ENCODED_LEN:
        raise MigrationContextError(
            "canonical length invariant failed",
            code="internal_length",
        )
    return encoded


def _read_lp8(encoded: bytes, offset: int, field: str) -> tuple[bytes, int]:
    if offset + 8 > len(encoded):
        raise MigrationContextError(
            "truncated LP8 prefix",
            code="truncated_field",
            field=field,
        )
    length = int.from_bytes(encoded[offset : offset + 8], "big")
    start = offset + 8
    end = start + length
    if end > len(encoded):
        raise MigrationContextError(
            "truncated LP8 value",
            code="truncated_field",
            field=field,
        )
    return encoded[start:end], end


def _require_nonzero(field: bytes, name: str) -> None:
    if not any(field):
        raise MigrationContextError(
            "uses the reserved all-zero sentinel",
            code="zero_field",
            field=name,
        )


def decode_context(encoded: bytes) -> dict[str, Any]:
    """Strictly decode canonical bytes into normalized JSON-shaped input."""

    if not isinstance(encoded, bytes):
        raise MigrationContextError("context must be bytes", code="type_error")
    fields: list[bytes] = []
    offset = 0
    for name, _ in FIELD_SPECS:
        field, offset = _read_lp8(encoded, offset, name)
        fields.append(field)
    if offset != len(encoded):
        raise MigrationContextError("trailing bytes", code="trailing_bytes")
    for (name, expected_length), field in zip(FIELD_SPECS, fields, strict=True):
        if len(field) != expected_length:
            raise MigrationContextError(
                f"expected {expected_length} bytes, got {len(field)}",
                code="field_length",
                field=name,
            )
    if fields[0] != MIGRATION_CONTEXT_DOMAIN:
        raise MigrationContextError(
            "wrong context domain",
            code="invalid_domain",
            field="domain",
        )
    schema_version = int.from_bytes(fields[1], "big")
    if schema_version != MIGRATION_CONTEXT_SCHEMA_VERSION:
        raise MigrationContextError(
            f"unsupported schema {schema_version}",
            code="unsupported_schema",
            field="schema_version",
        )
    for index in (2, 5, 6, 7, 10, 11):
        _require_nonzero(fields[index], FIELD_SPECS[index][0])

    reverse_roles = {code: name for name, code in ENCAPSULATOR_ROLES.items()}
    role = reverse_roles.get(fields[3][0])
    if role is None:
        raise MigrationContextError(
            "unknown encapsulator role",
            code="unknown_enum",
            field="encapsulator_role",
        )
    migration_epoch = _monotonic_u64(
        int.from_bytes(fields[4], "big"),
        "migration_epoch",
    )
    selected_suite = _closed_code(
        fields[8][0],
        SELECTED_SUITES,
        "selected_suite",
    )
    security_floor = _closed_code(
        fields[9][0],
        SECURITY_FLOORS,
        "security_floor",
    )
    decoded: dict[str, Any] = {
        "protocol_id": fields[2].hex(),
        "encapsulator_role": role,
        "migration_epoch": migration_epoch,
        "initiator_policy_digest": fields[5].hex(),
        "responder_policy_digest": fields[6].hex(),
        "capability_transcript_hash": fields[7].hex(),
        "selected_suite": selected_suite,
        "security_floor": security_floor,
        "transition_state_hash": fields[10].hex(),
        "pre_kem_transcript_hash": fields[11].hex(),
    }
    if encode_input(decoded) != encoded:
        raise MigrationContextError(
            "context does not round-trip",
            code="noncanonical_context",
        )
    return decoded


def expected_values(encoded: bytes) -> dict[str, Any]:
    """Return every frozen output derived from the complete canonical bytes."""

    return {
        "encoded_hex": encoded.hex(),
        "length": len(encoded),
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "sha3_256": hashlib.sha3_256(encoded).hexdigest(),
    }


def _validate_expected_shape(value: dict[str, Any], name: str) -> None:
    if type(value["length"]) is not int:
        raise MigrationContextError(
            "length must be an integer",
            code="expected_type",
            field=f"{name}.length",
        )
    lengths = {
        "encoded_hex": MIGRATION_CONTEXT_ENCODED_LEN,
        "sha256": 32,
        "sha3_256": 32,
    }
    for key, expected_length in lengths.items():
        candidate = value[key]
        field = f"{name}.{key}"
        if not isinstance(candidate, str) or candidate.lower() != candidate:
            raise MigrationContextError(
                "must be lowercase hex",
                code="expected_type",
                field=field,
            )
        try:
            decoded = bytes.fromhex(candidate)
        except ValueError as error:
            raise MigrationContextError(
                "is not hex",
                code="invalid_hex",
                field=field,
            ) from error
        if len(decoded) != expected_length or len(candidate) != expected_length * 2:
            raise MigrationContextError(
                f"must encode exactly {expected_length} bytes",
                code="field_length",
                field=field,
            )


def render_vectors(document: dict[str, Any]) -> dict[str, Any]:
    """Render expected outputs from exact vector inputs."""

    _exact_keys(document, {"schema_version", "vectors"}, "document")
    if type(document["schema_version"]) is not int or (
        document["schema_version"] != VECTOR_SCHEMA_VERSION
    ):
        raise MigrationContextError(
            "unsupported vector schema",
            code="unsupported_schema",
            field="schema_version",
        )
    vectors = document["vectors"]
    if not isinstance(vectors, list) or not vectors:
        raise MigrationContextError(
            "must be a non-empty array",
            field="vectors",
        )
    names: set[str] = set()
    rendered: list[dict[str, Any]] = []
    for index, candidate in enumerate(vectors):
        name_path = f"vectors[{index}]"
        vector = _object(candidate, name_path)
        allowed = {"name", "input", "expected"}
        if not set(vector).issubset(allowed) or not {"name", "input"}.issubset(vector):
            raise MigrationContextError(
                "keys are invalid",
                code="schema_keys",
                field=name_path,
            )
        name = vector["name"]
        if not isinstance(name, str) or not name or name in names:
            raise MigrationContextError(
                "name is invalid or duplicated",
                field=f"{name_path}.name",
            )
        names.add(name)
        input_value = _object(vector["input"], f"{name_path}.input")
        rendered.append(
            {
                "name": name,
                "input": copy.deepcopy(input_value),
                "expected": expected_values(encode_input(input_value)),
            }
        )
    return {"schema_version": VECTOR_SCHEMA_VERSION, "vectors": rendered}


def verify_vectors(document: dict[str, Any]) -> None:
    """Fail unless every frozen expected value matches canonical recomputation."""

    rendered = render_vectors(document)
    for index, candidate in enumerate(document["vectors"]):
        name_path = f"vectors[{index}]"
        vector = _object(candidate, name_path)
        _exact_keys(vector, {"name", "input", "expected"}, name_path)
        expected = _object(vector["expected"], f"{name_path}.expected")
        _exact_keys(expected, EXPECTED_KEYS, f"{name_path}.expected")
        _validate_expected_shape(expected, f"{name_path}.expected")
        if expected != rendered["vectors"][index]["expected"]:
            raise MigrationContextError(
                "expected values do not match canonical bytes",
                code="expected_mismatch",
                field=f"{name_path}.expected",
            )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("verify", "render"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("--vectors", type=pathlib.Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    document = load_json(args.vectors)
    if args.command == "verify":
        verify_vectors(document)
        print("MIGRATION_CONTEXT_V1_VECTORS_PASS")
    else:
        print(json.dumps(render_vectors(document), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except MigrationContextError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
