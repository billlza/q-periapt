#!/usr/bin/env python3
"""Independent PrekeySelectionV1 codec and frozen-vector verifier."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import pathlib
import sys
from typing import Any

from evidence_io import EvidenceIOError, load_json_object_snapshot


PREKEY_SELECTION_DOMAIN = b"Q-PERIAPT-CONTINUITY-PREKEY-SELECTION/v1"
PREKEY_SELECTION_DIGEST_DOMAIN = b"Q-PERIAPT-CONTINUITY-PREKEY-SELECTION-DIGEST/v1"
PREKEY_SELECTION_SCHEMA_VERSION = 1
VECTOR_SCHEMA_VERSION = 1
PREKEY_SELECTION_ENCODED_LEN = 492
PREKEY_SELECTION_DIGEST_PREIMAGE_LEN = 555

CLASSICAL_MODES = {"one_time": 1, "signed_only": 2}
POST_QUANTUM_MODES = {"one_time": 1, "last_resort": 2}
QUALITY_CODES = {
    ("one_time", "one_time"): 1,
    ("signed_only", "last_resort"): 2,
    ("signed_only", "one_time"): 3,
    ("one_time", "last_resort"): 4,
}


class PrekeyVectorError(ValueError):
    """A prekey vector or canonical record is invalid."""

    def __init__(self, message: str, *, code: str = "invalid_input", field: str | None = None):
        self.code = code
        self.field = field
        location = f" field={field}" if field is not None else ""
        super().__init__(f"{code}{location}: {message}")


def load_json(path: pathlib.Path) -> dict[str, Any]:
    """Load one strict, immutable JSON-object snapshot."""

    try:
        return load_json_object_snapshot(
            path,
            label=f"PrekeySelectionV1 vectors {path}",
        ).value
    except EvidenceIOError as error:
        raise PrekeyVectorError(f"cannot load {path}: {error}", code="unsafe_json") from error


def _object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PrekeyVectorError("must be an object", field=name)
    return value


def _exact_keys(value: dict[str, Any], expected: set[str], name: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise PrekeyVectorError(
            f"keys differ: missing={missing} extra={extra}",
            code="schema_keys",
            field=name,
        )


def _hex(value: Any, length: int, name: str) -> bytes:
    if not isinstance(value, str) or len(value) != length * 2:
        raise PrekeyVectorError(
            f"must be exactly {length} bytes of lowercase hex",
            code="field_length",
            field=name,
        )
    if value.lower() != value:
        raise PrekeyVectorError("must use lowercase hex", code="noncanonical_hex", field=name)
    try:
        decoded = bytes.fromhex(value)
    except ValueError as error:
        raise PrekeyVectorError("is not hex", code="invalid_hex", field=name) from error
    if len(decoded) != length:
        raise PrekeyVectorError("decoded length differs", code="field_length", field=name)
    if not any(decoded):
        raise PrekeyVectorError(
            "uses the reserved all-zero sentinel",
            code="zero_field",
            field=name,
        )
    return decoded


def _monotonic_u64(value: Any, name: str) -> int:
    if type(value) is not int or not 1 <= value < (1 << 64) - 1:
        raise PrekeyVectorError(
            "must be an integer in 1..2^64-2",
            code="monotonic_range",
            field=name,
        )
    return value


def _enum(value: Any, values: dict[str, int], name: str) -> tuple[str, bytes]:
    if not isinstance(value, str) or value not in values:
        raise PrekeyVectorError("is not a closed enum value", code="unknown_enum", field=name)
    return value, bytes([values[value]])


def lp8(value: bytes) -> bytes:
    """Encode one unsigned-64-bit big-endian length-prefixed field."""

    return len(value).to_bytes(8, "big") + value


def _party(value: Any, name: str) -> tuple[list[bytes], dict[str, Any]]:
    party = _object(value, name)
    _exact_keys(
        party,
        {"account_id", "device_id", "device_epoch", "identity_credential_digest"},
        name,
    )
    account = _hex(party["account_id"], 32, f"{name}.account_id")
    device = _hex(party["device_id"], 16, f"{name}.device_id")
    epoch = _monotonic_u64(party["device_epoch"], f"{name}.device_epoch")
    credential = _hex(
        party["identity_credential_digest"],
        32,
        f"{name}.identity_credential_digest",
    )
    normalized = {
        "account_id": account,
        "device_id": device,
        "device_epoch": epoch,
        "identity_credential_digest": credential,
    }
    return [account, device, epoch.to_bytes(8, "big"), credential], normalized


def _classical(value: Any, name: str) -> tuple[list[bytes], str]:
    leg = _object(value, name)
    _exact_keys(leg, {"mode", "signed_prekey_id", "selected_prekey_id"}, name)
    mode_name, mode = _enum(leg["mode"], CLASSICAL_MODES, f"{name}.mode")
    signed = _hex(leg["signed_prekey_id"], 32, f"{name}.signed_prekey_id")
    selected = _hex(leg["selected_prekey_id"], 32, f"{name}.selected_prekey_id")
    if (mode_name == "one_time") != (selected != signed):
        raise PrekeyVectorError(
            "selected ID relation does not match mode",
            code="mode_key_relation",
            field=name,
        )
    return [mode, signed, selected], mode_name


def _post_quantum(value: Any, name: str) -> tuple[list[bytes], str]:
    leg = _object(value, name)
    _exact_keys(
        leg,
        {"mode", "last_resort_prekey_id", "selected_prekey_id"},
        name,
    )
    mode_name, mode = _enum(leg["mode"], POST_QUANTUM_MODES, f"{name}.mode")
    last_resort = _hex(
        leg["last_resort_prekey_id"],
        32,
        f"{name}.last_resort_prekey_id",
    )
    selected = _hex(leg["selected_prekey_id"], 32, f"{name}.selected_prekey_id")
    if (mode_name == "one_time") != (selected != last_resort):
        raise PrekeyVectorError(
            "selected ID relation does not match mode",
            code="mode_key_relation",
            field=name,
        )
    return [mode, last_resort, selected], mode_name


INPUT_KEYS = {
    "suite_digest",
    "responder",
    "bundle_epoch",
    "directory_checkpoint_digest",
    "signed_prekey_manifest_digest",
    "classical",
    "post_quantum",
}


def encode_input(value: dict[str, Any]) -> dict[str, Any]:
    """Validate and encode one complete canonical selection input."""

    _exact_keys(value, INPUT_KEYS, "input")
    suite_digest = _hex(value["suite_digest"], 32, "input.suite_digest")
    responder_fields, responder = _party(value["responder"], "input.responder")
    bundle_epoch = _monotonic_u64(value["bundle_epoch"], "input.bundle_epoch")
    checkpoint = _hex(
        value["directory_checkpoint_digest"],
        32,
        "input.directory_checkpoint_digest",
    )
    manifest = _hex(
        value["signed_prekey_manifest_digest"],
        32,
        "input.signed_prekey_manifest_digest",
    )
    classical_fields, classical_mode = _classical(value["classical"], "input.classical")
    post_quantum_fields, post_quantum_mode = _post_quantum(
        value["post_quantum"],
        "input.post_quantum",
    )
    fields = [
        PREKEY_SELECTION_DOMAIN,
        PREKEY_SELECTION_SCHEMA_VERSION.to_bytes(2, "big"),
        suite_digest,
        *responder_fields,
        bundle_epoch.to_bytes(8, "big"),
        checkpoint,
        manifest,
        *classical_fields,
        *post_quantum_fields,
    ]
    record = b"".join(lp8(field) for field in fields)
    digest_preimage = lp8(PREKEY_SELECTION_DIGEST_DOMAIN) + lp8(record)
    if len(record) != PREKEY_SELECTION_ENCODED_LEN:
        raise PrekeyVectorError("record length invariant failed", code="internal_length")
    if len(digest_preimage) != PREKEY_SELECTION_DIGEST_PREIMAGE_LEN:
        raise PrekeyVectorError("digest length invariant failed", code="internal_length")
    return {
        "record": record,
        "digest_preimage": digest_preimage,
        "selection_digest": hashlib.sha3_256(digest_preimage).digest(),
        "quality_code": QUALITY_CODES[(classical_mode, post_quantum_mode)],
        "suite_digest": suite_digest,
        "responder": responder,
        "directory_checkpoint_digest": checkpoint,
        "signed_prekey_manifest_digest": manifest,
    }


def _read_lp8(encoded: bytes, offset: int, field: str) -> tuple[bytes, int]:
    if offset + 8 > len(encoded):
        raise PrekeyVectorError("truncated LP8 prefix", code="truncated_field", field=field)
    length = int.from_bytes(encoded[offset : offset + 8], "big")
    start = offset + 8
    end = start + length
    if end > len(encoded):
        raise PrekeyVectorError("truncated LP8 value", code="truncated_field", field=field)
    return encoded[start:end], end


def decode_record(encoded: bytes) -> dict[str, Any]:
    """Strictly decode one canonical record into normalized JSON-shaped input."""

    if not isinstance(encoded, bytes):
        raise PrekeyVectorError("record must be bytes", code="type_error")
    field_names = [
        "domain",
        "schema_version",
        "suite_digest",
        "responder.account_id",
        "responder.device_id",
        "responder.device_epoch",
        "responder.identity_credential_digest",
        "bundle_epoch",
        "directory_checkpoint_digest",
        "signed_prekey_manifest_digest",
        "classical.mode",
        "classical.signed_prekey_id",
        "classical.selected_prekey_id",
        "post_quantum.mode",
        "post_quantum.last_resort_prekey_id",
        "post_quantum.selected_prekey_id",
    ]
    fields: list[bytes] = []
    offset = 0
    for field in field_names:
        value, offset = _read_lp8(encoded, offset, field)
        fields.append(value)
    if offset != len(encoded):
        raise PrekeyVectorError("trailing bytes", code="trailing_bytes")
    lengths = [40, 2, 32, 32, 16, 8, 32, 8, 32, 32, 1, 32, 32, 1, 32, 32]
    for name, field, expected in zip(field_names, fields, lengths, strict=True):
        if len(field) != expected:
            raise PrekeyVectorError(
                f"expected {expected} bytes, got {len(field)}",
                code="field_length",
                field=name,
            )
    if fields[0] != PREKEY_SELECTION_DOMAIN:
        raise PrekeyVectorError("wrong record domain", code="invalid_domain", field="domain")
    schema = int.from_bytes(fields[1], "big")
    if schema != PREKEY_SELECTION_SCHEMA_VERSION:
        raise PrekeyVectorError(
            f"unsupported schema {schema}",
            code="unsupported_schema",
            field="schema_version",
        )
    reverse_classical = {value: name for name, value in CLASSICAL_MODES.items()}
    reverse_pq = {value: name for name, value in POST_QUANTUM_MODES.items()}
    classical_mode = reverse_classical.get(fields[10][0])
    post_quantum_mode = reverse_pq.get(fields[13][0])
    if classical_mode is None:
        raise PrekeyVectorError(
            "unknown classical mode", code="unknown_enum", field="classical.mode"
        )
    if post_quantum_mode is None:
        raise PrekeyVectorError(
            "unknown post-quantum mode", code="unknown_enum", field="post_quantum.mode"
        )
    decoded: dict[str, Any] = {
        "suite_digest": fields[2].hex(),
        "responder": {
            "account_id": fields[3].hex(),
            "device_id": fields[4].hex(),
            "device_epoch": int.from_bytes(fields[5], "big"),
            "identity_credential_digest": fields[6].hex(),
        },
        "bundle_epoch": int.from_bytes(fields[7], "big"),
        "directory_checkpoint_digest": fields[8].hex(),
        "signed_prekey_manifest_digest": fields[9].hex(),
        "classical": {
            "mode": classical_mode,
            "signed_prekey_id": fields[11].hex(),
            "selected_prekey_id": fields[12].hex(),
        },
        "post_quantum": {
            "mode": post_quantum_mode,
            "last_resort_prekey_id": fields[14].hex(),
            "selected_prekey_id": fields[15].hex(),
        },
    }
    if encode_input(decoded)["record"] != encoded:
        raise PrekeyVectorError("record does not round-trip", code="noncanonical_record")
    return decoded


EXPECTED_KEYS = {
    "quality_code",
    "record_len",
    "record_sha256",
    "record_hex",
    "digest_preimage_len",
    "digest_preimage_sha256",
    "digest_preimage_hex",
    "selection_digest_sha3_256",
}


def expected_values(encoded: dict[str, Any]) -> dict[str, Any]:
    """Return all frozen outputs derived from canonical bytes."""

    record = encoded["record"]
    preimage = encoded["digest_preimage"]
    return {
        "quality_code": encoded["quality_code"],
        "record_len": len(record),
        "record_sha256": hashlib.sha256(record).hexdigest(),
        "record_hex": record.hex(),
        "digest_preimage_len": len(preimage),
        "digest_preimage_sha256": hashlib.sha256(preimage).hexdigest(),
        "digest_preimage_hex": preimage.hex(),
        "selection_digest_sha3_256": encoded["selection_digest"].hex(),
    }


def render_vectors(document: dict[str, Any]) -> dict[str, Any]:
    """Render expected outputs from exact vector inputs."""

    _exact_keys(document, {"schema_version", "vectors"}, "document")
    if document["schema_version"] != VECTOR_SCHEMA_VERSION:
        raise PrekeyVectorError("unsupported vector schema", code="unsupported_schema")
    vectors = document["vectors"]
    if not isinstance(vectors, list) or not vectors:
        raise PrekeyVectorError("vectors must be a non-empty array", field="vectors")
    names: set[str] = set()
    rendered: list[dict[str, Any]] = []
    for index, candidate in enumerate(vectors):
        vector = _object(candidate, f"vectors[{index}]")
        allowed = {"name", "input", "expected"}
        if not set(vector).issubset(allowed) or not {"name", "input"}.issubset(vector):
            raise PrekeyVectorError("vector keys are invalid", field=f"vectors[{index}]")
        name = vector["name"]
        if not isinstance(name, str) or not name or name in names:
            raise PrekeyVectorError("name is invalid or duplicated", field=f"vectors[{index}].name")
        names.add(name)
        input_value = _object(vector["input"], f"vectors[{index}].input")
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
        vector = _object(candidate, f"vectors[{index}]")
        _exact_keys(vector, {"name", "input", "expected"}, f"vectors[{index}]")
        expected = _object(vector["expected"], f"vectors[{index}].expected")
        _exact_keys(expected, EXPECTED_KEYS, f"vectors[{index}].expected")
        if expected != rendered["vectors"][index]["expected"]:
            raise PrekeyVectorError(
                "expected values do not match canonical bytes",
                code="expected_mismatch",
                field=f"vectors[{index}].expected",
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
        print("PREKEY_SELECTION_V1_VECTORS_PASS")
    else:
        print(json.dumps(render_vectors(document), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PrekeyVectorError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
