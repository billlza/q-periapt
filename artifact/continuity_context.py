#!/usr/bin/env python3
"""Independent LifecycleContextV1 encoder and frozen-vector verifier."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import pathlib
import sys
from typing import Any

from evidence_io import EvidenceIOError, load_json_object_snapshot
from prekey_selection import PrekeyVectorError, encode_input as encode_prekey_selection


POLICY_CONTEXT_DOMAIN = b"Q-PERIAPT-POLICY-CONTEXT/v1"
LIFECYCLE_CONTEXT_DOMAIN = b"Q-PERIAPT-CONTINUITY-LIFECYCLE/v1"
CONTEXT_DIGEST_DOMAIN = b"Q-PERIAPT-CONTINUITY-CONTEXT-DIGEST/v1"
LIFECYCLE_SCHEMA_VERSION = 1
VECTOR_SCHEMA_VERSION = 2

IDENTITY_MODES = {"accountable": 1, "deniable": 2}
DIRECTIONS = {"initiator_to_responder": 1, "responder_to_initiator": 2}
AUTHENTICATION_STAGES = {
    "prekey_authenticated": 1,
    "peer_confirmed": 2,
    "mutually_confirmed": 3,
}
ROOT_KINDS = {"dh": 1, "pq": 2, "hybrid": 3}

EXPECTED_LENGTHS = {
    "bootstrap": {"body": 666, "policy_bound_kctx": 749, "digest_preimage": 803},
    "root_transition": {
        "body": 626,
        "policy_bound_kctx": 709,
        "digest_preimage": 763,
    },
}


class ContextVectorError(ValueError):
    """A vector or candidate context is invalid."""


def load_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        return load_json_object_snapshot(
            path,
            label=f"Continuity context vectors {path}",
        ).value
    except EvidenceIOError as error:
        raise ContextVectorError(f"cannot load {path}: {error}") from error


def _object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContextVectorError(f"{name} must be an object")
    return value


def _exact_keys(value: dict[str, Any], expected: set[str], name: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ContextVectorError(f"{name} keys differ: missing={missing} extra={extra}")


def _hex(value: Any, length: int, name: str) -> bytes:
    if not isinstance(value, str) or len(value) != length * 2:
        raise ContextVectorError(f"{name} must be exactly {length} bytes of lowercase hex")
    if value.lower() != value:
        raise ContextVectorError(f"{name} must use lowercase hex")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as error:
        raise ContextVectorError(f"{name} is not hex") from error
    if len(decoded) != length:
        raise ContextVectorError(f"{name} decoded length differs")
    if not any(decoded):
        raise ContextVectorError(f"{name} uses the reserved all-zero sentinel")
    return decoded


def _u16(value: Any, name: str) -> bytes:
    if type(value) is not int or not 1 <= value <= 0xFFFF:
        raise ContextVectorError(f"{name} must be an integer in 1..65535")
    return value.to_bytes(2, "big")


def _monotonic_u64(value: Any, name: str) -> int:
    if type(value) is not int or not 1 <= value < (1 << 64) - 1:
        raise ContextVectorError(f"{name} must be an integer in 1..2^64-2")
    return value


def _epoch_u64(value: Any, name: str) -> int:
    # Ratchet counters use the full u64 domain. Zero is a valid initial epoch
    # and MAX is a valid terminal/non-advancing epoch; only a required MAX + 1
    # transition is overflow. Device/roster generations use _monotonic_u64.
    if type(value) is not int or not 0 <= value < (1 << 64):
        raise ContextVectorError(f"{name} must be an integer in 0..2^64-1")
    return value


def _enum(value: Any, values: dict[str, int], name: str) -> bytes:
    if not isinstance(value, str) or value not in values:
        raise ContextVectorError(f"{name} is not a closed enum value")
    return bytes([values[value]])


def lp8(value: bytes) -> bytes:
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
    return [account, device, epoch.to_bytes(8, "big"), credential], {
        "account_id": account,
        "device_id": device,
        "device_epoch": epoch,
        "identity_credential_digest": credential,
    }


def _common_fields(value: dict[str, Any], kind_code: int) -> list[bytes]:
    initiator_fields, initiator_identity = _party(value["initiator"], "input.initiator")
    responder_fields, responder_identity = _party(value["responder"], "input.responder")
    if (
        initiator_identity["account_id"],
        initiator_identity["device_id"],
    ) == (
        responder_identity["account_id"],
        responder_identity["device_id"],
    ):
        raise ContextVectorError("initiator and responder are the same logical device")
    return [
        LIFECYCLE_CONTEXT_DOMAIN,
        LIFECYCLE_SCHEMA_VERSION.to_bytes(2, "big"),
        bytes([kind_code]),
        _hex(value["protocol_id"], 16, "input.protocol_id"),
        _u16(value["wire_version"], "input.wire_version"),
        _hex(value["suite_digest"], 32, "input.suite_digest"),
        _hex(value["session_id"], 32, "input.session_id"),
        *initiator_fields,
        *responder_fields,
        _enum(value["identity_mode"], IDENTITY_MODES, "input.identity_mode"),
        _enum(value["direction"], DIRECTIONS, "input.direction"),
        _enum(
            value["authentication_stage"],
            AUTHENTICATION_STAGES,
            "input.authentication_stage",
        ),
    ]


COMMON_KEYS = {
    "kind",
    "policy_digest",
    "protocol_id",
    "wire_version",
    "suite_digest",
    "session_id",
    "initiator",
    "responder",
    "identity_mode",
    "direction",
    "authentication_stage",
}


def encode_input(value: dict[str, Any]) -> dict[str, bytes]:
    kind = value.get("kind")
    if kind == "bootstrap":
        _exact_keys(
            value,
            COMMON_KEYS
            | {
                "roster_version",
                "roster_digest",
                "directory_checkpoint_digest",
                "prekey_selection",
                "key_schedule_transcript_digest",
            },
            "input",
        )
        if value["authentication_stage"] != "prekey_authenticated":
            raise ContextVectorError("bootstrap requires prekey_authenticated")
        if value["direction"] != "initiator_to_responder":
            raise ContextVectorError("bootstrap requires initiator_to_responder")
        try:
            prekey = encode_prekey_selection(
                _object(value["prekey_selection"], "input.prekey_selection")
            )
        except PrekeyVectorError as error:
            raise ContextVectorError(f"invalid input.prekey_selection: {error}") from error
        suite_digest = _hex(value["suite_digest"], 32, "input.suite_digest")
        _, responder = _party(value["responder"], "input.responder")
        checkpoint = _hex(
            value["directory_checkpoint_digest"],
            32,
            "input.directory_checkpoint_digest",
        )
        if prekey["suite_digest"] != suite_digest:
            raise ContextVectorError("prekey selection suite does not match outer context")
        if prekey["responder"] != responder:
            raise ContextVectorError("prekey selection responder does not match outer context")
        if prekey["directory_checkpoint_digest"] != checkpoint:
            raise ContextVectorError("prekey selection checkpoint does not match outer context")
        fields = _common_fields(value, 1)
        fields.extend(
            [
                _monotonic_u64(value["roster_version"], "input.roster_version").to_bytes(8, "big"),
                _hex(value["roster_digest"], 32, "input.roster_digest"),
                checkpoint,
                bytes([prekey["quality_code"]]),
                prekey["signed_prekey_manifest_digest"],
                prekey["selection_digest"],
                _hex(
                    value["key_schedule_transcript_digest"],
                    32,
                    "input.key_schedule_transcript_digest",
                ),
            ]
        )
    elif kind == "root_transition":
        _exact_keys(
            value,
            COMMON_KEYS
            | {
                "root_transition_kind",
                "prior_context_digest",
                "prior_root_epoch",
                "next_root_epoch",
                "prior_dh_epoch",
                "next_dh_epoch",
                "prior_pq_epoch",
                "next_pq_epoch",
                "transition_transcript_digest",
            },
            "input",
        )
        if value["authentication_stage"] not in {"peer_confirmed", "mutually_confirmed"}:
            raise ContextVectorError("root transition requires a confirmed stage")
        transition_kind = value["root_transition_kind"]
        transition_code = _enum(transition_kind, ROOT_KINDS, "input.root_transition_kind")
        prior_root = _epoch_u64(value["prior_root_epoch"], "input.prior_root_epoch")
        next_root = _epoch_u64(value["next_root_epoch"], "input.next_root_epoch")
        prior_dh = _epoch_u64(value["prior_dh_epoch"], "input.prior_dh_epoch")
        next_dh = _epoch_u64(value["next_dh_epoch"], "input.next_dh_epoch")
        prior_pq = _epoch_u64(value["prior_pq_epoch"], "input.prior_pq_epoch")
        next_pq = _epoch_u64(value["next_pq_epoch"], "input.next_pq_epoch")
        if prior_root == (1 << 64) - 1 or next_root != prior_root + 1:
            raise ContextVectorError("root epoch must advance exactly once")
        expected_dh = prior_dh + (transition_kind in {"dh", "hybrid"})
        expected_pq = prior_pq + (transition_kind in {"pq", "hybrid"})
        if expected_dh >= 1 << 64 or expected_pq >= 1 << 64:
            raise ContextVectorError("component epoch overflow")
        if next_dh != expected_dh or next_pq != expected_pq:
            raise ContextVectorError("component epoch movement does not match transition kind")
        fields = _common_fields(value, 2)
        fields.extend(
            [
                transition_code,
                _hex(value["prior_context_digest"], 32, "input.prior_context_digest"),
                prior_root.to_bytes(8, "big"),
                next_root.to_bytes(8, "big"),
                prior_dh.to_bytes(8, "big"),
                next_dh.to_bytes(8, "big"),
                prior_pq.to_bytes(8, "big"),
                next_pq.to_bytes(8, "big"),
                _hex(
                    value["transition_transcript_digest"],
                    32,
                    "input.transition_transcript_digest",
                ),
            ]
        )
    else:
        raise ContextVectorError("input.kind is not a closed context variant")

    body = b"".join(lp8(field) for field in fields)
    policy_digest = _hex(value["policy_digest"], 32, "input.policy_digest")
    policy_bound = lp8(POLICY_CONTEXT_DOMAIN) + lp8(policy_digest) + lp8(body)
    digest_preimage = lp8(CONTEXT_DIGEST_DOMAIN) + lp8(policy_bound)
    expected_lengths = EXPECTED_LENGTHS[kind]
    actual_lengths = {
        "body": len(body),
        "policy_bound_kctx": len(policy_bound),
        "digest_preimage": len(digest_preimage),
    }
    if actual_lengths != expected_lengths:
        raise ContextVectorError(
            f"canonical length invariant failed: actual={actual_lengths} expected={expected_lengths}"
        )
    return {
        "body": body,
        "policy_bound_kctx": policy_bound,
        "digest_preimage": digest_preimage,
    }


def expected_values(encoded: dict[str, bytes]) -> dict[str, Any]:
    return {
        "body_len": len(encoded["body"]),
        "body_sha256": hashlib.sha256(encoded["body"]).hexdigest(),
        "policy_bound_kctx_len": len(encoded["policy_bound_kctx"]),
        "policy_bound_kctx_sha256": hashlib.sha256(encoded["policy_bound_kctx"]).hexdigest(),
        "digest_preimage_len": len(encoded["digest_preimage"]),
        "digest_preimage_sha256": hashlib.sha256(encoded["digest_preimage"]).hexdigest(),
        "context_digest_sha3_256": hashlib.sha3_256(encoded["digest_preimage"]).hexdigest(),
    }


EXPECTED_KEYS = {
    "body_len",
    "body_sha256",
    "policy_bound_kctx_len",
    "policy_bound_kctx_sha256",
    "digest_preimage_len",
    "digest_preimage_sha256",
    "context_digest_sha3_256",
}


def render_vectors(document: dict[str, Any]) -> dict[str, Any]:
    _exact_keys(document, {"schema_version", "vectors"}, "document")
    if document["schema_version"] != VECTOR_SCHEMA_VERSION:
        raise ContextVectorError("unsupported vector schema")
    vectors = document["vectors"]
    if not isinstance(vectors, list) or not vectors:
        raise ContextVectorError("vectors must be a non-empty array")
    names: set[str] = set()
    rendered: list[dict[str, Any]] = []
    for index, candidate in enumerate(vectors):
        vector = _object(candidate, f"vectors[{index}]")
        allowed = {"name", "input", "expected"}
        if not set(vector).issubset(allowed) or not {"name", "input"}.issubset(vector):
            raise ContextVectorError(f"vectors[{index}] keys are invalid")
        name = vector["name"]
        if not isinstance(name, str) or not name or name in names:
            raise ContextVectorError(f"vectors[{index}].name is invalid or duplicated")
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
    rendered = render_vectors(document)
    vectors = document["vectors"]
    for index, candidate in enumerate(vectors):
        vector = _object(candidate, f"vectors[{index}]")
        _exact_keys(vector, {"name", "input", "expected"}, f"vectors[{index}]")
        expected = _object(vector["expected"], f"vectors[{index}].expected")
        _exact_keys(expected, EXPECTED_KEYS, f"vectors[{index}].expected")
        if expected != rendered["vectors"][index]["expected"]:
            raise ContextVectorError(f"vectors[{index}] expected values do not match canonical bytes")


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
        print("CONTINUITY_CONTEXT_V1_VECTORS_PASS")
    else:
        print(json.dumps(render_vectors(document), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ContextVectorError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
