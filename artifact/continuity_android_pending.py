"""Require complete configured-owner pending-write outcomes; Rust checks authority."""
from pathlib import Path
import hashlib

import continuity_android_contract as contract
import rust_sdk_profile as sdk

TEST = "android_pending_write::signed_fixed_unapplied"
LABEL = "signed-fixed-unapplied"
MARKER = ("qualified original pending write signed/fixed/unapplied: public configuration, original unknown delivery, "
          "independent exact R2 approval, query-only retry, expired activation refused")
COMPLETED = b"original-configuration;exact-roster;unknown-message-retained;query-only;no-activation\n"
CASES = (
    ("original.request", "managed-witness-create"), ("authority-created", "authority-create"),
    ("genesis", "managed-witness-prepare"), ("activated.request", "managed-witness-activate"),
    ("roster-peer-unassociated", "roster-witness-peer-unassociated"),
    ("roster-peer-associated", "authority-peer-associate"), ("roster-connected", "roster-witness-peer-connect"),
    ("roster-unknown", "roster-witness-peer-uncertain"), ("original-roster-unknown", "pending-roster-unknown"),
    ("pending-before-expiry", "pending-request"), ("pending-after-expiry", "pending-request"),
    ("damaged-metadata", "pending-confirm-damaged"), ("unapproved", "pending-confirm-unapproved"),
    ("confirmed", "pending-confirm"), ("retried", "pending-confirm"), ("pending-absent", "pending-request-absent"),
    ("still-expired", "pending-activate-expired"), ("original-identity-after", "pending-identity"),
)
PUBLIC = tuple(name for name, _ in CASES) + tuple(name + "." + suffix for name, _ in CASES for suffix in ("stdout", "stderr")) + (
    "completed", "expiry-observation", "roster-effect-before", "unprocessed-original-advance",
    "inputs/pending-proposal", "inputs/pending-metadata", "inputs/connection-session", "inputs/connection-message",
)


def request(data: bytes) -> tuple[bytes, bytes, bytes]:
    sdk.require(1006 <= len(data) <= 436 + 8388608 + 8192, "pending request size differs")
    metadata_length, signed_length = int.from_bytes(data[:4], "big"), int.from_bytes(data[4:8], "big")
    sdk.require(569 <= metadata_length <= 8388608 and 1 <= signed_length <= 8192
                and len(data) == 436 + metadata_length + signed_length and data[401:404] == bytes(3),
                "pending request framing differs")
    proposal, binding, metadata = data[8:401], data[404:436], data[436:436+metadata_length]
    sdk.require(proposal[:8] == b"QPWRPL01" and metadata[:8] == b"QPWRMD01"
                and proposal[8:361] == metadata[8:361] and any(binding), "pending request scope differs")
    offset = 361
    for _ in range(2):
        sdk.require(len(metadata) - offset >= 8, "missing complete view length")
        size = int.from_bytes(metadata[offset:offset+8], "big"); offset += 8
        sdk.require(96 <= size <= len(metadata) - offset, "complete view exceeds retained metadata")
        offset += size
    sdk.require(offset == len(metadata), "trailing incomplete view metadata")
    return proposal, binding, metadata


def verify_execution(stdout: bytes, directory: Path) -> dict:
    contract.verify_single(stdout, TEST)
    sdk.require(stdout.decode().splitlines().count(MARKER) == 1, "pending-write scenario missing or duplicated")
    base = directory / LABEL
    def read(name): return sdk.snapshot(base / name).data
    for name, mode in CASES:
        sdk.require(read(name + ".stdout") == f"fixed:{mode}:passed\n".encode()
                    and read(name + ".stderr") == b"", "pending-write foreign process did not complete")
    sdk.require(read("completed") == COMPLETED, "pending-write completion missing")
    original = read("original.request")
    sdk.require(len(original) == 5506 and original == read("activated.request") == read("original-identity-after"),
                "original configured identity changed")
    first, second = request(read("pending-before-expiry")), request(read("pending-after-expiry"))
    sdk.require(first == second and first[0] == read("inputs/pending-proposal")
                and first[2] == read("inputs/pending-metadata"), "original approved metadata changed")
    for name, code in [("roster-peer-unassociated",201),("original-roster-unknown",218),
                       ("damaged-metadata",102),("unapproved",103),("pending-absent",201),("still-expired",104)]:
        sdk.require(read(name) == code.to_bytes(4,"big"), "pending-write refusal changed: " + name)
    sdk.require(read("confirmed") == read("retried") == b"\x01", "original target or exact retry not confirmed")
    session, message = read("inputs/connection-session"), read("inputs/connection-message")
    sdk.require(len(session) == len(message) == 32 and any(session) and any(message)
                and read("roster-connected") == session and read("roster-unknown") == session + message
                and read("roster-effect-before") == session + message + b"persisted before process exit",
                "original unknown delivery or real business effect changed")
    observation = read("expiry-observation")
    sdk.require(len(observation) == 16 and 0 < int.from_bytes(observation[:8],"big") < int.from_bytes(observation[8:],"big"),
                "actual policy expiry missing")
    advance = read("unprocessed-original-advance")
    sdk.require(len(advance) == 3674 and advance[204] == 2, "unapplied original Advance missing")
    return {LABEL: {"foreign_processes": len(CASES), "original_identity": True, "unknown_message_retained": True,
        "query_only_confirmation": True, "activation_after_expiry": False,
        "metadata_sha256": hashlib.sha256(first[2]).hexdigest(), "binding": first[1].hex()}}
