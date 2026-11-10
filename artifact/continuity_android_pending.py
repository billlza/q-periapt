"""Require complete configured-owner pending-write outcomes; Rust checks authority."""
from pathlib import Path
import hashlib

import continuity_android_contract as contract
import rust_sdk_profile as sdk

TEST = "android_pending_write::signed_fixed_unapplied"
LABEL = "signed-fixed-unapplied"
TESTS = {f"{carrier}-{trust}-{outcome}": f"android_pending_write::{carrier}_{trust}_{outcome}"
         for carrier in ("signed", "tls") for trust in ("fixed", "recoverable") for outcome in ("unapplied", "applied")}
QUERY_TESTS = {label: "android_pending_query::" + label.replace("-", "_")
               for label in ("signed-fixed-unapplied", "tls-recoverable-applied")}
PROCESS_TESTS = {label: "android_pending_process::" + label.replace("-", "_") for label in QUERY_TESTS}
CONTINUATION_TESTS = {label: "android_pending_continuation::" + label.replace("-", "_") for label in QUERY_TESTS}
MARKER = ("qualified original pending write signed/fixed/unapplied: public configuration, original unknown delivery, "
          "independent exact R2 approval, query-only retry, expired activation refused")
COMPLETED = b"original-configuration;exact-roster;unknown-message-retained;query-only;no-activation\n"
CONTINUED_COMPLETED = b"original-configuration;exact-roster;unknown-message-retained;query-only;expired-activation-denied;independent-renewal;traffic-after-rekey\n"
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
LEGACY_PUBLIC = tuple(name for name, _ in CASES) + tuple(name + "." + suffix for name, _ in CASES for suffix in ("stdout", "stderr")) + (
    "completed", "expiry-observation", "roster-effect-before", "unprocessed-original-advance",
    "inputs/pending-proposal", "inputs/pending-metadata", "inputs/connection-session", "inputs/connection-message",
)


def cases(applied: bool, *, legacy: bool = False, query_cancel: bool = False, process_loss: bool = False) -> tuple:
    sdk.require(sum((legacy, query_cancel, process_loss)) <= 1, "conflicting pending recovery cuts")
    if legacy: return CASES
    selected = list(CASES)
    index = selected.index(("unapproved", "pending-confirm-unapproved"))
    selected[index:index] = [("cancelled", "pending-confirm-cancelled"), ("pending-after-cancel", "pending-request")]
    if applied: selected.remove(("unapproved", "pending-confirm-unapproved"))
    if query_cancel:
        index = selected.index(("confirmed", "pending-confirm"))
        selected[index:index] = [("query-cancelled", "pending-confirm-inflight"), ("pending-after-inflight", "pending-request")]
    if process_loss:
        index = selected.index(("confirmed", "pending-confirm"))
        selected[index:index] = [("query-process-cut", "pending-confirm-process-cut"), ("pending-after-process-cut", "pending-request"),
                                 ("confirmation-result-cut", "pending-confirm-result-cut"), ("pending-after-result-cut", "pending-request-absent")]
    return tuple(selected)


def public(applied: bool, *, legacy: bool = False, query_cancel: bool = False, process_loss: bool = False) -> tuple:
    sdk.require(sum((legacy, query_cancel, process_loss)) <= 1, "conflicting pending recovery cuts")
    if legacy: return LEGACY_PUBLIC
    steps = cases(applied, query_cancel=query_cancel, process_loss=process_loss)
    common = tuple(name for name in LEGACY_PUBLIC if name in (
        "completed", "expiry-observation", "roster-effect-before", "inputs/pending-proposal",
        "inputs/pending-metadata", "inputs/connection-session", "inputs/connection-message"))
    return tuple(name for name, _ in steps) + tuple(name + "." + suffix for name, _ in steps for suffix in ("stdout", "stderr")) + common + (
        "controller-read-only",) + (("processed-original-advance", "original-advance-reply") if applied else ("unprocessed-original-advance",)) + (
        ("query-cancel-transcript", "query-cancel-control", "query-cancel-prefix", "query-cancel-store-unchanged",
         "query-confirmation-transcript", "inputs/cancel-control-token") if query_cancel else ()) + (
        ("query-process-cut.exit", "confirmation-result-cut.exit", "process-cut-transcript", "process-cut-control", "process-cut-prefix",
         "process-cut-store-unchanged", "query-confirmation-transcript", "inputs/cancel-control-token") if process_loss else ())


def marker(label: str) -> str:
    return ("qualified original pending write " + label.replace("-", "/") + ": public configuration, original unknown delivery, "
            "exact R2 effect, pre-cancel retained intent, query-only retry, expired activation refused")


def query_marker(label: str) -> str:
    return ("qualified pending Query cancellation " + label.replace("-", "/") + ": remote reply barrier, native cancellation with witness uncertainty, "
            "unchanged witness, retained original intent, distinct retry challenges")


def process_marker(label: str) -> str:
    return ("qualified pending process loss " + label.replace("-", "/") + ": held Query process exit, lost confirmation result, "
            "original intent and target, fresh Query retries, expired activation refused")


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


def _verify_interruption(stdout: bytes, read, label: str, first: tuple, advance: bytes, *, process_loss: bool) -> None:
    prefix_name = "process-cut" if process_loss else "query-cancel"
    expected_marker = process_marker(label) if process_loss else query_marker(label)
    sdk.require(stdout.decode().splitlines().count(expected_marker) == 1 and read(prefix_name + "-store-unchanged") == b"\1", "interruption observation missing")
    if process_loss:
        for phase, name in [(1,"query-process-cut"),(2,"confirmation-result-cut")]:
            sdk.require(read(name) == b"QPPCUT01" + bytes([phase]) + first[1] and read(name + ".exit") == (77).to_bytes(4,"big"), "original process cut phase or exit missing")
        sdk.require(request(read("pending-after-process-cut")) == first and read("pending-after-result-cut") == (201).to_bytes(4,"big"), "process loss did not preserve intent or confirmed target")
    else:
        sdk.require(read("query-cancelled") == (218).to_bytes(4,"big") and request(read("pending-after-inflight")) == first, "in-flight cancellation or retained intent missing")
    control, token = read(prefix_name + "-control"), read("inputs/cancel-control-token")
    tail = b"\1\4\0\x4d" if process_loss else b"\1\2\3"
    sdk.require(len(token) == 32 and any(token) and control == b"QPCCAN01" + token + first[1] + tail, "interruption signal is not bound to the original request")
    trace = read("query-confirmation-transcript")
    count = 4 if process_loss else 3
    sdk.require(len(trace) == count*7334 and trace[:7334] == read(prefix_name + "-transcript"), "interrupted and retried Query transcript missing")
    challenges, commands = set(), set()
    for index in range(count):
        frame = trace[index*7334:(index+1)*7334]; query, reply = frame[1:3675], frame[3675:]
        sdk.require(frame[0] == (0 if index == 0 else 1) and query[4:12] == b"QPANRQ01" and query[204] == reply[204] == 1
            and query[12:140] == advance[12:140] and any(query[172:204]), "Query cancellation changed authority, subject, operation or result")
        challenges.add(query[172:204]); commands.add(query[140:172])
    sdk.require(len(challenges) == count and len(commands) == 1, "retry reused a challenge or changed the Query command")
    prefix = read(prefix_name + "-prefix")
    sdk.require(0 < len(prefix) < 3659, "held reply prefix bound")
    if label.startswith("signed-"):
        sdk.require(prefix == (3659).to_bytes(4,"big") + trace[3675:5475], "held signed prefix differs from the recorded reply")


def verify_execution(stdout: bytes, directory: Path, label: str = LABEL, *, batch: bool = False,
                     legacy: bool = False, catalog: frozenset[str] = contract.TESTS, query_cancel: bool = False, process_loss: bool = False,
                     continuation: bool = False) -> dict:
    sdk.require(sum((legacy, query_cancel, process_loss, continuation)) <= 1, "conflicting pending recovery cuts")
    process_loss = process_loss or continuation
    tests = CONTINUATION_TESTS if continuation else PROCESS_TESTS if process_loss else QUERY_TESTS if query_cancel else TESTS
    sdk.require(label in tests and (not legacy or (label == LABEL and not batch and catalog == contract.SINGLE_PENDING_TESTS)),
                "unknown pending recovery route or historical scope")
    if batch: contract.verify_batch(stdout, frozenset(tests.values()), catalog=catalog)
    else: contract.verify_single(stdout, tests[label], catalog=catalog)
    sdk.require(stdout.decode().splitlines().count(MARKER if legacy else marker(label)) == 1, "pending-write scenario missing or duplicated")
    carrier, trust, outcome = label.split("-"); applied = outcome == "applied"
    result_label = label + ("-continuation" if continuation else "-process-loss" if process_loss else "-query-cancel" if query_cancel else "")
    base = directory / result_label
    def read(name): return sdk.snapshot(base / name).data
    for name, mode in cases(applied, legacy=legacy, query_cancel=query_cancel, process_loss=process_loss):
        expected_stdout = b"" if mode in ("pending-confirm-process-cut", "pending-confirm-result-cut") else f"{trust}:{mode}:passed\n".encode()
        sdk.require(read(name + ".stdout") == expected_stdout
                    and read(name + ".stderr") == b"", "pending-write foreign process did not complete")
    sdk.require(read("completed") == (CONTINUED_COMPLETED if continuation else COMPLETED), "pending-write completion missing")
    original = read("original.request")
    sdk.require(len(original) == 5506 and original == read("activated.request") == read("original-identity-after"),
                "original configured identity changed")
    first, second = request(read("pending-before-expiry")), request(read("pending-after-expiry"))
    sdk.require(first == second and first[0] == read("inputs/pending-proposal")
                and first[2] == read("inputs/pending-metadata"), "original approved metadata changed")
    if not legacy:
        sdk.require(request(read("pending-after-cancel")) == first and read("controller-read-only") == bytes([applied]),
                    "cancellation lost the original intent or controller mutation scope changed")
    codes = [("roster-peer-unassociated",201),("original-roster-unknown",218),
             ("damaged-metadata",102),("pending-absent",201),("still-expired",104)]
    if not applied: codes.append(("unapproved",103))
    if not legacy: codes.append(("cancelled",302))
    for name, code in codes:
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
    advance = read("processed-original-advance" if applied else "unprocessed-original-advance")
    sdk.require(len(advance) == 3674 and advance[204] == 2, "original Advance missing")
    if applied:
        reply = read("original-advance-reply")
        sdk.require(len(reply) == 3659 and reply[204] == 2, "original applied result missing")
    if query_cancel or process_loss:
        _verify_interruption(stdout, read, label, first, advance, process_loss=process_loss)
    return {result_label: {"foreign_processes": len(cases(applied, legacy=legacy, query_cancel=query_cancel, process_loss=process_loss)), "original_identity": True, "unknown_message_retained": True,
        "query_only_confirmation": True, "activation_after_expiry": False,
        "metadata_sha256": hashlib.sha256(first[2]).hexdigest(), "binding": first[1].hex()}}
