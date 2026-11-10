#!/usr/bin/env python3
"""Read only public artifacts from the real directory CLI; never open its private state."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import argparse
import base64
import hashlib
import json
from pathlib import Path
import sys

PUBLIC_FILES = frozenset((
    "pin.json", "first.bin", "retry.bin", "cancelled.bin", "fork.bin", "fresh.bin",
    "conflict.bin", "original-history.json", "inspection.json", "expected.json",
    "cli-trace.jsonl", "history-trace.jsonl", "bad-signature.bin",
    "wrong-service.json", "wrong-key.json",
))
SOURCE_FILES = ("directory_cli_checks.py", "qperiapt_continuity_reference/directory_lease.py",
                "qperiapt_continuity_reference/wire.py")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "duplicate public field")
        value[key] = item
    return value


def decode_json(raw):
    def nonfinite(value):
        raise ValueError("non-finite public JSON: " + value)
    return json.loads(raw, object_pairs_hook=unique, parse_constant=nonfinite)


def validate_trace(rows, historical):
    require(len(rows) == 31 and len(historical) == 4, "CLI process census differs")
    for row in rows + historical:
        require(type(row) is dict and set(row) == {"arguments", "exit", "stdout", "stderr"}
                and type(row["arguments"]) is list and row["arguments"]
                and all(type(s) is str for s in row["arguments"])
                and type(row["exit"]) is int and row["exit"] in (0, 1)
                and type(row["stdout"]) is str and type(row["stderr"]) is str,
                "CLI process trace shape")
        require((row["exit"] == 0 and not row["stderr"])
                or (row["exit"] == 1 and not row["stdout"] and row["stderr"]),
                "CLI process result or diagnostics differ")

    def event(verb, last, exit_code, error=None):
        matches = [(i, r) for i, r in enumerate(rows)
                   if r["arguments"][0] == verb and r["arguments"][-1] == last]
        require(len(matches) == 1, "missing or repeated CLI event: " + last)
        i, row = matches[0]
        require(row["exit"] == exit_code and
                (error is None or row["stderr"] == "Error: " + error + "\n"),
                "CLI failure boundary differs: " + last)
        return i, row

    lost, _ = event("issue", "@occupied.bin", 1)
    lookup, looked = event("lookup", "@first.bin", 0)
    retry, _ = event("issue", "@first-retry.bin", 0)
    require(lost < lookup < retry and decode_json(looked["stdout"]) ==
            {"historical": True, "cancelled": False}, "lost output was not reconciled")
    event("issue", "@changed.bin", 1, "Conflict")
    event("issue", "@unused.bin", 1, "Unauthorized")
    event("issue", "@duplicate.bin", 1, "KeyAlreadyReserved")
    event("issue", "@reactivated.bin", 1, "Cancelled")
    event("issue", "@reassigned.bin", 1, "KeyAlreadyReserved")
    cancellation = [(i, r) for i, r in enumerate(rows)
                    if r["arguments"][0] == "cancel" and r["exit"] == 0]
    require(len(cancellation) == 2 and all(decode_json(r["stdout"]) == {"cancelled": True}
            for _, r in cancellation), "cancellation and its exact retry missing")
    bad_cancel, _ = event("cancel", "@issue-first.json", 1,
                          '\"Approval scope differs from the independently selected operation\"')
    cancelled_lookup, cancelled_result = event("lookup", "@cancelled.bin", 0)
    require(bad_cancel < cancellation[0][0] < cancellation[1][0] < cancelled_lookup
            and decode_json(cancelled_result["stdout"]) == {"historical": True, "cancelled": True},
            "cancelled history or unauthorized cancellation boundary missing")
    for key in ("reuse-classical", "reuse-pq"):
        before, _ = event("issue", "@" + key + "-before-cancel.bin", 1, "KeyAlreadyReserved")
        after, _ = event("issue", "@" + key + "-after-cancel.bin", 1, "KeyAlreadyReserved")
        require(before < cancellation[0][0] < cancellation[1][0] < after,
                "one-time reservation not checked across actual cancellation")
    fresh, _ = event("issue", "@fresh-pair-after-cancel.bin", 0)
    require(fresh > cancellation[1][0], "fresh allocation did not follow cancellation")
    event("issue", "@fork.bin", 0)
    live, live_result = event("check-receipt", "@first.bin", 0)
    require(live < cancellation[0][0] and
            decode_json(live_result["stdout"])["signature_and_scope"] is True,
            "original current SDK receipt verification missing")
    proof = [r for r in rows if r["arguments"][0] == "prove-conflict"]
    require(len(proof) == 2 and [r["exit"] for r in proof] == [1, 0]
            and proof[0]["arguments"][3] == "@first-retry.bin"
            and proof[1]["arguments"][3] == "@fork.bin",
            "exact replay or real conflict proof missing")
    event("check-conflict", "@proof/conflict.bin", 0)
    require([r["arguments"] for r in historical] == [
        ["check-historical-receipt", "@pin.json", "@receipt.bin"],
        ["check-historical-receipt", "@pin.json", "@bad-signature.bin"],
        ["check-historical-receipt", "@wrong-service.json", "@receipt.bin"],
        ["check-historical-receipt", "@wrong-key.json", "@receipt.bin"]],
        "isolated SDK historical input scope differs")
    require([r["exit"] for r in historical] == [0, 1, 1, 1],
            "SDK historical positive or rejection missing")


def verify(provider_root, input_directory, output):
    peer = Path(__file__).resolve().parent
    sys.path.append(str(peer))
    from qperiapt_continuity_reference.provider import load_provider
    crypto, backend = load_provider(provider_root)
    from cryptography.exceptions import InvalidSignature
    from qperiapt_continuity_reference import directory_lease
    from qperiapt_continuity_reference.directory_lease import DirectoryPin, DirectoryLeaseConflict
    from qperiapt_continuity_reference.wire import VerificationKey
    root = input_directory.resolve(strict=True)
    require(root.is_dir() and {p.name for p in root.iterdir()} == PUBLIC_FILES,
            "directory input must contain only the closed public artifact set")
    inputs = {}
    for name in sorted(PUBLIC_FILES):
        path = root / name
        require(path.is_file() and not path.is_symlink(), "non-regular public input")
        with path.open("rb") as stream:
            data = stream.read(256 * 1024 + 1)
        require(len(data) <= 256 * 1024, "public input capacity")
        inputs[name] = data
    parsed = {name: decode_json(data) for name, data in inputs.items() if name.endswith(".json")}
    rows = [decode_json(line) for line in inputs["cli-trace.jsonl"].splitlines()]
    history_rows = [decode_json(line) for line in inputs["history-trace.jsonl"].splitlines()]
    validate_trace(rows, history_rows)
    expected, inspection = parsed["expected.json"], parsed["inspection.json"]
    require(expected["schema"] == "qperiapt-directory-cli-public/1"
            and expected["directory_cli"] == "source-build", "CLI producer boundary differs")
    for field in ("completed", "cancelled", "output_loss_preserved_existing_file",
                  "exact_retry_preserved_original", "changed_request_refused",
                  "both_algorithm_reservations_checked_before_and_after_cancel",
                  "fresh_pair_issued_after_cancel", "historical_inputs_only_pin_and_receipt",
                  "rust_live_scope_checked", "rust_canonical_conflict_checked", "historical_only"):
        require(expected[field] is True, "unexecuted CLI obligation: " + field)
    require(expected["private_keys_exported"] is False and expected["release_claim_eligible"] is False,
            "CLI scope promoted")
    counts = expected["ledger_operation_counts"]
    require(type(counts) is dict and counts == {"after_exact_retry": 1, "after_cancel_and_refusals": 1,
                                               "after_fresh_pair": 2}
            and all(type(count) is int for count in counts.values()),
            "CLI producer observed a second allocation during retry or refusal")

    def octets(value, length):
        require(type(value) is list and len(value) == length
                and all(type(n) is int and 0 <= n <= 255 for n in value), "public identifier")
        return bytes(value)

    def pin_from(value):
        require(type(value) is dict and set(value) == {"schema", "service", "public_key"}
                and value["schema"] == "qperiapt-directory-pin/1", "directory pin schema")
        text = value["public_key"]
        require(type(text) is str, "directory public key encoding")
        key = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
        require(base64.urlsafe_b64encode(key).rstrip(b"=").decode() == text, "noncanonical public key")
        return DirectoryPin(octets(value["service"], 32), VerificationKey(key))

    pin = pin_from(parsed["pin.json"])
    require(rows[0]["arguments"][0] == "prepare-key" and rows[1]["arguments"][0] == "show-key"
            and decode_json(rows[0]["stdout"]) == decode_json(rows[1]["stdout"]) == parsed["pin.json"],
            "service pin differs from independently retained provisioning output")
    first = pin.verify_historical_lease(inputs["first.bin"])
    fork = pin.verify_historical_lease(inputs["fork.bin"])
    fresh = pin.verify_historical_lease(inputs["fresh.bin"])
    require(inputs["first.bin"] == inputs["retry.bin"] == inputs["cancelled.bin"],
            "original signed wire changed on retry or cancellation")
    for receipt, request in ((first, expected["request"]), (fork, expected["other_request"])):
        s = receipt.statement
        require(s.service == pin.binding == octets(inspection["service_binding"], 32)
                and s.operation == octets(request["operation"], 32)
                and s.requester == octets(request["requester"], 32)
                and s.checkpoint == octets(request["checkpoint"], 32) == octets(inspection["checkpoint"], 32)
                and s.validity.start == request["valid_from"] and s.validity.end == request["valid_until"]
                and s.account == octets(expected["account"], 32)
                and s.device == octets(expected["device"], 16)
                and s.generation == expected["generation"] and s.family == octets(expected["family"], 32)
                and s.selection == octets(inspection["selection_digest"], 32),
                "service, request, identity or selection binding differs")
    s = first.statement
    sdk_history = {"historical": True, "original_statement": list(first.statement_digest),
                   "service_binding": list(pin.binding), "request": expected["request"],
                   "manifest_digest": list(s.manifest), "selection_digest": list(s.selection),
                   "classical_fingerprint": list(s.classical_fingerprint),
                   "post_quantum_fingerprint": list(s.pq_fingerprint)}
    require(parsed["original-history.json"] == sdk_history ==
            decode_json(history_rows[0]["stdout"]), "SDK and independent history differ")
    require(s.classical != fresh.statement.classical and s.pq != fresh.statement.pq,
            "fresh allocation reused a reserved key")
    proof = DirectoryLeaseConflict.verify(pin, inputs["first.bin"], inputs["fork.bin"])
    require(proof.classical and proof.pq and proof.to_bytes() == inputs["conflict.bin"]
            == DirectoryLeaseConflict.verify(pin, inputs["fork.bin"], inputs["first.bin"]).to_bytes()
            == DirectoryLeaseConflict.from_bytes(pin, inputs["conflict.bin"]).to_bytes(),
            "SDK and independent canonical conflict bytes differ")
    refused = []
    def reject(name, action):
        try:
            action()
        except (ValueError, InvalidSignature):
            refused.append(name)
        else:
            raise AssertionError("accepted negative control: " + name)
    reject("bad-signature", lambda: pin.verify_historical_lease(inputs["bad-signature.bin"]))
    reject("wrong-service", lambda: pin_from(parsed["wrong-service.json"]).verify_historical_lease(inputs["first.bin"]))
    reject("wrong-public-key", lambda: pin_from(parsed["wrong-key.json"]).verify_historical_lease(inputs["first.bin"]))
    reject("exact-retry-is-not-conflict", lambda: DirectoryLeaseConflict.verify(pin, inputs["first.bin"], inputs["retry.bin"]))
    changed = bytearray(inputs["first.bin"]); changed[4 + directory_lease.BODY_BYTES] ^= 1
    reject("bad-pq-signature", lambda: pin.verify_historical_lease(bytes(changed)))
    output.mkdir()
    public = output / "public"; public.mkdir()
    for name, data in inputs.items():
        (public / name).write_bytes(data)
        require((root / name).read_bytes() == data, "public input changed during verification")
    report = {"schema": "qperiapt-independent-directory-cli/1", "completed": True,
              "provider": {"cryptography": crypto.__version__, "openssl": backend.openssl_version_text()},
              "source_sha256": {name: hashlib.sha256((peer / name).read_bytes()).hexdigest() for name in SOURCE_FILES},
              "implementation": str(Path(directory_lease.__file__).resolve()),
              "public_files": {name: hashlib.sha256(data).hexdigest() for name, data in inputs.items()},
              "verified_original_receipts": 3, "exact_retry": True, "canonical_conflict_matched": True,
              "negative_controls": refused, "cli_processes": len(rows), "historical_processes": len(history_rows),
              "historical_only": True, "current_authorization_or_consumption": False,
              "directory_cli": "source-build", "session_qualified": False, "release_claim_eligible": False}
    (output / "RESULT.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("provider-root", "input", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    result = verify(args.provider_root, args.input, args.output)
    print(json.dumps({key: result[key] for key in ("completed", "verified_original_receipts", "canonical_conflict_matched", "negative_controls")}))


if __name__ == "__main__":
    main()
