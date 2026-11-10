#!/usr/bin/env python3
"""Check original policy transaction metadata using retained native approvals.

No native fixture is regenerated and no original installation is changed here.
This is a state/codec check, not a durable session continuation qualification.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import argparse
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys


def scenario(public, after_g):
    from cryptography.exceptions import InvalidSignature
    from qperiapt_continuity_reference.authority import PolicyPins, PolicyMaterials, authenticate_policy
    from qperiapt_continuity_reference.identity import DevicePin, verify_device
    from qperiapt_continuity_reference.policy_record import Grant, Record, MAX_RECORD, MAX_GRANT, _stored_scope
    from qperiapt_continuity_reference.wire import VerificationKey, digest, require
    files = {}

    def read(name):
        raw = (public / name).read_bytes()
        fingerprint = hashlib.sha256(raw).hexdigest()
        require(files.setdefault(name, fingerprint) == fingerprint, "native input changed between reads")
        return raw

    policy_root = VerificationKey(read("pin-policy-root"))
    account_root = VerificationKey(read("account-root"))
    policies = []
    for version, now in ((1, 150), (2, 190), (3, 270)):
        head = read(f"policy-head-{version}")
        pins = PolicyPins(read("pin-sdk-root"), read("pin-sdk-state"), policy_root, version, head[8:])
        materials = PolicyMaterials(read("sdk-document"), read("sdk-signature"), read(f"policy-{version}"))
        policies.append(authenticate_policy(pins, materials, now))
    head = read("renewal-1/original-roster-head")
    original_pin = DevicePin(account_root, read("account"), int.from_bytes(head[:8], "big"), head[8:], bytes([1]) * 16, 1)
    original = verify_device(original_pin, read("renewal-1/original-credential"),
                             read("renewal-1/original-roster"), policies[0].family, 150)
    original_policy = policies[0].history
    record, refusals, result = Record(), [], []

    def refuses(name, call, reason=None):
        try:
            call()
        except (ValueError, InvalidSignature) as error:
            require(reason is None or reason in str(error), f"unexpected refusal {name}: {error}")
            refusals.append({"case": name, "type": type(error).__name__, "error": str(error)})
        else:
            raise ValueError("missing refusal: " + name)

    for cycle, now in ((1, 190), (2, 270)):
        approval = read(f"renewal-{cycle}/approval")
        scope = _stored_scope(approval)
        grant = Grant.current_inputs(approval, scope, original_policy, policies[cycle - 1].history,
                                    policies[cycle], original, read(f"renewal-{cycle}/current-credential"),
                                    read(f"renewal-{cycle}/current-roster"), now)
        current = grant.current
        args = (original_policy, original, scope.journal, current)
        require((current.credential != original.credential) == after_g, "native credential profile differs")
        require(record.request(scope.operation, *args) == scope, "request differs from native actual predecessor")
        require(Grant.read(grant.encode(), original_policy, original) == grant, "grant roundtrip")
        before = record.encode()
        require(Record.read(before, *args) == record, "previous policy record roundtrip")
        pending = record.stage(grant, *args, now)
        require(record.encode() == before and pending.status(scope.operation)["status"] == "Pending",
                "stage mutated original state or lost operation")
        saved = pending.encode()
        require(Record.read(saved, *args) == pending and len(saved) <= MAX_RECORD, "pending record roundtrip")
        resigned = Grant.current_inputs(read(f"renewal-{cycle}/approval-resigned"), scope, original_policy,
                    policies[cycle - 1].history, policies[cycle], original, grant.certificate,
                    current.roster_wire, now)
        require(pending.stage(resigned, *args, now) is pending, "retry replaced original signatures")
        label = lambda name: f"P{cycle}-{name}"
        refuses(label("pending-blocks-traffic"), lambda: pending.admit(original_policy, now), "pending")
        refuses(label("pending-blocks-next-request"), lambda: pending.request(bytes([90]) * 32, *args), "pending")
        unknown = bytes([89]) * 32
        refuses(label("unknown-is-not-closed"), lambda: pending.status(unknown), "unavailable")
        refuses(label("unknown-cannot-expire"), lambda: pending.reconcile_expired(unknown, *args, 500, 9, bytes([8]) * 32), "unavailable")
        refuses(label("other-journal"), lambda: Record.read(saved, original_policy, original, bytes([88]) * 32, current), "another journal")
        changed_roster = replace(current, pin=replace(current.pin, roster_version=current.pin.roster_version + 1))
        changed_roster = replace(changed_roster, authority=digest(b"AUTHORITY",
                changed_roster.pin.account + changed_roster.pin.checkpoint() + original_policy.family))
        refuses(label("pending-current-roster-differs"), lambda: Record.read(saved, *args[:-1], changed_roster), "predecessor")
        refuses(label("pending-current-credential-differs"), lambda:
                Record.read(saved, *args[:-1], replace(current, credential=bytes([87]) * 32)),
                "predecessor" if cycle == 1 else "credential changed")
        substituted = replace(grant, approval=replace(grant.approval,
                              scope=replace(scope, operation=bytes([86]) * 32)))
        refuses(label("modified-grant-object"), lambda: record.stage(substituted, *args, now), "metadata")
        if cycle == 1:
            later_wire = read("renewal-2/approval")
            later_scope = _stored_scope(later_wire)
            later = Grant.current_inputs(later_wire, later_scope, original_policy, policies[1].history,
                        policies[2], original, read("renewal-2/current-credential"),
                        read("renewal-2/current-roster"), 270)
            refuses(label("another-valid-approval-cannot-replace-pending"),
                    lambda: pending.stage(later, *args, 270), "another policy")
        expiry = min(grant.target.validity.end, current.validity.end, current.roster_validity.end)
        refuses(label("not-yet-expired"), lambda:
                pending.reconcile_expired(scope.operation, *args, expiry - 1, 9, bytes([8]) * 32), "not expired")
        expired = pending.reconcile_expired(scope.operation, *args, expiry, 9, bytes([8]) * 32)
        require(expired.status(scope.operation)["status"] == "ExpiredUncommitted"
                and expired.floor == expiry and expired.active == record.active, "expiry changed adopted policy")
        require(Record.read(expired.encode(), *args) == expired, "expiry roundtrip")
        refuses(label("expired-cannot-commit"), lambda: expired.commit(scope.operation, *args, expiry), "expired uncommitted")
        refuses(label("abandoned-cannot-restage"), lambda: expired.stage(grant, *args, expiry), "abandoned")
        refuses(label("abandoned-request-cannot-be-reissued"), lambda: expired.request(scope.operation, *args), "disposition")
        refuses(label("backdated-admission"), lambda: expired.admit(original_policy, now), "floor")
        refuses(label("commit-after-expiry"), lambda: pending.commit(scope.operation, *args, expiry), "expired")
        committed = pending.commit(scope.operation, *args, now)
        require(committed.status(scope.operation)["status"] == "Committed" and committed.pending is None,
                "exact pending policy did not commit")
        committed.admit(original_policy, now)
        refuses(label("committed-request-cannot-be-reissued"), lambda: committed.request(scope.operation, *args), "disposition")
        refuses(label("expired-stage-retry-is-not-current-permission"),
                lambda: committed.stage(resigned, *args, 500), "expired")
        require(Record.read(committed.encode(), *args) == committed, "committed record roundtrip")
        require(committed.commit(scope.operation, *args, 500) is committed
                and committed.reconcile_expired(scope.operation, *args, 500, 9, bytes([8]) * 32) is committed,
                "historical observation reclassified completed policy")
        refuses(label("historical-commit-not-current-permission"), lambda: committed.admit(original_policy, 500), "expired")
        refuses(label("record-trailing"), lambda: Record.read(saved + b"\0", *args))
        refuses(label("record-truncated"), lambda: Record.read(saved[:-1], *args))
        oversized = bytearray(saved)
        oversized[16:20] = (MAX_GRANT + 1).to_bytes(4, "big")
        refuses(label("record-field-bound"), lambda: Record.read(bytes(oversized), *args), "capacity")
        require(pending.encode() == saved, "negative control changed original pending bytes")
        result.append({"cycle": cycle, "pending_bytes": len(saved), "committed_bytes": len(committed.encode()),
                       "statement": grant.approval.statement.hex(), "original_journal": scope.journal.hex()})
        record = committed
    for name, expected in files.items():
        require(hashlib.sha256((public / name).read_bytes()).hexdigest() == expected, "native input changed")
    return {"prior_real_credential_renewal": after_g, "cycles": result, "refusals": refusals,
            "input_files": files}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("provider-root", "proof-directory", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    sys.path.append(str(root))
    from qperiapt_continuity_reference.provider import load_provider
    provider, backend = load_provider(args.provider_root)
    from qperiapt_continuity_reference.wire import require
    sources = [Path(__file__).resolve(), *sorted((root / "qperiapt_continuity_reference").glob("*.py"))]
    inventory = lambda: {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
    before = inventory()
    args.output.mkdir()
    results = [scenario(args.proof_directory / "public" / name, after_g) for name, after_g in
               (("unchanged-credential", False), ("after-credential-renewal", True))]
    require(before == inventory(), "policy record sources changed")
    report = {"source_files": before, "native_proof_result_sha256": hashlib.sha256(
              (args.proof_directory / "RESULT.json").read_bytes()).hexdigest(), "profiles": results,
              "provider": {"cryptography": provider.__version__, "openssl": backend.openssl_version_text()},
              "scope": "Pure independent transaction/codec checks with retained real native P1/P2 approvals. No journal mutation, witness transaction or traffic continuation."}
    (args.output / "RESULT.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"profiles": len(results), "refusals": [len(r["refusals"]) for r in results]}))


if __name__ == "__main__":
    main()
