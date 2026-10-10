"""Public linkage for first-use policy renewal; native execution checks signatures.

Request/status records are native ABI readbacks from the collector's host. Signed
policy/approval/proposal envelopes use their canonical big-endian wire format.
"""
import hashlib
import sys

import rust_sdk_profile as sdk

REQUEST_BYTES = 33176
COMMON = frozenset({
    "policy-request.bin", "policy-request-replayed.bin", "policy-approvals.bin",
    "policy-statement.bin", "policy-root.bin", "original-policy.bin", "target-policy.bin",
    "target-version.bin", "target-digest.bin", "policy-refused.bin", "policy-after-refusal.bin",
    "policy-staged.bin", "policy-stage-replayed.bin",
})
LOCAL = frozenset({"policy-committed.bin", "policy-commit-replayed.bin"})
WITNESS = frozenset({"policy-proposal.bin", "proposal-replayed.bin", "proposal-recovered.bin",
                     "witness-applied.bin", "witness-reconciled.bin"})
EXPIRY = frozenset({"expired-activation.bin", "expired-request.bin", "expiry-observation.bin",
                    "receiver-policy.bin"})


def names(carrier: str) -> frozenset[str]:
    sdk.require(carrier in {"local", "signed", "tls"}, "configuration policy carrier differs")
    return COMMON | (LOCAL if carrier == "local" else WITNESS)


def marker(language: str, carrier: str, profile: str) -> str:
    return (f"INDEPENDENT_CONFIGURATION_POLICY_RENEWAL_PASS language={language} carrier={carrier} profile={profile} "
            "original_session=true original_message=true uncertain_before_update=true acknowledged=true effects=1")


def expiry_marker(language: str, carrier: str, profile: str) -> str:
    return (f"INDEPENDENT_CONFIGURATION_EXPIRED_POLICY_PASS language={language} carrier={carrier} profile={profile} "
            "old_activation_refused=true original_request=true receiver_adopted_before_expiry=true")


def digest(domain: bytes, value: bytes) -> bytes:
    return hashlib.sha3_256(len(domain).to_bytes(8, "big") + domain
                           + len(value).to_bytes(8, "big") + value).digest()


def counter(data: bytes, order: str = sys.byteorder) -> int:
    return int.from_bytes(data, order)


def _request(data: dict[str, bytes], account: bytes) -> bytes:
    raw = data["policy-request.bin"]
    sdk.require(len(raw) == REQUEST_BYTES and raw == data["policy-request-replayed.bin"]
                == data["policy-after-refusal.bin"], "configuration policy original request changed")
    sdk.require(data["policy-refused.bin"] == (102).to_bytes(4, sys.byteorder),
                "configuration policy tampered approval was not refused")
    sdk.require(all(any(raw[start:start + 32]) for start in range(0, 160, 32))
                and raw[96:128] == raw[128:160] and raw[280:320] == bytes(40)
                and raw[320:352] == account, "configuration policy original scope differs")
    records = []
    for start in (392, 8588, 16784, 24980):
        length = counter(raw[start:start + 4])
        record = raw[start + 4:start + 8196]
        sdk.require(0 < length <= 8192 and record[length:] == bytes(8192 - length),
                    "configuration policy public record length or padding differs")
        records.append(record[:length])
    sdk.require(records[0] == records[2] and records[1] == records[3]
                and raw[160:200] == raw[352:392]
                and 0 < counter(raw[160:168]) < 2**64 - 1 and any(raw[168:200]),
                "configuration policy changed credential or roster")
    return raw


def _checkpoint(wire: bytes, family: bytes) -> tuple[int, bytes, bytes]:
    length = counter(wire[:4], "big")
    body = wire[4:4 + length]
    sdk.require(length in {168, 200} and len(wire) == 4 + length + 3373
                and body[:8] == b"QPSESP03" and body[8:40] == family,
                "configuration policy envelope or family differs")
    sdk.require(counter(body[48:56], "big") < counter(body[56:64], "big") < 2**64 - 1,
                "configuration policy validity differs")
    return counter(body[40:48], "big"), digest(
        b"Q-PERIAPT-CONTINUITY-SESSION-POLICY-CANDIDATE/v1", body), body


def verify_expiry(data: dict[str, bytes], *, family: bytes, original_request: bytes,
                  identity_until: int) -> dict:
    """Bind actual-clock expiry/refusal to P0 and the original retained request."""
    _, _, original = _checkpoint(data["original-policy.bin"], family)
    target = _checkpoint(data["target-policy.bin"], family)
    receiver = _checkpoint(data["receiver-policy.bin"], family)
    sdk.require(receiver == target, "configuration expiry receiver adopted another policy")
    observation = data["expiry-observation.bin"]
    sdk.require(len(observation) == 24, "configuration expiry observation width differs")
    until, at, adopted = (counter(observation[n:n + 8], "big") for n in (0, 8, 16))
    sdk.require(counter(original[48:56], "big") <= adopted < until
                == counter(original[56:64], "big") <= at < identity_until
                and at < counter(target[2][56:64], "big"),
                "configuration expiry did not observe expired P0 with live identity and target")
    sdk.require(data["expired-activation.bin"] == (104).to_bytes(4, sys.byteorder)
                and data["expired-request.bin"] == original_request,
                "configuration expiry did not refuse activation and preserve original request")
    return dict(policy_until=until, observed_at=at, receiver_adopted_at=adopted)


def _approvals(data: dict[str, bytes], raw: bytes, family: bytes,
               original: bytes, target: bytes) -> bytes:
    approvals = data["policy-approvals.bin"]
    sdk.require(len(approvals) == 7618 and approvals[:8] == b"QPPRNB01",
                "configuration policy approval container differs")
    statements = []
    offset = 8
    for _ in range(2):
        length = counter(approvals[offset:offset + 2], "big")
        sdk.require(length == 3803, "configuration policy approval length differs")
        offset += 2
        wire = approvals[offset:offset + length]
        offset += length
        sdk.require(counter(wire[:4], "big") == 426 and wire[4:12] == b"QPPRNW01",
                    "configuration policy approval envelope differs")
        statements.append(wire[4:430])
    body = statements[0]
    sdk.require(statements[1] == body and offset == len(approvals),
                "configuration policy issuer statements differ")
    sdk.require(body[8:168] == raw[:160] and any(body[168:200]) and body[200:232] == family
                and body[232:272] == counter(raw[160:168]).to_bytes(8, "big") + raw[168:200]
                and body[272:312] == original and body[312:352] == original
                and body[352:392] == target and body[392:] == bytes(33) + b"\x01",
                "configuration policy approval scope or established-session restriction differs")
    statement = digest(b"Q-PERIAPT-POLICY-RENEWAL-CANDIDATE/v1", body)
    sdk.require(data["policy-statement.bin"] == statement,
                "configuration policy statement digest differs")
    return statement


def _status(data: dict[str, bytes], name: str, phase: int,
            raw: bytes, statement: bytes, target: bytes) -> None:
    expected = (phase.to_bytes(4, sys.byteorder) + bytes(4) + raw[:32] + statement
                + counter(target[:8], "big").to_bytes(8, sys.byteorder) + target[8:] + bytes(48))
    sdk.require(data[name] == expected, "configuration policy status differs: " + name)


def _witness(data: dict[str, bytes], raw: bytes, statement: bytes) -> None:
    proposal, genesis = data["policy-proposal.bin"], data["genesis.bin"]
    sdk.require(len(genesis) == 164 and genesis[:4] == b"\x00\x00\x00\x02"
                and genesis[4:36] == genesis[36:68]
                and all(any(genesis[start:start + 32]) for start in (4, 36, 68, 100, 132)),
                "configuration policy original genesis differs")
    sdk.require(len(proposal) == 296 and proposal[:8] == b"QPPWNP01"
                and proposal == data["proposal-replayed.bin"] == data["proposal-recovered.bin"],
                "configuration policy original witness proposal changed")
    sdk.require(proposal[40:136] == genesis[36:132] and raw[32:64] == genesis[4:36]
                and proposal[136:168] == raw[:32] and proposal[168:200] == statement,
                "configuration policy witness journal or statement differs")
    sdk.require(proposal[200:208] == proposal[248:256]
                and 0 < counter(proposal[200:208], "big") < 2**64 - 1
                and 0 < counter(proposal[208:216], "big") < 2**64 - 2
                and counter(proposal[256:264], "big") == counter(proposal[208:216], "big") + 1
                and proposal[216:248] != proposal[264:296],
                "configuration policy witness original sealed target differs")
    sdk.require(data["witness-applied.bin"] == data["witness-reconciled.bin"]
                == (2).to_bytes(4, sys.byteorder), "configuration policy witness did not reconcile Applied")


def verify(data: dict[str, bytes], *, carrier: str, account: bytes, family: bytes) -> str:
    """Require P0 -> P1 between original uncertain delivery and exact retry."""
    raw = _request(data, account)
    root = data["policy-root.bin"]
    sdk.require(len(root) == 1985 and any(root) and family == digest(
        b"Q-PERIAPT-CONTINUITY-POLICY-AUTHORITY-CANDIDATE/v1", root),
        "configuration policy independently pinned family differs")
    old_version, old_digest, old_body = _checkpoint(data["original-policy.bin"], family)
    new_version, new_digest, new_body = _checkpoint(data["target-policy.bin"], family)
    sdk.require(old_version == 1 and new_version == 2 and old_body[64:] == new_body[64:]
                and old_body[48:56] == new_body[48:56]
                and counter(new_body[56:64], "big") == counter(old_body[56:64], "big") + 600,
                "configuration policy renewal changed the SDK/suite/authority or expiry extension")
    original = old_version.to_bytes(8, "big") + old_digest
    target = new_version.to_bytes(8, "big") + new_digest
    sdk.require(raw[200:240] == old_version.to_bytes(8, sys.byteorder) + old_digest
                and raw[240:280] == raw[200:240]
                and data["target-version.bin"] == target[:8] and data["target-digest.bin"] == target[8:],
                "configuration policy original/target checkpoint differs")
    statement = _approvals(data, raw, family, original, target)
    _status(data, "policy-staged.bin", 1, raw, statement, target)
    sdk.require(data["policy-stage-replayed.bin"] == data["policy-staged.bin"],
                "configuration policy stage replay changed")
    if carrier == "local":
        _status(data, "policy-committed.bin", 2, raw, statement, target)
        sdk.require(data["policy-commit-replayed.bin"] == data["policy-committed.bin"],
                    "configuration policy commit replay changed")
    else:
        _witness(data, raw, statement)
    return raw[:32].hex()
