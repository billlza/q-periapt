"""Public readback for original-owner witnessed credential renewal.

Native endpoints verify signatures and authenticate private journal state. This
reader checks canonical public commitments, cross-file scope and signed-message
framing; it is not a second signature implementation or a source of approval.
"""
from pathlib import Path
import re

import rust_sdk_profile as sdk
from continuity_c_witness import commit, head, RECORD_BYTES
from continuity_enrollment import _registration, _validity
from continuity_roster_renewal import envelope

TEST = "witness_credential_renewal::original_witnessed_credential_renewal_recovers_applied_and_closed_without_sdk_runtime"
CASES = ("tcp-applied", "tcp-closed", "tls-applied", "tls-closed")
LABELS = ("key", "create", "request", "request-retry", "accept", "storage", "renewal-original-active",
          "renewal-original-status", "renewal-stage", "renewal-prepare", "renewal-prepare-reopened",
          "pending-no-sdk-commit", "pending-no-sdk-history", "renewal-terminal", "history", "retry",
          "runtime-unavailable", "renewal-current-activation", "renewal-final-status")
MATERIALS = frozenset({
    "enrollment-root", "enrollment-intent", "enrollment-request", "enrollment-reopened-request",
    "grant-certificate", "grant-roster", "trusted-account", "trusted-roster-version", "trusted-roster-digest",
    "family", "policy-root", "policy-version", "policy-digest", "protocol-policy", "witness-id", "witness-public",
    "witness-subject", "enrollment-genesis-subject", "enrollment-genesis-digest", "credential-renewal",
    "credential-operation", "credential-statement", "renewal-version", "renewal-digest", "credential-proposal",
    "credential-proposal-original", "renewal-image-digests", "renewal-witness-transcript", "renewal-tls-transcript", "renewal-carrier-observations",
})
FILES = MATERIALS | {f"witness-enrollment-{label}.{ext}" for label in LABELS for ext in ("stdout", "stderr")}
SCOPE = ("actual selected foreign owner with the shared native engine; original registration, exact proposal, "
         "TCP/TLS Applied and Closed, historical recovery without SDK state and refusal of a new Commit without "
         "current authority; public framing/commitment readback, not independent signature verification, "
         "signed-policy expiry, fault-matrix, physical-platform or release qualification")


def grant_fields(wire: bytes) -> list[bytes]:
    sdk.require(8 < len(wire) <= 65536 and wire[:8] == b"QPRNB001", "renewal grant container differs")
    fields, offset = [], 8
    for _ in range(6):
        sdk.require(offset + 2 <= len(wire), "truncated renewal field length")
        size = int.from_bytes(wire[offset:offset + 2], "big")
        offset += 2
        sdk.require(0 < size <= 8192 and offset + size <= len(wire), "renewal field exceeds its bound")
        fields.append(wire[offset:offset + size])
        offset += size
    sdk.require(offset == len(wire), "renewal grant has trailing fields")
    return fields


def proposal(wire: bytes, authority: bytes, subject: bytes, operation: bytes, statement: bytes):
    sdk.require(len(wire) == 296 and wire[:8] == b"QPCRNP01"
                and wire[8:40] == authority and wire[40:136] == subject
                and wire[136:168] == operation and wire[168:200] == statement
                and all(any(wire[n:n + 32]) for n in (8, 40, 72, 104, 136, 168)),
                "renewal proposal original scope differs")
    expected, target = head(wire[200:248]), head(wire[248:296])
    sdk.require(expected[0] == target[0] and expected[1] + 1 == target[1] and expected[2] != target[2],
                "renewal proposal heads are not an exact adjacent transition")
    return expected, target, commit(b"Q-PERIAPT-ANCHOR-CREDENTIAL-PROPOSAL/v1", wire)


def _signed_records(data: bytes, authority: bytes, subject: bytes, binding: bytes, expected, target,
         closed: bool, authorities: tuple[bytes, bytes], pending_range: tuple[int, int]) -> dict:
    sdk.require(data and len(data) % RECORD_BYTES == 0 and len(data) <= RECORD_BYTES * 4096,
                "renewal signed exchange framing differs")
    challenges, operations, outcomes = set(), [], []
    commit_id = commit(b"Q-PERIAPT-CONTINUITY-ANCHOR-COMMAND/v1", authority + subject + b"\x05" + binding + bytes(64))
    terminal = 9 if closed else 8
    seen_terminal = seen_ack = False
    prepared = 0
    for offset in range(0, len(data), RECORD_BYTES):
        row = data[offset:offset + RECORD_BYTES]
        sdk.require(row[0] == 1, "unqualified lost response in basic renewal transcript")
        rq = envelope(row[1:3675], b"QPANRQ01", 297)
        rs = envelope(row[3675:], b"QPANRS01", 282)
        sdk.require(rq[8:40] == rs[8:40] == authority and rq[40:136] == rs[40:136] == subject,
                    "renewal witness authority or subject differs")
        command, challenge, op = rq[136:168], rq[168:200], rq[200:]
        sdk.require(any(challenge) and challenge not in challenges, "renewal attempt challenge reused")
        challenges.add(challenge)
        sdk.require(command == commit(b"Q-PERIAPT-CONTINUITY-ANCHOR-COMMAND/v1", authority + subject + op)
                    and rs[136:168] == commit(b"Q-PERIAPT-CONTINUITY-ANCHOR-REQUEST/v1", rq)
                    and rs[168:200] == command, "renewal witness command or attempt binding differs")
        kind, outcome, observed = op[0], rs[200], head(rs[201:249])
        flag, last = rs[249], rs[250:282]
        sdk.require((flag == 0 and last == bytes(32)) or (flag == 1 and any(last)), "renewal last-command encoding differs")
        sdk.require((observed == expected and flag == 0) or (observed == target and flag == 1 and last == commit_id),
                    "renewal head lacks its exact original or committed history")
        operations.append(kind); outcomes.append(outcome)
        if kind == 1:
            sdk.require(op[1:] == bytes(96) and outcome == 1 and observed == (expected if closed or not seen_terminal else target),
                        "renewal ordinary query advanced the head")
        elif kind == 4:
            sdk.require(op[1:33] == authorities[0 if closed or not seen_terminal else 1] and op[33:] == bytes(64) and outcome == 5
                        and observed == (expected if closed or not seen_terminal else target), "renewal current-authority admission differs")
        else:
            sdk.require(kind in (5, 6, 7, 8) and op[1:] == binding + bytes(64), "renewal used another proposal or ordinary Advance")
            if outcome == 7:
                sdk.require(kind == 6 and not seen_terminal and observed == expected, "renewal Prepared state differs")
                prepared += 1
            elif outcome == terminal:
                sdk.require(kind in (5, 6, 7) and observed == (expected if closed else target), "renewal terminal head differs")
                sdk.require(not seen_ack, "retired renewal became a retained terminal again")
                sdk.require(seen_terminal or kind == (7 if closed else 5), "renewal terminal observation precedes its unique mutation")
                seen_terminal = True
                if not closed: sdk.require(flag == 1 and last == commit_id, "Applied renewal lacks exact Commit identity")
            elif outcome == 11:
                sdk.require(kind == 8 and seen_terminal and observed == (expected if closed else target), "renewal ACK precedes terminal")
                seen_ack = True
            else:
                sdk.require(False, "renewal witness outcome is not a proven basic-flow disposition")
    sdk.require(seen_terminal and seen_ack and prepared >= 2
                and operations.count(7 if closed else 5) == 1
                and (5 if closed else 7) not in operations, "renewal terminal or no-SDK refusal trace is incomplete")
    first, end = pending_range
    sdk.require(0 < first < end < len(operations) and end - first == 2
                and operations[first:end] == [6, 6] and outcomes[first:end] == [7, 7],
                "no-SDK interval dispatched a mutation or omitted exact historical observation")
    return dict(requests=len(operations), operations=operations, outcomes=outcomes, prepared_observations=prepared)


def _case(read, case: str) -> dict:
    closed, tls = case.endswith("closed"), case.startswith("tls")
    def fixed(name, size, nonzero=False):
        value = read(name, size)
        sdk.require(len(value) == size and (not nonzero or any(value)), "renewal field width differs: " + name)
        return value
    def command(label, expected=None):
        value = read(f"witness-enrollment-{label}.stdout", 65536)
        sdk.require(read(f"witness-enrollment-{label}.stderr", 65536) == b""
                    and (expected is None or value == expected), "renewal command readback differs: " + label)
        return value
    def state(label, phase):
        match = re.fullmatch(rb"enrollment-phase:([1-6])\n([0-9a-f]{64})\n([0-9a-f]{64})\n", command(label))
        sdk.require(match is not None and int(match[1]) == phase, "renewal original enrollment phase differs")
        return bytes.fromhex(match[2].decode()), bytes.fromhex(match[3].decode())
    command("key", b"enrollment-key\n")
    created = state("create", 1)
    sdk.require(created == state("request", 2) == state("request-retry", 2) and created[1] == bytes(32), "renewal changed pending identity")
    active = state("renewal-original-status", 5)
    sdk.require(active == state("accept", 3) == state("storage", 3) == state("renewal-final-status", 5)
                and active[0] == created[0] and all(any(v) for v in active), "renewal replaced original enrollment/journal")
    intent = fixed("enrollment-intent", 72)
    request = envelope(read("enrollment-request"), b"QPENRQ01", 2129)
    virtual = {"signer-id":active[0], "public-key":request[144:], "local-device":intent[:16],
               "local-generation":intent[16:24], "enrollment-validity":intent[56:72],
               "accepted-journal":active[1], "active-journal":active[1], "reopened-journal":active[1]}
    names = {"local-root":"enrollment-root", "local-account":"trusted-account", "request":"enrollment-request",
             "reopened-request":"enrollment-reopened-request", "local-certificate":"grant-certificate", "local-roster":"grant-roster",
             "local-roster-version":"trusted-roster-version", "local-roster-digest":"trusted-roster-digest"}
    def registration_read(_role, name, maximum=8192):
        return virtual[name] if name in virtual else read(names.get(name, name), maximum)
    def registration_fixed(role, name, width, *, nonzero=False):
        value = registration_read(role, name, width)
        sdk.require(len(value) == width and (not nonzero or any(value)), "renewal registration field differs")
        return value
    original, _ = _registration(case, registration_read, registration_fixed)
    family = fixed("family", 32, True)
    sdk.require(family == intent[24:56], "renewal approved policy family differs")
    policy_root = fixed("policy-root", 1985)
    policy = envelope(read("protocol-policy"), b"QPSESP03", 200)
    policy_id = commit(b"Q-PERIAPT-CONTINUITY-SESSION-POLICY-CANDIDATE/v1", policy)
    suite = commit(b"Q-PERIAPT-CONTINUITY-BOOTSTRAP-SUITE-CANDIDATE/v1",
                   b"ML-KEM-768+X25519/ContextBound;ML-DSA-65+P-256/SHA-256;HKDF-SHA-256;HMAC-SHA-256")
    authority = commit(b"Q-PERIAPT-CONTINUITY-ANCHOR-AUTHORITY/v1", fixed("witness-id", 32, True) + fixed("witness-public", 1985))
    sdk.require(policy_root[1952] in (2, 3) and family == commit(b"Q-PERIAPT-CONTINUITY-POLICY-AUTHORITY-CANDIDATE/v1", policy_root)
                and policy[8:40] == family and policy[40:48] == fixed("policy-version", 8)
                and 0 < int.from_bytes(policy[40:48], "big") < 2**64 - 1
                and policy_id == fixed("policy-digest", 32, True) and policy[64:96] == suite
                and int.from_bytes(policy[128:132], "big") > 0
                and policy[164] == 1 and policy[165:198] == b"\x01" + authority and int.from_bytes(policy[198:], "big") > 0,
                "renewal exact signed policy/witness scope differs")
    _validity(policy[48:64])
    statement_wire, original_wire, previous_wire, next_wire, old_roster_wire, next_roster_wire = grant_fields(read("credential-renewal", 65536))
    sdk.require(original_wire == previous_wire == read("grant-certificate") and old_roster_wire == read("grant-roster"),
                "renewal grant replaced original or previous credential")
    old = envelope(original_wire, b"QPCERT01", 2097)
    new = envelope(next_wire, b"QPCERT01", 2097)
    start, until = _validity(old[64:80]); next_start, next_until = _validity(new[64:80])
    sdk.require(old[:64] == new[:64] and old[80:] == new[80:] and start == next_start and until < next_until,
                "renewal is not a same-key validity extension")
    new_digest = commit(b"Q-PERIAPT-CONTINUITY-CREDENTIAL-CANDIDATE/v1", new)
    next_roster = envelope(next_roster_wire, b"QPROST01", 122)
    next_version, next_digest = fixed("renewal-version", 8), fixed("renewal-digest", 32, True)
    sdk.require(int.from_bytes(next_version, "big") > original["roster_version"]
                and int.from_bytes(next_version, "big") < 2**64 - 1
                and next_roster[:48] == b"QPROST01" + old[8:40] + next_version
                and next_roster[64:] == b"\x00\x01" + old[40:64] + new_digest
                and next_digest == commit(b"Q-PERIAPT-CONTINUITY-ROSTER-CANDIDATE/v1", next_roster), "renewal target roster differs")
    a, b = _validity(next_roster[48:64]); sdk.require(max(a, next_start) < min(b, next_until), "renewal target validity has no overlap")
    operation = fixed("credential-operation", 32, True)
    statement = envelope(statement_wire, b"QPCRNW01", 369)
    wanted = (b"QPCRNW01" + operation + old[8:64] + family
              + commit(b"Q-PERIAPT-CREDENTIAL-RENEWAL-KEY/v1", old[112:])
              + bytes.fromhex(original["credential"]) * 2 + new_digest + policy_id
              + fixed("trusted-roster-version", 8) + fixed("trusted-roster-digest", 32)
              + next_version + next_digest + b"\x01")
    sdk.require(statement == wanted, "renewal root statement does not bind its complete materials")
    statement_id = fixed("credential-statement", 32, True)
    sdk.require(statement_id == commit(b"Q-PERIAPT-CREDENTIAL-RENEWAL-STATEMENT/v1", statement), "renewal statement commitment differs")
    owner = commit(b"Q-PERIAPT-CONTINUITY-BOOTSTRAP-CANDIDATE/v1/storage-owner", old[8:64] + bytes.fromhex(original["credential"]))
    subject = active[1] + owner + policy_id
    sdk.require(subject == fixed("witness-subject", 96) == fixed("enrollment-genesis-subject", 96), "renewal original subject differs")
    wire = fixed("credential-proposal", 296)
    sdk.require(wire == fixed("credential-proposal-original", 296), "renewal restart resealed its proposal")
    expected, target, binding = proposal(wire, authority, subject, operation, statement_id)
    images = fixed("renewal-image-digests", 96)
    sdk.require(expected[:2] == (1, 1) and expected[2] == fixed("enrollment-genesis-digest", 32)
                and images == expected[2] * 2 + (expected[2] if closed else target[2]), "renewal image observations differ from exact proposal")
    def status(phase):
        return (f"credential-phase:{phase}\n{operation.hex()}\n{statement_id.hex()}\ncredential-head:"
                f"{0 if phase == 1 else int.from_bytes(next_version, 'big')}\n"
                f"{bytes(32).hex() if phase == 1 else next_digest.hex()}\ncredential-observed:0\n").encode()
    for label in ("renewal-stage", "pending-no-sdk-history"): command(label, status(1))
    for label in ("renewal-prepare", "renewal-prepare-reopened"): command(label, b"credential-witness-prepared\n")
    command("pending-no-sdk-commit", b"credential-witness-commit-refused:702\n")
    for label in ("renewal-terminal", "history", "retry"): command(label, status(4 if closed else 2))
    command("runtime-unavailable", b"enrollment-activation-refused:702\n")
    activated = command("renewal-original-active")
    sdk.require(re.fullmatch(rb"enrollment-active\n[0-9a-f]{64}\n", activated) is not None, "renewal lacks original device activation")
    command("renewal-current-activation", activated)
    counts = fixed("renewal-carrier-observations", 64)
    admissions = [int.from_bytes(counts[n:n + 8], "big") for n in range(0, 32, 8)]
    tcp_counts = [int.from_bytes(counts[n:n + 8], "big") for n in range(32, 64, 8)]
    trace = read("renewal-witness-transcript", RECORD_BYTES * 4096)
    tls_trace = read("renewal-tls-transcript", RECORD_BYTES * 4096)
    authorities = tuple(commit(b"Q-PERIAPT-CONTINUITY-AUTHORITY-CANDIDATE/v1", old[8:40] + checkpoint + family)
                        for checkpoint in (fixed("trusted-roster-version", 8) + fixed("trusted-roster-digest", 32), next_version + next_digest))
    if tls:
        sdk.require(trace == b"" and tcp_counts == [0] * 4
                    and admissions[0] == 0 < admissions[1] < admissions[2] < admissions[3]
                    and admissions[3] * RECORD_BYTES == len(tls_trace), "renewal TLS routing/admission evidence differs")
        carrier = _signed_records(tls_trace, authority, subject, binding, expected, target, closed, authorities, (admissions[1], admissions[2]))
        carrier.update(transport="mutual-tls", tls_admissions=admissions, plaintext_requests=0)
    else:
        sdk.require(tls_trace == b"" and admissions == [0] * 4 and tcp_counts[0] == 0 and tcp_counts[3] * RECORD_BYTES == len(trace),
                    "TCP renewal carrier accounting differs")
        carrier = _signed_records(trace, authority, subject, binding, expected, target, closed, authorities, (tcp_counts[1], tcp_counts[2]))
        carrier["transport"] = "signed-tcp"
    return dict(original=original, target_version=int.from_bytes(next_version, "big"), operation=operation.hex(),
                statement=statement_id.hex(), proposal=binding.hex(), terminal="Closed" if closed else "Committed", carrier=carrier)


def verify(stdout: bytes, directory: Path, *, language: str = "C") -> dict:
    sdk.require(language in ("C", "Swift", "Kotlin"), "unsupported witnessed renewal language")
    text = stdout.decode()
    lines = [f"C_WITNESSED_RENEWAL carrier={case.split('-')[0]} terminal={case.split('-')[1]} "
             "original_proposal=true original_owner=true no_sdk_historical=true current_activation=true" for case in CASES]
    sdk.require(re.findall(r"C_WITNESSED_RENEWAL[^\n]*", text) == lines, "witnessed renewal four-case execution differs")
    for line in lines: text = text.replace(line + "\n", "")
    sdk.require(re.findall(r"^test ([a-z_:]+) \.\.\. ok$", text, re.MULTILINE) == [TEST]
                and len(re.findall(r"^test result:", text, re.MULTILINE)) == 1
                and re.search(r"^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 5 filtered out;", text, re.MULTILINE),
                "witnessed renewal test did not complete")
    sdk.require(directory.is_dir() and not directory.is_symlink() and {p.name for p in directory.iterdir()} == set(CASES),
                "witnessed renewal case inventory differs")
    public, cases = {}, {}
    for case in CASES:
        folder = directory / case
        sdk.require(folder.is_dir() and not folder.is_symlink() and {p.name for p in folder.iterdir()} == FILES
                    and all(p.is_file() and not p.is_symlink() for p in folder.iterdir()), "witnessed renewal public inventory differs")
        def read(name, maximum=8192):
            snap = sdk.snapshot(folder / name, maximum=maximum)
            public[case + "/" + name] = snap.sha256
            return snap.data
        cases[case] = _case(read, case)
    sdk.require(len(public) == len(FILES) * 4, "witnessed renewal left exported evidence unchecked")
    return dict(schema_version=1, completed=True, language=language, scope=SCOPE, cases=cases,
                public_readbacks=public, release_claim_eligible=False)


def export(stdout: bytes, directory: Path, destination: Path, *, language: str = "C") -> dict:
    checked = verify(stdout, directory, language=language)
    destination.mkdir(mode=0o700, parents=True)
    for name in checked["public_readbacks"]: sdk.copy(directory / name, destination / name)
    sdk.require(verify(stdout, destination, language=language) == checked, "witnessed renewal evidence changed during export")
    return checked


def qualify(outside: Path, output: Path, profile: str, runtime: dict, binary: Path, run,
            *, language: str = "C", variant: str = "") -> dict:
    """Execute the archive-derived harness with the selected real foreign client."""
    sdk.require(profile in ("debug", "release")
                and ((language in ("C", "Swift") and variant == "")
                     or (language == "Kotlin" and variant in ("-serial", "-g1"))),
                "unqualified witnessed renewal execution profile")
    sdk.require((language == "C" and runtime.get("QPERIAPT_INSTALLED_CLIENT_LANGUAGE") in (None, "C"))
                or runtime.get("QPERIAPT_INSTALLED_CLIENT_LANGUAGE") == language, "witnessed renewal selected another language")
    client = Path(runtime["QPERIAPT_C_OWNER_CLIENT"])
    original = sdk.snapshot(binary, maximum=256 * 1024**2)
    executable = sdk.snapshot(client, maximum=256 * 1024**2)
    label = "witnessed-credential-renewal-" + profile + variant
    evidence = outside / (language.lower() + "-" + label + "-runtime")
    selected = dict(runtime, QPERIAPT_WITNESSED_RENEWAL_EVIDENCE=str(evidence))
    selected.pop("QPERIAPT_PUBLIC_SERVICE_EVIDENCE", None)
    stdout = run([str(binary), "--exact", TEST, "--nocapture"], label, runtime=selected)
    checked = export(stdout, evidence, output / (language.lower() + "-witnessed-renewal-public") / (profile + variant), language=language)
    sdk.require(sdk.snapshot(binary, maximum=256 * 1024**2).sha256 == original.sha256
                and sdk.snapshot(client, maximum=256 * 1024**2).sha256 == executable.sha256,
                "witnessed renewal harness or client changed during execution")
    checked.update(binary=dict(sha256=original.sha256, bytes=original.size),
                   foreign_client_sha256=executable.sha256)
    sdk.write_json(output / (language.upper() + "_WITNESSED_RENEWAL_" + (profile + variant).replace("-", "_").upper() + ".json"), checked)
    return checked
