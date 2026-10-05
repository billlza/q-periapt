"""Public readback of real original-policy expiry and foreign-owner recovery.

Native endpoints verify signatures and authenticated private state. This reader
checks public bindings, operation windows and clock observations, not signatures,
secret storage or independent implementation/physical platform qualification.
"""
from dataclasses import dataclass
from pathlib import Path
import re

import rust_sdk_profile as sdk
import continuity_witnessed_renewal as renewal
from continuity_c_witness import commit, RECORD_BYTES

TEST = "witness_policy_expiry::original_foreign_owner_recovers_after_real_signed_policy_expiry"
CASES = renewal.CASES
LABELS = ("key", "create", "request", "request-retry", "accept", "storage", "expiry-original-active",
          "expiry-original-status", "expiry-stage", "expiry-prepare", "expiry-pending-status",
          "expiry-prepare-reopened", "expiry-activation-before", "expiry-history", "expiry-transition",
          "expiry-retry", "expiry-terminal-history", "expiry-activation-after", "expiry-final-status", "expiry-commit-cut")
CALLS = LABELS[11:18]
MATERIALS = (renewal.MATERIALS - {"renewal-image-digests", "renewal-witness-transcript",
    "renewal-tls-transcript", "renewal-carrier-observations"}) | {
    "expiry-image-digests", "expiry-sdk-binding", "expiry-observations", "expiry-witness-transcript",
    "expiry-tcp-transcript", "expiry-withheld-request", "expiry-withheld-reply", "expiry-setup-status-request",
    "expiry-setup-status-reply", "expiry-commit-cut-observations", "enrollment-policy-refusal-before-recovery", "enrollment-policy-refusal"}
FILES = MATERIALS | {f"witness-enrollment-{label}.{ext}" for label in LABELS for ext in ("stdout", "stderr")}
SCOPE = ("real signed-policy wall-clock expiry with SDK and successor credential authority still live; "
         "selected foreign owner recovers original Applied/Closed over TCP and mutual TLS; actual foreign Commit "
         "is durably Applied before SIGKILL with its reply withheld, original local Pending retained and a fresh "
         "native signed Status verified before expiry; public framing/binding readback, not independent signature "
         "verification, transport-error return qualification, physical-platform or release qualification")


@dataclass(frozen=True)
class Point:
    label: str
    time: int
    elapsed_ms: int
    count: int


def observations(wire: bytes, materials, applied: bool) -> list[Point]:
    labels = ["prepared", "expired"] + [name for name in CALLS for _ in range(2)]
    sdk.require(len(wire) >= 42 and wire[:8] == b"QPCEPX01" and wire[40:42] == bytes([int(applied), len(labels)]),
                "policy expiry observation header differs")
    values = [int.from_bytes(wire[n:n + 8], "big") for n in range(8, 40, 8)]
    policy_from, policy_until, credential_from, credential_until = values
    sdk.require(wire[8:24] == materials.policy[48:64] and policy_until - policy_from == 121
                and (credential_from, credential_until) == materials.credential_validity,
                "expiry intervals differ from original signed authority")
    offset, points = 42, []
    for label in labels:
        size = len(label)
        sdk.require(offset + 1 + size + 24 <= len(wire) and wire[offset:offset + 1] == bytes([size])
                    and wire[offset + 1:offset + 1 + size] == label.encode(), "expiry point order or width differs")
        offset += 1 + size
        points.append(Point(label, *(int.from_bytes(wire[n:n + 8], "big") for n in range(offset, offset + 24, 8))))
        offset += 24
    sdk.require(offset == len(wire), "expiry observations have trailing data")
    first = points[0]
    sdk.require(policy_from <= first.time < policy_until and first.count > 0
                and first.count == points[1].count, "expiry wait lost original prepared state")
    for index, point in enumerate(points):
        sdk.require(0 <= point.elapsed_ms <= 300_000 and point.count <= 4096
                    and credential_from <= point.time < credential_until
                    and materials.roster_validity[0] <= point.time < materials.roster_validity[1],
                    "successor authority or bounded expiry observation is invalid")
        if index:
            previous = points[index - 1]
            sdk.require(point.time >= max(previous.time, policy_until)
                        and point.elapsed_ms >= previous.elapsed_ms and point.count >= previous.count
                        and abs((point.time - first.time) * 1000 - (point.elapsed_ms - first.elapsed_ms)) <= 2000,
                        "expiry clock, currentness or monotonic observations differ")
    return points


def signed_history(read, materials, points: list[Point], applied: bool, tls: bool) -> dict:
    trace = read("expiry-witness-transcript", RECORD_BYTES * 4096)
    tcp = read("expiry-tcp-transcript", RECORD_BYTES * 4096)
    sdk.require(tcp == (b"" if tls else trace), "expiry selected carrier used plaintext fallback or differs")
    frames = list(renewal.bound_exchange_frames(trace, materials.authority, materials.subject))
    commit_id = commit(b"Q-PERIAPT-CONTINUITY-ANCHOR-COMMAND/v1",
                       materials.authority + materials.subject + b"\x05" + materials.binding + bytes(64))
    before = points[1].count
    sdk.require(points[-1].count == len(frames) and 0 < before < len(frames), "expiry carrier accounting differs")
    terminal = acknowledged = False
    mutations, acknowledgements = [], []
    for index, frame in enumerate(frames):
        op, kind, outcome = frame.operation, frame.kind, frame.outcome
        sdk.require(frame.wire[0] == (0 if applied and kind == 5 else 1),
                    "expiry reply loss is not the exact foreign Commit")
        sdk.require((frame.observed == materials.expected and frame.has_last == 0)
                    or (frame.observed == materials.target and frame.has_last == 1 and frame.last == commit_id),
                    "expiry head lacks exact original or committed history")
        if kind in (1, 4):
            sdk.require(index < before and not terminal and frame.observed == materials.expected,
                        "expiry admitted runtime or queried ordinary state after terminal/expiry")
            sdk.require((kind == 1 and op[1:] == bytes(96) and outcome == 1)
                        or (kind == 4 and op[1:] == materials.authorities[0] + bytes(64) and outcome == 5),
                        "expiry ordinary authority or reserved encoding differs")
            continue
        sdk.require(kind in (5, 6, 7, 8) and op[1:] == materials.binding + bytes(64),
                    "expiry used another proposal or ordinary Advance")
        wanted_head = materials.target if applied and terminal else materials.expected
        if kind in (5, 7):
            sdk.require(not terminal and kind == (5 if applied else 7)
                        and ((index < before) if applied else (index >= before))
                        and outcome == (8 if applied else 9)
                        and frame.observed == (materials.target if applied else materials.expected),
                        "expiry mutation was repeated, late, reordered or used another terminal")
            terminal = True; mutations.append(index)
        elif kind == 6:
            sdk.require(not acknowledged and outcome == ((8 if applied else 9) if terminal else 7)
                        and frame.observed == wanted_head, "expiry Status precedes mutation or revives retired history")
        else:
            sdk.require(terminal and not acknowledged and index >= before and outcome == 11
                        and frame.observed == wanted_head, "expiry ACK precedes terminal or is repeated")
            acknowledged = True; acknowledgements.append(index)
    sdk.require(terminal and acknowledged and len(mutations) == len(acknowledgements) == 1,
                "expiry exact terminal/ACK history is incomplete")
    # Bind every observed expired command to its actual wire operation interval.
    windows = [[], [], [(6, 8), (8, 11)] if applied else [(6, 7)],
               [] if applied else [(6, 7)], [] if applied else [(7, 9), (6, 9), (8, 11)], [], []]
    cursor = before
    for call, wanted, start, end in zip(CALLS, windows, points[2::2], points[3::2], strict=True):
        sdk.require(start.count == cursor and [(f.kind, f.outcome) for f in frames[start.count:end.count]] == wanted,
                    "expired command dispatched unexpected witness operations: " + call)
        cursor = end.count
    sdk.require(cursor == len(frames) and all(f.kind != 5 for f in frames[before:]),
                "expired recovery dispatched an unaccounted Commit")
    cut_request, cut_reply = read("expiry-withheld-request"), read("expiry-withheld-reply")
    status_request, status_reply = read("expiry-setup-status-request"), read("expiry-setup-status-reply")
    if applied:
        index = mutations[0]
        sdk.require(index >= 1 and (frames[index - 1].kind, frames[index - 1].outcome) == (6, 7)
                    and index + 2 == before and frames[index + 1].kind == 6 and frames[index + 1].outcome == 8
                    and cut_request == frames[index].wire[1:3675] and cut_reply == frames[index].wire[3675:]
                    and status_request == frames[index + 1].wire[1:3675] and status_reply == frames[index + 1].wire[3675:],
                    "Applied setup lacks foreign pre-reconcile, exact withheld Commit or fresh pre-expiry Status")
    else:
        sdk.require(cut_request == cut_reply == status_request == status_reply == b"",
                    "Closed expiry contains an unrelated Applied setup")
    return dict(transport="mutual-tls" if tls else "signed-tcp", requests=len(frames),
                expiry_index=before, operations=[f.kind for f in frames], outcomes=[f.outcome for f in frames],
                no_new_commit_after_expiry=True)


def commit_cut(wire, materials, points, applied, tls):
    if not applied:
        sdk.require(wire == b"", "Closed expiry contains a foreign Commit cut")
        return None
    sdk.require(len(wire) == 28 and wire[:12] == b"QPCECK01" + bytes([tls, 9, 1, 0]),
                "foreign Commit kill or original Pending observation differs")
    at, encrypted = int.from_bytes(wire[12:20], "big"), int.from_bytes(wire[20:], "big")
    sdk.require(int.from_bytes(materials.policy[48:56], "big") <= at <= points[0].time
                and ((0 < encrypted <= 256 * 1024) if tls else encrypted == 0),
                "foreign Commit cut clock or encrypted reply bound differs")
    return dict(exit_signal=9, local_phase="Pending", time=at, withheld_encrypted_bytes=encrypted)


def case_readback(read, case: str) -> dict:
    applied, tls = case.endswith("applied"), case.startswith("tls")
    def command(label, expected=None):
        value = read(f"witness-enrollment-{label}.stdout", 65536)
        sdk.require(read(f"witness-enrollment-{label}.stderr", 65536) == b""
                    and (expected is None or value == expected), "expiry command differs: " + label)
        return value
    def state(label, phase):
        match = re.fullmatch(rb"enrollment-phase:([1-6])\n([0-9a-f]{64})\n([0-9a-f]{64})\n", command(label))
        sdk.require(match is not None and int(match[1]) == phase, "expiry enrollment phase differs")
        return bytes.fromhex(match[2].decode()), bytes.fromhex(match[3].decode())
    command("key", b"enrollment-key\n")
    created = state("create", 1)
    sdk.require(created == state("request", 2) == state("request-retry", 2) and created[1] == bytes(32),
                "expiry original pending identity differs")
    active = state("expiry-original-status", 5)
    sdk.require(active == state("accept", 3) == state("storage", 3) == state("expiry-final-status", 5)
                and active[0] == created[0] and all(any(v) for v in active), "expiry original enrollment/journal changed")
    materials = renewal.verify_materials(read, case, active, image_name="expiry-image-digests")
    activated = command("expiry-original-active")
    sdk.require(re.fullmatch(rb"enrollment-active\n[0-9a-f]{64}\n", activated) is not None, "expiry original activation missing")
    for label in ("expiry-stage", "expiry-pending-status"): command(label, materials.status(1))
    for label in ("expiry-prepare", "expiry-prepare-reopened"): command(label, b"credential-witness-prepared\n")
    for label in ("expiry-activation-before", "expiry-activation-after"):
        command(label, b"enrollment-activation-refused:104\n")
    for name in ("enrollment-policy-refusal-before-recovery", "enrollment-policy-refusal"):
        sdk.require(read(name, 1024) == b"candidate validity interval denied", "expiry validity diagnostic differs")
    command("expiry-history", materials.status(2 if applied else 1))
    command("expiry-transition", materials.status(2) if applied else b"credential-witness-commit-refused:104\n")
    for label in ("expiry-retry", "expiry-terminal-history"): command(label, materials.status(2 if applied else 4))
    sdk.require(read("expiry-sdk-binding", 68) == materials.policy[96:164], "expiry live SDK binding differs from original policy")
    points = observations(read("expiry-observations"), materials, applied)
    command("expiry-commit-cut", b"")
    cut = commit_cut(read("expiry-commit-cut-observations", 28), materials, points, applied, tls)
    carrier = signed_history(read, materials, points, applied, tls)
    return dict(original=materials.original, operation=materials.operation.hex(), statement=materials.statement.hex(),
                proposal=materials.binding.hex(), terminal="Committed" if applied else "Closed", carrier=carrier,
                policy_until=int.from_bytes(materials.policy[56:64], "big"),
                credential_until=materials.credential_validity[1], observed_expired=points[1].time,
                observations=[vars(point) for point in points], foreign_commit_killed=applied, commit_cut=cut)


def verify(stdout: bytes, directory: Path, *, language="C") -> dict:
    sdk.require(language in ("C", "Swift", "Kotlin"), "unsupported expiry language")
    text = stdout.decode()
    lines = re.findall(r"WITNESSED_POLICY_EXPIRY[^\n]*", text)
    sdk.require(len(lines) == 4, "expiry four-case execution differs")
    for line in lines: text = text.replace(line + "\n", "")
    sdk.require(re.findall(r"^test ([a-z_:]+) \.\.\. ok$", text, re.MULTILINE) == [TEST]
                and len(re.findall(r"^test result:", text, re.MULTILINE)) == 1
                and re.search(r"^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out;", text, re.MULTILINE),
                "expiry test did not complete")
    sdk.require(directory.is_dir() and not directory.is_symlink() and {p.name for p in directory.iterdir()} == set(CASES),
                "expiry case inventory differs")
    public, cases = {}, {}
    for case, line in zip(CASES, lines, strict=True):
        folder = directory / case
        sdk.require(folder.is_dir() and not folder.is_symlink() and {p.name for p in folder.iterdir()} == FILES
                    and all(p.is_file() and not p.is_symlink() for p in folder.iterdir()), "expiry public inventory differs")
        def read(name, maximum=8192):
            snap = sdk.snapshot(folder / name, maximum=maximum)
            public[case + "/" + name] = snap.sha256
            return snap.data
        checked = case_readback(read, case)
        match = re.fullmatch(r"WITNESSED_POLICY_EXPIRY case=" + case + r" policy_until=(\d+) observed=(\d+) credential_until=(\d+) "
                             r"sdk_present=true original_policy=true no_new_commit=true foreign_commit_killed=(true|false)", line)
        sdk.require(match is not None and int(match[1]) == checked["policy_until"]
                    and checked["policy_until"] <= int(match[2]) <= checked["observed_expired"]
                    and checked["observed_expired"] - int(match[2]) <= 1
                    and int(match[3]) == checked["credential_until"]
                    and (match[4] == "true") == checked["foreign_commit_killed"], "expiry execution and public observations differ")
        cases[case] = checked
    sdk.require(len(public) == len(FILES) * 4, "expiry left public evidence unchecked")
    return dict(schema_version=1, completed=True, language=language, scope=SCOPE, cases=cases,
                public_readbacks=public, release_claim_eligible=False)


def export(stdout: bytes, directory: Path, destination: Path, *, language="C") -> dict:
    checked = verify(stdout, directory, language=language)
    destination.mkdir(mode=0o700, parents=True)
    for name in checked["public_readbacks"]: sdk.copy(directory / name, destination / name)
    sdk.require(verify(stdout, destination, language=language) == checked, "expiry evidence changed during export")
    return checked


def qualify(outside: Path, output: Path, profile: str, runtime: dict, binary: Path, run,
            *, language="C", variant="") -> dict:
    sdk.require(profile in ("debug", "release") and ((language in ("C", "Swift") and variant == "")
                or (language == "Kotlin" and variant in ("-serial", "-g1"))), "unqualified expiry execution profile")
    sdk.require((language == "C" and runtime.get("QPERIAPT_INSTALLED_CLIENT_LANGUAGE") in (None, "C"))
                or runtime.get("QPERIAPT_INSTALLED_CLIENT_LANGUAGE") == language, "expiry selected another language")
    client = Path(runtime["QPERIAPT_C_OWNER_CLIENT"])
    original = sdk.snapshot(binary, maximum=256 * 1024**2)
    executable = sdk.snapshot(client, maximum=256 * 1024**2)
    label = "witnessed-policy-expiry-" + profile + variant
    evidence = outside / (language.lower() + "-" + label + "-runtime")
    selected = dict(runtime, QPERIAPT_WITNESSED_POLICY_EXPIRY_EVIDENCE=str(evidence))
    selected.pop("QPERIAPT_PUBLIC_SERVICE_EVIDENCE", None)
    selected.pop("QPERIAPT_WITNESSED_RENEWAL_EVIDENCE", None)
    stdout = run([str(binary), "--exact", TEST, "--nocapture"], label, runtime=selected)
    checked = export(stdout, evidence, output / (language.lower() + "-witnessed-policy-expiry-public") / (profile + variant), language=language)
    sdk.require(sdk.snapshot(binary, maximum=256 * 1024**2).sha256 == original.sha256
                and sdk.snapshot(client, maximum=256 * 1024**2).sha256 == executable.sha256,
                "expiry harness or client changed during execution")
    checked.update(binary=dict(sha256=original.sha256, bytes=original.size), foreign_client_sha256=executable.sha256)
    sdk.write_json(output / (language.upper() + "_WITNESSED_POLICY_EXPIRY_" + (profile + variant).replace("-", "_").upper() + ".json"), checked)
    return checked
