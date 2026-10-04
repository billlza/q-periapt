"""Public bindings for original grant cancellation and killed foreign owners.

Native endpoints verify signatures and private journal authentication. This
reader checks public commitments and exact recorded dispatch windows. A TLS
server completion does not establish that the killed peer consumed its reply.
"""
from pathlib import Path
import re

import rust_sdk_profile as sdk
import continuity_witnessed_renewal as renewal
from continuity_c_witness import commit, head, RECORD_BYTES

TEST = "witness_cancellation::grant_only_cancellation_recovers_original_foreign_owner_after_process_loss"
CASES = tuple(f"{carrier}-{validity}-{cut}" for carrier in ("tcp", "tls")
              for validity in ("live", "expired") for cut in ("status", "ack"))
LABELS = ("key", "create", "request", "request-retry", "accept", "storage", "cancel-original-active",
          "cancel-original-status", "cancel-stage", "cancel-reserve", "cancel-reserve-reopened",
          "cancel-pending", "cancel-commit-refused", "cancel-cut", "cancel-cut-status", "cancel-recover",
          "cancel-repeat", "cancel-activation", "cancel-final-status")
MATERIALS = (renewal.MATERIALS - {"credential-proposal", "credential-proposal-original", "renewal-image-digests",
    "renewal-witness-transcript", "renewal-tls-transcript", "renewal-carrier-observations"}) | {
    "credential-cancellation", "credential-cancellation-original", "cancel-image-digests", "cancel-observations",
    "cancel-witness-transcript", "cancel-tcp-transcript"}
FILES = MATERIALS | {f"witness-enrollment-{label}.{ext}" for label in LABELS for ext in ("stdout", "stderr")}
SCOPE = ("selected foreign owner with the shared native engine; target-free original journal reservation without SDK state; "
         "TCP/mutual-TLS recovery after killing the owner at Status or ACK under live or really expired signed policy; "
         "independent control-plane Closed, unchanged sealed image and historical cleanup; public framing/commitment readback, "
         "not independent signature verification, independent protocol implementation, physical-platform or release qualification")


def descriptor(wire, materials):
    sdk.require(len(wire) == 248 and wire[:8] == b"QPCRNC01"
                and wire[8:40] == materials.authority and wire[40:136] == materials.subject
                and wire[136:168] == materials.operation and wire[168:200] == materials.statement,
                "cancellation descriptor original scope or target-free grammar differs")
    return head(wire[200:]), commit(b"Q-PERIAPT-ANCHOR-CREDENTIAL-CANCELLATION/v1", wire)


def observations(wire, materials, tls, expired, ack):
    sdk.require(len(wire) == 116 and wire[:12] == b"QPGCFL01" + bytes([tls, expired, 8 if ack else 6, 4 if ack else 1]),
                "cancellation observation grammar or cut differs")
    names = ("policy_from", "policy_until", "credential_until", "prepared_at", "cut_at", "finished_at",
             "before", "admitted", "failures", "cut_index", "recovered", "failed_index", "exit_signal")
    points = dict(zip(names, (int.from_bytes(wire[n:n + 8], "big") for n in range(12, 116, 8)), strict=True))
    a, b, c = (points[name] for name in ("prepared_at", "cut_at", "finished_at"))
    sdk.require(wire[12:28] == materials.policy[48:64]
                and points["credential_until"] == materials.credential_validity[1]
                and max(points["policy_from"], materials.credential_validity[0], materials.roster_validity[0]) <= a <= b <= c
                and c < min(points["credential_until"], materials.roster_validity[1]) and c - a <= 300,
                "cancellation clocks or current successor grant differ")
    sdk.require((expired and points["policy_until"] - points["policy_from"] == 121 and a >= points["policy_until"])
                or (not expired and c < points["policy_until"]), "cancellation signed-policy currentness differs")
    sdk.require(points["exit_signal"] == 9 and 0 < points["before"] < points["recovered"] <= points["admitted"] <= 4096
                and points["cut_index"] == points["before"] + (3 if ack else 2)
                and points["recovered"] == points["before"] + 5
                and points["failures"] in ((0, 1) if tls else (0,))
                and points["failed_index"] == (points["cut_index"] if points["failures"] else 2**64 - 1),
                "cancellation cut/failure admission accounting differs")
    return points


def signed_history(read, materials, expected, binding, points, tls, expired, ack):
    trace = read("cancel-witness-transcript", RECORD_BYTES * 4096)
    sdk.require(read("cancel-tcp-transcript", RECORD_BYTES * 4096) == (b"" if tls else trace),
                "cancellation carrier differs or used plaintext fallback")
    frames = list(renewal.bound_exchange_frames(trace, materials.authority, materials.subject))
    sdk.require(len(frames) + points["failures"] == points["admitted"], "cancellation carrier census differs")
    middle = [(6, 10), (6, 10)] + ([(6, 9), (8, 11), (8, 11)] if ack else [(6, 9), (6, 9), (8, 11)])
    ordinary = [[], []]
    ordinals = [n for n in range(points["admitted"]) if n != points["failed_index"]]
    for index, frame in zip(ordinals, frames, strict=True):
        op, kind, outcome = frame.operation, frame.kind, frame.outcome
        sdk.require(frame.observed == expected and frame.has_last == 0 and frame.last == bytes(32),
                    "cancellation changed the original head or retained a Commit")
        sdk.require(frame.wire[0] == (0 if not tls and index == points["cut_index"] else 1),
                    "cancellation lost response is not the selected owner cut")
        if points["before"] <= index < points["recovered"]:
            sdk.require((kind, outcome) == middle[index - points["before"]] and op[1:] == binding + bytes(64),
                        "cancellation historical dispatch order, outcome or binding differs")
        else:
            sdk.require(index < points["before"] or not expired, "expired cancellation admitted runtime after recovery")
            sdk.require((kind == 1 and op[1:] == bytes(96) and outcome == 1)
                        or (kind == 4 and op[1:] == materials.authorities[0] + bytes(64) and outcome == 5),
                        "cancellation ordinary request changed original authority")
            ordinary[int(index >= points["recovered"])].append(kind)
    sdk.require(ordinary[0].count(4) == 1 and ordinary[0].count(1) > 0
                and (ordinary[1] == [] if expired else ordinary[1].count(4) == 1 and ordinary[1].count(1) > 0),
                "cancellation original activation or final policy refusal is incomplete")
    return dict(transport="mutual-tls" if tls else "signed-tcp", admitted=points["admitted"],
                recorded=len(frames), failed_admissions=points["failures"], cut_index=points["cut_index"],
                record_ordinals=ordinals, operations=[f.kind for f in frames], outcomes=[f.outcome for f in frames],
                tls_records_mean="server completion; peer consumption unproven" if tls else None,
                no_device_commit_or_close=True)


def case_readback(read, case):
    tls, expired, ack = case.startswith("tls"), "-expired-" in case, case.endswith("ack")
    def command(label, expected=None):
        value = read(f"witness-enrollment-{label}.stdout", 65536)
        sdk.require(read(f"witness-enrollment-{label}.stderr", 65536) == b""
                    and (expected is None or value == expected), "cancellation command differs: " + label)
        return value
    def state(label, phase):
        match = re.fullmatch(rb"enrollment-phase:([1-6])\n([0-9a-f]{64})\n([0-9a-f]{64})\n", command(label))
        sdk.require(match is not None and int(match[1]) == phase, "cancellation original enrollment phase differs")
        return bytes.fromhex(match[2].decode()), bytes.fromhex(match[3].decode())
    command("key", b"enrollment-key\n")
    created = state("create", 1)
    sdk.require(created == state("request", 2) == state("request-retry", 2) and created[1] == bytes(32),
                "cancellation changed pending identity")
    active = state("cancel-original-status", 5)
    sdk.require(active == state("accept", 3) == state("storage", 3) == state("cancel-final-status", 5)
                and active[0] == created[0] and all(any(v) for v in active), "cancellation replaced original enrollment/journal")
    materials = renewal.verify_grant_materials(read, case, active)
    wire = read("credential-cancellation", 248)
    sdk.require(wire == read("credential-cancellation-original", 248), "cancellation restart changed original reservation")
    expected, binding = descriptor(wire, materials)
    sdk.require(expected[:2] == (1, 1) and expected[2] == read("enrollment-genesis-digest", 32)
                and read("cancel-image-digests", 96) == expected[2] * 3, "cancellation changed its sealed image")
    for label in ("cancel-stage", "cancel-pending"): command(label, materials.status(1))
    for label in ("cancel-reserve", "cancel-reserve-reopened"): command(label, b"credential-witness-cancel-reserved\n")
    command("cancel-commit-refused", f"credential-witness-commit-refused:{104 if expired else 215}\n".encode())
    command("cancel-cut", b"")
    command("cancel-cut-status", materials.status(4 if ack else 1))
    for label in ("cancel-recover", "cancel-repeat"): command(label, materials.status(4))
    activated = command("cancel-original-active")
    sdk.require(re.fullmatch(rb"enrollment-active\n[0-9a-f]{64}\n", activated) is not None,
                "cancellation lacks original activation")
    command("cancel-activation", b"enrollment-activation-refused:104\n" if expired else activated)
    points = observations(read("cancel-observations", 116), materials, tls, expired, ack)
    carrier = signed_history(read, materials, expected, binding, points, tls, expired, ack)
    return dict(original=materials.original, operation=materials.operation.hex(), statement=materials.statement.hex(),
                cancellation=binding.hex(), terminal="Closed", cut_local_phase=4 if ack else 1,
                policy_expired=expired, observations=points, carrier=carrier)


def verify(stdout: bytes, directory: Path, *, language="C"):
    sdk.require(language in ("C", "Swift", "Kotlin"), "unsupported cancellation language")
    text = stdout.decode()
    lines = [f"WITNESSED_CANCELLATION case={case} original_reservation=true no_target=true no_sdk_prepare=true "
             f"killed_owner=true local_cut_phase={4 if case.endswith('ack') else 1} closed=true "
             f"policy_expired={'true' if '-expired-' in case else 'false'}" for case in CASES]
    sdk.require(re.findall(r"WITNESSED_CANCELLATION[^\n]*", text) == lines, "cancellation eight-case execution differs")
    for line in lines: text = text.replace(line + "\n", "")
    sdk.require(re.findall(r"^test ([a-z_:]+) \.\.\. ok$", text, re.MULTILINE) == [TEST]
                and len(re.findall(r"^test result:", text, re.MULTILINE)) == 1
                and re.search(r"^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 7 filtered out;", text, re.MULTILINE),
                "cancellation test did not complete")
    sdk.require(directory.is_dir() and not directory.is_symlink() and {p.name for p in directory.iterdir()} == set(CASES),
                "cancellation case inventory differs")
    public, cases = {}, {}
    for case in CASES:
        folder = directory / case
        sdk.require(folder.is_dir() and not folder.is_symlink() and {p.name for p in folder.iterdir()} == FILES
                    and all(p.is_file() and not p.is_symlink() for p in folder.iterdir()), "cancellation public inventory differs")
        def read(name, maximum=8192):
            snap = sdk.snapshot(folder / name, maximum=maximum)
            public[case + "/" + name] = snap.sha256
            return snap.data
        cases[case] = case_readback(read, case)
    sdk.require(len(public) == len(FILES) * 8, "cancellation left exported evidence unchecked")
    return dict(schema_version=1, completed=True, language=language, scope=SCOPE, cases=cases,
                public_readbacks=public, release_claim_eligible=False)


def export(stdout, directory, destination, *, language="C"):
    checked = verify(stdout, directory, language=language)
    destination.mkdir(mode=0o700, parents=True)
    for name in checked["public_readbacks"]: sdk.copy(directory / name, destination / name)
    sdk.require(verify(stdout, destination, language=language) == checked, "cancellation evidence changed during export")
    return checked


def qualify(outside, output, profile, runtime, binary, run, *, language="C", variant=""):
    sdk.require(profile in ("debug", "release") and ((language in ("C", "Swift") and variant == "")
                or (language == "Kotlin" and variant in ("-serial", "-g1"))), "unqualified cancellation execution profile")
    sdk.require((language == "C" and runtime.get("QPERIAPT_INSTALLED_CLIENT_LANGUAGE") in (None, "C"))
                or runtime.get("QPERIAPT_INSTALLED_CLIENT_LANGUAGE") == language, "cancellation selected another language")
    client = Path(runtime["QPERIAPT_C_OWNER_CLIENT"])
    original = sdk.snapshot(binary, maximum=256 * 1024**2)
    executable = sdk.snapshot(client, maximum=256 * 1024**2)
    label = "witnessed-cancellation-" + profile + variant
    evidence = outside / (language.lower() + "-" + label + "-runtime")
    selected = dict(runtime, QPERIAPT_WITNESSED_CANCELLATION_EVIDENCE=str(evidence))
    for key in ("QPERIAPT_PUBLIC_SERVICE_EVIDENCE", "QPERIAPT_WITNESSED_RENEWAL_EVIDENCE", "QPERIAPT_WITNESSED_POLICY_EXPIRY_EVIDENCE"):
        selected.pop(key, None)
    stdout = run([str(binary), "--exact", TEST, "--nocapture"], label, runtime=selected)
    checked = export(stdout, evidence, output / (language.lower() + "-witnessed-cancellation-public") / (profile + variant), language=language)
    sdk.require(sdk.snapshot(binary, maximum=256 * 1024**2).sha256 == original.sha256
                and sdk.snapshot(client, maximum=256 * 1024**2).sha256 == executable.sha256,
                "cancellation harness or client changed during execution")
    checked.update(binary=dict(sha256=original.sha256, bytes=original.size), foreign_client_sha256=executable.sha256)
    sdk.write_json(output / (language.upper() + "_WITNESSED_CANCELLATION_" + (profile + variant).replace("-", "_").upper() + ".json"), checked)
    return checked
