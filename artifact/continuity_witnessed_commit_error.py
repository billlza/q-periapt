"""Public bindings for an actual foreign Commit transport-error return and reopen.

Native endpoints verify signatures and private storage. These checks bind public
observations to the original operation; they do not replace signature verification.
"""
from pathlib import Path
import re
import rust_sdk_profile as sdk
import continuity_witnessed_renewal as renewal
from continuity_c_witness import commit, RECORD_BYTES

TEST = "witness_commit_error::foreign_commit_transport_error_closes_and_reopens_original_owner"
CASES = tuple(f"{carrier}-{validity}" for carrier in ("tcp", "tls") for validity in ("live", "expired"))
LABELS = ("key", "create", "request", "request-retry", "accept", "storage", "error-original-active",
          "error-original-status", "error-stage", "error-prepare", "error-return", "error-pending",
          "error-recovered", "error-repeat", "error-final-status", "error-activation")
MATERIALS = (renewal.MATERIALS - {"renewal-image-digests", "renewal-witness-transcript", "renewal-tls-transcript",
    "renewal-carrier-observations"}) | {"error-image-digests", "error-observations", "error-witness-transcript",
    "error-tcp-transcript", "error-observer-request", "error-observer-reply", "error-cut-prefix"}
FILES = MATERIALS | {f"witness-enrollment-{label}.{ext}" for label in LABELS for ext in ("stdout", "stderr")}
SCOPE = ("actual selected foreign Commit returns218 after durable Applied with withheld TCP/TLS reply; "
         "same handle Closed and explicit close before normal process exit; fresh original Pending reopen, "
         "independent native fresh signed Applied Status, then live/real-expired policy recovery and one ACK; "
         "shared native engine and public commitment readback, not independent implementation, signature oracle, "
         "physical-platform, installed archive or release qualification")


def observations(wire, materials, tls, expired):
    sdk.require(len(wire) == 132 and wire[:12] == b"QPCEER01" + bytes([tls, expired, 218, 2]),
                "Commit error code, Closed handle or observation grammar differs")
    names = ("policy_from", "policy_until", "credential_until", "prepared_at", "returned_at", "observed_at",
             "recovery_at", "finished_at", "before", "after_error", "after_observer", "after_recovery",
             "final_count", "exit_code", "encrypted_reply_bytes")
    points = dict(zip(names, (int.from_bytes(wire[n:n+8], "big") for n in range(12, 132, 8)), strict=True))
    times = [points[k] for k in names[3:8]]
    sdk.require(wire[12:28] == materials.policy[48:64] and points["credential_until"] == materials.credential_validity[1]
                and times == sorted(times) and times[-1] - times[0] <= 300
                and max(points["policy_from"], materials.credential_validity[0], materials.roster_validity[0]) <= times[0]
                and times[-1] < min(points["credential_until"], materials.roster_validity[1])
                and points["returned_at"] < points["policy_until"] and points["observed_at"] < points["policy_until"],
                "Commit error authority, order or bounded clock observation differs")
    sdk.require((expired and points["policy_until"] - points["policy_from"] == 121 and points["recovery_at"] >= points["policy_until"])
                or (not expired and points["finished_at"] < points["policy_until"]), "Commit error recovery currentness differs")
    before = points["before"]
    sdk.require(0 < before < points["final_count"] <= 4096 and points["after_error"] == before + 2
                and points["after_observer"] == before + 3 and points["after_recovery"] == points["final_count"] == before + 5
                and points["exit_code"] == 0 and ((0 < points["encrypted_reply_bytes"] <= 256 * 1024) if tls
                                                 else points["encrypted_reply_bytes"] == 0),
                "Commit error dispatch, normal exit or encrypted reply accounting differs")
    return points


def signed_history(read, materials, points, tls):
    wire = read("error-witness-transcript", RECORD_BYTES * 4096)
    sdk.require(read("error-tcp-transcript", RECORD_BYTES * 4096) == (b"" if tls else wire),
                "Commit error carrier differs or used plaintext fallback")
    frames = list(renewal.bound_exchange_frames(wire, materials.authority, materials.subject))
    sdk.require(len(frames) == points["final_count"], "Commit error transcript census differs")
    before = points["before"]
    command = commit(b"Q-PERIAPT-CONTINUITY-ANCHOR-COMMAND/v1",
                     materials.authority + materials.subject + b"\x05" + materials.binding + bytes(64))
    ordinary = []
    tail = [(6, 7), (5, 8), (6, 8), (6, 8), (8, 11)]
    for index, frame in enumerate(frames):
        sdk.require(frame.wire[0] == (0 if index == before + 1 else 1), "Commit error lost another reply")
        applied = index >= before + 1
        sdk.require(frame.observed == (materials.target if applied else materials.expected)
                    and frame.has_last == int(applied) and frame.last == (command if applied else bytes(32)),
                    "Commit error original/target head or retained Commit differs")
        if index < before:
            sdk.require((frame.kind == 1 and frame.operation[1:] == bytes(96) and frame.outcome == 1)
                        or (frame.kind == 4 and frame.operation[1:] == materials.authorities[0] + bytes(64) and frame.outcome == 5),
                        "Commit error setup used another current authority")
            ordinary.append(frame.kind)
        else:
            sdk.require((frame.kind, frame.outcome) == tail[index - before] and frame.operation[1:] == materials.binding + bytes(64),
                        "Commit error reconciliation, mutation or ACK order differs")
    sdk.require(ordinary.count(4) == 1 and ordinary.count(1) > 0, "Commit error original activation missing")
    observed = frames[before + 2]
    sdk.require(read("error-observer-request") == observed.wire[1:3675]
                and read("error-observer-reply") == observed.wire[3675:], "Commit error lacks exact fresh Applied observation")
    expected_prefix = b"" if tls else (3659).to_bytes(4, "big") + frames[before + 1].wire[3675:5475]
    sdk.require(read("error-cut-prefix", 1804) == expected_prefix, "Commit error held another TCP reply prefix")
    return dict(transport="mutual-tls" if tls else "signed-tcp", requests=len(frames), lost_index=before + 1,
                operations=[f.kind for f in frames], outcomes=[f.outcome for f in frames], unique_commit=True, unique_ack=True)


def case_readback(read, case):
    tls, expired = case.startswith("tls"), case.endswith("expired")
    def command(label, expected=None):
        value = read(f"witness-enrollment-{label}.stdout", 65536)
        sdk.require(read(f"witness-enrollment-{label}.stderr", 65536) == b"" and (expected is None or value == expected),
                    "Commit error command differs: " + label)
        return value
    def state(label, phase):
        match = re.fullmatch(rb"enrollment-phase:([1-6])\n([0-9a-f]{64})\n([0-9a-f]{64})\n", command(label))
        sdk.require(match is not None and int(match[1]) == phase, "Commit error enrollment phase differs")
        return bytes.fromhex(match[2].decode()), bytes.fromhex(match[3].decode())
    command("key", b"enrollment-key\n")
    created = state("create", 1)
    sdk.require(created == state("request", 2) == state("request-retry", 2) and created[1] == bytes(32),
                "Commit error replaced the pending signing identity")
    active = state("error-original-status", 5)
    sdk.require(active == state("accept", 3) == state("storage", 3) == state("error-final-status", 5)
                and active[0] == created[0] and all(any(v) for v in active), "Commit error replaced enrollment or journal")
    materials = renewal.verify_materials(read, case, active, image_name="error-image-digests")
    sdk.require(re.fullmatch(rb"enrollment-active\n[0-9a-f]{64}\n", command("error-original-active")) is not None,
                "Commit error lacks original activation")
    for label in ("error-stage", "error-pending"): command(label, materials.status(1))
    command("error-prepare", b"credential-witness-prepared\n")
    command("error-return", b"credential-witness-commit-refused:218\n")
    for label in ("error-recovered", "error-repeat"): command(label, materials.status(2))
    command("error-activation", b"enrollment-activation-refused:104\n" if expired else b"")
    points = observations(read("error-observations", 132), materials, tls, expired)
    carrier = signed_history(read, materials, points, tls)
    return dict(original=materials.original, operation=materials.operation.hex(), statement=materials.statement.hex(),
                proposal=materials.binding.hex(), terminal="Committed", policy_expired=expired, observations=points, carrier=carrier)


def verify(stdout, directory, *, language="C"):
    sdk.require(language in ("C", "Swift", "Kotlin"), "unsupported Commit error language")
    text = stdout.decode()
    lines = [f"WITNESSED_COMMIT_ERROR case={case} returned=218 owner_closed=true normal_exit=true original_pending=true "
             f"committed=true policy_expired={'true' if case.endswith('expired') else 'false'}" for case in CASES]
    sdk.require(re.findall(r"WITNESSED_COMMIT_ERROR[^\n]*", text) == lines, "Commit error four-case execution differs")
    for line in lines: text = text.replace(line + "\n", "")
    sdk.require(re.findall(r"^test ([a-z_:]+) \.\.\. ok$", text, re.MULTILINE) == [TEST]
                and len(re.findall(r"^test result:", text, re.MULTILINE)) == 1
                and re.search(r"^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 10 filtered out;", text, re.MULTILINE),
                "Commit error test did not complete")
    sdk.require(directory.is_dir() and not directory.is_symlink() and {p.name for p in directory.iterdir()} == set(CASES),
                "Commit error case inventory differs")
    public, cases = {}, {}
    for case in CASES:
        folder = directory / case
        sdk.require(folder.is_dir() and not folder.is_symlink() and {p.name for p in folder.iterdir()} == FILES
                    and all(p.is_file() and not p.is_symlink() for p in folder.iterdir()), "Commit error public inventory differs")
        def read(name, maximum=8192):
            snap = sdk.snapshot(folder / name, maximum=maximum);public[case + "/" + name] = snap.sha256
            return snap.data
        cases[case] = case_readback(read, case)
    sdk.require(len(public) == 4 * len(FILES), "Commit error left exported evidence unchecked")
    return dict(schema_version=1, completed=True, language=language, cases=cases, public_readbacks=public,
                scope=SCOPE, release_claim_eligible=False)


def export(stdout, directory, destination, *, language="C"):
    checked = verify(stdout, directory, language=language);destination.mkdir(mode=0o700, parents=True)
    for name in checked["public_readbacks"]: sdk.copy(directory / name, destination / name)
    sdk.require(verify(stdout, destination, language=language) == checked, "Commit error evidence changed during export")
    return checked


def qualify(outside, output, profile, runtime, binary, run, *, language="C", variant=""):
    sdk.require(profile in ("debug", "release") and ((language in ("C", "Swift") and variant == "")
                or (language == "Kotlin" and variant in ("-serial", "-g1"))), "unqualified Commit error execution profile")
    sdk.require((language == "C" and runtime.get("QPERIAPT_INSTALLED_CLIENT_LANGUAGE") in (None, "C"))
                or runtime.get("QPERIAPT_INSTALLED_CLIENT_LANGUAGE") == language, "Commit error selected another language")
    client = Path(runtime["QPERIAPT_C_OWNER_CLIENT"])
    original = sdk.snapshot(binary, maximum=256 * 1024**2);executable = sdk.snapshot(client, maximum=256 * 1024**2)
    label = "witnessed-commit-error-" + profile + variant
    evidence = outside / (language.lower() + "-" + label + "-runtime")
    selected = dict(runtime, QPERIAPT_WITNESSED_COMMIT_ERROR_EVIDENCE=str(evidence))
    for key in ("QPERIAPT_PUBLIC_SERVICE_EVIDENCE", "QPERIAPT_WITNESSED_RENEWAL_EVIDENCE",
                "QPERIAPT_WITNESSED_POLICY_EXPIRY_EVIDENCE", "QPERIAPT_WITNESSED_CANCELLATION_EVIDENCE"): selected.pop(key, None)
    stdout = run([str(binary), "--exact", TEST, "--nocapture"], label, runtime=selected)
    checked = export(stdout, evidence, output / (language.lower() + "-witnessed-commit-error-public") / (profile + variant), language=language)
    sdk.require(sdk.snapshot(binary, maximum=256 * 1024**2).sha256 == original.sha256
                and sdk.snapshot(client, maximum=256 * 1024**2).sha256 == executable.sha256,
                "Commit error harness or client changed during execution")
    checked.update(binary=dict(sha256=original.sha256, bytes=original.size), foreign_client_sha256=executable.sha256)
    sdk.write_json(output / (language.upper() + "_WITNESSED_COMMIT_ERROR_" + (profile + variant).replace("-", "_").upper() + ".json"), checked)
    return checked
