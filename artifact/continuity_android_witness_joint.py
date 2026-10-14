"""Original G/T witness outcomes; public readback is separate from native signature checks."""
from pathlib import Path
import continuity_android_contract as contract
import continuity_android_joint_policy as local
from continuity_c_witness import commit
import rust_sdk_profile as sdk

TESTS = {carrier + "-" + profile + "-" + outcome:
         "android_policy_renewal::joint::witness::" + carrier + "_" + profile + "_" + outcome
         for carrier in ("signed", "tls") for profile in ("fixed", "recoverable")
         for outcome in ("applied", "closed")}


def cases(committed: bool) -> tuple:
    common = list(local.cases(False)); common = common[:next(i for i, (name, _) in enumerate(common) if name == "joint-expired-current")]
    common.insert(1, ("authority-created", "authority-create"))
    at = next(i for i, (name, _) in enumerate(common) if name == "policy-connected")
    common[at:at] = [("policy-peer-unassociated", "policy-peer-unassociated"), ("policy-peer-associated", "authority-peer-associate")]
    at = next(i for i, (name, _) in enumerate(common) if name == "policy-target-created")
    common.insert(at, ("joint-request-local-refused", "policy-joint-request-local-refused"))
    steps = common
    for label, mode in (("joint-local-reconcile-refused", "local-refused"), ("joint-local-history-refused", "history-local-refused")):
        steps += [(label, "policy-joint-witness-" + mode), (label + "-status", "policy-joint-status")]
    if committed:
        steps += [("joint-proposal", "policy-joint-witness-prepare"), ("joint-proposal-replayed", "policy-joint-witness-prepare"),
                  ("joint-proposal-recovered", "policy-joint-witness-recover"), ("joint-commit-unknown", "policy-joint-witness-commit-unknown"),
                  ("joint-unknown-pending", "policy-joint-status"), ("joint-close-loses-to-applied", "policy-joint-witness-close"),
                  ("joint-applied-recovered", "policy-joint-witness-reconcile"), ("joint-commit-replayed", "policy-joint-witness-commit-replay"),
                  ("joint-activated", "policy-joint-activate"), ("joint-activated-reopened", "policy-joint-activate"),
                  ("policy-message-acknowledged", "policy-joint-peer-retry")]
    else:
        steps += [("joint-cancellation", "policy-joint-witness-cancel-prepare"), ("joint-cancellation-replayed", "policy-joint-witness-cancel-prepare"),
                  ("joint-reserved-commit-refused", "policy-joint-witness-reserved-commit-refused"),
                  ("joint-reserved-activate-refused", "policy-joint-witness-reserved-activate-refused"), ("joint-reserved-pending", "policy-joint-status")]
    steps += [("joint-expired-current", "policy-joint-current-expired"), ("joint-expired-close", "policy-joint-witness-close")]
    for i in range(2): steps += [(f"joint-history-{i}", "policy-joint-witness-reconcile"), (f"joint-history-status-{i}", "policy-joint-status")]
    if committed: steps += [("joint-expired-commit-replayed", "policy-joint-witness-commit-replay")]
    return tuple(steps + [("joint-request-reused", "policy-joint-request-reused"), ("joint-final-request", "policy-joint-next-request"), ("final.identity", "policy-identity")])


def public(carrier: str, committed: bool) -> tuple:
    sdk.require(carrier in ("signed", "tls"), "witness carrier")
    outputs = tuple(name for name, _ in cases(committed))
    files = outputs + tuple(name + "." + suffix for name in outputs for suffix in ("stdout", "stderr"))
    files += tuple(name for name in local.public(False) if name.startswith("inputs/"))
    files += ("policy-process-count", "policy-effect-before", "joint-expiry-observation", "receiver-policy", "receiver-policy-adopted",
              "receiver-target-created.stdout", "receiver-target-created.stderr", "joint-expired-history-transcript")
    files += tuple("inputs/" + name for name in ("credential-next-operation", "witness-carrier", "witness-id", "witness-public", "witness-subject",
        "authority-id", "authority-application", "authority-checkpoint", "authority-peer-application", "peer/responder-account"))
    if carrier == "tls": files += ("inputs/witness-tls-cert", "inputs/witness-tls-peer", "inputs/witness-tls-name")
    if committed: files += ("policy-effect-after", "credential-peer-admit.stdout", "credential-peer-admit.stderr",
                           "joint-lost-commit-request", "joint-lost-commit-reply", "joint-explicit-close-transcript", "joint-commit-recovery-transcript")
    sdk.require(len(files) == len(set(files)), "duplicate joint witness public member")
    return files


def transcript(value: bytes, *, cached_terminal: bool = False) -> None:
    sdk.require((cached_terminal or len(value) > 0) and len(value) <= 128 * 7334 and len(value) % 7334 == 0, "joint history transcript width")
    sdk.require(all(value[i] == 1 and value[i + 205] not in (5, 7) for i in range(0, len(value), 7334)), "history sent new Commit/Close")


def verify_execution(stdout: bytes, directory: Path, carrier: str, profile: str, committed: bool) -> dict:
    label = carrier + "-" + profile + ("-applied" if committed else "-closed")
    sdk.require(label in TESTS, "joint witness route"); contract.verify_single(stdout, TESTS[label])
    base = directory / (carrier + "-" + profile)
    def read(name): return sdk.snapshot(base / name).data
    count = len(cases(committed))
    sdk.require(read("policy-process-count") == count.to_bytes(8, "big"), "joint witness process census")
    marker = f"qualified witnessed joint policy {carrier}/{profile}: {count} foreign processes; committed={str(committed).lower()}, expired original and target, exact historical outcome, original identity"
    sdk.require(stdout.decode().splitlines().count(marker) == 1, "joint witness route incomplete")
    for name, mode in cases(committed):
        sdk.require(read(name + ".stdout") == f"{profile}:{mode}:passed\n".encode() and not read(name + ".stderr"), "joint witness process failed: " + name)
    identity = read("original.identity"); prepared = read("prepared")
    sdk.require(len(identity) == 64 and any(identity[:32]) and identity == read("final.identity")
        and len(prepared) == 164 and prepared[:4] == (2).to_bytes(4, "big") and prepared[4:36] == identity[32:]
        and prepared[36:132] == read("inputs/witness-subject") and any(prepared[132:])
        and read("original.request") == read("activated.request") and read("inputs/witness-carrier") == carrier.encode(), "original witness enrollment changed")
    authority = read("authority-created")
    sdk.require(len(authority) == 72 and authority == read("inputs/authority-checkpoint")
        and authority[:32] == read("inputs/authority-application") and authority[32:40] == (1).to_bytes(8, "big")
        and authority[40:] == read("inputs/trusted-account") and read("policy-peer-unassociated") == (201).to_bytes(4, "big")
        and read("policy-peer-associated") == read("inputs/authority-peer-application") + (1).to_bytes(8, "big") + read("inputs/peer/responder-account"), "managed association changed")
    request = read("joint-request"); records = local._records(request)
    cp = read("inputs/trusted-roster-version") + read("inputs/trusted-roster-digest")
    sdk.require(request == read("joint-request-replayed") and request[:32] == read("inputs/credential-operation")
        and request[32:64] == identity[32:] and any(request[64:96]) and request[96:128] == read("inputs/policy-digest")
        and request[128:168] == read("inputs/policy-version") + read("inputs/policy-digest") and not any(request[168:208])
        and request[208:248] == request[248:288] == cp and request[288:304] == read("inputs/enrollment-intent")[-16:]
        and request[304:336] == read("inputs/trusted-account") and records == (read("inputs/grant-certificate"), read("inputs/grant-roster")) * 2, "joint issuer predecessor changed")
    statement = read("inputs/credential-statement"); grant = read("inputs/joint-credential-statement")
    sdk.require(len(statement) == len(grant) == 32 and any(statement) and statement != grant, "joint T/G domain confused")
    pending = (1).to_bytes(4, "big") + request[:32] + statement + bytes(48)
    applied = (2).to_bytes(4, "big") + request[:32] + statement + read("inputs/renewal-version") + read("inputs/renewal-digest") + bytes(8)
    terminal = applied if committed else (4).to_bytes(4, "big") + applied[4:]
    sdk.require(read("joint-absent") == bytes(116), "joint initial status")
    for name, code in (("joint-bad-approval", 102), ("joint-bad-predecessor", 105), ("joint-unselected", 1)):
        sdk.require(read(name) == code.to_bytes(4, "big") and read(name + "-status") == bytes(116), "joint refusal changed state")
    sdk.require(read("joint-staged") == read("joint-stage-replayed") == read("joint-pending-reopened") == pending, "joint staged identity")
    sdk.require(read("joint-request-local-refused") == (216).to_bytes(4, "big"), "issuer request downgraded witness")
    for name in ("joint-local-reconcile-refused", "joint-local-history-refused"):
        sdk.require(read(name) == (216).to_bytes(4, "big") and read(name + "-status") == pending, "joint history downgraded witness")
    coordination = read("joint-proposal" if committed else "joint-cancellation"); base_length = 296 if committed else 248
    sdk.require(len(coordination) == base_length + 33 and coordination[:8] == (b"QPCRNP02" if committed else b"QPCRNC02")
        and coordination[8:40] == commit(b"Q-PERIAPT-CONTINUITY-ANCHOR-AUTHORITY/v1", read("inputs/witness-id") + read("inputs/witness-public"))
        and coordination[40:136] == prepared[36:132] and coordination[136:200] == request[:32] + grant
        and coordination[base_length:] == b"\1" + statement, "joint coordination grammar or identity")
    sdk.require(read("joint-proposal-replayed" if committed else "joint-cancellation-replayed") == coordination, "coordination replay changed")
    if committed:
        sdk.require(read("joint-proposal-recovered") == coordination and read("joint-commit-unknown") == (218).to_bytes(4, "big")
            and read("joint-unknown-pending") == pending, "lost Commit outcome invented")
        lost, reply = read("joint-lost-commit-request"), read("joint-lost-commit-reply")
        sdk.require(len(lost) == 3674 and lost[204] == 5 and len(reply) == 3659 and reply[204] == 8, "missing actual lost Commit/Applied exchange")
        for name in ("joint-close-loses-to-applied", "joint-applied-recovered", "joint-commit-replayed", "joint-expired-commit-replayed"):
            sdk.require(read(name) == applied, "Close or replay changed Applied")
        sdk.require(read("joint-activated") == read("joint-activated-reopened") == identity, "joint activation changed owner")
        closing = read("joint-explicit-close-transcript")
        sdk.require(0 < len(closing) <= 128 * 7334 and len(closing) % 7334 == 0, "explicit Close trace width")
        operations = [closing[i + 205] for i in range(0, len(closing), 7334)]
        sdk.require(operations.count(7) == 1 and 5 not in operations
            and all(closing[i] == 1 for i in range(0, len(closing), 7334)), "explicit Close retried Commit or did not dispatch Close")
        transcript(read("joint-commit-recovery-transcript"), cached_terminal=True)
    else:
        sdk.require(read("joint-reserved-commit-refused") == read("joint-reserved-activate-refused") == (215).to_bytes(4, "big")
            and read("joint-reserved-pending") == pending, "cancellation reservation authorized use")
    sdk.require(read("joint-expired-close") == terminal, "expired terminal outcome")
    for i in range(2): sdk.require(read(f"joint-history-{i}") == read(f"joint-history-status-{i}") == terminal, "history lost terminal identity")
    transcript(read("joint-expired-history-transcript"), cached_terminal=committed)
    times = read("joint-expiry-observation"); sdk.require(len(times) == 32, "expiry width")
    p0, at0, p1, at1 = (int.from_bytes(times[i:i + 8], "big") for i in range(0, 32, 8))
    sdk.require(0 < p0 <= at0 < p1 <= at1 and read("expired-activation") == read("joint-expired-current") == (104).to_bytes(4, "big"), "expiry/current admission")
    current = read("joint-final-request"); values = local._records(current)
    sdk.require(read("joint-request-reused") == (211).to_bytes(4, "big") and current[:32] == read("inputs/credential-next-operation") != request[:32]
        and current[32:128] == request[32:128] and current[248:288] == request[248:288] and current[304:336] == request[304:336]
        and values[:2] == records[:2], "next request lost original identity")
    if committed:
        sdk.require(current[128:168] == read("inputs/policy-target/policy-version") + read("inputs/policy-target/policy-digest")
            and current[168:204] == statement + (1).to_bytes(4, "big") and current[208:248] == applied[68:108]
            and values[2:] == (read("inputs/renewed-certificate"), read("inputs/renewed-roster")), "Applied predecessor not retained")
    else:
        sdk.require(current[32:] == request[32:], "Closed adopted uncommitted G/T")
    session, message = read("policy-connected"), read("policy-message-unknown")
    sdk.require(len(session) == 32 and len(message) == 64 and message[:32] == session
        and read("policy-effect-before") == message + b"persisted before process exit", "original message identity")
    if committed:
        sdk.require(read("policy-message-acknowledged") == message and read("policy-effect-after") == read("policy-effect-before")
            and read("credential-peer-admit.stdout") == b"independent-peer-admitted\n" and not read("credential-peer-admit.stderr"), "original retry failed or duplicated effect")
    return {"foreign_processes": count, "terminal": "applied" if committed else "closed", "original_message_retried": committed,
            "historical_reads": 2, "history_sends_no_commit_or_close": True, "release_claim_eligible": False}


def qualify(binary, consumer, installed, output, profile, runtime, run) -> dict:
    results = {}
    for label, test in TESTS.items():
        carrier, trust, outcome = label.split("-"); committed = outcome == "applied"
        directory = installed / ("witness-joint-" + label)
        stdout = run([str(binary), "--exact", test, "--nocapture"], profile + "-witness-joint-" + label,
                     consumer, dict(runtime, QPC_ANDROID_CASES=str(directory)))
        results[label] = verify_execution(stdout, directory, carrier, trust, committed)
        exported = output / ("android-jni-" + profile + "-witness-joint-" + label)
        for name in public(carrier, committed): sdk.copy(directory / (carrier + "-" + trust) / name, exported / (carrier + "-" + trust) / name)
        sdk.require(verify_execution(stdout, exported, carrier, trust, committed) == results[label], "joint witness public export differs")
    return results
