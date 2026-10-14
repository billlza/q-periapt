"""Public receipts for local joint G/T; native execution verifies signatures and storage."""
from pathlib import Path
import continuity_android_contract as contract
import continuity_android_policy_renewal as policy
import rust_sdk_profile as sdk

TESTS = {profile + "-" + outcome: "android_policy_renewal::joint::" + profile + "_" + outcome
         for profile in ("fixed", "recoverable") for outcome in ("applied", "pending")}


def cases(committed: bool) -> tuple:
    steps = list(policy.cases("local")[:7])
    steps += [("joint-request", "policy-joint-request"), ("joint-request-replayed", "policy-joint-request"),
              ("policy-target-created", "policy-target-create"), ("joint-absent", "policy-joint-status")]
    for label, mode in (("joint-bad-approval", "stage-refused"), ("joint-bad-predecessor", "stage-predecessor"), ("joint-unselected", "unselected")):
        steps += [(label, "policy-joint-" + mode), (label + "-status", "policy-joint-status")]
    steps += [("joint-staged", "policy-joint-stage"), ("joint-stage-replayed", "policy-joint-stage"),
              ("joint-pending-reopened", "policy-joint-status")]
    if committed:
        steps += [("joint-committed", "policy-joint-reconcile"), ("joint-committed-reopened", "policy-joint-status"),
                  ("joint-activated", "policy-joint-activate"), ("joint-activated-reopened", "policy-joint-activate"),
                  ("policy-message-acknowledged", "policy-joint-peer-retry")]
    steps += [("joint-expired-current", "policy-joint-current-expired")]
    for index in range(2):
        steps += [(f"joint-history-{index}", "policy-joint-history" + ("" if committed else "-pending")),
                  (f"joint-history-status-{index}", "policy-joint-status")]
    if committed: steps += [("joint-request-reused", "policy-joint-request-reused"),
                            ("joint-final-request", "policy-joint-next-request")]
    return tuple(steps + [("final.identity", "policy-identity")])


def public(committed: bool) -> tuple:
    outputs = tuple(name for name, _ in cases(committed))
    files = outputs + tuple(name + "." + suffix for name in outputs for suffix in ("stdout", "stderr"))
    files += ("policy-process-count", "policy-effect-before", "joint-expiry-observation", "receiver-policy", "receiver-policy-adopted",
              "receiver-target-created.stdout", "receiver-target-created.stderr")
    if committed: files += ("policy-effect-after", "credential-peer-admit.stdout", "credential-peer-admit.stderr", "inputs/credential-next-operation")
    files += tuple("inputs/" + name for name in ("enrollment-root", "enrollment-intent", "family", "trusted-account",
        "trusted-roster-version", "trusted-roster-digest", "grant-certificate", "grant-roster", "policy-root", "protocol-policy",
        "policy-version", "policy-digest", "credential-operation", "credential-statement", "credential-renewal",
        "joint-approvals", "joint-credential-statement", "renewal-version", "renewal-digest", "renewed-certificate", "renewed-roster",
        "policy-target/protocol-policy", "policy-target/policy-version", "policy-target/policy-digest"))
    return files


def _records(request: bytes) -> tuple:
    sdk.require(len(request) == 33120 and request[204:208] == bytes(4), "joint issuer request width/reserved")
    values = []
    for offset in (336, 8532, 16728, 24924):
        length = int.from_bytes(request[offset:offset + 4], "big")
        sdk.require(0 < length <= 8192 and not any(request[offset + 4 + length:offset + 8196]), "joint issuer record length/tail")
        values.append(request[offset + 4:offset + 4 + length])
    return tuple(values)


def verify_execution(stdout: bytes, directory: Path, profile: str, committed: bool) -> dict:
    label = profile + ("-applied" if committed else "-pending")
    sdk.require(label in TESTS, "joint route")
    contract.verify_single(stdout, TESTS[label])
    base = directory / ("local-" + profile)
    def read(name): return sdk.snapshot(base / name).data
    count = len(cases(committed))
    sdk.require(read("policy-process-count") == count.to_bytes(8, "big"), "joint process census")
    marker = f"qualified joint policy {profile}: {count} foreign processes; committed={str(committed).lower()}, expired original and target, exact historical outcome, original identity and one effect"
    sdk.require(stdout.decode().splitlines().count(marker) == 1, "joint route incomplete")
    for name, mode in cases(committed):
        sdk.require(read(name + ".stdout") == f"{profile}:{mode}:passed\n".encode() and not read(name + ".stderr"), "joint process outcome: " + name)
    identity = read("original.identity"); prepared = read("prepared")
    sdk.require(len(identity) == 64 and any(identity[:32]) and identity == read("final.identity")
        and len(prepared) == 164 and prepared[:4] == (1).to_bytes(4, "big")
        and prepared[4:36] == identity[32:] and not any(prepared[36:])
        and read("original.request") == read("activated.request"), "joint original identity/storage changed")
    request = read("joint-request"); records = _records(request)
    sdk.require(request == read("joint-request-replayed") and request[:32] == read("inputs/credential-operation")
        and request[32:64] == identity[32:] and any(request[64:96])
        and request[96:128] == read("inputs/policy-digest")
        and request[128:168] == read("inputs/policy-version") + read("inputs/policy-digest")
        and not any(request[168:208]) and request[304:336] == read("inputs/trusted-account")
        and records == (read("inputs/grant-certificate"), read("inputs/grant-roster")) * 2, "joint issuer original scope changed")
    cp = read("inputs/trusted-roster-version") + read("inputs/trusted-roster-digest")
    sdk.require(request[208:248] == request[248:288] == cp and request[288:304] == read("inputs/enrollment-intent")[-16:], "joint predecessor changed")
    statement = read("inputs/credential-statement"); grant_statement = read("inputs/joint-credential-statement")
    sdk.require(len(statement) == len(grant_statement) == 32 and any(statement) and statement != grant_statement,
                "joint T confused with credential G statement")
    pending = (1).to_bytes(4, "big") + request[:32] + statement + bytes(48)
    applied = (2).to_bytes(4, "big") + request[:32] + statement + read("inputs/renewal-version") + read("inputs/renewal-digest") + bytes(8)
    sdk.require(read("joint-absent") == bytes(116), "joint original status")
    for name, code in (("joint-bad-approval", 102), ("joint-bad-predecessor", 105), ("joint-unselected", 1)):
        sdk.require(read(name) == code.to_bytes(4, "big") and read(name + "-status") == bytes(116), "joint refusal changed state")
    sdk.require(read("joint-staged") == read("joint-stage-replayed") == read("joint-pending-reopened") == pending, "joint pending identity")
    sdk.require(read("expired-activation") == read("joint-expired-current") == (104).to_bytes(4, "big"), "expired policy accepted")
    times = read("joint-expiry-observation")
    sdk.require(len(times) == 32, "joint expiry observation width")
    p0, at0, p1, at1 = (int.from_bytes(times[i:i + 8], "big") for i in range(0, 32, 8))
    sdk.require(0 < p0 <= at0 < p1 <= at1, "joint expiry order")
    for index in range(2):
        sdk.require(read(f"joint-history-{index}") == (applied if committed else (215).to_bytes(4, "big"))
            and read(f"joint-history-status-{index}") == (applied if committed else pending), "history invented or lost joint commit")
    session = read("policy-connected"); message = read("policy-message-unknown")
    sdk.require(len(session) == 32 and len(message) == 64 and message[:32] == session
        and read("policy-effect-before") == message + b"persisted before process exit", "original message effect missing")
    if committed:
        sdk.require(read("joint-request-reused") == (211).to_bytes(4, "big"), "completed G operation reused")
        sdk.require(read("joint-committed") == read("joint-committed-reopened") == applied
            and read("joint-activated") == read("joint-activated-reopened") == identity
            and read("policy-message-acknowledged") == message and read("policy-effect-after") == read("policy-effect-before")
            and read("credential-peer-admit.stdout") == b"independent-peer-admitted\n" and not read("credential-peer-admit.stderr"), "joint admission or original retry failed")
        current = read("joint-final-request"); values = _records(current)
        sdk.require(current[:32] == read("inputs/credential-next-operation") != request[:32]
            and current[32:128] == request[32:128] and current[128:168] == read("inputs/policy-target/policy-version") + read("inputs/policy-target/policy-digest")
            and current[168:204] == statement + (1).to_bytes(4, "big") and current[208:248] == applied[68:108]
            and current[248:288] == request[248:288] and current[304:336] == request[304:336]
            and values[:2] == records[:2] and values[2:] == (read("inputs/renewed-certificate"), read("inputs/renewed-roster")), "terminal joint issuer snapshot changed")
    return {"foreign_processes": count, "committed": committed, "original_message_retried": committed,
            "historical_reads": 2, "real_policy_expiry": True, "release_claim_eligible": False}


def qualify(binary, consumer, installed, output, profile, runtime, run) -> dict:
    results = {}
    for label, test in TESTS.items():
        trust, outcome = label.split("-", 1); committed = outcome == "applied"
        directory = installed / ("joint-policy-" + label)
        stdout = run([str(binary), "--exact", test, "--nocapture"], profile + "-joint-policy-" + label,
                     consumer, dict(runtime, QPC_ANDROID_CASES=str(directory)))
        results[label] = verify_execution(stdout, directory, trust, committed)
        exported = output / ("android-jni-" + profile + "-joint-policy-" + label)
        for name in public(committed): sdk.copy(directory / ("local-" + trust) / name, exported / ("local-" + trust) / name)
        sdk.require(verify_execution(stdout, exported, trust, committed) == results[label], "joint public export differs")
    return results
