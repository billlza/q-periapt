"""Two applied G/T generations over the original foreign owner and message."""
from pathlib import Path
import continuity_android_contract as contract
import continuity_android_joint_policy as local
import continuity_android_witness_joint as witness
from continuity_c_witness import commit
import rust_sdk_profile as sdk

TESTS = {carrier + "-" + trust: "android_policy_renewal::joint::cycle::" + carrier + "_" + trust
         for carrier in ("local", "signed", "tls") for trust in ("fixed", "recoverable")}


def cases(carrier: str) -> tuple:
    original = list(local.cases(True) if carrier == "local" else witness.cases(True))
    original = [(name, mode) for name, mode in original if name not in ("policy-message-acknowledged", "final.identity")]
    second = [("joint-request", "policy-joint-request"), ("joint-request-replayed", "policy-joint-request")]
    if carrier != "local": second.append(("joint-request-local-refused", "policy-joint-request-local-refused"))
    second += [("policy-target-created", "policy-target-create"), ("joint-before-stage", "policy-joint-status")]
    for label, mode in (("joint-bad-approval", "refused"), ("joint-missing-predecessor", "missing"), ("joint-bad-predecessor", "predecessor")):
        second += [(label, "policy-joint-stage-next-" + mode), (label + "-status", "policy-joint-status")]
    second += [("joint-staged", "policy-joint-stage-next"), ("joint-stage-replayed", "policy-joint-stage-next"),
               ("joint-pending-reopened", "policy-joint-status")]
    if carrier == "local":
        second += [("joint-committed", "policy-joint-reconcile"), ("joint-committed-reopened", "policy-joint-status")]
    else:
        steps = list(witness.cases(True))
        first = next(i for i, (name, _) in enumerate(steps) if name == "joint-proposal")
        last = next(i for i, (name, _) in enumerate(steps) if name == "joint-activated")
        second += steps[first:last]
    second += [("joint-activated", "policy-joint-activate"), ("joint-activated-reopened", "policy-joint-activate"),
               ("policy-message-acknowledged", "policy-joint-peer-retry"), ("joint-expired-current", "policy-joint-current-expired")]
    for i in range(2):
        second += [(f"joint-history-{i}", "policy-joint-history" if carrier == "local" else "policy-joint-witness-reconcile"),
                   (f"joint-history-status-{i}", "policy-joint-status")]
    second += [("joint-request-reused", "policy-joint-request-reused"), ("joint-final-request", "policy-joint-next-request")]
    return tuple(original + [("cycle-" + name, mode) for name, mode in second] + [("final.identity", "policy-identity")])


def public(carrier: str) -> tuple:
    previous = local.public(True) if carrier == "local" else witness.public(carrier, True)
    omitted = {"policy-message-acknowledged", "policy-message-acknowledged.stdout", "policy-message-acknowledged.stderr", "policy-effect-after"}
    files = [name for name in previous if name not in omitted]
    second = [name for name, _ in cases(carrier) if name.startswith("cycle-")]
    files += second + [name + "." + suffix for name in second for suffix in ("stdout", "stderr")]
    files += ["cycle-expiry-observation", "cycle-policy-effect-after", "cycle-credential-peer-admit.stdout", "cycle-credential-peer-admit.stderr"]
    files += ["cycle-inputs/" + name.removeprefix("inputs/") for name in previous if name.startswith("inputs/")]
    files += ["cycle-inputs/previous-policy-authorization"]
    files += [prefix + "policy-target/" + name for prefix in ("inputs/", "cycle-inputs/") for name in ("family", "policy-root")]
    files += ["cycle-inputs/policy-previous/" + name for name in ("family", "policy-root", "policy-version", "policy-digest", "protocol-policy")]
    if carrier != "local":
        files += ["cycle-" + name for name in ("joint-lost-commit-request", "joint-lost-commit-reply",
                  "joint-explicit-close-transcript", "joint-commit-recovery-transcript", "joint-expired-history-transcript")]
    sdk.require(len(files) == len(set(files)), "duplicate cycle public member")
    return tuple(files)


def _coordination(read, prefix, inputs, request, statement, pending, applied, subject) -> None:
    proposal = read(prefix + "joint-proposal")
    authority = commit(b"Q-PERIAPT-CONTINUITY-ANCHOR-AUTHORITY/v1", read(inputs + "witness-id") + read(inputs + "witness-public"))
    sdk.require(len(proposal) == 329 and proposal[:8] == b"QPCRNP02" and proposal[8:40] == authority
        and proposal[40:136] == subject and proposal[136:200] == request[:32] + read(inputs + "joint-credential-statement")
        and proposal[296:] == b"\1" + statement, "cycle witness proposal binding")
    sdk.require(read(prefix + "joint-proposal-replayed") == read(prefix + "joint-proposal-recovered") == proposal
        and read(prefix + "joint-commit-unknown") == (218).to_bytes(4, "big")
        and read(prefix + "joint-unknown-pending") == pending, "cycle unknown commit")
    lost, reply = read(prefix + "joint-lost-commit-request"), read(prefix + "joint-lost-commit-reply")
    sdk.require(len(lost) == 3674 and lost[204] == 5 and len(reply) == 3659 and reply[204] == 8, "cycle lost Commit exchange")
    for name in ("joint-close-loses-to-applied", "joint-applied-recovered", "joint-commit-replayed"):
        sdk.require(read(prefix + name) == applied, "cycle witness terminal identity")
    closing = read(prefix + "joint-explicit-close-transcript")
    sdk.require(0 < len(closing) <= 128 * 7334 and len(closing) % 7334 == 0, "cycle explicit Close width")
    operations = [closing[i + 205] for i in range(0, len(closing), 7334)]
    sdk.require(operations.count(7) == 1 and 5 not in operations and all(closing[i] == 1 for i in range(0, len(closing), 7334)),
                "cycle explicit Close changed Commit")
    for name in ("joint-commit-recovery-transcript", "joint-expired-history-transcript"):
        witness.transcript(read(prefix + name), cached_terminal=True)


def verify_execution(stdout: bytes, directory: Path, carrier: str, trust: str, *, batch: bool = False) -> dict:
    label = carrier + "-" + trust
    sdk.require(label in TESTS, "cycle route")
    if batch: contract.verify_batch(stdout, frozenset(TESTS.values()))
    else: contract.verify_single(stdout, TESTS[label])
    base = directory / label
    def read(name): return sdk.snapshot(base / name).data
    steps = cases(carrier)
    marker = f"qualified joint policy cycle {carrier}/{trust}: {len(steps)} foreign processes; two applied G/T generations, three real policy expiries, original identity session message and one effect"
    sdk.require(stdout.decode().splitlines().count(marker) == 1
        and read("policy-process-count") == len(steps).to_bytes(8, "big"), "cycle execution census")
    for name, mode in steps:
        sdk.require(read(name + ".stdout") == f"{trust}:{mode}:passed\n".encode() and not read(name + ".stderr"), "cycle process outcome: " + name)
    identity, prepared = read("original.identity"), read("prepared")
    sdk.require(len(identity) == 64 and any(identity[:32]) and identity == read("final.identity")
        and len(prepared) == 164 and prepared[4:36] == identity[32:]
        and prepared[:4] == (1 if carrier == "local" else 2).to_bytes(4, "big")
        and read("original.request") == read("activated.request"), "cycle original owner changed")
    original = read("joint-request"); original_records = local._records(original)
    original_cp = read("inputs/policy-version") + read("inputs/policy-digest")
    roster = read("inputs/trusted-roster-version") + read("inputs/trusted-roster-digest")
    sdk.require(original[32:64] == identity[32:] and original[96:128] == read("inputs/policy-digest")
        and original[128:168] == original_cp and not any(original[168:208])
        and original[208:248] == original[248:288] == roster
        and original_records == (read("inputs/grant-certificate"), read("inputs/grant-roster")) * 2,
        "cycle original issuer scope")
    prior = bytes(116)
    for prefix, inputs in (("", "inputs/"), ("cycle-", "cycle-inputs/")):
        request = read(prefix + "joint-request"); records = local._records(request)
        statement = read(inputs + "credential-statement")
        sdk.require(request == read(prefix + "joint-request-replayed") and request[:32] == read(inputs + "credential-operation")
            and request[32:128] == original[32:128] and request[248:288] == original[248:288]
            and request[304:336] == original[304:336] and records[:2] == original_records[:2], "cycle issuer original binding")
        sdk.require(len(statement) == 32 and any(statement) and statement != read(inputs + "joint-credential-statement"), "cycle G/T domain")
        pending = (1).to_bytes(4, "big") + request[:32] + statement + bytes(48)
        applied = (2).to_bytes(4, "big") + request[:32] + statement + read(inputs + "renewal-version") + read(inputs + "renewal-digest") + bytes(8)
        sdk.require(read(prefix + ("joint-before-stage" if prefix else "joint-absent")) == prior, "cycle prior terminal lost")
        refusals = (("joint-bad-approval", 102), ("joint-bad-predecessor", 103 if prefix else 105),
                    ("joint-missing-predecessor", 105) if prefix else ("joint-unselected", 1))
        for name, code in refusals:
            sdk.require(read(prefix + name) == code.to_bytes(4, "big") and read(prefix + name + "-status") == prior, "cycle refusal changed state")
        sdk.require(read(prefix + "joint-staged") == read(prefix + "joint-stage-replayed") == read(prefix + "joint-pending-reopened") == pending,
                    "cycle staged intent changed")
        sdk.require(read(prefix + "joint-activated") == read(prefix + "joint-activated-reopened") == identity, "cycle activation changed owner")
        for i in range(2):
            sdk.require(read(prefix + f"joint-history-{i}") == read(prefix + f"joint-history-status-{i}") == applied, "cycle terminal history changed")
        if carrier != "local":
            sdk.require(read(prefix + "joint-request-local-refused") == (216).to_bytes(4, "big"), "cycle witness downgrade")
            _coordination(read, prefix, inputs, request, statement, pending, applied, prepared[36:132])
        else:
            sdk.require(read(prefix + "joint-committed") == read(prefix + "joint-committed-reopened") == applied, "cycle local commit")
        current = read(prefix + "joint-final-request"); values = local._records(current)
        sdk.require(read(prefix + "joint-request-reused") == (211).to_bytes(4, "big")
            and current[:32] == read(inputs + "credential-next-operation") != request[:32]
            and current[32:128] == original[32:128] and current[248:288] == original[248:288]
            and current[304:336] == original[304:336] and values[:2] == original_records[:2]
            and current[128:168] == read(inputs + "policy-target/policy-version") + read(inputs + "policy-target/policy-digest")
            and current[168:204] == statement + (1).to_bytes(4, "big") and current[208:248] == applied[68:108]
            and values[2:] == (read(inputs + "renewed-certificate"), read(inputs + "renewed-roster")), "cycle next predecessor")
        if not prefix: sdk.require(current == read("cycle-joint-request"), "G2 request differs from actual G1 continuation")
        prior = applied
    sdk.require(read("cycle-inputs/previous-policy-authorization") == read("inputs/credential-statement"), "cycle previous T substituted")
    for name in ("family", "policy-root", "policy-version", "policy-digest", "protocol-policy"):
        sdk.require(read("cycle-inputs/policy-previous/" + name) == read("inputs/policy-target/" + name), "cycle previous policy substituted")
    times, second = read("joint-expiry-observation"), read("cycle-expiry-observation")
    sdk.require(len(times) == 32 and len(second) == 16, "cycle expiry widths")
    p0, at0, p1, at1, p2, at2 = (int.from_bytes((times + second)[i:i+8], "big") for i in range(0, 48, 8))
    sdk.require(0 < p0 <= at0 < p1 <= at1 < p2 <= at2
        and all(read(name) == (104).to_bytes(4, "big") for name in ("expired-activation", "joint-expired-current", "cycle-joint-expired-current")),
        "cycle current use before real expiry")
    message = read("policy-message-unknown")
    sdk.require(len(message) == 64 and message[:32] == read("policy-connected")
        and read("cycle-policy-message-acknowledged") == message
        and read("policy-effect-before") == read("cycle-policy-effect-after") == message + b"persisted before process exit"
        and not (base / "policy-message-acknowledged").exists(), "original message was not retained through both generations")
    for prefix in ("", "cycle-"):
        sdk.require(read(prefix + "credential-peer-admit.stdout") == b"independent-peer-admitted\n"
                    and not read(prefix + "credential-peer-admit.stderr"), "cycle peer credential admission")
    return {"generations":2, "foreign_processes":len(steps), "real_expiries":3,
            "original_identity_and_message_preserved":True, "release_claim_eligible":False}


def qualify(binary, consumer, installed, output, profile, runtime, run) -> dict:
    directory = installed / "joint-cycle-cases"; directory.mkdir(mode=0o700)
    stdout = run([str(binary), "android_policy_renewal::joint::cycle::", "--test-threads=6", "--show-output"],
                 profile + "-joint-cycle", consumer, dict(runtime, QPC_ANDROID_CASES=str(directory)))
    results = {}
    identities = set()
    for label in TESTS:
        carrier, trust = label.split("-"); case = directory / label
        results[label] = verify_execution(stdout, case, carrier, trust, batch=True)
        identities.add(sdk.snapshot(case / label / "original.identity").data)
        exported = output / ("android-jni-" + profile + "-joint-cycle-" + label)
        for name in public(carrier): sdk.copy(case / label / name, exported / label / name)
        sdk.require(verify_execution(stdout, exported, carrier, trust, batch=True) == results[label], "cycle public export differs")
    sdk.require(len(identities) == len(TESTS), "cycle routes reused an original owner")
    return results
