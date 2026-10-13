"""Public linkage for actual G issuance after P; native execution verifies signatures."""
from pathlib import Path
import continuity_android_contract as contract
import continuity_android_policy_renewal as policy
import rust_sdk_profile as sdk

TESTS = {carrier + "-" + profile: "android_policy_renewal::credential_" + carrier + "_" + profile
         for carrier in ("local", "signed", "tls") for profile in ("fixed", "recoverable")}


def cases(carrier: str) -> tuple:
    sdk.require(carrier in ("local", "signed", "tls"), "credential carrier")
    result = [("credential-request", "request"), ("credential-request-replayed", "request")]
    if carrier != "local": result += [("credential-request-no-downgrade", "request-local-refused")]
    result += [("credential-absent", "status"), ("credential-refused", "stage-refused"),
               ("credential-after-refusal", "status"), ("credential-staged", "stage"), ("credential-stage-replayed", "stage")]
    result += ([("credential-local-activated", "local"), ("credential-committed", "status"),
                ("credential-local-activated-replayed", "local"), ("credential-commit-replayed", "status"), ("credential-historical", "status")]
               if carrier == "local" else [("credential-proposal", "prepare"), ("credential-proposal-replayed", "prepare"),
                ("credential-unknown", "commit-unknown"), ("credential-recovered", "reconcile"),
                ("credential-commit-replayed", "commit"), ("credential-close-applied", "close")])
    return tuple((name, "policy-credential-" + mode) for name, mode in result) + (
        ("credential-active-identity", "policy-activate-renewed"), ("credential-terminal", "policy-credential-status"),
        ("credential-next-request", "policy-credential-next-request"))


def public(carrier: str) -> tuple:
    steps = cases(carrier)
    names = policy.public(carrier) + tuple(name for name, _ in steps)
    names += tuple(name + "." + suffix for name, _ in steps for suffix in ("stdout", "stderr"))
    names += ("credential-peer-admit.stdout", "credential-peer-admit.stderr")
    names += tuple("inputs/" + name for name in ("credential-operation", "credential-next-operation", "credential-statement",
        "credential-renewal", "renewed-certificate", "renewed-roster", "renewal-version", "renewal-digest"))
    if carrier != "local": names += ("credential-lost-commit-request", "credential-lost-commit-reply", "credential-historical-transcript")
    return names


def _request(data: bytes) -> tuple[bytes, ...]:
    sdk.require(len(data) == 33120 and data[200:208] == b"\0\0\0\1\0\0\0\0" and any(data[168:200]),
                "G request lacks canonical retained P authorization")
    values = []
    for offset in (336, 8532, 16728, 24924):
        length = int.from_bytes(data[offset:offset + 4], "big")
        sdk.require(0 < length <= 8192 and not any(data[offset + 4 + length:offset + 8196]), "G public record length/tail")
        values.append(data[offset + 4:offset + 4 + length])
    return tuple(values)


def verify_execution(stdout: bytes, directory: Path, profile: str, carrier: str) -> dict:
    label = carrier + "-" + profile
    sdk.require(label in TESTS, "credential policy route")
    contract.verify_single(stdout, TESTS[label])
    result = policy.verify_route(directory, profile, carrier, with_credential=True)
    marker = f"qualified policy renewal {carrier}/{profile}: {result['foreign_processes']} foreign processes; expired P0, independent P2, original identity session message and one effect"
    sdk.require(stdout.decode().splitlines().count(marker) == 1, "P then G route incomplete")
    base = directory / label
    def read(name): return sdk.snapshot(base / name).data
    for name, mode in cases(carrier):
        sdk.require(read(name + ".stdout") == f"{profile}:{mode}:passed\n".encode() and not read(name + ".stderr"), "G process outcome: " + name)
    identity = read("original.identity"); original_request = read("inputs/renewal-request")
    request = read("credential-request"); records = _request(request)
    target = read("inputs/policy-target/policy-version") + read("inputs/policy-target/policy-digest")
    sdk.require(read("credential-request-replayed") == request and request[:32] == read("inputs/credential-operation")
        and request[32:64] == identity[32:] and request[64:96] == original_request[64:96]
        and request[96:128] == read("inputs/policy-digest") and request[128:168] == target
        and request[168:200] == read("inputs/renewal-statement") and request[304:336] == read("inputs/trusted-account"), "G issuer scope changed")
    original_cp = read("inputs/trusted-roster-version") + read("inputs/trusted-roster-digest")
    sdk.require(request[208:248] == request[248:288] == original_cp
        and request[288:304] == read("inputs/enrollment-intent")[-16:]
        and records == (read("inputs/grant-certificate"), read("inputs/grant-roster")) * 2, "G issuer predecessor substituted")
    operation = request[:32]; statement = read("inputs/credential-statement")
    sdk.require(len(statement) == 32 and any(statement), "G statement absent")
    pending = (1).to_bytes(4, "big") + operation + statement + bytes(48)
    committed = (2).to_bytes(4, "big") + operation + statement + read("inputs/renewal-version") + read("inputs/renewal-digest") + bytes(8)
    sdk.require(read("credential-absent") == read("credential-after-refusal") == bytes(116)
        and read("credential-refused") == (102).to_bytes(4, "big")
        and read("credential-staged") == read("credential-stage-replayed") == pending
        and read("credential-terminal") == read("credential-commit-replayed") == committed
        and read("credential-active-identity") == identity, "G status or original owner changed")
    next_request = read("credential-next-request"); next_records = _request(next_request)
    sdk.require(next_request[:32] == read("inputs/credential-next-operation") != operation
        and next_request[32:208] == request[32:208] and next_request[248:288] == request[248:288]
        and next_request[304:336] == request[304:336]
        and next_request[208:248] == committed[68:108] and next_records[:2] == records[:2]
        and next_records[2:] == (read("inputs/renewed-certificate"), read("inputs/renewed-roster")), "next G lost original or current predecessor")
    if carrier == "local":
        sdk.require(read("credential-committed") == read("credential-historical") == committed, "local G terminal recovery")
        sdk.require(read("credential-local-activated") == read("credential-local-activated-replayed") == identity, "local consuming activation changed original identity")
    else:
        proposal = read("credential-proposal")
        sdk.require(len(proposal) == 329 and proposal[:8] == b"QPCRNP03" and proposal[297:329] == request[168:200]
            and proposal[296] == 0 and proposal[136:200] == operation + statement
            and read("credential-proposal-replayed") == proposal, "G confused retained P with T adoption")
        sdk.require(read("credential-request-no-downgrade") == (216).to_bytes(4, "big")
            and read("credential-unknown") == (218).to_bytes(4, "big")
            and read("credential-recovered") == read("credential-close-applied") == committed, "required witness G outcome")
        request, reply = read("credential-lost-commit-request"), read("credential-lost-commit-reply")
        sdk.require(len(request) == 3674 and request[204] == 5 and len(reply) == 3659 and reply[204] == 8, "lost G Commit/Applied exchange")
        trace = read("credential-historical-transcript")
        sdk.require(0 < len(trace) <= 128 * 7334 and len(trace) % 7334 == 0, "G history transcript bound")
        sdk.require(all(trace[i] == 1 and trace[i + 205] not in (5, 7) for i in range(0, len(trace), 7334)), "history dispatched new G Commit/Close")
    sdk.require(read("credential-peer-admit.stdout") == b"independent-peer-admitted\n" and not read("credential-peer-admit.stderr"), "counterparty did not admit G")
    return dict(result, credential_renewed=True, issuer_request_from_public_owner=True, next_issuer_predecessor_advanced=True)


def qualify(binary, consumer, installed, output, profile, runtime, run) -> dict:
    results = {}
    for label, test in TESTS.items():
        carrier, trust = label.split("-", 1)
        directory = installed / ("policy-credential-" + label)
        stdout = run([str(binary), "--exact", test, "--nocapture"], profile + "-policy-credential-" + label,
                     consumer, dict(runtime, QPC_ANDROID_CASES=str(directory)))
        results[label] = verify_execution(stdout, directory, trust, carrier)
        exported = output / ("android-jni-" + profile + "-policy-credential-" + label)
        for name in public(carrier): sdk.copy(directory / label / name, exported / label / name)
        sdk.require(verify_execution(stdout, exported, trust, carrier) == results[label], "P then G public export differs")
    return results
