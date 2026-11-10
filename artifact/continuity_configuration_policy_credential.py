"""Public P/G linkage for C and Swift; signatures are checked by native execution."""
from pathlib import Path
import hashlib
import re
import sys
import tempfile
import continuity_first_account as account
import continuity_first_configuration as first
import continuity_configuration_policy as policy
import rust_sdk_profile as sdk
from evidence_io import parse_strict_json_bytes

TESTS = {carrier + "-" + profile: "managed_policy_credential_" + carrier + "_" + profile
         for carrier in ("signed", "tls") for profile in ("fixed", "recoverable")}
COMMANDS = ("credential-request", "credential-request-replayed", "credential-next-request", "credential-original-identity",
    "credential-absent", "credential-refused", "credential-after-refusal", "credential-staged", "credential-stage-replayed",
    "credential-proposal", "credential-proposal-replayed", "credential-unknown", "credential-recovered", "credential-commit-replayed",
    "credential-close-applied", "credential-renewed-identity")
INPUTS = ("credential-operation", "credential-next-operation", "credential-statement", "credential-renewal", "renewal-version", "renewal-digest",
    "renewal-statement", "renewed-certificate", "renewed-roster", "grant-certificate", "grant-roster")
RECORDS = ("credential-lost-commit-request", "credential-lost-commit-reply", "credential-historical-transcript", "credential-peer.stdout", "credential-peer.stderr")


def _request(data: bytes, byteorder: str) -> tuple:
    sdk.require(len(data) == 33120 and data[200:208] == (1).to_bytes(4, byteorder) + bytes(4) and any(data[168:200]), "retained P request shape")
    records = []
    for start in (336, 8532, 16728, 24924):
        length = int.from_bytes(data[start:start + 4], byteorder)
        sdk.require(0 < length <= 8192 and not any(data[start + 4 + length:start + 8196]), "issuer record length/tail")
        records.append(data[start + 4:start + 4 + length])
    return tuple(records)


def verify_execution(stdout: bytes, evidence: Path, *, language: str, carrier: str, profile: str, byteorder: str = sys.byteorder) -> dict:
    label = carrier + "-" + profile
    sdk.require(language in ("C", "Swift", "Kotlin") and label in TESTS and byteorder in ("little", "big"), "P/G qualification scope")
    text = stdout.decode()
    sdk.require(re.findall(r"^test (\S+) \.\.\. ok$", text, re.M) == [TESTS[label]]
        and len(re.findall(r"^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 10 filtered out;", text, re.M)) == 1, "P/G native execution incomplete")
    renewal = (f"INDEPENDENT_CONFIGURATION_POLICY_CREDENTIAL_RENEWAL_PASS language={language} carrier={carrier} profile={profile} "
               "original_session=true original_message=true uncertain_before_update=true acknowledged=true effects=1")
    managed = (f"MANAGED_POLICY_CREDENTIAL_CONFIGURATION_PASS language={language} carrier={carrier} profile={profile} "
               "request_before_association=true original_registry=true missing_registry=211 release_qualified=false")
    expected = {renewal, managed, first.connection_marker(language, carrier, profile), policy.expiry_marker(language, carrier, profile)}
    markers = re.findall(r"^(?:INDEPENDENT_|MANAGED_).*$", text, re.M)
    sdk.require(len(markers) == 4 and set(markers) == expected and text.index(policy.expiry_marker(language, carrier, profile)) < text.index(renewal), "P/G phase order or markers")
    sdk.require({p.name for p in evidence.iterdir()} == {label}, "P/G scenario set")
    folder = evidence / label
    commands = dict(account.COMMANDS)
    lifetime = {"registry-closed": "REGISTRY_CLOSED", "registry-released": "REGISTRY_RELEASED"} if language in ("Swift", "Kotlin") else {}
    commands.update(lifetime)
    names = ({"registry-gc.bin"} if language == "Kotlin" else set()) | account.BASE | {n + ".bin" for n in lifetime} | {n + "." + ext for n in commands for ext in ("stdout", "stderr")} | policy.names(carrier) | policy.EXPIRY
    sdk.require({p.name for p in folder.iterdir()} == names | {"credential"}, "P/G public root inventory")
    data = {name: sdk.snapshot(folder / name, maximum=65536).data for name in names}
    sdk.require(parse_strict_json_bytes(data["manifest.json"], label="P/G manifest") == dict(schema_version=1, language=language, carrier=carrier, profile=profile, release_claim_eligible=False), "P/G manifest")
    owner, family, until, original_digest = first.verify_original(data)
    policy_operation = policy.verify(data, carrier=carrier, account=owner, family=family, byteorder=byteorder)
    policy.verify_expiry(data, family=family, original_request=data["request.bin"], identity_until=until)
    sdk.require(data["account"] == owner and data["family"] == family and data["revision"] == (1).to_bytes(8, "big")
        and all(len(data[n]) == 32 and any(data[n]) for n in ("registry-id", "application", "witness-id"))
        and len(data["witness-public"]) == 1985 and data["registry-required.bin"] == data["request.bin"], "P/G managed account binding")
    for command, outcome in commands.items():
        sdk.require(data[command + ".stdout"] == f"QPC_CONFIGURATION_{outcome}\n".encode() and not data[command + ".stderr"], "P/G original process outcome")
    for name in lifetime: sdk.require(data[name + ".bin"] == data["request.bin"], "P/G registry lifetime scope")
    if language == "Kotlin":
        raw = data["registry-gc.bin"]
        sdk.require(len(raw) == 16 and 1 <= int.from_bytes(raw[:8], "big") <= 1024
            and 1 <= int.from_bytes(raw[8:12], "big") <= 32 and int.from_bytes(raw[12:16], "big") == 63,
            "P/G Kotlin registry collection or slot reclamation was not observed")
    directory = folder / "credential"
    members = set(COMMANDS) | {n + "." + ext for n in COMMANDS for ext in ("stdout", "stderr")} | {n + ".bin" for n in INPUTS} | set(RECORDS)
    sdk.require({p.name for p in directory.iterdir()} == members, "G public inventory")
    g = {name: sdk.snapshot(directory / name, maximum=1024 * 1024).data for name in members}
    for name in COMMANDS:
        marker = b"QPC_CONFIGURATION_CREDENTIAL_OPERATION\n" if name == "credential-original-identity" else b"QPC_CONFIGURATION_POLICY_CREDENTIAL_OPERATION\n"
        sdk.require(g[name + ".stdout"] == marker and not g[name + ".stderr"], "G process outcome")
    request = g["credential-request"]; records = _request(request, byteorder); previous = data["policy-request.bin"]
    target = int.from_bytes(data["target-version.bin"], "big").to_bytes(8, byteorder) + data["target-digest.bin"]
    identity = data["request.bin"][12:44] + data["genesis.bin"][4:36]
    sdk.require(request == g["credential-request-replayed"] and request[:32] == g["credential-operation.bin"]
        and request[32:96] == previous[32:96] and request[96:128] == previous[208:240]
        and request[128:168] == target and request[168:200] == data["policy-statement.bin"] == g["renewal-statement.bin"]
        and request[208:248] == request[248:288] == previous[160:200] and request[304:336] == owner
        and records == (g["grant-certificate.bin"], g["grant-roster.bin"]) * 2, "issuer request substituted original or current inputs")
    valid_from = int.from_bytes(data["intent.bin"][56:64], "big"); valid_until = int.from_bytes(data["intent.bin"][64:72], "big")
    sdk.require(request[288:304] == valid_from.to_bytes(8, byteorder) + valid_until.to_bytes(8, byteorder), "issuer predecessor validity")
    operation, statement = g["credential-operation.bin"], g["credential-statement.bin"]
    sdk.require(len(statement) == 32 and any(statement) and g["credential-original-identity"] == g["credential-renewed-identity"] == identity, "G original identity")
    pending = (1).to_bytes(4, byteorder) + operation + statement + bytes(52)
    cp = int.from_bytes(g["renewal-version.bin"], "big").to_bytes(8, byteorder) + g["renewal-digest.bin"]
    committed = (2).to_bytes(4, byteorder) + operation + statement + bytes(4) + cp + bytes(8)
    sdk.require(g["credential-absent"] == g["credential-after-refusal"] == bytes(120)
        and g["credential-refused"] == (102).to_bytes(4, byteorder) and g["credential-unknown"] == (218).to_bytes(4, byteorder)
        and g["credential-staged"] == g["credential-stage-replayed"] == pending
        and g["credential-recovered"] == g["credential-commit-replayed"] == g["credential-close-applied"] == committed, "G status/unknown outcome")
    proposal = g["credential-proposal"]
    sdk.require(len(proposal) == 329 and proposal[:8] == b"QPCRNP03" and proposal[136:200] == operation + statement
        and proposal[296] == 0 and proposal[297:] == request[168:200] and g["credential-proposal-replayed"] == proposal, "G retained P was replaced or relabeled T")
    next_request = g["credential-next-request"]; next_records = _request(next_request, byteorder)
    sdk.require(next_request[:32] == g["credential-next-operation.bin"] != operation and next_request[32:208] == request[32:208]
        and next_request[248:288] == request[248:288] and next_request[304:336] == owner and next_request[208:248] == cp
        and next_records[:2] == records[:2] and next_records[2:] == (g["renewed-certificate.bin"], g["renewed-roster.bin"]), "next issuer request predecessor")
    lost, reply = g["credential-lost-commit-request"], g["credential-lost-commit-reply"]
    sdk.require(len(lost) == 3674 and lost[204] == 5 and len(reply) == 3659 and reply[204] == 8, "actual lost Commit/Applied")
    history = g["credential-historical-transcript"]
    sdk.require(0 < len(history) <= 128 * 7334 and len(history) % 7334 == 0
        and all(history[i] == 1 and history[i + 205] not in (5, 7) for i in range(0, len(history), 7334)), "historical recovery dispatched new G Commit/Close")
    sdk.require(g["credential-peer.stdout"] == b"independent-peer-admitted\n" and not g["credential-peer.stderr"], "counterparty G admission")
    hashes = {str(p.relative_to(evidence)): hashlib.sha256(p.read_bytes()).hexdigest() for p in folder.rglob('*') if p.is_file()}
    return dict(completed=True, release_claim_eligible=False, language=language, route=label, original_request_sha256=original_digest,
        policy_operation=policy_operation, credential_operation=operation.hex(), original_session=data["session.bin"].hex(),
        original_message=data["unknown.bin"][32:].hex(), business_effects=1, public_readbacks=hashes)


def qualify(outside, output, profile, runtime, helper, client, receiver, run, *, language: str, collector: str = "") -> dict:
    sdk.require(language in ("C", "Swift", "Kotlin"), "qualified P/G client language")
    sdk.require(collector in ("Serial", "G1") if language == "Kotlin" else collector == "", "P/G collector differs")
    binaries = {str(path): sdk.snapshot(Path(path), maximum=256 * 1024**2).sha256 for path in (helper, client, receiver)}
    results = {}
    for label, test in TESTS.items():
        carrier, trust = label.split("-", 1)
        evidence = Path(tempfile.mkdtemp(prefix="policy-credential-", dir=outside)).resolve()
        env = dict(runtime, QPC_CONFIGURATION_CLIENT=str(client), QPC_CONFIGURATION_LANGUAGE=language,
                   QPC_CONFIGURATION_RECEIVER=str(receiver), QPERIAPT_MANAGED_CONFIGURATION_EVIDENCE=str(evidence))
        env.pop("QPERIAPT_PUBLIC_SERVICE_EVIDENCE", None); env.pop("QPERIAPT_CONFIGURATION_EVIDENCE", None)
        name = "policy-credential-" + language.lower() + "-" + profile + ("-" + collector.lower() if collector else "") + "-" + label
        stdout = run([str(helper), "--exact", test, "--nocapture"], name, runtime=env)
        results[label] = verify_execution(stdout, evidence, language=language, carrier=carrier, profile=trust)
        exported = output / (name + "-public")
        for relative, digest in results[label]["public_readbacks"].items():
            sdk.require(sdk.snapshot(evidence / relative).sha256 == digest, "P/G public input drift")
            sdk.copy(evidence / relative, exported / relative)
        sdk.require(verify_execution(stdout, exported, language=language, carrier=carrier, profile=trust) == results[label], "P/G exported readback differs")
    sdk.require(all(sdk.snapshot(Path(path), maximum=256 * 1024**2).sha256 == digest for path, digest in binaries.items()), "P/G executable drift")
    return dict(completed=True, release_claim_eligible=False, language=language, collector=collector, routes=results, binaries=binaries)
