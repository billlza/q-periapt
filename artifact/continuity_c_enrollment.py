"""Read back the real C registration, original-session and roster-continuation trace.

This is structural cross-file verification. The actual C/native endpoints and the
independent authority test verify signatures; this reader is not a second engine.
"""
from pathlib import Path
import re

import rust_sdk_profile as sdk
from continuity_c_witness import commit
from continuity_enrollment import PUBLIC_KEY_BYTES, _registration
from continuity_roster_renewal import envelope

TEST = "c_registration_owns_original_identity_through_connection_and_roster_refresh"
SCOPE = ("actual installed C registration and original enrolled device parent to native Rust TLS peer; "
         "same host and shared protocol engine; original request/credential/journal/session survive roster refresh "
         "and receiver exit after application commit; public structural readback, not an independent signature engine")
PAYLOAD = b"persisted before process exit"
WITNESS_TESTS = {
    "signed-tcp": "c_registration_signed_tcp_requires_current_witness_and_recovers_cancelled_activation",
    "mutual-tls": "c_registration_mutual_tls_requires_current_witness_authority",
}
RENEWAL_TESTS = {
    "credential_renewal::c_original_registration_stages_current_root_grant_and_retains_signer_and_installation",
    "credential_renewal::c_real_clock_expired_pending_reconciles_without_policy_or_tls_for_status_and_recovers_original_registration",
    "credential_renewal::peer_credential_renewal::c_peer_grants_restore_original_expired_session_and_fence_cached_children",
}


def verify_renewal_execution(stdout: bytes, *, language: str = "C") -> dict:
    """Validate shared harness output; caller must bind the selected client binary."""
    sdk.require(language in {"C", "Swift", "Kotlin"}, "unsupported credential renewal language")
    text = stdout.decode()
    names = re.findall(r"^test ([a-z_:]+) \.\.\. ok$", text, re.MULTILINE)
    sdk.require(len(names) == 3 and set(names) == RENEWAL_TESTS
                and len(re.findall(r"^test result: ok\. 3 passed; 0 failed; 0 ignored; 0 measured; 4 filtered out;", text, re.MULTILINE)) == 1,
                "C credential renewal workloads were not executed completely")
    sdk.require(re.findall(r"^C_CREDENTIAL_RENEWAL.*$", text, re.MULTILINE) == [
        "C_CREDENTIAL_RENEWAL original_registration=true same_signer=true same_journal=true pending_readback=true committed_readback=true expired_committed_preserved=true expired_owner_refused=true admitted_signature_failure_closed_owner=true"],
        "C committed credential renewal scope differs")
    sdk.require(re.findall(r"^C_PEER_CREDENTIAL_RENEWAL.*$", text, re.MULTILINE) == [
        "C_PEER_CREDENTIAL_RENEWAL original_tls_session=true actual_expiry=true wrong_pin_and_operation_refused=true cached_child_fenced=true persisted_grant=true exact_outbox_readback=true"],
        "C peer credential renewal scope differs")
    expiry = re.findall(r"^C_CREDENTIAL_EXPIRY actual_wall_clock=true target_until=([0-9]+) observed_at=([0-9]+) no_policy_status=true same_registration=true separate_root_operation=true$", text, re.MULTILINE)
    sdk.require(len(expiry) == 1 and 0 < int(expiry[0][0]) <= int(expiry[0][1]),
                "C expiry observation precedes its real target lifetime")
    return dict(completed=True, language=language, tests=sorted(RENEWAL_TESTS), actual_wall_clock=True,
                target_until=int(expiry[0][0]), observed_at=int(expiry[0][1]),
                scope=language + " owner runtime assertions with original-registration and historical peer readbacks; raw C output-buffer checks apply only to C; same native engine; no renewed TLS delivery, required-witness local renewal or independent-engine claim",
                release_claim_eligible=False)


def owner_transfer(read, prefix: str, language: str) -> dict:
    sdk.require(language in {"C", "Swift", "Kotlin"}, "unsupported enrollment language")
    if language == "C":
        return {}
    wanted = (b"old-registration-released original-device-live\n" if language == "Swift"
              else b"old-registration-collected original-device-live\n")
    sdk.require(read(prefix + "/" + language.lower() + "-enrollment-transfer", 128) == wanted,
                "foreign enrollment owner transfer was not observed")
    return dict(language=language, original_owner_transfer=True)


def registration_readback(read, prefix, signing, journal):
    intent = read(prefix + "/enrollment-intent", 72)
    sdk.require(len(intent) == 72, "C original approved intent width")
    sdk.require(read(prefix + "/family", 32) == intent[24:56], "C enrollment configured policy family differs")
    request = read(prefix + "/enrollment-request")
    body = envelope(request, b"QPENRQ01", 144 + PUBLIC_KEY_BYTES)
    virtual = {
        "signer-id": signing, "public-key": body[144:], "local-device": intent[:16],
        "local-generation": intent[16:24], "enrollment-validity": intent[56:72], "family": intent[24:56],
        "accepted-journal": journal, "active-journal": journal, "reopened-journal": journal,
    }
    files = {
        "local-root": "enrollment-root", "local-account": "trusted-account",
        "request": "enrollment-request", "reopened-request": "enrollment-reopened-request",
        "local-certificate": "grant-certificate", "local-roster": "grant-roster",
        "local-roster-version": "trusted-roster-version", "local-roster-digest": "trusted-roster-digest",
    }

    def registration_read(_role, name, maximum=8192):
        return virtual[name] if name in virtual else read(prefix + "/" + files[name], maximum)

    def registration_fixed(role, name, width, *, nonzero=False):
        value = registration_read(role, name, width)
        sdk.require(len(value) == width and (not nonzero or any(value)), "C enrollment field differs: " + name)
        return value

    registration, original_roster = _registration(prefix, registration_read, registration_fixed)
    renewal_wire = read(prefix + "/renewal-roster")
    renewal = envelope(renewal_wire, b"QPROST01", len(original_roster))
    renewal_version = read(prefix + "/renewal-version", 8)
    sdk.require(renewal_version == (2).to_bytes(8, "big") and original_roster[40:48] == (1).to_bytes(8, "big")
                and renewal == original_roster[:40] + renewal_version + original_roster[48:]
                and commit(b"Q-PERIAPT-CONTINUITY-ROSTER-CANDIDATE/v1", renewal) == read(prefix + "/renewal-digest", 32),
                "C enrollment refresh changed the original credential or expected roster")
    return registration


def verify_execution(stdout: bytes, directory: Path, *, language: str = "C") -> dict:
    text = stdout.decode()
    sdk.require(re.findall(r"^test ([a-z_]+) \.\.\. ok$", text, re.MULTILINE) == [TEST]
                and re.search(r"^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 6 filtered out;", text, re.MULTILINE),
                "C registration workload was not executed completely")
    sdk.require(re.findall(r"^C_ENROLLMENT_COMPLETE.*$", text, re.MULTILINE) == [
        "C_ENROLLMENT_COMPLETE original_identity=true lease_retained=true original_session=true roster_refresh=true delivery_exact=true"],
        "C registration completion scope differs")
    public = {}

    def read(name: str, maximum: int = 8192) -> bytes:
        snap = sdk.snapshot(directory / name, maximum=maximum)
        public[name] = snap.sha256
        return snap.data

    def command(label: str, expected: bytes | None = None) -> bytes:
        stem = "enrolled/enrollment-" + label
        value = read(stem + ".stdout", 65536)
        sdk.require(read(stem + ".stderr", 65536) == b"", "C registration diagnostic failure: " + label)
        if expected is not None:
            sdk.require(value == expected, "C registration command readback differs: " + label)
        return value

    def state(label: str, phase: int):
        match = re.fullmatch(rb"enrollment-phase:([1-6])\n([0-9a-f]{64})\n([0-9a-f]{64})\n", command(label))
        sdk.require(match is not None and int(match[1]) == phase, "C registration phase differs: " + label)
        signing, journal = bytes.fromhex(match[2].decode()), bytes.fromhex(match[3].decode())
        sdk.require(any(signing) and (any(journal) if phase >= 3 else journal == bytes(32)), "registration ID shape")
        return signing, journal

    command("key", b"enrollment-key\n")
    creating = state("create", 1)
    requested = state("request", 2)
    sdk.require(creating == requested == state("request-retry", 2) == state("after-reject", 2),
                "C registration request or failed acceptance changed original identity")
    command("reject", b"enrollment-signature-refused\n")
    accepted = state("accept", 3)
    sdk.require(accepted[0] == creating[0] and accepted == state("storage", 3) == state("active", 5)
                == state("refresh", 6) == state("final-status", 5) == state("after-missing-registration", 5),
                "C registration continuation changed identity")
    command("missing-registration", b"enrollment-open-refused:204\n")
    command("creation-refused", b"enrollment-open-refused:211\n")
    command("key-conflict", b"enrollment-key-refused:211\n")
    command("cancel", b"enrollment-cancelled\n")
    activated = command("held")
    sdk.require(re.fullmatch(rb"enrollment-active\n[0-9a-f]{64}\n", activated) is not None,
                "C enrollment activation did not expose device parent")
    command("activate-current", activated)
    sdk.require(read("enrolled/enrollment-held", 1) == read("enrolled/release-enrollment", 1) == b"1",
                "C enrollment lease barrier missing")
    observation = read("enrolled/enrollment-lease-observation", 16)
    sdk.require(len(observation) == 16, "C enrollment lease observation width")
    child, parent = int.from_bytes(observation[:8], "big"), int.from_bytes(observation[8:], "big")
    sdk.require(child > 0 and parent > 0 and child != parent, "C enrollment lacks separate lease contender")

    registration = registration_readback(read, "enrolled", creating[0], accepted[1])
    sdk.require(read("enrolled/enrollment-genesis-subject", 96) == bytes(96)
                and read("enrolled/enrollment-genesis-digest", 32) == bytes(32), "local registration selected another protection profile")

    def identifier(label):
        value = command(label)
        sdk.require(re.fullmatch(rb"[0-9a-f]{64}\n", value) is not None, "C enrollment connection identifier")
        result = bytes.fromhex(value[:-1].decode())
        sdk.require(any(result), "zero C connection identifier")
        return result

    session, message = identifier("connect"), identifier("next")
    command("uncertain", b"delivery-unknown-committed\n")
    command("retry", b"consumed\n")
    sdk.require(read("responder/session", 32) == session, "C registered peers disagree on session")
    effect = "responder/application-" + message.hex()
    sdk.require(read(effect, 65536) == session + message + PAYLOAD, "C enrollment application readback differs")
    sdk.require(len(list((directory / "responder").glob("application-*"))) == 1, "C enrollment repeated application effect")
    transfer = owner_transfer(read, "enrolled", language)
    return dict(scope=SCOPE.replace("C registration", language + " registration"), completed=True,
                release_claim_eligible=False, registration=registration, **transfer,
                refreshed_roster_version=2, session=session.hex(), message=message.hex(),
                independent_lease_processes={language + "_owner": child, "Rust_contender": parent}, public_readbacks=public)


def export(stdout: bytes, directory: Path, destination: Path, *, language: str = "C") -> dict:
    """Copy the exact public closure; no wrapping, signer, TLS key or database files."""
    checked = verify_execution(stdout, directory, language=language)
    destination.mkdir(mode=0o700, parents=True)
    for name in checked["public_readbacks"]:
        sdk.copy(directory / name, destination / name)
    sdk.require(verify_execution(stdout, destination, language=language) == checked, "C enrollment evidence changed during export")
    sdk.require({p.relative_to(destination).as_posix() for p in destination.rglob("*") if p.is_file()}
                == set(checked["public_readbacks"]), "C enrollment public inventory differs")
    return checked


def verify_witness(stdout: bytes, directory: Path, carrier: str, *, language: str = "C") -> dict:
    from continuity_c_witness import RECORD_BYTES, transcript
    sdk.require(carrier in WITNESS_TESTS, "unsupported C enrollment witness carrier")
    text = stdout.decode()
    sdk.require(re.findall(r"^test ([a-z_]+) \.\.\. ok$", text, re.MULTILINE) == [WITNESS_TESTS[carrier]]
                and re.search(r"^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 5 filtered out;", text, re.MULTILINE),
                "C witnessed enrollment workload was not executed completely")
    prefix, public = "enrolled-witness", {}

    def read(name, maximum=8192):
        snap = sdk.snapshot(directory / name, maximum=maximum)
        public[name] = snap.sha256
        return snap.data

    def command(label, expected=None):
        name = prefix + "/witness-enrollment-" + label
        value = read(name + ".stdout", 65536)
        sdk.require(read(name + ".stderr", 65536) == b"", "witnessed enrollment diagnostic failure")
        sdk.require(expected is None or value == expected, "witnessed enrollment command differs: " + label)
        return value

    def state(label, phase):
        match = re.fullmatch(rb"enrollment-phase:([1-6])\n([0-9a-f]{64})\n([0-9a-f]{64})\n", command(label))
        sdk.require(match is not None and int(match[1]) == phase, "witnessed enrollment phase differs")
        signing, journal = bytes.fromhex(match[2].decode()), bytes.fromhex(match[3].decode())
        sdk.require(any(signing) and (any(journal) if phase >= 3 else journal == bytes(32)), "witnessed enrollment ID shape")
        return signing, journal

    command("key", b"enrollment-key\n")
    created = state("create", 1)
    sdk.require(created == state("request", 2) == state("request-retry", 2), "witness enrollment replaced request")
    accepted = state("accept", 3)
    sdk.require(created[0] == accepted[0] and accepted == state("storage", 3) == state("active", 5)
                == state("after-missing-required", 5) == state("refresh", 6) == state("after-denial", 5) == state("renewed-status", 5),
                "witness enrollment replaced original owner or concealed committed Active")
    command("missing-required", b"enrollment-activation-refused:216\n")
    sdk.require(read(prefix + "/enrollment-required-refusal",512) == b"authenticated witness is required",
                "missing-witness refusal was relabelled")
    activated = command("activate")
    match = re.fullmatch(rb"enrollment-active\n([0-9a-f]{64})\n", activated)
    sdk.require(match is not None and any(bytes.fromhex(match[1].decode())), "witness activation omitted device state")
    command("renewed", activated)
    sdk.require(re.findall(r"^C_ENROLLMENT_WITNESS_COMPLETE.*$", text, re.MULTILINE) == [
        "C_ENROLLMENT_WITNESS_COMPLETE carrier=" + carrier + " journal=" + accepted[1].hex()
        + " next_account=" + match[1].decode()], "witness enrollment completion disagrees with original state")
    command("denied", b"enrollment-activation-refused:218\n")
    sdk.require(read(prefix + "/enrollment-authority-refusal", 512).endswith(
        b"witness enrollment authority is not current or valid"), "refusal was not authenticated current-authority denial")
    registration = registration_readback(read, prefix, accepted[0], accepted[1])
    subject = read(prefix + "/witness-subject", 96)
    genesis = read(prefix + "/enrollment-genesis-digest", 32)
    sdk.require(len(subject) == 96 and subject[:32] == accepted[1] and all(any(subject[n:n+32]) for n in (0,32,64))
                and subject == read(prefix + "/enrollment-genesis-subject", 96)
                and len(genesis) == 32 and any(genesis), "witness enrollment original genesis differs")
    identity, key = read(prefix + "/witness-id", 32), read(prefix + "/witness-public", 1985)
    sdk.require(len(identity) == 32 and any(identity) and len(key) == 1985 and key[1952] in (2,3),
                "witness enrollment pin shape differs")
    detail = {}
    if carrier == "signed-tcp":
        command("cancel-activate", b"enrollment-activation-cancelled\n")
        sdk.require(state("cancelled-status", 5) == accepted, "cancelled activation changed registration")
        command("cancelled-reopen", activated)
        sdk.require(read(prefix + "/enrollment-cancel-query", 1) == b"1", "cancelled witness barrier missing")
        account, family = bytes.fromhex(registration['account']), bytes.fromhex(registration['family'])
        previous = commit(b"Q-PERIAPT-CONTINUITY-AUTHORITY-CANDIDATE/v1", account + (1).to_bytes(8,'big')
                          + bytes.fromhex(registration['roster_digest']) + family)
        current = commit(b"Q-PERIAPT-CONTINUITY-AUTHORITY-CANDIDATE/v1", account + (2).to_bytes(8,'big')
                         + read(prefix + "/renewal-digest",32) + family)
        wire = read(prefix + "/enrollment-witness-transcript", RECORD_BYTES*128)
        protocol = transcript(wire, commit(b"Q-PERIAPT-CONTINUITY-ANCHOR-AUTHORITY/v1",identity+key),
            expected_lost_advances=0, expected_lost_queries=1, expected_subjects=1,
            authority_observations=[(previous,5),(current,6),(current,5),(current,5)])
        sdk.require(protocol['logical_advances'] == 1, "witness registration refresh advanced more than once")
        rows = [wire[n:n+RECORD_BYTES] for n in range(0,len(wire),RECORD_BYTES)]
        sdk.require(all(row[45:141] == subject for row in rows) and rows[0][3896:3928] == genesis,
                    "witness registration substituted subject or genesis")
        lost = [row for row in rows if row[0] == 0]
        sdk.require(len(lost) == 1 and read(prefix + "/witness-cancelled-prefix",1804)
                    == (3659).to_bytes(4,'big') + lost[0][3675:5475], "cancelled enrollment lost another signed reply")
        detail['protocol'] = protocol
    else:
        admissions = read(prefix + "/enrollment-tls-admissions",8)
        denied = read(prefix + "/enrollment-tls-denial-admissions",16)
        sdk.require(len(admissions) == 8 and len(denied) == 16
                    and 0 < int.from_bytes(denied[:8],'big') < int.from_bytes(denied[8:],'big')
                    <= int.from_bytes(admissions,'big'), "authority denial lacks real TLS admission")
        server, client = read(prefix + "/witness-tls-peer"), read(prefix + "/witness-tls-cert")
        sdk.require(server and client and server != client and read(prefix + "/witness-tls-name",128) == b"localhost",
                    "witness enrollment TLS peer identity differs")
        detail['TLS_admissions'] = int.from_bytes(admissions,'big')
        detail['TLS_denial_admissions'] = [int.from_bytes(denied[:8],'big'),int.from_bytes(denied[8:],'big')]
    transfer = owner_transfer(read, prefix, language)
    return dict(scope="actual " + language + " original registration with " + carrier + "; same-host native witness, independent control-plane authorization, no independent witness engine",
                completed=True, release_claim_eligible=False, carrier=carrier, registration=registration,
                next_account=match[1].decode(), **transfer, **detail, public_readbacks=public)


def export_witness(stdout: bytes, directory: Path, destination: Path, carrier: str, *, language: str = "C") -> dict:
    checked = verify_witness(stdout, directory, carrier, language=language)
    destination.mkdir(mode=0o700, parents=True)
    for name in checked["public_readbacks"]: sdk.copy(directory / name, destination / name)
    sdk.require(verify_witness(stdout, destination, carrier, language=language) == checked, "C witness enrollment evidence changed during export")
    sdk.require({p.relative_to(destination).as_posix() for p in destination.rglob("*") if p.is_file()}
                == set(checked["public_readbacks"]), "C witness enrollment public inventory differs")
    return checked


def qualify_foreign(outside: Path, output: Path, profile: str, runtime: dict,
                    native: dict, run, *, language: str, collector: str = "") -> dict:
    """Execute the selected installed foreign client against the exact C cohort's
    archive-derived authority harness. The native build log and binary receipt
    must agree; a matching test name cannot substitute for that provenance.
    """
    import continuity_c_consumer as c
    sdk.require(profile in {"debug", "release"} and
                ((language == "Swift" and collector == "") or
                 (language == "Kotlin" and collector in {"Serial", "G1"})),
                "unqualified foreign registration profile")
    binaries = {}
    for target in ("enrollment", "enrollment_witness"):
        label = target.replace("_", "-")
        build_log = sdk.snapshot(output / ("c-" + label + "-build-" + profile + ".stdout"), maximum=32 * 1024**2)
        binary = c.built_artifact(build_log.data, outside / "c-consumer", outside / "build" / profile,
                                  library=False, test_name=target)
        expected = (native["enrollment"]["binary"] if target == "enrollment"
                    else native["enrollment_witness"]["signed-tcp"]["binary"])
        if target == "enrollment_witness":
            sdk.require(expected == native["enrollment_witness"]["mutual-tls"]["binary"],
                        "witnessed registration traces used different native harnesses")
        observed = sdk.snapshot(binary, maximum=c.MAX_BINARY)
        sdk.require(observed.sha256 == expected["sha256"] and observed.size == expected["bytes"],
                    "foreign registration native harness changed before execution")
        binaries[target] = (binary, observed.sha256)
    variant = "-" + collector.lower() if collector else ""
    result = {}
    for carrier, test in {"local": TEST, **WITNESS_TESTS}.items():
        target = "enrollment" if carrier == "local" else "enrollment_witness"
        binary, identity = binaries[target]
        label = "enrollment-" + carrier + "-" + profile + variant
        evidence = outside / (language.lower() + "-" + label + "-runtime")
        selected = dict(runtime, QPERIAPT_PUBLIC_SERVICE_EVIDENCE=str(evidence))
        stdout = run([str(binary), "--exact", test, "--nocapture"], label, runtime=selected)
        destination = output / (language.lower() + "-enrollment-public") / (profile + variant) / carrier
        checked = (export(stdout, evidence, destination, language=language) if carrier == "local"
                   else export_witness(stdout, evidence, destination, carrier, language=language))
        sdk.require(sdk.snapshot(binary, maximum=c.MAX_BINARY).sha256 == identity,
                    "foreign registration native harness changed during execution")
        result[carrier] = dict(execution=checked, native_harness_sha256=identity)
    binary, identity = binaries["enrollment"]
    sdk.require(native["credential_renewal"]["binary"] == native["enrollment"]["binary"],
                "foreign renewal must use the C-qualified original enrollment harness")
    sdk.require(runtime.get("QPERIAPT_INSTALLED_CLIENT_LANGUAGE") == language,
                "foreign renewal language selection differs")
    client = Path(runtime["QPERIAPT_C_OWNER_CLIENT"])
    client_identity = sdk.snapshot(client, maximum=c.MAX_BINARY)
    selected = dict(runtime)
    selected.pop("QPERIAPT_PUBLIC_SERVICE_EVIDENCE", None)
    stdout = run([str(binary), "credential_renewal::", "--nocapture"],
                 "credential-renewal-" + profile + variant, runtime=selected)
    checked = verify_renewal_execution(stdout, language=language)
    sdk.require(sdk.snapshot(binary, maximum=c.MAX_BINARY).sha256 == identity
                and sdk.snapshot(client, maximum=c.MAX_BINARY).sha256 == client_identity.sha256,
                "foreign renewal harness or client changed during execution")
    result["credential_renewal"] = dict(execution=checked, native_harness_sha256=identity,
                                        foreign_client_sha256=client_identity.sha256)
    from continuity_witnessed_renewal import qualify as qualify_witnessed_renewal
    binary, identity = binaries["enrollment_witness"]
    sdk.require("witnessed_credential_renewal" in native, "C cohort lacks witnessed credential renewal qualification")
    sdk.require(native["witnessed_credential_renewal"]["binary"] == native["enrollment_witness"]["signed-tcp"]["binary"],
                "foreign witnessed renewal must use the C-qualified original harness")
    result["witnessed_credential_renewal"] = qualify_witnessed_renewal(
        outside, output, profile, runtime, binary, run, language=language, variant=variant)
    sdk.write_json(output / (language.upper() + "_ENROLLMENT_" + (profile + variant).replace("-", "_").upper() + ".json"), result)
    return result
