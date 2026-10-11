"""Managed first registration through installed foreign processes, with public-only readback."""
import hashlib
import re
from pathlib import Path

import continuity_first_configuration as configuration
import continuity_configuration_policy as policy
import continuity_configuration_credential as credentials
import rust_sdk_profile as sdk
from evidence_io import parse_strict_json_bytes

TEST = "managed_first_registration_preserves_identity_and_delivery"
SCOPE = ("installed C/Swift/Kotlin first registration, account selection, witnessed activation and original-message "
         "recovery; fixed and recoverable SDK roots; signed TCP and mutual TLS witness; "
         "real-clock protocol-policy expiry and independently approved renewal; same host and shared native engine; "
         "no credential renewal or independent implementation claim")
BASE = {"manifest.json", "request.bin", "replayed.bin", "root.bin", "intent.bin", "genesis.bin",
        "session.bin", "unknown.bin", "acknowledged.bin", "after-traffic.bin", "effect.bin",
        "registry-required.bin", "registry-id", "family", "witness-id", "witness-public",
        "application", "account", "revision"}
COMMANDS = {"request": "REQUEST_PASS", "genesis": "GENESIS_PASS", "missing": "WITNESS_REQUIRED",
            "active": "ACTIVATION_PASS", "active-reopened": "ACTIVATION_PASS",
            "registry-required": "REGISTRY_REQUIRED", "connected": "CONNECTION_PASS",
            "uncertain": "UNKNOWN_COMMITTED", "acknowledged": "ORIGINAL_ACKNOWLEDGED",
            "after-traffic": "REQUEST_PASS"}


def marker(language: str, carrier: str, profile: str, *, credential: bool = False) -> str:
    prefix = "MANAGED_CREDENTIAL_CONFIGURATION" if credential else "MANAGED_CONFIGURATION"
    return (f"{prefix}_PASS language={language} carrier={carrier} profile={profile} request_before_association=true "
            "original_registry=true missing_registry=211 release_qualified=false")


def verify_execution(stdout: bytes, evidence: Path, *, language: str, credential: bool = False) -> dict:
    sdk.require(not credential or language in {"C", "Swift"}, "managed credential adapter is not qualified for this language")
    test = credentials.TEST if credential else TEST
    renewal = credentials if credential else policy
    text = stdout.decode()
    sdk.require(language in {"C", "Swift", "Kotlin"} and re.findall(r"^test ([a-z_]+) \.\.\.", text, re.MULTILINE) == [test]
                and len(re.findall(r"^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 6 filtered out;",
                                   text, re.MULTILINE)) == 1, "managed first registration did not execute completely")
    scenarios = [(c, p) for c in ("signed", "tls") for p in ("fixed", "recoverable")]
    expected = {marker(language, c, p, credential=credential) for c, p in scenarios} | {
        configuration.connection_marker(language, c, p) for c, p in scenarios}
    expected |= {renewal.marker(language, c, p) for c, p in scenarios}
    expected |= {renewal.expiry_marker(language, c, p) for c, p in scenarios}
    markers = re.findall(r"^(?:MANAGED_|INDEPENDENT_).*$", text, re.MULTILINE)
    sdk.require(len(markers) == 16 and set(markers) == expected, "managed first registration matrix differs")
    for carrier, profile in scenarios:
        sdk.require(text.index(renewal.expiry_marker(language, carrier, profile))
                    < text.index(renewal.marker(language, carrier, profile))
                    < text.index(configuration.connection_marker(language, carrier, profile)),
                    "managed configuration expiry/recovery phase order differs")
    directories = {f"{c}-{p}" for c, p in scenarios}
    sdk.require(not evidence.is_symlink() and {p.name for p in evidence.iterdir()} == directories,
                "managed first registration scenarios differ")
    commands = dict(COMMANDS)
    if credential: commands["after-traffic"] = "CREDENTIAL_OPERATION"
    lifetime = {"registry-closed": "REGISTRY_CLOSED", "registry-released": "REGISTRY_RELEASED"} if language in {"Swift", "Kotlin"} else {}
    commands.update(lifetime)
    names = BASE | {f"{name}.{extension}" for name in commands for extension in ("stdout", "stderr")} | {n + ".bin" for n in lifetime}
    if language == "Kotlin": names.add("registry-gc.bin")
    names |= credentials.NAMES if credential else policy.names("signed") | policy.EXPIRY
    hashes, requests, registries, gc_observations = {}, set(), set(), {}
    policy_operations, expiry_observations = set(), {}
    for carrier, profile in scenarios:
        name = f"{carrier}-{profile}"
        folder = evidence / name
        sdk.require(folder.is_dir() and not folder.is_symlink() and {p.name for p in folder.iterdir()} == names,
                    "managed first registration public inventory differs or includes private material")
        data = {leaf: sdk.snapshot(folder / leaf, maximum=credentials.MAX_READBACK if credential else 65536).data for leaf in names}
        manifest = parse_strict_json_bytes(data["manifest.json"], label="managed registration metadata")
        sdk.require(manifest == dict(schema_version=1, language=language, profile=profile, carrier=carrier,
                                    release_claim_eligible=False) and type(manifest["schema_version"]) is int
                    and manifest["release_claim_eligible"] is False, "managed first registration metadata differs")
        account, family, valid_until, digest = configuration.verify_original(data, after_traffic="identity" if credential else "request")
        if credential:
            operation, observed = credentials.verify(data, account=account, family=family, identity_until=valid_until)
            policy_operations.add(operation)
            expiry_observations[name] = observed
        else:
            policy_operations.add(policy.verify(data, carrier=carrier, account=account, family=family))
            expiry_observations[name] = policy.verify_expiry(
                data, family=family, original_request=data["request.bin"], identity_until=valid_until)
        sdk.require(data["account"] == account and data["family"] == family
                    and data["revision"] == (1).to_bytes(8, "big")
                    and all(len(data[n]) == 32 and any(data[n]) for n in ("registry-id", "application", "witness-id"))
                    and len(data["witness-public"]) == 1985
                    and data["registry-required.bin"] == data["request.bin"],
                    "managed first registration account binding or omission refusal differs")
        for command in lifetime:
            sdk.require(data[command + ".bin"] == data["request.bin"], "registry lifetime probe lost the original request")
        for command, outcome in commands.items():
            sdk.require(data[command + ".stdout"] == f"QPC_CONFIGURATION_{outcome}\n".encode()
                        and data[command + ".stderr"] == b"", "managed first registration process outcome differs")
        if language == "Kotlin":
            raw = data["registry-gc.bin"]
            collections, rounds, slots = int.from_bytes(raw[:8], "big"), int.from_bytes(raw[8:12], "big"), int.from_bytes(raw[12:16], "big")
            sdk.require(len(raw) == 16 and 1 <= collections <= 1024 and 1 <= rounds <= 32 and slots == 63,
                        "Kotlin registry collection or native slot reclamation was not observed")
            gc_observations[name] = dict(collections=collections, rounds=rounds, available_slots=slots)
        requests.add(digest)
        registries.add(data["registry-id"])
        hashes.update({name + "/" + leaf: hashlib.sha256(value).hexdigest() for leaf, value in data.items()})
    sdk.require(len(requests) == 4 and len(registries) == 4, "managed registration scenarios reused original identities")
    sdk.require(len(policy_operations) == 4, "managed scenarios reused a policy renewal operation")
    scope = (f"installed {language} managed first registration, real-clock credential expiry, unknown commit recovery and original-message delivery; "
             "same host and native engine; no independent implementation, cross-platform or release qualification") if credential else SCOPE
    return dict(completed=True, scope=scope, language=language, release_claim_eligible=False,
                scenarios=sorted(directories), public_readbacks=hashes, missing_registry=211,
                original_message_recovered=True, host_effects_per_scenario=1,
                registry_lifetime_probes=sorted(lifetime), gc_observations=gc_observations,
                policy_renewal_composition=not credential, real_clock_policy_expiry=not credential,
                expiry_observations=expiry_observations, credential_renewal_qualified=credential,
                real_clock_credential_expiry=credential,
                signature_verification="shared native execution only")
