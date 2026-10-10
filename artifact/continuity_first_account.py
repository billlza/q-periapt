"""Managed first registration through the installed C process, with public-only readback."""
import hashlib
import re
from pathlib import Path

import continuity_first_configuration as configuration
import rust_sdk_profile as sdk
from evidence_io import parse_strict_json_bytes

TEST = "managed_c_first_registration_preserves_identity_and_delivery"
SCOPE = ("installed C first registration, account selection, witnessed activation and original-message "
         "recovery; fixed and recoverable SDK roots; signed TCP and mutual TLS witness; "
         "same host and shared native engine; no managed policy renewal or independent implementation claim")
BASE = {"manifest.json", "request.bin", "replayed.bin", "root.bin", "intent.bin", "genesis.bin",
        "session.bin", "unknown.bin", "acknowledged.bin", "after-traffic.bin", "effect.bin",
        "registry-required.bin", "registry-id", "family", "witness-id", "witness-public",
        "application", "account", "revision"}
COMMANDS = {"request": "REQUEST_PASS", "genesis": "GENESIS_PASS", "missing": "WITNESS_REQUIRED",
            "active": "ACTIVATION_PASS", "active-reopened": "ACTIVATION_PASS",
            "registry-required": "REGISTRY_REQUIRED", "connected": "CONNECTION_PASS",
            "uncertain": "UNKNOWN_COMMITTED", "acknowledged": "ORIGINAL_ACKNOWLEDGED",
            "after-traffic": "REQUEST_PASS"}


def marker(carrier: str, profile: str) -> str:
    return (f"MANAGED_CONFIGURATION_PASS carrier={carrier} profile={profile} request_before_association=true "
            "original_registry=true missing_registry=211 release_qualified=false")


def verify_execution(stdout: bytes, evidence: Path, *, language: str) -> dict:
    text = stdout.decode()
    sdk.require(language == "C" and re.findall(r"^test ([a-z_]+) \.\.\.", text, re.MULTILINE) == [TEST]
                and len(re.findall(r"^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 5 filtered out;",
                                   text, re.MULTILINE)) == 1, "managed first registration did not execute completely")
    scenarios = [(c, p) for c in ("signed", "tls") for p in ("fixed", "recoverable")]
    expected = {marker(c, p) for c, p in scenarios} | {
        configuration.connection_marker("C", c, p) for c, p in scenarios}
    markers = re.findall(r"^(?:MANAGED_|INDEPENDENT_).*$", text, re.MULTILINE)
    sdk.require(len(markers) == 8 and set(markers) == expected, "managed first registration matrix differs")
    directories = {f"{c}-{p}" for c, p in scenarios}
    sdk.require(not evidence.is_symlink() and {p.name for p in evidence.iterdir()} == directories,
                "managed first registration scenarios differ")
    names = BASE | {f"{name}.{extension}" for name in COMMANDS for extension in ("stdout", "stderr")}
    hashes, requests, registries = {}, set(), set()
    for carrier, profile in scenarios:
        name = f"{carrier}-{profile}"
        folder = evidence / name
        sdk.require(folder.is_dir() and not folder.is_symlink() and {p.name for p in folder.iterdir()} == names,
                    "managed first registration public inventory differs or includes private material")
        data = {leaf: sdk.snapshot(folder / leaf, maximum=65536).data for leaf in names}
        manifest = parse_strict_json_bytes(data["manifest.json"], label="managed registration metadata")
        sdk.require(manifest == dict(schema_version=1, language="C", profile=profile, carrier=carrier,
                                    release_claim_eligible=False) and type(manifest["schema_version"]) is int
                    and manifest["release_claim_eligible"] is False, "managed first registration metadata differs")
        account, family, _, digest = configuration.verify_original(data)
        sdk.require(data["account"] == account and data["family"] == family
                    and data["revision"] == (1).to_bytes(8, "big")
                    and all(len(data[n]) == 32 and any(data[n]) for n in ("registry-id", "application", "witness-id"))
                    and len(data["witness-public"]) == 1985
                    and data["registry-required.bin"] == data["request.bin"],
                    "managed first registration account binding or omission refusal differs")
        for command, outcome in COMMANDS.items():
            sdk.require(data[command + ".stdout"] == f"QPC_CONFIGURATION_{outcome}\n".encode()
                        and data[command + ".stderr"] == b"", "managed first registration process outcome differs")
        requests.add(digest)
        registries.add(data["registry-id"])
        hashes.update({name + "/" + leaf: hashlib.sha256(value).hexdigest() for leaf, value in data.items()})
    sdk.require(len(requests) == 4 and len(registries) == 4, "managed registration scenarios reused original identities")
    return dict(completed=True, scope=SCOPE, language="C", release_claim_eligible=False,
                scenarios=sorted(directories), public_readbacks=hashes, missing_registry=211,
                original_message_recovered=True, host_effects_per_scenario=1,
                signature_verification="shared native execution only")
