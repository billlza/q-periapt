"""Execute explicit first-use configuration through installed foreign owners.

Public readback checks grammar, original-input linkage and exact replay. Native
execution verifies signatures; this reader does not claim a second crypto engine.
"""
from pathlib import Path
import hashlib
import os
import re

import continuity_c_consumer as c
import rust_sdk_profile as sdk
from evidence_io import parse_strict_json_bytes

TESTS = frozenset({
    "independent_c_configuration_creates_and_resumes_original_identity",
    "independent_c_required_witness_registration_uses_original_host_trust",
})
SCOPE = "unpublished explicit configuration, independent host trust and original registration; installed foreign process and shared native Rust engine; same host"


def verify_execution(stdout: bytes, evidence: Path, *, language: str) -> dict:
    sdk.require(language in {"C", "Swift", "Kotlin"}, "unknown configuration language")
    text = stdout.decode("utf-8")
    tests = re.findall(r"^test ([a-z_]+) \.\.\.", text, re.MULTILINE)
    sdk.require(len(tests) == 2 and set(tests) == TESTS and len(re.findall(
        r"^test result: ok\. 2 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out;", text, re.MULTILINE)) == 1,
        "configuration execution did not run both complete scenarios")
    expected = {f"INDEPENDENT_CONFIGURATION_PASS language={language} profile={profile} original_request_replayed=true"
                for profile in ("fixed", "recoverable")} | {
        f"INDEPENDENT_WITNESS_CONFIGURATION_PASS language={language} carrier={carrier} profile={profile} remote_genesis_only=true original_request_replayed=true"
        for carrier in ("signed", "tls") for profile in ("fixed", "recoverable")}
    markers = re.findall(r"^INDEPENDENT_.*$", text, re.MULTILINE)
    sdk.require(len(markers) == 6 and set(markers) == expected, "configuration execution omitted or duplicated a trust/carrier scenario")
    directories = {f"{carrier}-{profile}" for carrier in ("local", "signed", "tls") for profile in ("fixed", "recoverable")}
    sdk.require(not evidence.is_symlink() and {p.name for p in evidence.iterdir()} == directories,
                "configuration public scenario set differs")
    hashes = {}
    requests = set()
    for name in sorted(directories):
        carrier, profile = name.split("-")
        folder = evidence / name
        names = {"manifest.json", "request.bin", "replayed.bin", "root.bin", "intent.bin"}
        if carrier != "local": names.add("genesis.bin")
        sdk.require(folder.is_dir() and not folder.is_symlink() and {p.name for p in folder.iterdir()} == names,
                    "configuration public inventory differs or includes private material")
        data = {leaf: sdk.snapshot(folder / leaf, maximum=16384).data for leaf in names}
        manifest = parse_strict_json_bytes(data["manifest.json"], label="configuration public metadata")
        sdk.require(manifest == dict(schema_version=1, language=language, profile=profile, carrier=carrier,
                                     release_claim_eligible=False) and type(manifest["schema_version"]) is int
                    and manifest["release_claim_eligible"] is False, "configuration public metadata differs")
        request, intent, root = data["request.bin"], data["intent.bin"], data["root.bin"]
        sdk.require(len(root) == 1985 and len(intent) == 72 and any(root) and any(intent[:16]) and any(intent[24:56]),
                    "configuration original public inputs differ")
        generation = int.from_bytes(intent[16:24], "big")
        valid_from, valid_until = int.from_bytes(intent[56:64], "big"), int.from_bytes(intent[64:72], "big")
        sdk.require(0 < generation < 2**64 - 1 and valid_from < valid_until < 2**64 - 1,
                    "configuration original scope is empty or unbounded")
        sdk.require(len(request) == 4 + 2129 + 3373 and request == data["replayed.bin"]
                    and request[:4] == (2129).to_bytes(4, "big"), "configuration original request did not replay exactly")
        body = request[4:4 + 2129]
        domain = b"Q-PERIAPT-CONTINUITY-ACCOUNT-CANDIDATE/v1"
        account = hashlib.sha3_256(len(domain).to_bytes(8, "big") + domain + len(root).to_bytes(8, "big") + root).digest()
        sdk.require(body[:8] == b"QPENRQ01" and any(body[8:40]) and body[40:72] == account
                    and body[72:96] == intent[:24] and body[96:112] == intent[56:72]
                    and body[112:144] == intent[24:56] and body[144:] != root,
                    "configuration public request grammar or original intent differs")
        requests.add(hashlib.sha256(request).hexdigest())
        if carrier != "local":
            genesis = data["genesis.bin"]
            sdk.require(len(genesis) == 164 and genesis[:4] == b"\x00\x00\x00\x02"
                        and genesis[4:36] == genesis[36:68]
                        and all(any(genesis[i:i+32]) for i in (4, 36, 68, 100, 132)),
                        "configuration public genesis is truncated or misbound")
        hashes.update({name + "/" + leaf: hashlib.sha256(value).hexdigest() for leaf, value in data.items()})
    sdk.require(len(requests) == 6, "configuration scenarios reused a device registration request")
    return dict(completed=True, scope=SCOPE, language=language, release_claim_eligible=False,
                scenarios=sorted(directories), public_readbacks=hashes,
                extra_owner_cases=language != "C", signature_verification="shared native execution only")


def _qualify(outside: Path, output: Path, profile: str, runtime: dict, helper: Path, client: Path,
             run, *, language: str, collector: str = "") -> dict:
    sdk.require(profile in {"debug", "release"} and ((language == "Kotlin" and collector in {"Serial", "G1"})
                or (language in {"C", "Swift"} and not collector)), "configuration qualification profile differs")
    label = "configuration-" + language.lower() + "-" + profile + ("-" + collector.lower() if collector else "")
    evidence = outside / label
    evidence.mkdir(mode=0o700)
    identities = {name: sdk.snapshot(path, maximum=c.MAX_BINARY) for name, path in (("helper", helper), ("client", client))}
    environment = dict(runtime, QPC_CONFIGURATION_CLIENT=str(client), QPC_CONFIGURATION_LANGUAGE=language,
                       QPERIAPT_CONFIGURATION_EVIDENCE=str(evidence))
    stdout = run([str(helper), "independent_c_", "--nocapture", "--test-threads=1"], label, runtime=environment)
    checked = verify_execution(stdout, evidence, language=language)
    exported = output / "configuration-public" / language.lower() / profile / (collector.lower() or "default")
    for name, digest in checked["public_readbacks"].items():
        sdk.require(sdk.snapshot(evidence / name).sha256 == digest, "configuration public record changed before export")
        sdk.copy(evidence / name, exported / name)
    sdk.require(verify_execution(stdout, exported, language=language) == checked, "configuration exported readback differs")
    checked["binaries"] = {}
    for name, path in (("helper", helper), ("client", client)):
        identity = identities[name]
        sdk.require(sdk.snapshot(path, maximum=c.MAX_BINARY).sha256 == identity.sha256,
                    "configuration executable changed during execution")
        checked["binaries"][name] = dict(path=str(path), sha256=identity.sha256, bytes=identity.size)
    checked["collector"] = collector or None
    return checked


def qualify_native(outside, output, consumer, build, cargo, runtime, cc, platform_flags,
                   installed, filename, profile, run) -> dict:
    extra = ["--release"] if profile == "release" else []
    built = run([*cargo, "test", "--locked", "--offline", "--test", "first_configuration", "--no-run",
                 "--message-format=json", "-j", "2", *extra], "configuration-build-" + profile)
    helper = c.built_artifact(built, consumer, build, library=False, test_name="first_configuration")
    client = installed / "qpc-first-configuration-client"
    darwin = os.uname().sysname == "Darwin"
    run([str(cc), *platform_flags, "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wpedantic",
         *( ["-O2"] if profile == "release" else ["-O0", "-g"] ),
         str(consumer / "first_configuration_client.c"), "-I", str(consumer), "-L", str(installed), "-l" + c.LIBRARY,
         "-Wl,-rpath," + ("@loader_path" if darwin else "$ORIGIN"), "-o", str(client)], "configuration-compile-" + profile)
    if darwin:
        dependencies = run(["/usr/bin/otool", "-L", str(client)], "configuration-dependencies-" + profile).decode()
        loader = run(["/usr/bin/otool", "-l", str(client)], "configuration-loader-" + profile).decode()
    else:
        dependencies = run(["/usr/bin/readelf", "-d", str(client)], "configuration-dependencies-" + profile).decode()
        loader = dependencies
    c.verify_linkage(dependencies, loader, filename, darwin=darwin)
    sdk.require(run([str(client), "--guard"], "configuration-guard-" + profile, runtime=runtime)
                == b"QPC_CONFIGURATION_HEADER_GUARD_PASS\n", "configuration short-header guard did not execute")
    checked = _qualify(outside, output, profile, runtime, helper, client, run, language="C")
    checked["short_header_guard"] = True
    return checked


def qualify_foreign(outside, output, profile, runtime, native, run, client, *, language, collector="") -> dict:
    sdk.require(language in {"Swift", "Kotlin"}, "configuration foreign adapter differs")
    row = native["first_configuration"]
    sdk.require(row["completed"] and row["short_header_guard"] and row["language"] == "C",
                "configuration foreign qualification needs completed native configuration")
    helper = row["binaries"]["helper"]
    sdk.require(sdk.snapshot(Path(helper["path"]), maximum=c.MAX_BINARY).sha256 == helper["sha256"],
                "configuration native helper changed before foreign execution")
    return _qualify(outside, output, profile, runtime, Path(helper["path"]), client, run,
                    language=language, collector=collector)
