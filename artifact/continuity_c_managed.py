"""Installed C managed traffic readback, including host-effect uncertainty."""
from pathlib import Path
import re

import rust_sdk_profile as sdk
from continuity_c_witness import RECORD_BYTES, commit, export_selected, transcript

TEST = "managed_c_session_preserves_original_delivery_and_revokes_cached_owners"
MARKER = (b"MANAGED_C_TRAFFIC same_session=true unknown_delivery=2 exact_retry=3 rekey=1 "
          b"query_closed=202 send_closed=1202 new_registry_old_owner_closed=1202 closed_no_dispatch=true "
          b"wrong_registry=211 bad_witness=218 release_qualified=false\n")
SCOPE = ("same-host installed managed C initiator and C receiver sharing the native engine; "
         "application TLS and signed-TCP witness; independently seeded registry and trust; "
         "not first-use enrollment, account retirement, independent implementation or other language qualification")
PAYLOAD = b"persisted before process exit"


def verify_execution(stdout: bytes, directory: Path) -> dict:
    text = stdout.decode()
    sdk.require(re.findall(r"^test ([a-z_]+) \.\.\. ok$", text, re.MULTILINE) == [TEST]
                and re.search(r"^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out;",
                              text, re.MULTILINE), "managed C workload did not execute completely")
    public, logs = {}, {}
    def read(name, maximum=65536, *, log=False):
        value = sdk.snapshot(directory / name, maximum=maximum)
        (logs if log else public)[name] = value.sha256
        return value.data
    sdk.require(read("managed-traffic-result") == MARKER, "managed C result or scope differs")
    identifiers = [read(name, 32) for name in ("managed-session", "managed-message", "managed-next-message")]
    sdk.require(all(len(value) == 32 and any(value) for value in identifiers)
                and identifiers[1] != identifiers[2], "managed C original identifiers differ")
    session, message, following = identifiers
    s, m, n = (value.hex() for value in identifiers)
    commands = {
        "connect": s + "\n", "next": m + "\n", "wrong-registry": "managed-rejected:211\n",
        "bad-witness": "managed-rejected:218\n", "uncertain": "managed-delivery-unknown:2\n",
        "closed": "managed-closed query=202 send=1202 reopened_registry_old_owner=1202 original_status=2\n",
        "resend": "managed-consumed:3\n", "rekey": "managed-rekey:1\n",
        "next-rekey": n + "\n", "post-rekey": "managed-consumed:3\n",
    }
    for label, expected in commands.items():
        sdk.require(read(f"managed-{label}.stdout", log=True) == expected.encode()
                    and read(f"managed-{label}.stderr", log=True) == b"", "managed C command outcome differs")
    servers = {"bootstrap": f"served:1:0:0:0\n{s}\n{'0'*64}\n", "unknown": "",
               "resend": f"served:2:0:1:0\n{s}\n{m}\n", "rekey": "server-rekey-1\n",
               "post-rekey": f"served:2:0:1:1\n{s}\n{n}\n"}
    for label, expected in servers.items():
        output = read(f"traffic-{label}.stdout", log=True)
        readiness, separator, body = output.partition(b"\n")
        port = re.fullmatch(rb"listening:([1-9][0-9]{0,4})", readiness)
        sdk.require(separator and port is not None and int(port[1]) <= 65535 and body == expected.encode()
                    and read(f"traffic-{label}.stderr", log=True) == b"", "managed C receiver outcome differs")
    expected_effects = {f"application-{m}", f"application-{n}"}
    sdk.require({p.name for p in (directory / "responder").glob("application-*")} == expected_effects,
                "managed C application-effect census differs")
    for identifier in (message, following):
        sdk.require(read("responder/application-" + identifier.hex()) == session + identifier + PAYLOAD,
                    "managed C host effect differs from the original operation")
    identity, public_key = read("initiator/witness-id", 32), read("initiator/witness-public", 1985)
    sdk.require(len(identity) == 32 and len(public_key) == 1985, "managed witness pin shape differs")
    authority = commit(b"Q-PERIAPT-CONTINUITY-ANCHOR-AUTHORITY/v1", identity + public_key)
    checked = transcript(read("managed-witness-transcript", RECORD_BYTES * 4096), authority,
                         expected_lost_advances=0)
    count = read("managed-witness-exchanges", 8)
    sdk.require(len(count) == 8 and int.from_bytes(count, "big") == checked["exchanges"]
                and checked["logical_advances"] > 0, "managed witness census differs")
    return {"completed": True, "scope": SCOPE, "release_claim_eligible": False,
            "session": s, "original_message": m, "post_rekey_message": n,
            "query_closed": 202, "send_closed": 1202, "reopened_registry_old_owner_closed": 1202,
            "closed_no_dispatch": True, "unknown_delivery_retained": True,
            "host_effect_deduplicated": True, "rekey_epoch": 1, "witness": checked,
            "public_readbacks": public, "command_logs": logs}


def qualify(outside: Path, output: Path, consumer: Path, installed: Path, build: Path,
            cc: Path, platform_flags: list[str], profile: str, cargo: list[str], run, *,
            darwin: bool, runtime: dict, filename: str) -> dict:
    from continuity_c_consumer import MAX_BINARY, built_artifact, verify_linkage
    executable = installed / "qpc-c-managed-client"
    run([str(cc), *platform_flags, "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wpedantic",
         *(["-O2"] if profile == "release" else ["-O0", "-g"]),
         str(consumer / "managed_client.c"), "-I", str(consumer), "-L", str(installed),
         "-lq_periapt_continuity_c_consumer", "-Wl,-rpath," + ("@loader_path" if darwin else "$ORIGIN"),
         "-o", str(executable)], "managed-compile-" + profile)
    if darwin:
        dependencies = run(["/usr/bin/otool", "-L", str(executable)], "managed-dependencies-" + profile).decode()
        loader = run(["/usr/bin/otool", "-l", str(executable)], "managed-loader-" + profile).decode()
    else:
        dependencies = run(["/usr/bin/readelf", "-d", str(executable)], "managed-dependencies-" + profile).decode()
        loader = dependencies
    verify_linkage(dependencies, loader, filename, darwin=darwin)
    built = run([*cargo, "test", "--locked", "--offline", "--test", "managed", "--no-run",
                 "--message-format=json", "-j", "2", *(["--release"] if profile == "release" else [])],
                "managed-build-" + profile)
    helper = built_artifact(built, consumer, build, library=False, test_name="managed")
    identities = {path: sdk.snapshot(path, maximum=MAX_BINARY).sha256
                  for path in (helper, executable, installed / filename)}
    evidence = outside / ("c-" + profile + "-managed-runtime")
    selected = dict(runtime, QPC_MANAGED_CLIENT=str(executable), QPERIAPT_PUBLIC_SERVICE_EVIDENCE=str(evidence))
    stdout = run([str(helper), "--exact", TEST, "--nocapture"], "managed-" + profile, runtime=selected)
    result = verify_execution(stdout, evidence)
    result["exported_public_files"] = export_selected(result, evidence, output / "c-managed-public" / profile,
        SCOPE, replay=lambda path: verify_execution(stdout, path))
    sdk.require(all(sdk.snapshot(path, maximum=MAX_BINARY).sha256 == digest for path, digest in identities.items()),
                "managed C binaries changed during qualification")
    result["binaries"] = {path.name: digest for path, digest in identities.items()}
    return result
