"""Installed C root controller recovery on the caller's default pthread stack."""
from pathlib import Path
import re

import rust_sdk_profile as sdk
from continuity_c_witness import RECORD_BYTES, commit, export_selected, transcript

TEST = "installed_c_root_controller_recovers_original_state_and_erasure_after_process_loss"
STAGES = ("begin", "preparing", "freeze", "freeze-retry", "retain", "retain-retry",
          "activation-unknown", "inventory", "prepare-report", "report", "prepare-ack",
          "journal", "signer", "verify")
CUTS = frozenset(("begin", "freeze", "retain", "inventory", "report", "prepare-ack", "journal", "signer"))
MARKER = (b"ROOT_C_LIFECYCLE processes=14 sigkill=8 witness_unknown=218 native_readbacks=3 "
          b"original_revision=2 report_preserved=true cleanup_keeps_successor=true "
          b"close_revokes_successor=true application_traffic=false\n")
SCOPE = ("same-host installed compiled C root controller on default pthread attributes, "
         "14 child processes and eight SIGKILL cuts after public calls; real signed-TCP witness "
         "query loss; three same-engine native readbacks. Not in-commit storage fault injection, "
         "application traffic, transition/adoption process variants, independent implementation or full release.")


def verify_execution(stdout: bytes, directory: Path, *, darwin: bool) -> dict:
    text = stdout.decode()
    sdk.require(re.findall(r"^test ([a-z_]+) \.\.\. ok$", text, re.MULTILINE) == [TEST]
                and re.search(r"^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out;",
                              text, re.MULTILINE), "C root workload did not execute completely")
    public, logs = {}, {}

    def read(name, maximum=65536, *, log=False):
        value = sdk.snapshot(directory / name, maximum=maximum)
        (logs if log else public)[name] = value.sha256
        return value.data

    def number(name):
        wire = read("public/" + name, 8)
        sdk.require(len(wire) == 8, "root numeric observation width differs")
        return int.from_bytes(wire, "big")

    sdk.require(read("public/result") == MARKER, "C root result or qualification scope differs")
    pids, stacks = [], {}
    for stage in STAGES:
        expected = b"" if stage in CUTS else f"root-stage-pass:{stage}\n".encode()
        sdk.require(read(stage + ".stdout", log=True) == expected
                    and read(stage + ".stderr", log=True) == b"", "C root stage outcome differs")
        pid = number("process-" + stage)
        sdk.require(0 < pid < 2**32 and pid not in pids, "root process observation differs")
        pids.append(pid)
        if stage in CUTS:
            sdk.require(number("cut-" + stage) == pid, "cut did not identify its owning process")
        if darwin:
            actual, configured = number("stack-" + stage), number("stack-default-" + stage)
            sdk.require(actual > 0 and configured > 0, "root thread stack observation absent")
            stacks[stage] = {"system_default_bytes": configured, "observed_bytes": actual}
    sdk.require({p.name for p in directory.glob("*.std*")} == set(logs), "C root log census differs")
    sdk.require({p.name for p in (directory / "public").glob("cut-*")} == {"cut-" + s for s in CUTS},
                "root process cut census differs")
    values = {}
    for name in ("registry-id", "family", "witness-id", "application", "account", "target-account",
                 "original-roster-digest", "target-roster-digest"):
        value = read("public/" + name, 32)
        sdk.require(len(value) == 32 and any(value), "root public identity differs")
        values[name] = value
    sdk.require(values["account"] != values["target-account"] and number("revision") == 1,
                "root original account mapping differs")
    for name in ("original-roster-version", "target-roster-version"):
        sdk.require(number(name) == 1, "root initial roster differs")
    key = read("public/witness-public", 1985)
    sdk.require(len(key) == 1985 and key[1952] in (2, 3), "root witness key shape differs")
    authority = commit(b"Q-PERIAPT-CONTINUITY-ANCHOR-AUTHORITY/v1", values["witness-id"] + key)
    old = commit(b"Q-PERIAPT-CONTINUITY-AUTHORITY-CANDIDATE/v1", values["account"]
                 + (1).to_bytes(8, "big") + values["original-roster-digest"] + values["family"])
    target = commit(b"Q-PERIAPT-CONTINUITY-AUTHORITY-CANDIDATE/v1", values["target-account"]
                    + (1).to_bytes(8, "big") + values["target-roster-digest"] + values["family"])
    setup = read("public/setup-witness-transcript", RECORD_BYTES * 4096)
    sdk.require(len(setup) == number("witness-start") * RECORD_BYTES,
                "root witness setup boundary differs")
    observed = transcript(read("public/witness-transcript", RECORD_BYTES * 4096), authority,
                          expected_lost_advances=0, expected_lost_queries=1, expected_subjects=2,
                          authority_observations=[(old, 5)] + [(target, 5)] * 7)
    sdk.require(observed["logical_advances"] == 2, "root activation changed its original journal more than once")
    for name, maximum in (("approved-plan", 8192), ("freeze-receipt", 65536), ("bound-proposal", 65536),
                          ("retirement-receipt", 8192), ("inventory", 313), ("inventory-receipt", 3690),
                          ("report-proposal", 353), ("report-receipt", 3730), ("host-report", 8388608), ("host-ack", 3730)):
        wire = read("public/" + name, maximum)
        fixed = {"retirement-receipt": 3449, "inventory": 313, "inventory-receipt": 3690,
                 "report-proposal": 353, "report-receipt": 3730, "host-ack": 3730}
        sdk.require(bool(wire) and (name not in fixed or len(wire) == fixed[name]),
                    "root original public proof is absent or truncated")
        headers = {"approved-plan": b"QPAFPL01", "bound-proposal": b"QPARPL02", "host-report": b"QPRDMD01"}
        sdk.require(name not in headers or wire.startswith(headers[name]), "root public proof grammar differs")
    return {"completed": True, "scope": SCOPE, "release_claim_eligible": False,
            "processes": len(pids), "sigkill_cuts": len(CUTS), "native_readbacks": 3,
            "application_traffic": False, "witness": observed, "default_thread_stacks": stacks,
            "public_readbacks": public, "command_logs": logs}


def qualify(outside: Path, output: Path, consumer: Path, installed: Path, build: Path,
            cc: Path, platform_flags: list[str], profile: str, cargo: list[str], run, *,
            darwin: bool, runtime: dict, filename: str) -> dict:
    from continuity_c_consumer import MAX_BINARY, built_artifact, verify_linkage
    executable = installed / "qpc-c-root-client"
    run([str(cc), *platform_flags, "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wpedantic", "-pthread",
         *(["-O2"] if profile == "release" else ["-O0", "-g"]), str(consumer / "root_client.c"),
         "-I", str(consumer), "-L", str(installed), "-lq_periapt_continuity_c_consumer",
         "-Wl,-rpath," + ("@loader_path" if darwin else "$ORIGIN"), "-o", str(executable)], "root-compile-" + profile)
    if darwin:
        dependencies = run(["/usr/bin/otool", "-L", str(executable)], "root-dependencies-" + profile).decode()
        loader = run(["/usr/bin/otool", "-l", str(executable)], "root-loader-" + profile).decode()
    else:
        dependencies = run(["/usr/bin/readelf", "-d", str(executable)], "root-dependencies-" + profile).decode()
        loader = dependencies
    verify_linkage(dependencies, loader, filename, darwin=darwin)
    built = run([*cargo, "test", "--locked", "--offline", "--test", "root", "--no-run",
                 "--message-format=json", "-j", "2", *(["--release"] if profile == "release" else [])], "root-build-" + profile)
    helper = built_artifact(built, consumer, build, library=False, test_name="root")
    identities = {path: sdk.snapshot(path, maximum=MAX_BINARY).sha256 for path in (helper, executable, installed / filename)}
    evidence = outside / ("c-" + profile + "-root-runtime")
    selected = dict(runtime, QPC_ROOT_CLIENT=str(executable), QPC_ROOT_EVIDENCE=str(evidence))
    # The reference preconditioning owns a fresh temporary installation, not a
    # prior main-traffic fixture supplied by the enclosing package collector.
    selected.pop("QPERIAPT_PUBLIC_SERVICE_EVIDENCE", None)
    stdout = run([str(helper), "--exact", TEST, "--nocapture"], "root-" + profile, runtime=selected)
    result = verify_execution(stdout, evidence, darwin=darwin)
    result["exported_public_files"] = export_selected(result, evidence, output / "c-root-public" / profile,
        SCOPE, replay=lambda path: verify_execution(stdout, path, darwin=darwin))
    sdk.require(all(sdk.snapshot(path, maximum=MAX_BINARY).sha256 == digest for path, digest in identities.items()),
                "root C binaries changed during qualification")
    result["binaries"] = {path.name: digest for path, digest in identities.items()}
    return result
