"""Installed C root controller recovery on the caller's default pthread stack."""
from pathlib import Path
import re

import rust_sdk_profile as sdk
from continuity_c_witness import RECORD_BYTES, commit, export_selected, transcript
import continuity_c_root_traffic as traffic
import continuity_c_root_alternatives as alternatives
from continuity_c_root_reverse import MARKER as REVERSE_MARKER

TEST = "installed_c_root_controller_recovers_original_state_and_erasure_after_process_loss"
STAGES = ("begin", "preparing", "freeze", "freeze-retry", "retain", "retain-retry",
          "activation-unknown", "inventory", "prepare-report", "report", "prepare-ack",
          "journal", "signer", "verify")
CUTS = frozenset(("begin", "freeze", "retain", "inventory", "report", "prepare-ack", "journal", "signer"))
MARKER = (b"ROOT_C_LIFECYCLE processes=14 sigkill=8 witness_unknown=218 native_readbacks=3 "
          b"original_revision=2 report_preserved=true cleanup_keeps_successor=true "
          b"close_revokes_successor=true application_traffic=true\n")
SCOPE = ("same-host installed compiled C root controller on default pthread attributes, "
         "31 child processes, nine SIGKILL cuts after public calls and one inside a persisted host callback; real signed-TCP witness "
         "query loss; independent C peer-root association; post-cutover mutual TLS, original-message "
         "recovery after peer effect persistence and sender loss, then rekey, another outbound message "
         "and reverse-message recovery after root receiver loss; "
         "three same-engine native readbacks. Not in-commit storage fault injection, transition/adoption "
         "process variants, independent implementation, cross-host/device or full release qualification.")


def scope(variant, *, windows=False):
    if windows:
        return scope(variant).replace('default pthread attributes', 'default native thread attributes').replace('SIGKILL', 'TerminateProcess')
    if variant == "original":
        return SCOPE
    stages, cuts = alternatives.layout(variant)
    return (f"same-host installed compiled C root {variant} recovery on default pthread attributes; "
            f"{len(stages) + 17} child processes and {len(cuts) + 2} SIGKILL cuts; original approval inputs, "
            "cleanup and bidirectional application-message recovery after rekey. Native readbacks use "
            "the same engine. Not in-commit storage fault injection, independent implementation, "
            "cross-host/device, power-loss or full release qualification.")


def verify_execution(stdout: bytes, directory: Path, *, darwin: bool, variant: str = "original", cut_ready: bool = False, windows: bool = False) -> dict:
    sdk.require(not (darwin and windows), 'root platform observations conflict')
    stages, cuts = (STAGES, CUTS) if variant == "original" else alternatives.layout(variant)
    marker = MARKER if variant == "original" else alternatives.marker(variant)
    if windows:
        marker = marker.replace(b'sigkill', b'terminateprocess')
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

    sdk.require(read("public/result") == marker, "C root result or qualification scope differs")
    pids, stacks = [], {}
    for stage in stages:
        expected = (f"root-cut-ready:{stage}\n".encode() if cut_ready else b"") if stage in cuts else f"root-stage-pass:{stage}\n".encode()
        sdk.require(read(stage + ".stdout", log=True) == expected
                    and read(stage + ".stderr", log=True) == b"", "C root stage outcome differs")
        pid = number("process-" + stage)
        sdk.require(0 < pid < 2**32 and pid not in pids, "root process observation differs")
        pids.append(pid)
        if stage in cuts:
            sdk.require(number("cut-" + stage) == pid, "cut did not identify its owning process")
        if darwin:
            actual, configured = number("stack-" + stage), number("stack-default-" + stage)
            sdk.require(actual > 0 and configured > 0, "root thread stack observation absent")
            stacks[stage] = {"system_default_bytes": configured, "observed_bytes": actual}
    sdk.require({p.name for p in directory.glob("*.std*")} == set(logs), "C root log census differs")
    sdk.require({p.name for p in (directory / "public").glob("cut-*")} == {"cut-" + s for s in cuts},
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
    freeze_proofs = () if variant == "adoption" else (("freeze-receipt", 65536),)
    for name, maximum in (("approved-plan", 8192), *freeze_proofs, ("bound-proposal", 65536),
                          ("retirement-receipt", 8192), ("inventory", 313), ("inventory-receipt", 3690),
                          ("report-proposal", 353), ("report-receipt", 3730), ("host-report", 8388608), ("host-ack", 3730)):
        wire = read("public/" + name, maximum)
        fixed = {"retirement-receipt": 3449, "inventory": 313, "inventory-receipt": 3690,
                 "report-proposal": 353, "report-receipt": 3730, "host-ack": 3730}
        sdk.require(bool(wire) and (name not in fixed or len(wire) == fixed[name]),
                    "root original public proof is absent or truncated")
        headers = {"approved-plan": b"QPAFPL01", "bound-proposal": b"QPARPL02", "host-report": b"QPRDMD01"}
        sdk.require(name not in headers or wire.startswith(headers[name]), "root public proof grammar differs")
    alternative = None if variant == "original" else alternatives.verify(read, variant)
    traffic_marker = traffic.MARKER.replace(b'sigkill', b'terminateprocess') if windows else traffic.MARKER
    reverse_marker = REVERSE_MARKER.replace(b'sigkill', b'terminateprocess') if windows else REVERSE_MARKER
    sdk.require(traffic_marker.decode().rstrip("\n") in text.splitlines(), "root traffic workload marker absent")
    sdk.require(reverse_marker.decode().rstrip("\n") in text.splitlines(), "reverse root workload marker absent")
    traffic_result = traffic.verify(directory, read, authority=authority, original=old, target=target,
                                   history=setup + read("public/witness-transcript", RECORD_BYTES * 4096),
                                   previous_pids=pids, darwin=darwin, cut_ready=cut_ready, windows=windows)
    return {"completed": True, "scope": scope(variant, windows=windows), "alternative": alternative, "release_claim_eligible": False,
            "processes": len(pids) + 17, "terminateprocess_cuts" if windows else "sigkill_cuts": len(cuts) + 2, "native_readbacks": 3,
            "application_traffic": traffic_result, "witness": observed, "default_thread_stacks": stacks,
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
    peer_executable = installed / "qpc-c-client"
    identities = {path: sdk.snapshot(path, maximum=MAX_BINARY).sha256
                  for path in (helper, executable, peer_executable, installed / filename)}
    def execute(variant):
        suffix = "" if variant == "original" else "-" + variant
        evidence = outside / ("c-" + profile + "-root-runtime" + suffix)
        selected = dict(runtime, QPC_ROOT_CLIENT=str(executable), QPC_ROOT_EVIDENCE=str(evidence),
                        QPERIAPT_C_CLIENT=str(peer_executable), QPC_ROOT_VARIANT=variant, QPC_ROOT_CLIENT_LANGUAGE="C")
        # Each route owns fresh state; no recovery input comes from another run.
        selected.pop("QPERIAPT_PUBLIC_SERVICE_EVIDENCE", None)
        stdout = run([str(helper), "--exact", TEST, "--nocapture"], "root-" + profile + suffix, runtime=selected)
        result = verify_execution(stdout, evidence, darwin=darwin, variant=variant)
        result["exported_public_files"] = export_selected(result, evidence, output / "c-root-public" / (profile + suffix),
            scope(variant), replay=lambda path: verify_execution(stdout, path, darwin=darwin, variant=variant))
        return result
    result = execute("original")
    result["alternatives"] = {variant: execute(variant) for variant in alternatives.VARIANTS}
    sdk.require(all(sdk.snapshot(path, maximum=MAX_BINARY).sha256 == digest for path, digest in identities.items()),
                "root C binaries changed during qualification")
    result["binaries"] = {path.name: digest for path, digest in identities.items()}
    result["driver"] = {"path": str(helper), "sha256": identities[helper]}
    result["peer"] = {"path": str(peer_executable), "sha256": identities[peer_executable]}
    return result
