"""Require actual installed explicit-peer inputs, traffic and owner lifetimes.

The native coordinator verifies signatures and durable operations. Structural
readback binds public records; it is not an independent cryptographic engine.
"""
from pathlib import Path
import hashlib

import continuity_c_consumer as c
import continuity_c_device as device
import continuity_c_enrollment as enrollment
from continuity_c_witness import export_selected
import rust_sdk_profile as sdk

LIFETIME = b"QPC_CONFIGURED_PEER_LIFETIME_PASS\n"
SCOPE = "explicit independent peer inputs under original device ownership; installed foreign process and shared native Rust engine; same host"


def _qualify(outside, output, profile, runtime, helper, client, run, *, language, collector=""):
    sdk.require(profile in {"debug", "release"} and language in {"C", "Swift", "Kotlin"}
                and collector in {"", "G1", "Serial"}
                and ((language == "Kotlin") == bool(collector)), "peer configuration selection differs")
    label = "peer-configuration-" + language.lower() + "-" + profile + ("-" + collector.lower() if collector else "")
    evidence = outside / label
    environment = dict(runtime, QPERIAPT_C_OWNER_CLIENT=str(client),
                       QPERIAPT_PUBLIC_SERVICE_EVIDENCE=str(evidence))
    identities = {name: sdk.snapshot(path, maximum=c.MAX_BINARY)
                  for name, path in (("helper", helper), ("client", client))}
    stdout = run([str(helper), "--exact", enrollment.CONFIGURED_TEST, "--nocapture"], label, runtime=environment)
    destination = output / "peer-configuration-public" / language.lower() / profile / (collector.lower() or "default")
    checked = enrollment.export(stdout, evidence, destination / "registration", language=language, configured=True)
    checked["exported_public_files"] = dict(checked["public_readbacks"])
    if language != "C":
        lifetime = run([str(client), "peer-configuration-lifetime", str(evidence / "enrolled"),
                        str(evidence / "enrolled/peer"), checked["session"]], label + "-lifetime", runtime=environment)
        sdk.require(lifetime == LIFETIME, "configured peer lifetime probe did not execute completely")
        checked["lifetime"] = dict(completed=True, stdout_sha256=hashlib.sha256(lifetime).hexdigest(),
            scope="public parent release/collection with live child, explicit parent close and real lease reopen, pending-child cancellation; bounded Cleaner observation only for JVM orphan reclamation")
    checked.update(explicit_peer_inputs=True, language=language, collector=collector or None, scope=SCOPE, binaries={})
    for name, path in (("helper", helper), ("client", client)):
        identity = identities[name]
        sdk.require(sdk.snapshot(path, maximum=c.MAX_BINARY).sha256 == identity.sha256,
                    "peer configuration executable changed during execution")
        checked["binaries"][name] = dict(path=str(path), sha256=identity.sha256, bytes=identity.size)
    return checked


def qualify_native(outside, output, profile, runtime, helper, trace, client, run):
    sdk.require(run([str(client), "peer-configuration-guard"], "peer-configuration-guard-" + profile, runtime=runtime)
                == b"QPC_PEER_CONFIGURATION_HEADER_GUARD_PASS\n", "peer configuration short-header guard did not execute")
    checked = _qualify(outside, output, profile, runtime, helper, client, run, language="C")
    identity = sdk.snapshot(trace, maximum=c.MAX_BINARY)
    evidence = outside / ("peer-configuration-device-" + profile)
    environment = dict(runtime, QPERIAPT_C_OWNER_CLIENT=str(client), QPERIAPT_PUBLIC_SERVICE_EVIDENCE=str(evidence))
    stdout = run([str(trace), "--exact", device.CONFIGURED_TEST, "--nocapture"],
                 "peer-configuration-device-" + profile, runtime=environment)
    peers = device.verify_execution(stdout, evidence, configured=True)
    peers["exported_public_files"] = export_selected(peers, evidence,
        output / "peer-configuration-public/c" / profile / "device", SCOPE,
        replay=lambda path: device.verify_execution(stdout, path, configured=True))
    sdk.require(sdk.snapshot(trace, maximum=c.MAX_BINARY).sha256 == identity.sha256,
                "configured device trace changed during execution")
    checked.update(short_header_guard=True, device_peers=peers)
    checked["binaries"]["device_trace"] = dict(path=str(trace), sha256=identity.sha256, bytes=identity.size)
    return checked


def qualify_foreign(outside, output, profile, runtime, native, run, client, *, language, collector=""):
    sdk.require(language in {"Swift", "Kotlin"}, "unknown configured peer language")
    row = native["peer_configuration"]
    sdk.require(row["completed"] and row["explicit_peer_inputs"] and row["short_header_guard"]
                and row["device_peers"]["completed"] and row["language"] == "C",
                "configured peer foreign qualification requires complete native execution")
    helper = row["binaries"]["helper"]
    sdk.require(sdk.snapshot(Path(helper["path"]), maximum=c.MAX_BINARY).sha256 == helper["sha256"],
                "configured peer helper changed before foreign execution")
    return _qualify(outside, output, profile, runtime, Path(helper["path"]), client, run,
                    language=language, collector=collector)
