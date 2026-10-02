"""Source-bound public readback of the C device-parent and peer-child workloads."""
from pathlib import Path
import re

import rust_sdk_profile as sdk
from evidence_io import parse_strict_json_bytes

TEST = "c_device_parents_keep_peer_lifetimes_and_reconcile_original_delivery"
WITNESS_TEST = "c_device_parents_require_original_witness_and_preserve_child_lifetimes"
SCOPE = "same-host C device parent and peer children; shared native engine; independent local identity and original delivery recovery"
WITNESS_SCOPE = "same-host C device parent and peer lifetime admission under required signed TCP and mutual TLS witnesses"


def _passed(stdout: bytes, name: str, filtered: int) -> None:
    text = stdout.decode()
    sdk.require(re.findall(r"^test ([a-z_:]+) \.\.\. ok$", text, re.MULTILINE) == [name]
                and re.search(rf"^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; {filtered} filtered out;", text, re.MULTILINE),
                "device parent workload did not execute completely")


def _readers(directory: Path):
    public, logs = {}, {}
    def read(name, maximum=65536):
        record = sdk.snapshot(directory / name, maximum=maximum)
        public[name] = record.sha256
        return record.data
    def command(name, expected=None, *, lifecycle=False, server=None):
        data = read(name + ".stdout")
        if lifecycle:
            match = re.fullmatch(rb"device-parent-lifecycle-passed:busy=([0-9]+)\n", data)
            sdk.require(match is not None and int(match[1]) <= 64, "device admission retry receipt differs")
        elif server is not None:
            match = re.fullmatch(rb"listening:([1-9][0-9]{0,4})\n(.*)", data, re.DOTALL)
            sdk.require(match is not None and int(match[1]) <= 65535 and match[2] == server,
                        "device server readiness or result differs")
        else:
            sdk.require(data == expected, "device command result differs")
        sdk.require(read(name + ".stderr") == b"", "device command reported an error")
        for suffix in (".stdout", ".stderr"):
            logs[name + suffix] = public.pop(name + suffix)
    return public, logs, read, command


def verify_execution(stdout: bytes, directory: Path) -> dict:
    _passed(stdout, TEST, 7)
    public, logs, read, command = _readers(directory)
    report = parse_strict_json_bytes(read("c-device-parent-public-result.json"), label="C device parent result")
    fields = {"schema_version", "completed", "session", "message", "local_roles", "owner_capacity",
              "independent_readbacks", "independent_identity_refusals", "sdk_revocation_refused",
              "physical_reopen_changed_files", "release_claim_eligible"}
    sdk.require(type(report) is dict and set(report) == fields and report["completed"] is True
                and report["sdk_revocation_refused"] is True and report["release_claim_eligible"] is False,
                "device parent result fields or authority differ")
    for name, expected in {"schema_version": 1, "local_roles": 2, "owner_capacity": 64,
                           "independent_readbacks": 2, "independent_identity_refusals": 4}.items():
        sdk.require(type(report[name]) is int and report[name] == expected, "device parent case census differs")
    count = report["physical_reopen_changed_files"]
    sdk.require(type(count) is int and 0 <= count <= 6, "physical reopen control census differs")
    for name in ("session", "message"):
        value = report[name]
        sdk.require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) and value != "0" * 64,
                    "device operation identity differs")
    session, message = report["session"], report["message"]
    for role in ("initiator", "responder"):
        command(f"{role}/c-device-lifecycle", lifecycle=True)
        command(f"{role}/c-device-reopen-control", b"device-open-close-passed\n")
        for refusal in ("wrong-local-id", "wrong-signer"):
            command(f"{role}/c-device-{refusal}", b"device-rejected:103\n")
    for name, value in {"bootstrap-client": session + "\n", "next": message + "\n",
                        "unknown": "delivery-unknown-committed\n", "replay": "consumed\n",
                        "final-status": "3\n", "revoked": "device-rejected:603\n"}.items():
        command("initiator/c-device-" + name, value.encode())
    command("responder/c-device-bootstrap-server", server=f"served:1:0:0:0\n{session}\n{'0' * 64}\n".encode())
    command("responder/c-device-crash-server", server=b"")
    command("responder/c-device-replay-server", server=f"served:2:0:1:0\n{session}\n{message}\n".encode())
    sdk.require(read("responder/peer/application-" + message) == bytes.fromhex(session + message)
                + b"persisted before process exit", "device application readback differs")
    sdk.require({path.relative_to(directory).as_posix() for path in directory.glob("*/c-device-*.std*")}
                == logs.keys(), "device command census differs")
    return dict(report, scope=SCOPE, public_readbacks=public, command_logs=logs)


def verify_witness_execution(stdout: bytes, directory: Path) -> dict:
    _passed(stdout, WITNESS_TEST, 10)
    public, logs, read, command = _readers(directory)
    report = parse_strict_json_bytes(read("c-device-parent-witness-public-result.json"), label="C witnessed device result")
    flags = {"completed", "missing_witness_refused", "wrong_pin_refused", "bad_signature_refused", "missing_tls_key_refused"}
    numbers = {"schema_version": 1, "local_roles": 2, "witness_profiles": 2}
    sdk.require(type(report) is dict and set(report) == flags | numbers.keys() | {"release_claim_eligible"}
                and all(report[name] is True for name in flags) and report["release_claim_eligible"] is False
                and all(type(report[name]) is int and report[name] == value for name, value in numbers.items()),
                "witnessed device result fields or scope differ")
    for label, code in {"missing-witness": 216, "wrong-witness": 211, "bad-signature": 218, "missing-tls-key": 500}.items():
        command("initiator/witness-parent-" + label, f"device-rejected:{code}\n".encode())
    for role in ("initiator", "responder"):
        for carrier in ("signed-tcp", "mutual-tls"):
            command(f"{role}/witness-parent-{carrier}", lifecycle=True)
    sdk.require({path.relative_to(directory).as_posix() for path in directory.glob("*/witness-parent-*.std*")}
                == logs.keys(), "witnessed device command census differs")
    return dict(report, scope=WITNESS_SCOPE, public_readbacks=public, command_logs=logs)
