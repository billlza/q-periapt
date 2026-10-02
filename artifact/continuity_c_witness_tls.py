"""Installed C witness TLS workload; finite runtime evidence, not a security proof."""
from pathlib import Path
import re

import rust_sdk_profile as sdk
from continuity_c_witness import export_selected
from evidence_io import parse_strict_json_bytes

TEST = "tls::c_tls_witness_connects_and_revoked_cleanup_keeps_original_authority"
SCOPE = "installed C operational/recovery owners over native mutual TLS witness; same host"


def verify_execution(stdout: bytes, directory: Path, *, language: str = "C") -> dict:
    sdk.require(language in {"C", "Swift", "Kotlin"}, "unsupported TLS witness language")
    text = stdout.decode()
    sdk.require(re.findall(r"^test ([a-z_:]+) \.\.\. ok$", text, re.MULTILINE) == [TEST]
                and re.search(r"^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out;", text, re.MULTILINE),
                "installed C TLS witness workload did not execute completely")
    public = {}

    def read(name, maximum=1048576):
        value = sdk.snapshot(directory / name, maximum=maximum)
        public[name] = value.sha256
        return value.data

    report = parse_strict_json_bytes(read("c-witness-tls-public-result.json"), label="C TLS witness result")
    sdk.require(set(report) == {"schema_version", "language", "completed", "carrier", "session", "message", "witness_exchanges",
                               "rejected_connections", "sdk_revoked_cleanup", "release_claim_eligible"},
                "C TLS witness result fields differ")
    sdk.require(type(report["schema_version"]) is int and report["schema_version"] == 2 and report["language"] == language
                and report["completed"] is True and report["sdk_revoked_cleanup"] is True
                and report["carrier"] == "q-periapt-anchor/1" and report["release_claim_eligible"] is False,
                "C TLS witness result scope differs")
    sdk.require(type(report["witness_exchanges"]) is int and report["witness_exchanges"] == 142
                and type(report["rejected_connections"]) is int and report["rejected_connections"] == 2,
                "C TLS witness exchange census differs")
    for name in ("session", "message"):
        sdk.require(type(report[name]) is str and re.fullmatch(r"[0-9a-f]{64}", report[name])
                    and report[name] != "0" * 64, "C TLS witness identity differs")
    session, message = report["session"], report["message"]
    expected = {
        "initiator/tls-missing-key": "rejected:500\n", "initiator/tls-wrong-name": "rejected:218\n",
        "initiator/tls-wrong-subject": "rejected:218\n", "initiator/tls-owner-kind": "operational-owner-not-recovery\n",
        "initiator/tls-bootstrap-client": session + "\n", "responder/tls-next": message + "\n",
        "responder/tls-send": "consumed\n", "responder/tls-revoked": "rejected:603\n",
        "responder/tls-cleanup-cancel": "cancelled-cleanup-not-frozen\n", "responder/tls-freeze": "",
        "responder/tls-ack": "", "responder/tls-retire": "original-report-closed-retired\n",
        "responder/tls-archive": "archive-closed-metadata-only\n",
    }
    servers = {"responder/tls-bootstrap-server": f"served:1:0:0:0\n{session}\n{'0' * 64}\n",
               "initiator/tls-message-server": f"served:2:0:1:1\n{session}\n{message}\n"}
    logs = verify_owner_readbacks(read, directory, session, message, expected, servers)
    return dict(report, scope=SCOPE.replace("installed C operational", "installed " + language + " operational"), public_readbacks=public, command_logs=logs,
                independent_implementation_qualified=False, full_tls_fault_matrix_qualified=False)


def verify_owner_readbacks(read, directory: Path, session: str, message: str, expected: dict, servers: dict) -> dict:
    effect = "initiator/application-" + message
    sdk.require(read(effect) == bytes.fromhex(session + message) + b"persisted before process exit"
                and len(list(directory.glob("*/application-*"))) == 1, "C TLS receiver effect differs")
    loss = read("responder/c-loss-report").decode()
    match = re.fullmatch(r"QPC-C-LOSS/1\nreport ([0-9a-f]{64})\nheader " + session +
                        r" ([0-9a-f]{64}) ([0-9a-f]{64}) ([0-9a-f]{32}) 2 1 0 0 0 0 0 0 1\n" +
                        r"epoch 0 0 1 1 0 0 0 0 0 " + "0" * 64 + r" 0 0 0\n", loss)
    sdk.require(match is not None and all(set(value) != {"0"} for value in match.groups()),
                "C TLS closure accounting differs")
    archive = read("responder/c-closure-archive")
    sdk.require(len(archive) == 362 and archive.startswith(b"QPCSCA01"), "C TLS closure archive differs")
    logs = {}
    for label in expected | servers:
        role, name = label.split("/")
        for suffix in ("stdout", "stderr"):
            leaf = f"{role}/witness-{name}.{suffix}"
            value = sdk.snapshot(directory / leaf, maximum=65536)
            logs[leaf] = value.sha256
            if suffix == "stderr":
                sdk.require(value.data == b"", "C TLS witness stderr is not empty")
            elif label in expected:
                sdk.require(value.data.decode() == expected[label], "C TLS witness command outcome differs")
            else:
                marker, tail = value.data.decode().split("\n", 1)
                port = re.fullmatch(r"listening:([1-9][0-9]{0,4})", marker)
                sdk.require(port is not None and int(port[1]) <= 65535 and tail == servers[label],
                            "C TLS witness server outcome differs")
    sdk.require({p.relative_to(directory).as_posix() for p in directory.glob("*/witness-*.std*")} == logs.keys(),
                "unexpected or missing C TLS witness command logs")
    return logs


def export_public(stdout: bytes, directory: Path, destination: Path) -> dict:
    return export_selected(verify_execution(stdout, directory), directory, destination, SCOPE,
                           replay=lambda path: verify_execution(stdout, path))
