"""Installed complete-account delivery with the original mutual-TLS witness."""
from pathlib import Path
import re

import continuity_c_account_tls as tls
from continuity_c_account_witness import DELIVERY_TEST as TEST
from evidence_io import parse_strict_json_bytes
import rust_sdk_profile as sdk

SCOPE = ("installed C complete-account delivery through the original native mutual-TLS witness; "
         "three installations, two recipient devices; application commit then receiver exit, original-ID retry and retained consumption; "
         "same host and shared engine; no own-account, independent witness engine, power-loss or complete fault-matrix qualification")
PHASES = dict.fromkeys(("bootstrap", "batch", "unknown", "status", "delivery0", "retained0", "delivery1", "retained1"), True)
PAYLOAD = b"persisted before process exit"


def scope(language: str) -> str:
    sdk.require(language in ("C", "Swift", "Kotlin"), "unqualified account delivery language")
    return SCOPE.replace("installed C ", "installed " + language + " ")


def identifier(data: bytes, length: int = 32) -> bytes:
    sdk.require(re.fullmatch(rb"[0-9a-f]{" + str(length * 2).encode() + rb"}", data) is not None
                and data != b"0" * (length * 2), "account delivery identifier differs")
    return bytes.fromhex(data.decode())


def listening(data: bytes) -> list[bytes]:
    lines = data.splitlines()
    sdk.require(lines and re.fullmatch(rb"listening:[1-9][0-9]{0,4}", lines[0]) is not None
                and int(lines[0].split(b":")[1]) <= 65535 and data == b"\n".join(lines) + b"\n",
                "account delivery receiver framing differs")
    return lines[1:]


def delivered(data: bytes, session: bytes, device: bytes) -> bytes:
    lines = data.splitlines()
    sdk.require(len(lines) == 4 and data == b"\n".join(lines) + b"\n" and lines[0] == b"account-delivered:1:1",
                "account member delivery framing differs")
    sdk.require(identifier(lines[1]) == session and identifier(lines[3], 16) == device,
                "account member delivery binding differs")
    return identifier(lines[2])


def phase_workload(data: bytes, language: str) -> dict:
    scope(language)
    observed = tls.phases(data, expected_phases=PHASES)
    counts = dict(zip(PHASES, ({"C": 121, "Swift": 127, "Kotlin": 126}[language], 5, 48, 4, 33, 10, 35, 10), strict=True))
    sdk.require({name: row["after_last_admission"] - row["first_admission"] for name, row in observed.items()} == counts,
                "account delivery phase workload differs")
    return observed


def verify_execution(stdout: bytes, directory: Path, *, language: str = "C") -> dict:
    selected_scope = scope(language)
    text = stdout.decode()
    sdk.require(re.findall(r"^test ([a-z_:]+) \.\.\. ok$", text, re.MULTILINE) == [TEST]
                and re.search(r"^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 6 filtered out;", text, re.MULTILINE),
                "account delivery trace did not execute completely")
    public = {}
    def read(name, maximum=65536):
        item = sdk.snapshot(directory / name, maximum=maximum); public[name] = item.sha256
        return item.data
    def command(prefix, expected=None):
        output = read(prefix + ".stdout")
        sdk.require(read(prefix + ".stderr") == b"", "account delivery command diagnostic differs")
        if expected is not None:
            sdk.require(output == expected, "account delivery command outcome differs: " + prefix)
        return output

    report = parse_strict_json_bytes(read("initiator/account-delivery-result.json"), label="account delivery result")
    sdk.require(isinstance(report, dict) and set(report) == {"schema_version", "language", "completed", "carrier",
        "witness_admissions", "batch", "release_claim_eligible"}
        and type(report["schema_version"]) is int and report["schema_version"] == 1
        and report["language"] == language and report["completed"] is True and report["release_claim_eligible"] is False
        and report["carrier"] == "q-periapt-anchor/1" and type(report["witness_admissions"]) is int
        and report["witness_admissions"] == {"C": 266, "Swift": 272, "Kotlin": 271}[language],
        "account delivery scope or census differs")
    sdk.require(type(report["batch"]) is str, "account delivery batch type differs")
    batch = identifier(report["batch"].encode())
    phases = phase_workload(read("initiator/account-delivery-phases", 1024), language)
    sdk.require(phases["retained1"]["after_last_admission"] == report["witness_admissions"],
                "account delivery phase census differs")
    roots = ["initiator", "responder", "responder-2"]
    accounts = [read(p + "/local-account", 32) for p in roots]
    devices = [read(p + "/local-device", 16) for p in roots]
    sdk.require(all(len(a) == 32 and a != bytes(32) for a in accounts) and accounts[0] != accounts[1] == accounts[2],
                "account delivery recipient accounts differ")
    sdk.require(len(set(devices)) == 3 and all(len(d) == 16 and d != bytes(16) for d in devices),
                "account delivery device identities differ")
    connected = command("initiator/cleanup-connect")
    lines = connected.splitlines()
    sdk.require(len(lines) == 2 and connected == b"\n".join(lines) + b"\n", "account delivery bootstrap framing differs")
    sessions = [identifier(line) for line in lines]
    sdk.require(sessions[0] != sessions[1], "account delivery sessions were aliased")
    command("initiator/cleanup-delivery-next", batch.hex().encode() + b"\n")
    command("initiator/cleanup-delivery-unknown", b"account-refused:311\n")
    command("initiator/cleanup-delivery-unknown-status", b"account-status:2\n" + b"0" * 64 + b"\n")
    sdk.require(listening(command("responder/cleanup-delivery-crash")) == []
                and read("initiator/account-delivery-crash-exit", 4) == (77).to_bytes(4, "big", signed=True),
                "account delivery original receiver exit differs")
    original = read("initiator/account-delivery-original-message", 32)
    sdk.require(len(original) == 32 and original != bytes(32), "account delivery original message differs")
    first_bytes = read("initiator/account-delivery-original-application")
    sdk.require(first_bytes == sessions[0] + original + PAYLOAD, "account first application snapshot differs")
    application = {}
    for index, peer in enumerate(roots[1:]):
        bootstrap = command(peer + "/cleanup-account-server")
        command(f"initiator/account-server-{index}", bootstrap)
        sdk.require(listening(bootstrap) == [b"served:1:0:0:0", sessions[index].hex().encode(), b"0" * 64],
                    "account delivery bootstrap peer differs")
        output = command(f"initiator/cleanup-delivery-member-{index}")
        message = delivered(output, sessions[index], devices[index + 1])
        sdk.require(index != 0 or message == original, "account retry replaced its original message")
        leaf = peer + "/application-" + message.hex()
        received = read(leaf)
        sdk.require(received == sessions[index] + message + PAYLOAD and (index != 0 or received == first_bytes),
                    "account receiver application readback differs")
        application[leaf] = public[leaf]
        sdk.require(listening(command(peer + "/cleanup-delivery-retry")) ==
                    [b"served:2:0:1:" + str(index).encode(), sessions[index].hex().encode(), message.hex().encode()],
                    "account application retry created another effect or skipped pending consumption")
        command(f"initiator/cleanup-delivery-retained-{index}", output.replace(b"account-delivered:1:1", b"account-delivered:1:0", 1))
        sdk.require({p.name for p in (directory / peer).glob("application-*")} == {"application-" + message.hex()},
                    "account delivery produced extra application records")
    certificates = [read("initiator/account-tls-server-cert", 8192)] + [read(f"initiator/account-tls-client-cert-{i}", 8192) for i in range(3)]
    subjects = [read(f"initiator/account-tls-subject-{i}", 96) for i in range(3)]
    sdk.require(len(set(certificates)) == 4 and all(certificates) and len(set(subjects)) == 3 and all(len(s) == 96 for s in subjects),
                "account delivery TLS authority census differs")
    result = dict(report, scope=selected_scope, phases=phases, original_message=original.hex(), application_readbacks=application)
    if language == "Kotlin":
        from continuity_kotlin_consumer import account_parent_lifetime
        result["parent_lifetime"] = account_parent_lifetime(read("initiator/kotlin-account-parent-lifetime", 256))
    result["public_readbacks"] = {name: value for name, value in public.items() if not name.endswith((".stdout", ".stderr"))}
    result["command_logs"] = {name: value for name, value in public.items() if name.endswith((".stdout", ".stderr"))}
    return result
