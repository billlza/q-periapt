"""Independent public readback of real C complete-account delivery and cancellation."""
from pathlib import Path
import re

import rust_sdk_profile as sdk
from evidence_io import parse_strict_json_bytes

TEST = "c_account_owner_requires_all_devices_and_reconciles_original_members"
SCOPE = "same-host C complete-account owner; three installations and two recipient devices; shared native protocol engine"
PAYLOAD = b"persisted before process exit"


def verify_execution(stdout: bytes, directory: Path, *, language: str = "C") -> dict:
    sdk.require(language in {"C", "Swift", "Kotlin"}, "unknown account client language")
    text = stdout.decode()
    sdk.require(re.findall(r"^test ([a-z_:]+) \.\.\. ok$", text, re.MULTILINE) == [TEST]
                and re.search(r"^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out;", text, re.MULTILINE),
                "complete-account workload did not execute completely")
    public, logs = {}, {}
    def read(name, maximum=65536):
        record = sdk.snapshot(directory / name, maximum=maximum)
        public[name] = record.sha256
        return record.data
    def command(name, expected=None):
        name = "initiator/c-account-" + name
        data = read(name + ".stdout")
        sdk.require(read(name + ".stderr") == b"", "account command reported an error")
        if expected is not None:
            sdk.require(data == expected, "account command result differs")
        for suffix in (".stdout", ".stderr"):
            logs[name + suffix] = public.pop(name + suffix)
        return data
    def identifier(value, length=32):
        sdk.require(type(value) is bytes and re.fullmatch(rb"[0-9a-f]{" + str(length * 2).encode() + rb"}", value)
                    and value != b"0" * (length * 2), "account operation identity differs")
        return bytes.fromhex(value.decode())
    def state(name, value):
        command(name, f"account-status:{value}\n{'0' * 64}\n".encode())

    report = parse_strict_json_bytes(read("initiator/c-account-result.json"), label="C account trace")
    flags = {"completed", "unknown_commit_reconciled", "cancelled_original_reconciled",
             "unary_refused", "reversed_targets_reconciled"}
    numbers = {"schema_version": 2, "devices": 3, "recipients": 2, "accounts": 2,
               "admission_refusals": 6, "shape_controls": 4, "application_readbacks": 5, "busy_owners": 3}
    sdk.require(type(report) is dict and set(report) == flags | numbers.keys() | {"cancellation_ms", "release_claim_eligible", "language"}
                and report["language"] == language and all(report[name] is True for name in flags) and report["release_claim_eligible"] is False
                and all(type(report[name]) is int and report[name] == value for name, value in numbers.items()),
                "account trace fields or census differ")
    elapsed = report["cancellation_ms"]
    sdk.require(type(elapsed) is int and 0 <= elapsed < 1000, "account cancellation exceeded observation bound")
    roots = ("initiator", "responder", "responder-2")
    accounts = [read(root + "/local-account") for root in roots]
    sdk.require(all(len(value) == 32 and value != bytes(32) for value in accounts)
                and accounts[0] != accounts[1] == accounts[2], "independent recipient account pins differ")
    devices = [read(root + "/local-device") for root in roots[1:]]
    sdk.require(all(len(value) == 16 and value != bytes(16) for value in devices)
                and devices[0] != devices[1], "recipient devices were aliased")
    connected = command("connect")
    lines = connected.splitlines()
    sdk.require(len(lines) == 2 and connected == b"\n".join(lines) + b"\n", "account bootstrap record differs")
    sessions = [identifier(line) for line in lines]
    sdk.require(sessions[0] != sessions[1], "account sessions were aliased")
    request = command("next")
    sdk.require(request.endswith(b"\n") and len(request) == 65, "original account ID framing differs")
    identifier(request[:-1])
    command("still-next", request)
    for index, code in enumerate((106, 1, 1, 302, 2, 211)):
        command(f"refusal-{index}", f"account-refused:{code}\n".encode())
        state(f"absent-{index}", 0)
    command("unknown", b"account-refused:311\n")
    state("committed-unknown", 2)
    command("changed-input", b"account-refused:211\n")
    command("unary-refused", b"account-refused:215\n")
    messages = []
    for index in range(2):
        data = command(f"deliver-{index}")
        parts = data.splitlines()
        sdk.require(len(parts) == 4 and parts[0] == b"account-delivered:1:1"
                    and data == b"\n".join(parts) + b"\n", "account member delivery record differs")
        session, message, device = identifier(parts[1]), identifier(parts[2]), identifier(parts[3], 16)
        sdk.require(session == sessions[index] and device == devices[index], "account member binding differs")
        messages.append(message)
        expected = session + message + PAYLOAD
        sdk.require(read(roots[index + 1] + "/application-" + message.hex()) == expected,
                    "original account application readback differs")
        retained = data.replace(b"account-delivered:1:1", b"account-delivered:1:0", 1)
        command(f"retained-{index}", retained)
        command(f"reversed-{index}", retained)
    state("committed-delivered", 2)
    cancelled = command("next-cancel")
    sdk.require(len(cancelled) == 65 and cancelled.endswith(b"\n") and cancelled != request,
                "cancelled account ID reused original operation")
    identifier(cancelled[:-1])
    command("cancel-active", f"account-refused:302\naccount-cancel-active:{elapsed}:3\n".encode())
    state("cancel-committed", 2)
    for index in range(2):
        data = command(f"after-cancel-{index}")
        parts = data.splitlines()
        sdk.require(len(parts) == 4 and parts[0] == b"account-delivered:1:1"
                    and data == b"\n".join(parts) + b"\n", "cancelled account replay record differs")
        session, message, device = identifier(parts[1]), identifier(parts[2]), identifier(parts[3], 16)
        sdk.require(session == sessions[index] and device == devices[index] and message != messages[index],
                    "cancelled account member binding differs")
        sdk.require(read(roots[index + 1] + "/application-" + message.hex()) == session + message + PAYLOAD,
                    "cancelled account application readback differs")
    sdk.require({path.relative_to(directory).as_posix() for path in directory.glob("*/c-account-*.std*")}
                == logs.keys() and len(logs) == 62, "account command census differs")
    return dict(report, scope=SCOPE.replace("C complete-account", language + " complete-account"), public_readbacks=public, command_logs=logs)
