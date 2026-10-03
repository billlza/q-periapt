"""Actual encrypted complete-account cleanup; signed-TCP reservation is fixture setup."""
from pathlib import Path
import re

import continuity_c_account_cleanup as cleanup
from continuity_c_account_witness import TLS_TEST as TEST
import rust_sdk_profile as sdk
from evidence_io import parse_strict_json_bytes

SCOPE = ("installed C original-account bootstrap and revoked cleanup over native mutual TLS witness; "
         "signed-TCP lost reservation and native loss-report oracle are separate fixture setup/readback; "
         "three original installations, no plaintext witness calls during foreign TLS phases; "
         "same host and shared engine; no lost TLS commit responses, own-account, power-loss or independent-engine qualification")
PHASES = {"bootstrap": True, "missing": False, "wrong-pin": False, "wrong-name": False,
          "wrong-subject": False, "freeze": True, "acknowledge": True, "retirement": True,
          "retired": True, "retired-missing": False, "retired-unavailable": False}


def scope(language: str) -> str:
    sdk.require(language in ("C", "Swift", "Kotlin"), "unqualified TLS account language")
    return SCOPE.replace("installed C ", "installed " + language + " ")


def phases(data: bytes, *, expected_phases: dict[str, bool] = PHASES) -> dict:
    sdk.require(len(data) <= 1024 and data.endswith(b"\n"), "TLS account phases truncated")
    rows = data.decode("ascii").splitlines()
    sdk.require(len(rows) == len(expected_phases), "TLS account phase omitted")
    result, previous = {}, 0
    for (label, admitted), row in zip(expected_phases.items(), rows, strict=True):
        match = re.fullmatch(rf"{label} (0|[1-9][0-9]*) (0|[1-9][0-9]*) 0", row)
        sdk.require(match is not None, "TLS account phase or plaintext count differs")
        before, after = map(int, match.groups())
        sdk.require(before == previous and before <= after <= 4096 and (after > before) == admitted,
                    "TLS account admission escaped its original phase")
        result[label] = dict(first_admission=before, after_last_admission=after, plaintext_exchanges=0)
        previous = after
    return result


def verify_execution(stdout: bytes, directory: Path, *, language: str = "C") -> dict:
    selected_scope = scope(language)
    text = stdout.decode()
    sdk.require(re.findall(r"^test ([a-z_:]+) \.\.\. ok$", text, re.MULTILINE) == [TEST]
                and re.search(r"^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 6 filtered out;",
                              text, re.MULTILINE), "TLS account trace did not execute completely")
    public = {}
    def read(name, maximum=1048576):
        item = sdk.snapshot(directory / name, maximum=maximum)
        public[name] = item.sha256
        return item.data
    report = parse_strict_json_bytes(read("account-tls-result.json"), label="TLS account result")
    sdk.require(isinstance(report, dict) and set(report) == {"schema_version", "language", "completed", "batch", "report",
        "carrier", "reservation_carrier", "witness_exchanges", "rejected_connections", "release_claim_eligible"}
        and type(report["schema_version"]) is int and report["schema_version"] == 1
        and report["language"] == language and report["completed"] is True
        and report["carrier"] == "q-periapt-anchor/1" and report["reservation_carrier"] == "signed-tcp"
        and report["release_claim_eligible"] is False and type(report["rejected_connections"]) is int
        and report["rejected_connections"] == 2, "TLS account result scope differs")
    accounting = cleanup.loss_report(directory)
    public.update(accounting["public_readbacks"])
    sdk.require(report["batch"] == accounting["batch"] and report["report"] == accounting["report"],
                "TLS cleanup changed original account or loss-report identity")
    observed = phases(read("account-tls-phases", 1024))
    counts = dict.fromkeys(PHASES, 0)
    counts.update(bootstrap={"C": 121, "Swift": 127, "Kotlin": 126}[language],
                  freeze=10, acknowledge=12, retirement=10, retired=1)
    sdk.require({label: row["after_last_admission"] - row["first_admission"]
                 for label, row in observed.items()} == counts,
                "TLS account admitted exchange workload differs")
    sdk.require(type(report["witness_exchanges"]) is int
                and report["witness_exchanges"] == observed["retired-unavailable"]["after_last_admission"],
                "TLS account exchange census differs")
    certificates = [read("account-tls-server-cert", 8192)] + [read(f"account-tls-client-cert-{i}", 8192) for i in range(3)]
    subjects = [read(f"account-tls-subject-{i}", 96) for i in range(3)]
    sdk.require(len(set(certificates)) == 4 and all(0 < len(value) <= 8192 for value in certificates)
                and len(set(subjects)) == 3 and all(len(value) == 96 for value in subjects),
                "TLS account credential or original subject census differs")
    outputs = {"reserve-lost": "account-refused:218\n", "missing": "account-selection-refused:216\n",
        "wrong-pin": "account-selection-refused:211\n", "wrong-name": "account-selection-refused:218\n",
        "wrong-subject": "account-selection-refused:218\n", "freeze": "account-frozen:" + report["report"] + "\n",
        "ack": "account-acknowledged:" + report["report"] + "\n", "retire": "account-retired\n",
        "retired": "account-selection-refused:112\n", "retired-missing": "account-selection-refused:216\n",
        "retired-unavailable": "account-selection-refused:218\n"}
    for label, expected in outputs.items():
        sdk.require(read("cleanup-" + label + ".stdout") == expected.encode()
                    and read("cleanup-" + label + ".stderr") == b"", "TLS account command outcome differs")
    for index in range(2):
        output = read(f"account-server-{index}.stdout").decode("ascii").splitlines()
        sdk.require(len(output) == 4 and re.fullmatch(r"listening:[1-9][0-9]{0,4}", output[0])
            and int(output[0].split(":")[1]) <= 65535
            and output[1:] == ["served:1:0:0:0", read(f"cleanup-session-{index}", 32).hex(), "0" * 64]
            and read(f"account-server-{index}.stderr") == b"", "TLS account bootstrap changed original session")
    result = dict(report, scope=selected_scope, phases=observed,
                  loss_accounting={k: v for k, v in accounting.items() if k != "public_readbacks"})
    if language == "Kotlin":
        from continuity_kotlin_consumer import account_parent_lifetime
        result["parent_lifetime"] = account_parent_lifetime(read("kotlin-account-parent-lifetime", 256))
    result["public_readbacks"] = {name: value for name, value in public.items() if not name.endswith((".stdout", ".stderr"))}
    result["command_logs"] = {name: value for name, value in public.items() if name.endswith((".stdout", ".stderr"))}
    return result
