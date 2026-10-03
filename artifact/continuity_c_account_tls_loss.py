"""Foreign original-account recovery after native committed TLS replies are withheld."""
from pathlib import Path
import re

import continuity_c_account_cleanup as cleanup
from continuity_c_account_witness import TLS_LOSS_TEST as TEST, PHASES
import rust_sdk_profile as sdk
from evidence_io import parse_strict_json_bytes

SCOPE = ("installed C original-account reservation/freeze/acknowledgement/retirement under native mutual TLS; "
         "four encrypted replies withheld after observed native witness commits; original TLS reconciliation before native readback; "
         "native fixture preparation/readback uses signed TCP separately; same host and shared engine; "
         "no independent TLS/witness implementation, power-loss or complete encrypted fault matrix qualification")


def scope(language: str) -> str:
    sdk.require(language in ("C", "Swift", "Kotlin"), "unqualified TLS loss language")
    return SCOPE.replace("installed C ", "installed " + language + " ")


def exchanges(data: bytes, stage_bytes: bytes) -> dict:
    sdk.require(len(data) <= 128 * 1024 and data.endswith(b"\n"), "TLS loss exchange framing differs")
    records = []
    for index, line in enumerate(data.decode("ascii").splitlines()):
        match = re.fullmatch(rf"{index} ([01]) ([01]) ([1-9][0-9]*)", line)
        sdk.require(match is not None and index < 4096 and int(match[3]) <= 256 * 1024,
                    "TLS loss exchange index or byte bound differs")
        advanced, delivered, count = map(int, match.groups())
        sdk.require(delivered or advanced, "TLS loss preceded native commitment")
        records.append(dict(advanced=bool(advanced), delivered=bool(delivered), encrypted_reply_bytes=count))
    sdk.require(records and len(stage_bytes) <= 512 and stage_bytes.endswith(b"\n"), "TLS loss stages missing")
    lines = stage_bytes.decode("ascii").splitlines()
    sdk.require(len(lines) == len(PHASES), "TLS loss phase omitted")
    stages, previous, selected = {}, 0, set()
    for phase, line in zip(PHASES, lines, strict=True):
        match = re.fullmatch(rf"{phase} (0|[1-9][0-9]*) ([1-9][0-9]*) (0|[1-9][0-9]*)", line)
        sdk.require(match is not None, "TLS loss phase framing differs")
        first, after, lost = map(int, match.groups())
        sdk.require(previous <= first <= lost < after <= len(records)
                    and [index for index in range(first, after) if not records[index]["delivered"]] == [lost],
                    "TLS loss escaped its original phase")
        previous = after; selected.add(lost)
        stages[phase] = dict(first_exchange=first, after_last_exchange=after, lost_exchange=lost)
    sdk.require(selected == {index for index, row in enumerate(records) if not row["delivered"]},
                "TLS loss census differs")
    return dict(exchanges=len(records), native_advances=sum(row["advanced"] for row in records),
                stages=stages, lost_indices=sorted(selected))


def require_workload(observed: dict, language: str) -> None:
    scope(language)
    offset = {"C": 0, "Swift": 6, "Kotlin": 5}[language]
    stages = {phase: dict(first_exchange=first + offset, after_last_exchange=after + offset,
                          lost_exchange=lost + offset)
              for phase, (first, after, lost) in zip(PHASES,
                  ((121, 131, 130), (136, 140, 139), (149, 156, 155), (164, 168, 167)), strict=True)}
    sdk.require(observed == dict(exchanges=178 + offset, native_advances=36, stages=stages,
                                lost_indices=[130 + offset, 139 + offset, 155 + offset, 167 + offset]),
                "TLS loss admitted exchange workload differs")


def verify_execution(stdout: bytes, directory: Path, *, language: str = "C") -> dict:
    selected_scope = scope(language)
    text = stdout.decode()
    sdk.require(re.findall(r"^test ([a-z_:]+) \.\.\. ok$", text, re.MULTILINE) == [TEST]
        and re.search(r"^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 6 filtered out;", text, re.MULTILINE),
        "TLS loss trace did not execute completely")
    public = {}
    def read(name, maximum=1048576):
        item = sdk.snapshot(directory / name, maximum=maximum); public[name] = item.sha256
        return item.data
    report = parse_strict_json_bytes(read("account-tls-loss-result.json"), label="TLS account loss result")
    sdk.require(isinstance(report, dict) and set(report) == {"schema_version", "language", "completed", "batch", "report",
        "carrier", "lost_advances", "witness_exchanges", "release_claim_eligible"}
        and type(report["schema_version"]) is int and report["schema_version"] == 1
        and report["language"] == language and report["completed"] is True and report["release_claim_eligible"] is False
        and report["carrier"] == "q-periapt-anchor/1" and type(report["lost_advances"]) is int and report["lost_advances"] == 4,
        "TLS account loss scope differs")
    accounting = cleanup.loss_report(directory); public.update(accounting["public_readbacks"])
    sdk.require(report["batch"] == accounting["batch"] and report["report"] == accounting["report"],
                "TLS loss changed original operation or loss report")
    observed = exchanges(read("account-tls-loss-exchanges", 128 * 1024), read("account-tls-loss-stages", 512))
    require_workload(observed, language)
    sdk.require(type(report["witness_exchanges"]) is int and report["witness_exchanges"] == observed["exchanges"],
                "TLS loss exchange census differs")
    certificates = [read("account-tls-server-cert", 8192)] + [read(f"account-tls-client-cert-{i}", 8192) for i in range(3)]
    subjects = [read(f"account-tls-subject-{i}", 96) for i in range(3)]
    sdk.require(len(set(certificates)) == 4 and all(0 < len(value) <= 8192 for value in certificates)
                and len(set(subjects)) == 3 and all(len(value) == 96 for value in subjects), "TLS loss authority census differs")
    outputs = {"reserve-lost": "account-refused:218\n", "reserve-reconciled": "account-status:1\n" + "0" * 64 + "\n",
        "missing": "account-selection-refused:216\n", "wrong-pin": "account-selection-refused:211\n",
        "freeze-lost": "account-freeze-outcome-unavailable\n", "freeze-reconciled": "account-frozen:" + report["report"] + "\n",
        "ack-lost": "account-acknowledgement-outcome-unavailable\n", "ack-reconciled": "account-acknowledged:" + report["report"] + "\n",
        "retire-lost": "account-retirement-outcome-unavailable\n", "retire-reconciled": "account-retired\n",
        "retired": "account-selection-refused:112\n", "retired-missing": "account-selection-refused:216\n",
        "retired-unavailable": "account-selection-refused:218\n"}
    for label, expected in outputs.items():
        sdk.require(read("cleanup-" + label + ".stdout") == expected.encode() and read("cleanup-" + label + ".stderr") == b"",
                    "TLS loss foreign command outcome differs")
    for index in range(2):
        lines = read(f"account-server-{index}.stdout").decode("ascii").splitlines()
        sdk.require(len(lines) == 4 and re.fullmatch(r"listening:[1-9][0-9]{0,4}", lines[0])
            and int(lines[0].split(":")[1]) <= 65535
            and lines[1:] == ["served:1:0:0:0", read(f"cleanup-session-{index}", 32).hex(), "0" * 64]
            and read(f"account-server-{index}.stderr") == b"", "TLS loss original bootstrap differs")
    result = dict(report, scope=selected_scope, observations=observed,
        loss_accounting={k: v for k, v in accounting.items() if k != "public_readbacks"})
    if language == "Kotlin":
        from continuity_kotlin_consumer import account_parent_lifetime
        result["parent_lifetime"] = account_parent_lifetime(read("kotlin-account-parent-lifetime", 256))
    result["public_readbacks"] = {name: value for name, value in public.items() if not name.endswith((".stdout", ".stderr"))}
    result["command_logs"] = {name: value for name, value in public.items() if name.endswith((".stdout", ".stderr"))}
    return result
