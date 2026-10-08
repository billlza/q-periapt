"""Cross-read installed retirement receipts, host accounting and actual application effects.

Native public APIs authenticate signatures and the private report MAC. This reader
checks public framing and bindings; it is not an independent protocol implementation.
"""
from pathlib import Path
import re

import rust_sdk_profile as sdk
from evidence_io import parse_strict_json_bytes
from continuity_c_witness import commit

STAGES = ("inventory", "prepare-report", "report", "report-reopen", "prepare-ack",
          "erase-journal", "erase-signer", "verify")
FILES = frozenset({"witness-request-count", "witness-id", "witness-public", "witness-subject", "retirement-proposal",
                   "retirement-receipt", "retirement-inventory", "retirement-inventory-receipt",
                   "retirement-report-proposal", "retirement-report-receipt", "retirement-host-report", "retirement-host-report-verified",
                   "retirement-report-reopened", "retirement-ack", "retirement-verified", "old-effect",
                   "new-effect", "signer-terminal", "result.json"}
                  | {"retirement-process-" + stage for stage in STAGES})
IDENTITIES = ("old_session", "old_message", "new_session", "new_message", "report_id")
FLAGS = ("required_witness", "old_authority_refused", "original_report_reopened", "journal_erased", "signer_erased")
COUNTS = {"report_sessions": 1, "unconsumed_deliveries": 1, "consumed_before": 0,
          "host_effects": 1, "recovery_processes": 8, "uncertain_process_exits": 3}
SCOPE = ("Native Rust public enrollment and required-witness generation replacement; "
         "original complete report, durable host accounting, independent purpose21 ACK and logical "
         "journal/signer erasure through eight recovery processes; fresh-generation TLS traffic. "
         "Native APIs verify signatures/private MAC; this reader checks public framing and bindings. "
         "Same host/implementation, signed TCP witness, no physical erasure or foreign-device claim.")
FOREIGN_TEST = "c_retired_enrollment_preserves_complete_report_and_original_erasure_across_processes"


def verify(directory: Path) -> dict:
    sdk.require(directory.is_dir() and not directory.is_symlink()
                and {p.name for p in directory.iterdir()} == FILES,
                "device retirement public inventory differs")
    public = {}

    def read(name: str, maximum=65536):
        p = directory / name
        sdk.require(p.is_file() and not p.is_symlink(), "retirement evidence is not a regular file")
        value = sdk.snapshot(p, maximum=maximum)
        public[name] = {"sha256": value.sha256, "bytes": value.size}
        return value.data

    def fixed(name: str, length: int):
        value = read(name, length)
        sdk.require(len(value) == length, "retirement evidence width differs: " + name)
        return value

    def envelope(name: str, expected: bytes):
        wire = fixed(name, 4 + len(expected) + 3373)
        sdk.require(int.from_bytes(wire[:4], "big") == len(expected) and wire[4:-3373] == expected,
                    "retirement receipt names a different original: " + name)

    result = parse_strict_json_bytes(read("result.json"), label="device retirement result")
    sdk.require(isinstance(result, dict) and set(result) == set(IDENTITIES) | set(FLAGS) | set(COUNTS),
                "retirement result shape differs")
    for name in IDENTITIES:
        sdk.require(isinstance(result[name], str) and re.fullmatch(r"[0-9a-f]{64}", result[name])
                    and any(bytes.fromhex(result[name])), "retirement identity differs")
    sdk.require(all(result[name] is True for name in FLAGS), "retirement lifecycle is incomplete")
    sdk.require(all(type(result[name]) is int and result[name] == value for name, value in COUNTS.items()),
                "retirement accounting or process census differs")
    sdk.require(result["old_session"] != result["new_session"] and result["old_message"] != result["new_message"],
                "retirement reused original traffic identity")
    request_count = int.from_bytes(fixed("witness-request-count", 8), "big")
    sdk.require(0 < request_count <= 512, "retirement witness trace exceeded its bounded workload")
    witness = fixed("witness-id", 32) + fixed("witness-public", 1985)
    binding = commit(b"Q-PERIAPT-CONTINUITY-ANCHOR-AUTHORITY/v1", witness)
    subject = fixed("witness-subject", 96)
    replacement = read("retirement-proposal")
    sdk.require(replacement.startswith(b"QPDRPL01" + binding), "replacement witness binding differs")
    replacement_id = commit(b"Q-PERIAPT-CONTINUITY-DEVICE-REPLACEMENT-CANDIDATE/v1", replacement)
    receipt = fixed("retirement-receipt", 3754)
    body = receipt[4:-3373]
    sdk.require(int.from_bytes(receipt[:4], "big") == 377
                and body.startswith(b"QPDRTR01" + binding + replacement_id + subject),
                "retirement proof binding differs")
    inventory = fixed("retirement-inventory", 313)
    sdk.require(inventory.startswith(b"QPRCLP01" + binding + replacement_id + subject)
                and inventory[168:200] == body[249:281] and inventory[200:248] == body[168:216]
                and inventory[280] in (0, 1), "retirement inventory changed original frozen state")
    envelope("retirement-inventory-receipt", inventory)
    expected = fixed("retirement-report-proposal", 353)
    report_id = bytes.fromhex(result["report_id"])
    sdk.require(expected == b"QPRRPT01" + inventory + report_id, "retirement report expectation differs")
    envelope("retirement-report-receipt", expected)
    envelope("retirement-ack", b"QPRACK01" + expected[8:])
    host = read("retirement-host-report", 8 * 1024 * 1024)
    sdk.require(len(host) > 322 and host.startswith(b"QPRDMD01" + inventory),
                "retirement host report is missing its original complete inventory")
    sdk.require(read("retirement-host-report-verified", 8 * 1024 * 1024) == host,
                "retirement complete host record changed across erasure")
    sdk.require(fixed("retirement-report-reopened", 32) == report_id
                and fixed("retirement-verified", 32) == report_id, "retirement lost its original report identity")
    pids = [int.from_bytes(fixed("retirement-process-" + stage, 8), "big") for stage in STAGES]
    sdk.require(all(pid > 0 for pid in pids) and len(set(pids)) == len(STAGES),
                "retirement did not cross independent recovery processes")
    for role, payload in (("old", b"retiring device effect before unavailable receipt"),
                          ("new", b"fresh required-witness replacement")):
        sdk.require(read(role + "-effect") == bytes.fromhex(result[role + "_session"] + result[role + "_message"]) + payload,
                    "retirement actual application effect differs")
    sdk.require(fixed("signer-terminal", 8) == b"QPSRET01", "retirement signer terminal differs")
    sdk.require(set(public) == FILES, "retirement evidence left unread files")
    return {"completed": True, "scope": SCOPE, "outcomes": result, "recovery_process_ids": pids, "witness_requests": request_count,
            "public_readbacks": public, "release_claim_eligible": False}


def export(directory: Path, destination: Path) -> dict:
    checked = verify(directory)
    destination.mkdir(mode=0o700, parents=True)
    for name, expected in checked["public_readbacks"].items():
        value = sdk.snapshot(directory / name, maximum=8 * 1024 * 1024)
        sdk.require(value.sha256 == expected["sha256"], "retirement evidence changed before export")
        with (destination / name).open("xb") as target:
            target.write(value.data)
    sdk.require(verify(destination) == checked, "exported retirement evidence differs")
    return checked


def export_foreign(stdout: bytes, directory: Path, destination: Path, *, language: str) -> dict:
    """Bind the actual selected foreign cleanup process trace to the same public records."""
    sdk.require(language in {"C", "Swift", "Kotlin"}, "unqualified retirement consumer language")
    text = stdout.decode("utf-8")
    sdk.require(re.findall(r"^test (\S+) \.\.\. (\S+)$", text, re.MULTILINE) == [(FOREIGN_TEST, "ok")]
                and len(re.findall(r"^test result:", text, re.MULTILINE)) == 1
                and re.search(r"^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out;", text, re.MULTILINE),
                "foreign retirement test did not complete its exact workload")
    checked = export(directory, destination)
    checked["consumer_language"] = language
    checked["scope"] = (
        f"{language} restricted retired-enrollment API across eight actual cleanup processes; "
        "native Rust enrollment, required-witness generation replacement and fresh-generation TLS traffic. "
        "Native independent readback compares the complete original report and checks session/message accounting; original report/host ACK and "
        "logical journal/signer erasure remain exact. Same host/implementation, signed TCP witness; "
        "no physical erasure, independent protocol or complete foreign-device lifecycle claim."
    )
    return checked


def qualify_foreign(outside: Path, output: Path, profile: str, runtime: dict,
                    native: dict, run, *, language: str) -> dict:
    """Run the selected foreign executable with the already qualified native harness."""
    import continuity_c_consumer as c
    sdk.require(profile in {"debug", "release"} and language in {"Swift", "Kotlin"}
                and runtime.get("QPERIAPT_INSTALLED_CLIENT_LANGUAGE") == language,
                "unqualified foreign retirement profile")
    log = sdk.snapshot(output / ("c-retirement-build-" + profile + ".stdout"), maximum=32 * 1024**2)
    binary = c.built_artifact(log.data, outside / "c-consumer", outside / "build" / profile,
                              library=False, test_name="retirement")
    original = sdk.snapshot(binary, maximum=c.MAX_BINARY)
    expected = native["device_retirement"]["binary"]
    sdk.require(original.sha256 == expected["sha256"] and original.size == expected["bytes"],
                "foreign retirement native harness changed before execution")
    client = sdk.snapshot(Path(runtime["QPERIAPT_C_OWNER_CLIENT"]), maximum=c.MAX_BINARY)
    evidence = outside / (language.lower() + "-" + profile + "-retirement-runtime")
    selected = dict(runtime, QPERIAPT_PUBLIC_SERVICE_EVIDENCE=str(evidence))
    stdout = run([str(binary), "--exact", FOREIGN_TEST, "--nocapture"],
                 "retirement-trace-" + profile, runtime=selected)
    directory = evidence.with_name(evidence.name + "-device-retirement") / "public"
    checked = export_foreign(stdout, directory, output / (language.lower() + "-retirement-public") / profile,
                             language=language)
    sdk.require(sdk.snapshot(binary, maximum=c.MAX_BINARY).sha256 == original.sha256
                and sdk.snapshot(client.path, maximum=c.MAX_BINARY).sha256 == client.sha256,
                "foreign retirement harness or executable changed during execution")
    return dict(execution=checked, native_harness_sha256=original.sha256, foreign_client_sha256=client.sha256)
