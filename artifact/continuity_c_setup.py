"""Actual C installation setup over independently prepared original enrollment inputs."""
from pathlib import Path
import re

import continuity_c_witness as witness
from evidence_io import parse_strict_json_bytes
import rust_sdk_profile as sdk

TESTS = {"local": "c_setup_preserves_original_creation_and_active_identity",
         "witness": "c_setup_requires_independent_original_witness_enrollment"}
SCOPE = ("installed C explicit Creating/Active setup over original configured keys, identity and policy; "
         "same native engine and host; no key enrollment API, credential renewal, activation-commit loss, "
         "physical power-loss or complete provisioning qualification")


def helper_inventory(data: bytes) -> None:
    from continuity_package import TESTS as NATIVE_TESTS
    names = re.findall(r"^([a-z_:]+): test$", data.decode(), re.MULTILINE)
    expected = set(TESTS.values()) | {"fixture::" + name for name in NATIVE_TESTS}
    sdk.require(len(names) == len(expected) and set(names) == expected
                and re.search(r"^5 tests, 0 benchmarks$", data.decode(), re.MULTILINE),
                "setup helper inventory differs")


def identifier(data: bytes) -> bytes:
    sdk.require(re.fullmatch(rb"[0-9a-f]{64}", data) is not None and data != b"0" * 64,
                "setup identifier differs")
    return bytes.fromhex(data.decode())


def verify_execution(stdout: bytes, directory: Path, *, scenario: str) -> dict:
    sdk.require(scenario in TESTS, "unsupported setup scenario")
    text = stdout.decode()
    sdk.require(re.findall(r"^test ([a-z_]+) \.\.\. ok$", text, re.MULTILINE) == [TESTS[scenario]]
                and re.search(r"^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 4 filtered out;", text, re.MULTILINE),
                "setup trace did not execute completely")
    public = {}
    def read(name, maximum=65536):
        item = sdk.snapshot(directory/name, maximum=maximum)
        public[name] = item.sha256
        return item.data
    def command(label, expected=None):
        output = read("setup-"+label+".stdout")
        sdk.require(read("setup-"+label+".stderr") == b"", "setup command diagnostic differs")
        if expected is not None: sdk.require(output == expected, "setup command outcome differs: "+label)
        return output
    flags = ({"pre_cancel_absent", "same_genesis", "active_prepare_refused"} if scenario == "local" else
             {"independent_enrollment", "missing_witness_refused", "same_genesis"})
    report = parse_strict_json_bytes(read("setup-"+scenario+"-result.json"), label="setup result")
    sdk.require(isinstance(report, dict) and set(report) == flags | {"schema_version", "language", "completed", "release_claim_eligible"}
                and type(report["schema_version"]) is int and report["schema_version"] == 1 and report["language"] == "C"
                and all(report[field] is True for field in flags | {"completed"}) and report["release_claim_eligible"] is False,
                "setup report scope differs")
    journal = read("setup-original-journal", 32)
    sdk.require(len(journal) == 32 and any(journal), "setup original journal missing")
    command("create", b"setup-status:1\n"+journal.hex().encode()+b"\n")
    command("active", b"setup-status:2\n"+journal.hex().encode()+b"\n")
    activated = command("activate")
    match = re.fullmatch(rb"setup-activated\n([0-9a-f]{64})\n", activated)
    sdk.require(match is not None, "setup activation framing differs")
    batch = identifier(match[1])
    command("reactivate", activated)
    detail = {}
    if scenario == "local":
        subject, digest, protection = bytes(96), bytes(32), b"1"
        command("precancel", b"setup-refused:302\n")
        command("creating", b"setup-status:1\n"+journal.hex().encode()+b"\n")
        command("active-refuses-prepare", b"setup-refused:211\n")
    else:
        subject = read("setup-original-subject", 96)
        digest = read("setup-original-image", 32)
        protection = b"2"
        sdk.require(len(subject) == 96 and subject[:32] == journal and all(any(subject[n:n+32]) for n in (0,32,64))
                    and len(digest) == 32 and any(digest), "setup original enrollment scope differs")
        command("required", b"setup-refused:216\n")
        command("active-required", b"setup-refused:216\n")
        command("bad-signature", b"setup-refused:218\n")
        cancelled = re.fullmatch(rb"setup-cancelled:218:(0|[1-9][0-9]{0,2})\n", command("cancel"))
        sdk.require(cancelled is not None, "setup held-witness cancellation bound differs")
        sdk.require(read("setup-cancel-barrier", 1) == b"1", "setup cancellation barrier differs")
        identity, key = read("witness-id",32), read("witness-public",1985)
        sdk.require(len(identity) == 32 and any(identity) and len(key) == 1985 and key[1952] in (2,3),
                    "setup witness pin shape differs")
        wire = read("setup-witness-transcript", witness.RECORD_BYTES*32)
        protocol = witness.transcript(wire, witness.commit(b"Q-PERIAPT-CONTINUITY-ANCHOR-AUTHORITY/v1",identity+key),
                                      expected_lost_advances=0, expected_lost_queries=1, expected_subjects=1)
        sdk.require(protocol["exchanges"] == protocol["fresh_challenges"] == 14 and protocol["logical_advances"] == 0,
                    "setup signed-witness workload differs")
        rows = [wire[n:n+witness.RECORD_BYTES] for n in range(0,len(wire),witness.RECORD_BYTES)]
        sdk.require(all(row[45:141] == subject and witness.head(row[3880:3928])[2] == digest for row in rows),
                    "setup witness replaced the original genesis")
        lost = [row for row in rows if row[0] == 0]
        sdk.require(len(lost) == 1 and read("witness-cancelled-prefix",1804) == (3659).to_bytes(4,"big")+lost[0][3675:5475],
                    "setup cancellation lost another reply")
        command("tls-reactivate",activated)
        sdk.require(read("setup-tls-admissions",8) == (5).to_bytes(8,"big") and read("witness-subject",96) == subject,
                    "setup TLS workload or subject differs")
        server, client = read("witness-tls-peer",8192), read("witness-tls-cert",8192)
        sdk.require(server and client and server != client and read("witness-tls-name",128) == b"localhost",
                    "setup TLS original authority differs")
        detail = dict(witness_protocol=protocol, tls_admissions=5, cancellation_ms=int(cancelled[1]))
    prepared = b"setup-prepared:"+protection+b"\n"+journal.hex().encode()+b"\n"+subject.hex().encode()+b"\n"+digest.hex().encode()+b"\n"
    command("prepare",prepared)
    command("prepare-repeat",prepared)
    return dict(report, scope=SCOPE, scenario=scenario, journal=journal.hex(), next_account=batch.hex(), **detail,
        public_readbacks={name:sha for name,sha in public.items() if not name.endswith((".stdout",".stderr"))},
        command_logs={name:sha for name,sha in public.items() if name.endswith((".stdout",".stderr"))})


def qualify(outside: Path, output: Path, profile: str, environment: dict, client: Path, helper: Path, library: Path, *, scenario: str) -> dict:
    sdk.require(scenario in TESTS, "unsupported setup qualification scenario")
    binaries = {}
    for role,path in dict(client=client,native_helper=helper,installed_library=library).items():
        item = sdk.snapshot(path,maximum=256*1024**2)
        binaries[role] = dict(path=str(path),sha256=item.sha256,bytes=item.size)
    result = dict(completed=False,scope=SCOPE,scenario=scenario,binaries=binaries,release_claim_eligible=False)
    prefix = "c-setup-"+scenario+"-"
    evidence = outside/(prefix+profile+"-runtime")
    runtime = {k:v for k,v in environment.items() if not k.startswith(("DYLD_","LD_","QPERIAPT_","QPC_"))}
    runtime.update(QPERIAPT_C_OWNER_CLIENT=str(client),QPERIAPT_EXPECTED_CONTINUITY_LIBRARY=str(library),QPERIAPT_PUBLIC_SERVICE_EVIDENCE=str(evidence))
    try:
        helper_inventory(sdk.command([str(helper),"--list"],output/(prefix+"inventory-"+profile),outside,environment=runtime))
        stdout = sdk.command([str(helper),"--exact",TESTS[scenario],"--nocapture"],output/(prefix+"trace-"+profile),outside,environment=runtime)
        selected = evidence/"initiator"
        checked = verify_execution(stdout,selected,scenario=scenario)
        public = witness.export_selected(checked,selected,output/(prefix+"public")/profile,SCOPE,
            replay=lambda path: verify_execution(stdout,path,scenario=scenario))
        sdk.require(all(sdk.snapshot(Path(row["path"]),maximum=256*1024**2).sha256 == row["sha256"] for row in binaries.values()),
                    "setup binary changed during execution")
        result.update(completed=True,execution=checked,public_files=public)
    finally:
        sdk.write_json(output/(prefix.upper().replace("-","_")+profile.upper()+".json"),result)
    return result
