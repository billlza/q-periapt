"""Original required-witness account recovery through actual installed foreign owners."""
from pathlib import Path
import re

import continuity_c_account_cleanup as cleanup
import continuity_c_witness as witness
import rust_sdk_profile as sdk
from evidence_io import parse_strict_json_bytes

TEST = "account_cleanup_requires_original_witness_and_reconciles_lost_advances"
TLS_TEST = "tls::account_cleanup_keeps_original_authority_over_mutual_tls"
TLS_LOSS_TEST = "tls_loss::account_cleanup_reconciles_four_committed_tls_reply_losses"
DELIVERY_TEST = "delivery::account_delivery_reconciles_original_members_with_tls_witness"
OWN_DELIVERY_TEST = "delivery::own_account_delivery_reconciles_original_members_with_tls_witness"
OWN_TLS_LOSS_TEST = "tls_loss::own_account_cleanup_reconciles_four_committed_tls_reply_losses"
SCOPE = ("installed C required-witness complete-account cleanup after SDK revocation; "
         "three original installations over native signed TCP; four lost committed witness responses; "
         "same host and shared engine; no TLS, own-account, power-loss or independent-engine qualification")
PHASES = ("reservation", "freeze", "acknowledge", "retirement")


def scope(language: str) -> str:
    sdk.require(language in ("C", "Swift", "Kotlin"), "unqualified account witness language")
    return SCOPE.replace("installed C ", "installed " + language + " ")


def helper_inventory(data: bytes) -> None:
    from continuity_package import TESTS
    names = re.findall(r"^([a-z_:]+): test$", data.decode(), re.MULTILINE)
    expected = {TEST, TLS_TEST, TLS_LOSS_TEST, DELIVERY_TEST, OWN_DELIVERY_TEST, OWN_TLS_LOSS_TEST} | {"fixture::" + name for name in TESTS}
    sdk.require(len(names) == len(expected) and set(names) == expected
                and re.search(r"^9 tests, 0 benchmarks$", data.decode(), re.MULTILINE),
                "account witness helper inventory differs")


def account_identities(read, *, same_account: bool) -> dict:
    """Read public pins and canonical roster commitments; native endpoints verify signatures."""
    sdk.require(type(same_account) is bool, "account layout selection differs")
    accounts, devices, rosters, bodies, digests = [], [], [], [], []
    for index in range(3):
        prefix = f"account-identity-{index}-"
        account, device, root = read(prefix + "account", 32), read(prefix + "device", 16), read(prefix + "root", 1985)
        version, digest = read(prefix + "roster-version", 8), read(prefix + "roster-digest", 32)
        roster = read(prefix + "roster", 8192)
        sdk.require(len(account) == 32 and len(device) == 16 and any(device)
                    and len(root) == 1985 and root[1952] in (2, 3)
                    and account == witness.commit(b"Q-PERIAPT-CONTINUITY-ACCOUNT-CANDIDATE/v1", root),
                    "account root commitment or device identity differs")
        length = int.from_bytes(roster[:4], "big")
        sdk.require(len(roster) == 4 + length + 3373 and 66 <= length <= 66 + 32 * 56,
                    "account roster envelope differs")
        body = roster[4:4 + length]
        sdk.require(body[:8] == b"QPROST01" and body[8:40] == account and version == (1).to_bytes(8, "big")
                    and body[40:48] == version and int.from_bytes(body[48:56], "big") < int.from_bytes(body[56:64], "big")
                    and len(digest) == 32 and digest == witness.commit(b"Q-PERIAPT-CONTINUITY-ROSTER-CANDIDATE/v1", body),
                    "account roster pin or canonical body differs")
        accounts.append(account); devices.append(device); rosters.append(roster); bodies.append(body); digests.append(digest)
    sdk.require(len(set(devices)) == 3 and accounts[1] == accounts[2]
                and (accounts[0] == accounts[1]) == same_account
                and rosters[1] == rosters[2] and (not same_account or rosters[0] == rosters[1]),
                "account layout or original roster identity differs")
    for index, body in enumerate(bodies):
        expected = sorted(devices if same_account else (devices[:1] if index == 0 else devices[1:]))
        count = int.from_bytes(body[64:66], "big")
        sdk.require(count == len(expected) and len(body) == 66 + count * 56, "account roster member census differs")
        rows = [body[offset:offset + 56] for offset in range(66, len(body), 56)]
        sdk.require([row[:16] for row in rows] == expected and len({row[24:] for row in rows}) == count
                    and all(row[16:24] == (1).to_bytes(8, "big") and any(row[24:]) for row in rows),
                    "account roster omitted, aliased or replaced an original device")
    return dict(accounts=[v.hex() for v in accounts], devices=[v.hex() for v in devices],
                roster_digests=[v.hex() for v in digests], account_count=len(set(accounts)))


def stages(data: bytes, transcript: bytes) -> dict:
    size = witness.RECORD_BYTES
    sdk.require(transcript and len(transcript) % size == 0 and len(transcript) <= size * 4096,
                "account witness transcript size differs")
    sdk.require(len(data) <= 512 and data.endswith(b"\n"), "account witness stages missing")
    rows = data.decode("ascii").splitlines()
    sdk.require(len(rows) == len(PHASES), "account witness phase omitted")
    result, previous, selected = {}, 0, set()
    for phase, row in zip(PHASES, rows, strict=True):
        match = re.fullmatch(rf"{phase} (0|[1-9][0-9]*) ([1-9][0-9]*) (0|[1-9][0-9]*)", row)
        sdk.require(match is not None, "account witness phase framing differs")
        start, end, lost = map(int, match.groups())
        sdk.require(previous <= start <= lost < end <= len(transcript) // size
                    and [index for index in range(start, end) if transcript[index * size] == 0] == [lost],
                    "account witness phase did not lose exactly its committed response")
        previous = end
        selected.add(lost)
        result[phase] = dict(first_exchange=start, after_last_exchange=end, lost_exchange=lost)
    sdk.require(selected == {index for index in range(len(transcript) // size) if transcript[index * size] == 0},
                "account witness loss escaped its original phase")
    return result


def verify_execution(stdout: bytes, directory: Path, *, language: str = "C") -> dict:
    selected_scope = scope(language)
    text = stdout.decode()
    sdk.require(re.findall(r"^test ([a-z_]+) \.\.\. ok$", text, re.MULTILINE) == [TEST]
                and re.search(r"^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out;",
                              text, re.MULTILINE), "account witness trace did not execute completely")
    public = {}
    def read(name, maximum=1048576):
        item = sdk.snapshot(directory / name, maximum=maximum)
        public[name] = item.sha256
        return item.data
    report = parse_strict_json_bytes(read("account-witness-result.json"), label="account witness result")
    sdk.require(isinstance(report, dict) and set(report) == {"schema_version", "language", "completed", "batch", "report",
                               "witness_exchanges", "lost_advances", "release_claim_eligible"}
                and type(report["schema_version"]) is int and report["schema_version"] == 1
                and report["language"] == language and report["completed"] is True
                and report["release_claim_eligible"] is False and type(report["lost_advances"]) is int
                and report["lost_advances"] == 4, "account witness result scope differs")
    accounting = cleanup.loss_report(directory)
    public.update(accounting["public_readbacks"])
    sdk.require(report["batch"] == accounting["batch"] and report["report"] == accounting["report"],
                "witnessed loss report changed original identities")
    wire = read("account-witness-transcript", witness.RECORD_BYTES * 4096)
    identity, key = read("witness-id", 32), read("witness-public", 1985)
    sdk.require(len(identity) == 32 and len(key) == 1985, "account witness original pin shape differs")
    authority = witness.commit(b"Q-PERIAPT-CONTINUITY-ANCHOR-AUTHORITY/v1", identity + key)
    protocol = witness.transcript(wire, authority, expected_lost_advances=4, expected_subjects=3)
    sdk.require(type(report["witness_exchanges"]) is int and report["witness_exchanges"] == protocol["exchanges"],
                "account witness exchange count differs")
    observed = stages(read("account-witness-stages", 512), wire)
    outputs = {
        "reserve-lost": "account-refused:218\n", "missing": "account-selection-refused:216\n",
        "wrong-pin": "account-selection-refused:211\n", "bad-signature": "account-selection-refused:218\n",
        "freeze-lost": "account-freeze-outcome-unavailable\n",
        "freeze-reconciled": "account-frozen:" + report["report"] + "\n",
        "ack-lost": "account-acknowledgement-outcome-unavailable\n",
        "ack-reconciled": "account-acknowledged:" + report["report"] + "\n",
        "retire-lost": "account-retirement-outcome-unavailable\n",
        "retire-reconciled": "account-retired\n", "retired": "account-selection-refused:112\n",
        "retired-missing": "account-selection-refused:216\n", "retired-unavailable": "account-selection-refused:218\n",
    }
    for label, expected in outputs.items():
        sdk.require(read("cleanup-" + label + ".stdout") == expected.encode()
                    and read("cleanup-" + label + ".stderr") == b"", "account witness command outcome differs")
    for index in range(2):
        output = read(f"account-server-{index}.stdout").decode("ascii").splitlines()
        sdk.require(len(output) == 4 and re.fullmatch(r"listening:[1-9][0-9]{0,4}", output[0])
                    and int(output[0].split(":")[1]) <= 65535
                    and output[1:] == ["served:1:0:0:0", read(f"cleanup-session-{index}", 32).hex(), "0" * 64]
                    and read(f"account-server-{index}.stderr") == b"", "witnessed bootstrap peer or original session differs")
    result = dict(report, scope=selected_scope, loss_accounting={k: v for k, v in accounting.items() if k != "public_readbacks"},
                  witness_protocol=protocol, stages=observed)
    if language == "Kotlin":
        from continuity_kotlin_consumer import account_parent_lifetime
        result["parent_lifetime"] = account_parent_lifetime(read("kotlin-account-parent-lifetime", 256))
    result["public_readbacks"] = {name: digest for name, digest in public.items()
                                  if not name.endswith((".stdout", ".stderr"))}
    result["command_logs"] = {name: digest for name, digest in public.items()
                              if name.endswith((".stdout", ".stderr"))}
    return result


def qualify(outside: Path, output: Path, profile: str, environment: dict, client: Path,
            helper: Path, library: Path, *, language: str = "C", jvm_runtime: dict[str, Path] | None = None,
            scenario: str = "signed-tcp") -> dict:
    from continuity_c_faults import jvm_command
    sdk.require((language == "Kotlin") == (jvm_runtime is not None), "account witness JVM closure differs")
    sdk.require(scenario in {"signed-tcp", "mutual-tls", "mutual-tls-loss", "mutual-tls-delivery", "own-tls-loss", "own-tls-delivery"}, "unknown account witness scenario")
    if scenario == "mutual-tls":
        import continuity_c_account_tls as tls
        selected_scope, selected_test, verify, suffix = tls.scope(language), TLS_TEST, tls.verify_execution, "account-tls"
    elif scenario == "mutual-tls-loss":
        import continuity_c_account_tls_loss as tls_loss
        selected_scope, selected_test, verify, suffix = tls_loss.scope(language), TLS_LOSS_TEST, tls_loss.verify_execution, "account-tls-loss"
    elif scenario == "mutual-tls-delivery":
        import continuity_c_account_delivery as delivery
        selected_scope, selected_test, verify, suffix = delivery.scope(language), DELIVERY_TEST, delivery.verify_execution, "account-delivery"
    elif scenario == "own-tls-loss":
        import continuity_c_account_tls_loss as tls_loss
        selected_scope, selected_test, verify, suffix = tls_loss.scope(language, same_account=True), OWN_TLS_LOSS_TEST, tls_loss.verify_own_execution, "own-account-tls-loss"
    elif scenario == "own-tls-delivery":
        import continuity_c_account_delivery as delivery
        selected_scope, selected_test, verify, suffix = delivery.scope(language, same_account=True), OWN_DELIVERY_TEST, delivery.verify_own_execution, "own-account-delivery"
    else:
        selected_scope, selected_test, verify, suffix = scope(language), TEST, verify_execution, "account-witness"
    if jvm_runtime is not None:
        jvm_command(jvm_runtime, library)
    paths = dict(client=client, native_helper=helper, installed_library=library, **(jvm_runtime or {}))
    identities = {}
    for role, path in paths.items():
        item = sdk.snapshot(path, maximum=256 * 1024**2)
        identities[role] = dict(path=str(path), sha256=item.sha256, bytes=item.size)
    result = dict(completed=False, scope=selected_scope, language=language, binaries=identities, release_claim_eligible=False)
    prefix = language.lower() + "-" + suffix + "-"
    evidence = outside / (prefix + profile + "-runtime")
    runtime = {k: v for k, v in environment.items()
               if not k.startswith(("DYLD_", "LD_", "QPERIAPT_", "QPC_", "JAVA_", "JDK_", "GRADLE_", "KOTLIN_"))
               and k not in {"_JAVA_OPTIONS", "CLASSPATH"}}
    runtime.update(QPERIAPT_C_OWNER_CLIENT=str(client), QPERIAPT_INSTALLED_CLIENT_LANGUAGE=language,
                   QPERIAPT_EXPECTED_CONTINUITY_LIBRARY=str(library), QPERIAPT_PUBLIC_SERVICE_EVIDENCE=str(evidence))
    try:
        helper_inventory(sdk.command([str(helper), "--list"], output / (prefix + "inventory-" + profile), outside, environment=runtime))
        stdout = sdk.command([str(helper), "--exact", selected_test, "--nocapture"], output / (prefix + "trace-" + profile), outside, environment=runtime)
        selected = evidence.with_name(evidence.name + "-account")
        if scenario not in {"mutual-tls-delivery", "own-tls-delivery"}:
            selected = selected / "initiator"
        checked = verify(stdout, selected, language=language)
        public = witness.export_selected(checked, selected, output / (prefix + "public") / profile, selected_scope,
            replay=lambda path: verify(stdout, path, language=language))
        sdk.require(all(sdk.snapshot(Path(item["path"]), maximum=256 * 1024**2).sha256 == item["sha256"]
                        for item in identities.values()), "account witness executed binaries changed")
        result.update(completed=True, execution=checked, public_files=public)
    finally:
        sdk.write_json(output / (prefix.upper().replace("-", "_") + profile.upper() + ".json"), result)
    return result
