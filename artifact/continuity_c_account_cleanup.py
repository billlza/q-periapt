"""Whole-account C loss accounting through real installed-library process cuts."""
from pathlib import Path
import hashlib
import re
import socket

import rust_sdk_profile as sdk
from evidence_io import parse_strict_json_bytes

SCOPE = ("installed C complete-account cleanup after operational SDK revocation; "
         "two original peer-account members and calibrated reservation process interruption; "
         "not power-loss or required-witness/own-account foreign qualification")
HELPERS = {"prepare_account_cleanup_case", "observe_account_cleanup_case", "revoke_account_cleanup_case",
           "compare_account_cleanup_report", "verify_account_cleanup_terminal"}
PROBES = ((0, "before"), (1, "before"), (1, "after"), (2, "before"), (2, "after"))


def loss_report(directory: Path) -> dict:
    from continuity_c_faults import DOMAIN
    public = {}
    def read(name, maximum=1048576):
        item = sdk.snapshot(directory / name, maximum=maximum)
        public[name] = item.sha256
        return item.data
    def fixed(name, width=32):
        value = read(name)
        sdk.require(len(value) == width and value != bytes(width), "account cleanup identity differs")
        return value.hex()
    batch, account = fixed("cleanup-batch"), fixed("cleanup-account")
    sdk.require(read("role") == b"\x01", "cleanup fixture selected a different local role")
    source = []
    for index in range(2):
        device = fixed(f"cleanup-device-{index}", 16)
        generation_bytes = read(f"peer-{index}/responder-generation")
        generation = int.from_bytes(generation_bytes, "big")
        sdk.require(len(generation_bytes) == 8 and generation > 0
                    and read(f"peer-{index}/responder-account").hex() == account,
                    "cleanup member account or generation differs")
        wire = read("cleanup-old-wire-" + device)
        sdk.require(wire.startswith(b"QPCMSG03"), "prior committed account ciphertext missing")
        digest = hashlib.sha3_256(len(DOMAIN).to_bytes(8, "big") + DOMAIN
                                 + len(wire).to_bytes(8, "big") + wire).hexdigest()
        source.append(dict(index=index, device=device, generation=generation,
            session=fixed(f"cleanup-session-{index}"), context=fixed(f"cleanup-context-{index}"),
            reserved=fixed(f"cleanup-reserved-{index}"), old=fixed("cleanup-old-message-" + device),
            wire=digest, incoming={position: fixed(f"cleanup-incoming-{index}-{position}")
                                  for position in range(3 + index) if position != 1}))
    sdk.require(all(len({row[field] for row in source}) == 2 for field in ("device", "session", "context")),
                "cleanup members were aliased")
    sdk.require(read("cleanup-connect.stdout") == "".join(row["session"] + "\n" for row in source).encode()
                and read("cleanup-connect.stderr") == b"", "actual C account bootstrap differs")
    data = read("c-account-loss-report")
    sdk.require(data == read("native-account-loss-report") and data.endswith(b"\n"),
                "C whole loss report differs from independent native readback")
    lines = data.decode("ascii").splitlines()
    sdk.require(len(lines) >= 4 and re.fullmatch(r"report [0-9a-f]{64}", lines[2]),
                "account loss report framing differs")
    report = lines[2].split()[1]
    sdk.require(report != "0" * 64, "account report identity is zero")
    expected = ["QPC-C-ACCOUNT-LOSS/1", "batch " + batch, "report " + report, "members 2"]
    for member, row in enumerate(sorted(source, key=lambda item: item["device"])):
        index = row["index"]
        expected.extend([
            f"member {member} {row['device']} {row['context']} {row['session']} 1 {row['generation']} 0 0 0 0 0 1",
            f"reserved {member} {row['reserved']} 29 13",
            f"epoch {member} 0 0 0 1 0 {3 + index} 0 0 0 {'0' * 64} 1 {2 + index} 1",
            f"unconfirmed {member} 0 0 {row['old']} {row['wire']}",
        ])
        for item, (position, identifier) in enumerate(sorted(row["incoming"].items())):
            expected.append(f"delivery {member} 0 {item} {identifier} {position} {7 + index + position}")
        expected.append(f"skipped {member} 0 0 1")
    sdk.require(lines == expected, "account report omitted or changed original loss accounting")
    sdk.require(read("cleanup-prepared") == b"two-original-members\n"
                and read("cleanup-observed") == b"reserved\n"
                and read("cleanup-revoked") == b"operational-policy-disabled\n"
                and read("cleanup-terminal-verified") == b"account-retired-independent-closure-refused\n",
                "account cleanup lifecycle readback differs")
    return dict(batch=batch, report=report, public_readbacks=public, members=2,
                reserved=2, unknown_messages=2, unconsumed=5, skipped=2)


def helper_inventory(data: bytes) -> None:
    from continuity_package import TESTS
    names = re.findall(r"^([a-z_:]+): test$", data.decode(), re.MULTILINE)
    expected = HELPERS | {"fixture::" + name for name in TESTS}
    sdk.require(len(names) == len(expected) and set(names) == expected
                and re.search(rf"^{len(expected)} tests, 0 benchmarks$", data.decode(), re.MULTILINE),
                "account cleanup helper inventory changed")


def native_result(data: bytes, name: str) -> None:
    names = re.findall(r"^test ([a-z_]+) \.\.\. ok$", data.decode(), re.MULTILINE)
    sdk.require(name in HELPERS and names == [name] and re.search(
        r"^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 7 filtered out;",
        data.decode(), re.MULTILINE), "account cleanup native helper did not execute completely")


def verify_public(result: dict, directory: Path) -> dict:
    from continuity_c_faults import events, MAX_SYNC
    sdk.require(result["schema_version"] == 1 and result["completed"] is True
                and result["release_claim_eligible"] is False and result["scope"] == SCOPE
                and result["profile"] in ("debug", "release"), "account cleanup result scope differs")
    cases = result["cases"]
    sdk.require(type(cases) is list and 2 <= len(cases) <= MAX_SYNC + 1
                and [row["cut"] for row in cases] == list(range(len(cases)))
                and all(row["side"] == "before" for row in cases)
                and [row["phase"] for row in cases] == ["committed"] + ["absent"] * (len(cases) - 2) + ["reserved"],
                "account reservation calibration is incomplete")
    readbacks = {}
    def read(name, maximum=2 * 1024**2):
        item = sdk.snapshot(directory / name, maximum=maximum)
        readbacks[name] = item.sha256
        return item.data
    checked = loss_report(directory / "selected")
    readbacks.update({"selected/" + name: value for name, value in checked["public_readbacks"].items()})
    labels = {"helper-inventory", "revoke", "freeze", "compare", "ack", "retire", "retired", "terminal"}
    labels.update(f"probe-{cut}-{side}" for cut, side in PROBES)
    for row in cases:
        labels.update(f"{name}-{row['cut']}" for name in ("prepare", "send", "observe"))
        if row["phase"] != "reserved":
            labels.add(f"disposition-{row['cut']}")
    sdk.require(set(result["commands"]) == labels, "account cleanup command census differs")
    output = {}
    for label in sorted(labels):
        command = parse_strict_json_bytes(read(f"commands/{label}.json"), label="account cleanup command")
        interrupted = ((label.startswith("send-") and label != "send-0")
                       or (label.startswith("probe-") and label != "probe-0-before"))
        expected_exit = 86 if interrupted else 0
        sdk.require(command == result["commands"][label] and command["completed"] is True
                    and not command.get("timed_out")
                    and command["exit"] == command["expected_exit"] == expected_exit,
                    "account cleanup command failed or changed")
        stdout, stderr = read(f"commands/{label}.stdout"), read(f"commands/{label}.stderr")
        sdk.require(stderr == b"" and hashlib.sha256(stdout).hexdigest() == command["stdout_sha256"]
                    and hashlib.sha256(stderr).hexdigest() == command["stderr_sha256"],
                    "account cleanup command byte identity differs")
        output[label] = stdout
    helper_inventory(output["helper-inventory"])
    for cut, side in PROBES:
        label = f"probe-{cut}-{side}"
        sdk.require(output[label] == b"" and result["commands"][label]["exit"] == (86 if cut else 0)
                    and events(read("events/" + label), cut, side) == (cut or 2)
                    and read(f"probe/{label}/control") == b"control"
                    and read(f"probe/{label}/target") == (b"one" if cut == 1 else b"onetwo"),
                    "account probe failed its independent inode controls")
    count = None
    for row in cases:
        cut = row["cut"]
        measured = events(read(f"events/send-{cut}"), cut, "before")
        if cut == 0:
            count = measured
        sdk.require(cut <= count and row["syncs"] == measured
                    and read(f"cases/{cut}/phase") == (row["phase"] + "\n").encode(),
                    "account reservation receipt and native disposition differ")
        native_result(output[f"prepare-{cut}"], "prepare_account_cleanup_case")
        native_result(output[f"observe-{cut}"], "observe_account_cleanup_case")
        sdk.require(output[f"send-{cut}"] == (b"" if cut else b"account-refused:311\n")
                    and result["commands"][f"send-{cut}"]["exit"] == (86 if cut else 0),
                    "account sender interruption differs")
        if row["phase"] != "reserved":
            expected = b"account-committed-not-abandoned\n" if cut == 0 else b"account-selection-refused:201\n"
            sdk.require(output[f"disposition-{cut}"] == expected, "account disposition was relabeled")
    for label, name in (("revoke", "revoke_account_cleanup_case"), ("compare", "compare_account_cleanup_report"),
                        ("terminal", "verify_account_cleanup_terminal")):
        native_result(output[label], name)
    for label, expected in (("freeze", "account-frozen:" + checked["report"] + "\n"),
                            ("ack", "account-acknowledged:" + checked["report"] + "\n"),
                            ("retire", "account-retired\n"), ("retired", "account-selection-refused:112\n")):
        sdk.require(output[label] == expected.encode(), "account cleanup lost its original report or batch")
    return dict(public_readbacks=readbacks, members=checked["members"], reserved=checked["reserved"],
                unknown_messages=checked["unknown_messages"], unconsumed=checked["unconsumed"],
                skipped=checked["skipped"], report=checked["report"], batch=checked["batch"])


def qualify(outside: Path, output: Path, profile: str, runtime: dict, client: Path,
            helper: Path, probe: Path, smoke: Path, library: Path) -> dict:
    from continuity_c_faults import Matrix, MAX_SYNC, events
    private = outside / ("account-cleanup-" + profile)
    private.mkdir(mode=0o700)
    artifacts = output / "c-account-cleanup" / profile
    artifacts.mkdir(parents=True, mode=0o700)
    # Reuse the existing bounded process runner and independently checked sync probe.
    runner = Matrix(private, artifacts, profile, runtime, client, helper, probe, smoke)
    identity = sdk.snapshot(library, maximum=256 * 1024**2)
    runner.binaries["installed_library"] = dict(path=str(library), sha256=identity.sha256, bytes=identity.size)
    runner.identities[str(library)] = identity.sha256
    runner.runtime["QPERIAPT_EXPECTED_CONTINUITY_LIBRARY"] = str(library)
    public = artifacts / "public"
    public.mkdir(mode=0o700)
    cases = []
    result = dict(schema_version=1, profile=profile, scope=SCOPE, completed=False,
                  release_claim_eligible=False, binaries=runner.binaries)
    def native(name, label, root=None, evidence=None):
        extra = {}
        if root is not None:
            extra["QPC_TEST_PATH"] = str(root)
        if evidence is not None:
            extra["QPERIAPT_PUBLIC_SERVICE_EVIDENCE"] = str(evidence)
        data = runner.command([helper, "--exact", name, "--nocapture"], label, extra=extra)
        native_result(data, name)
    def call(mode, label, root):
        identifier = sdk.snapshot(root / "cleanup-batch").data.hex()
        return runner.command([client, mode, root, identifier], label)
    try:
        helper_inventory(runner.command([helper, "--list"], "helper-inventory"))
        runner.probe_check()
        selected = None
        total = MAX_SYNC
        for cut in range(MAX_SYNC + 1):
            if cut > total:
                break
            evidence = runner.outside / f"reservation-{cut}"
            native("prepare_account_cleanup_case", f"prepare-{cut}", evidence=evidence)
            root = evidence.with_name(evidence.name + "-account") / "initiator"
            receipt = runner.receipt(f"send-{cut}")
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                address = "127.0.0.1:" + str(listener.getsockname()[1])
            arguments = [client, "account-send", root, root / "peer-0",
                sdk.snapshot(root / "cleanup-session-0").data.hex(), root / "peer-1",
                sdk.snapshot(root / "cleanup-session-1").data.hex(),
                sdk.snapshot(root / "cleanup-account").data.hex(), sdk.snapshot(root / "cleanup-batch").data.hex(),
                "0", address, "unknown"]
            data = runner.command(arguments, f"send-{cut}", expected=86 if cut else 0,
                extra=runner.inject(root / "journal.redb", receipt, cut, "before"))
            sdk.require(data == (b"" if cut else b"account-refused:311\n"), "account sender outcome differs")
            syncs = events(sdk.snapshot(receipt).data, cut, "before")
            if cut == 0:
                total = syncs
            native("observe_account_cleanup_case", f"observe-{cut}", root=root)
            phase = sdk.snapshot(root / "cleanup-observed").data.decode().strip()
            sdk.require(phase in ("absent", "reserved", "committed"), "unexpected account reservation phase")
            cases.append(dict(cut=cut, side="before", phase=phase, syncs=syncs))
            sdk.copy(root / "cleanup-observed", public / "cases" / str(cut) / "phase")
            if phase == "reserved":
                selected = root
                break
            call("recover-account-committed" if phase == "committed" else "recover-account-absent",
                 f"disposition-{cut}", root)
        sdk.require(selected is not None, "no real reserved account found within observed sync count")
        native("revoke_account_cleanup_case", "revoke", root=selected)
        call("recover-account-freeze", "freeze", selected)
        native("compare_account_cleanup_report", "compare", root=selected)
        call("recover-account-ack", "ack", selected)
        call("recover-account-retire", "retire", selected)
        call("recover-account-retired", "retired", selected)
        native("verify_account_cleanup_terminal", "terminal", root=selected)
        checked = loss_report(selected)
        for name in checked["public_readbacks"]:
            sdk.copy(selected / name, public / "selected" / name)
        for label in runner.command_records:
            prefix = artifacts / f"{runner.prefix}-{profile}-{label}"
            for suffix in ("json", "stdout", "stderr"):
                sdk.copy(Path(str(prefix) + "." + suffix), public / "commands" / (label + "." + suffix))
        for cut, side in PROBES:
            label = f"probe-{cut}-{side}"
            sdk.copy(runner.receipt(label), public / "events" / label)
            for leaf in ("target", "control"):
                sdk.copy(runner.outside / label / leaf, public / "probe" / label / leaf)
        for row in cases:
            label = f"send-{row['cut']}"
            sdk.copy(runner.receipt(label), public / "events" / label)
        sdk.require(all(sdk.snapshot(Path(path), maximum=256 * 1024**2).sha256 == digest
                        for path, digest in runner.identities.items()), "account cleanup binaries changed")
        verified = dict(result, completed=True, cases=cases, commands=runner.command_records)
        checked = verify_public(verified, public)
        verified["public_files"] = checked["public_readbacks"]
        verified["loss_accounting"] = {key: value for key, value in checked.items() if key != "public_readbacks"}
        sdk.write_json(public / "PUBLIC_FILES.json", dict(completed=True, files=verified["public_files"]))
        result = verified
    finally:
        result.update(cases=cases, commands=runner.command_records)
        sdk.write_json(artifacts / "ACCOUNT_CLEANUP.json", result)
    return result
