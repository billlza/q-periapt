"""Interrupt only owned test processes at real installed-C journal sync boundaries.

The SDK library is unchanged. A separately hashed probe is injected into selected
C children only; this qualifies process interruption, never a power-loss model.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import time

import rust_sdk_profile as sdk
from evidence_io import parse_strict_json_bytes

MAX_SYNC = 64
MAX_LOG = 2 * 1024**2
COMMAND_TIMEOUT = 90
HELPERS = {"prepare_fault_case", "observe_fault_case", "revoke_fault_case",
           "verify_closed_fault_case", "inspect_closure_fault_case"}
FIXTURE_TESTS = {"fixture::service_peer_process",
                 "fixture::owned_services_connect_restart_rekey_and_reconcile_unknown_delivery"}
DOMAIN = b"Q-PERIAPT-CONTINUITY-MESSAGES-CANDIDATE/v2/resolution-ciphertext/v1"
SCOPE = ("same-host installed C local-profile journal sync process interruptions; "
         "SDK revoked before complete reserved-loss accounting; not power-loss qualification")


def events(data: bytes, cut: int, side: str) -> int:
    sdk.require(type(cut) is int and 0 <= cut <= MAX_SYNC and side in ("before", "after"),
                "invalid sync-cut request")
    sdk.require(len(data) <= 8192 and data.endswith(b"\n"), "missing or oversized sync receipt")
    lines = data.decode("ascii").splitlines()
    sdk.require(lines and lines.pop(0) == f"armed {cut} {int(side == 'after')}",
                "sync probe did not arm the requested cut")
    if cut == 0:
        sdk.require(bool(lines), "missing sync calibration completion")
        match = re.fullmatch(r"done ([1-9][0-9]*) 0", lines.pop())
        sdk.require(match is not None, "sync calibration did not complete")
        count = int(match[1])
        sdk.require(1 <= count <= MAX_SYNC, "sync calibration exceeded its finite bound")
    else:
        count = cut
    expected = []
    for number in range(1, count + 1):
        expected.append(f"before {number} 0")
        if not (number == cut and side == "before"):
            expected.append(f"after {number} 0")
    sdk.require(lines == expected, "sync receipt omitted, repeated or changed a real boundary")
    return count


def plan(data: bytes) -> dict:
    value = parse_strict_json_bytes(data, label="C sync-fault original identities")
    fields = {"session", "message", "context", "peer_account", "peer_device"}
    sdk.require(isinstance(value, dict) and set(value) == fields, "fault fixture identity shape differs")
    for name in fields:
        size = 32 if name == "peer_device" else 64
        sdk.require(isinstance(value[name], str) and re.fullmatch(f"[0-9a-f]{{{size}}}", value[name]),
                    "fault fixture identity encoding differs")
    sdk.require(value["message"][:32] == "0" * 32, "fault fixture did not retain original epoch/slot zero")
    return value


def loss_report(data: bytes, original: dict, status: int, wire: bytes | None = None) -> str:
    sdk.require(type(status) is int and status in (0, 1, 2), "unknown pre-cleanup C message status")
    sdk.require(len(data) <= 1024**2 and data.endswith(b"\n"), "loss report is absent or oversized")
    rows = data.decode("ascii").splitlines()
    sdk.require(len(rows) >= 4 and rows[0] == "QPC-C-LOSS/1"
                and re.fullmatch(r"report [0-9a-f]{64}", rows[1]), "loss report identity differs")
    report = rows[1].split()[1]
    sdk.require(report != "0" * 64, "loss report identity is zero")
    expected = ["QPC-C-LOSS/1", "report " + report,
                f"header {original['session']} {original['context']} {original['peer_account']} "
                f"{original['peer_device']} 2 1 0 0 0 0 0 {int(status == 1)} 1"]
    if status == 1:
        expected.append(f"reserved 0 {original['message']} 29 13")
    expected.append(f"epoch 0 0 0 {int(status == 2)} 0 0 0 0 0 {'0' * 64} {int(status == 2)} 0 0")
    if status == 2:
        sdk.require(isinstance(wire, bytes) and wire.startswith(b"QPCMSG03"),
                    "committed fault outcome has no original wire")
        digest = hashlib.sha3_256(len(DOMAIN).to_bytes(8, "big") + DOMAIN
                                 + len(wire).to_bytes(8, "big") + wire).hexdigest()
        expected.append(f"unconfirmed 0 0 {original['message']} {digest}")
    else:
        sdk.require(wire is None, "unsent reservation was replaced by committed ciphertext")
    sdk.require(rows == expected, "C fault recovery did not retain complete original loss accounting")
    return report


def coverage(cases: list[dict]) -> dict:
    sdk.require(isinstance(cases, list) and cases, "fault matrix has no cases")
    sdk.require({row.get("phase") for row in cases} == {"send", "begin", "ack"}, "fault phase omitted")
    counts = {}
    for phase in ("send", "begin", "ack"):
        rows = [row for row in cases if row.get("phase") == phase]
        calibration = [row for row in rows if type(row.get("cut")) is int and row["cut"] == 0]
        sdk.require(len(calibration) == 1 and calibration[0].get("side") == "before",
                    "fault calibration missing or duplicated")
        count = calibration[0].get("syncs")
        sdk.require(type(count) is int and 1 <= count <= MAX_SYNC, "invalid calibrated sync count")
        expected = {(0, "before")} | {(n, side) for n in range(1, count + 1) for side in ("before", "after")}
        observed = []
        for row in rows:
            cut = row.get("cut")
            sdk.require(type(cut) is int and row.get("completed") is True
                        and type(row.get("syncs")) is int and row["syncs"] == (cut or count)
                        and type(row.get("status")) is int and row["status"] in (0, 1, 2),
                        "fault case is incomplete or has an invalid disposition")
            observed.append((cut, row.get("side")))
            if phase != "send":
                sdk.require(row["status"] == 1, "cleanup fault case has no retained reservation")
        sdk.require(len(observed) == len(expected) and set(observed) == expected,
                    "fault matrix omitted or repeated a before/after cut")
        if phase == "send":
            sdk.require({row["status"] for row in rows} == {0, 1, 2}
                        and any(row["side"] == "after" and row["status"] == 1 for row in rows),
                        "fault matrix did not execute all send dispositions")
        else:
            sdk.require({row.get("observed_phase") for row in rows}
                        == ({"open", "pending"} if phase == "begin" else {"pending", "closed"}),
                        "fault matrix omitted a cleanup commit outcome")
        counts[phase] = {"syncs": count, "cases": len(rows)}
    return counts


class Matrix:
    def __init__(self, outside: Path, output: Path, profile: str, runtime: dict,
                 client: Path, helper: Path, probe: Path, smoke: Path):
        self.outside = outside / ("c-fault-" + profile)
        self.outside.mkdir(mode=0o700)
        self.output, self.profile = output, profile
        self.client, self.helper, self.probe, self.smoke = client, helper, probe, smoke
        self.runtime = {k: v for k, v in runtime.items()
                        if not k.startswith(("DYLD_", "LD_", "QPERIAPT_", "QPC_TEST_"))}
        self.runtime["QPERIAPT_C_OWNER_CLIENT"] = str(client)
        self.command_records: dict = {}
        self.results: list = []
        self.identities = {str(p): sdk.snapshot(p, maximum=256 * 1024**2).sha256
                           for p in (client, helper, probe, smoke)}

    def command(self, argv: list, label: str, *, expected: int = 0, extra=None) -> bytes:
        prefix = self.output / f"c-fault-{self.profile}-{label}"
        argv = [str(a) for a in argv]
        environment = dict(self.runtime, **(extra or {}))
        started = time.monotonic()
        record = {"argv": argv, "expected_exit": expected, "completed": False}
        out_path, err_path = Path(str(prefix) + ".stdout"), Path(str(prefix) + ".stderr")
        try:
            with out_path.open("xb") as stdout, err_path.open("xb") as stderr:
                child = subprocess.Popen(argv, env=environment, cwd=self.outside,
                                         stdout=stdout, stderr=stderr, start_new_session=True)
                try:
                    record["exit"] = child.wait(timeout=COMMAND_TIMEOUT)
                except subprocess.TimeoutExpired:
                    record["timed_out"] = True
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError as disappeared:
                        sdk.require(child.poll() is not None,
                                    f"owned fault process group disappeared before child exit: {disappeared}")
                        record["exited_before_timeout_kill"] = True
                    child.wait()
                    raise
            stdout, stderr = sdk.snapshot(out_path, maximum=MAX_LOG), sdk.snapshot(err_path, maximum=MAX_LOG)
            record.update(stdout_sha256=stdout.sha256, stderr_sha256=stderr.sha256)
            sdk.require(record["exit"] == expected and stderr.data == b"",
                        f"C fault command {label} returned {record['exit']} instead of {expected}; inspect retained logs")
            record["completed"] = True
            return stdout.data
        finally:
            record["elapsed_seconds"] = round(time.monotonic() - started, 3)
            sdk.write_json(Path(str(prefix) + ".json"), record)
            self.command_records[label] = record

    def native(self, name: str, label: str, root: Path) -> None:
        sdk.require(name in HELPERS, "unknown fault helper invocation")
        stdout = self.command([self.helper, "--exact", name, "--nocapture"], label,
                              extra={"QPERIAPT_PUBLIC_SERVICE_EVIDENCE": str(root),
                                     "QPC_TEST_PATH": str(root / "responder")}).decode()
        names = re.findall(r"^test ([a-z_]+) \.\.\. ok$", stdout, re.MULTILINE)
        sdk.require(names == [name] and re.search(
            r"^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 6 filtered out;", stdout, re.MULTILINE),
            "installed fault helper did not execute the selected complete test")

    def c(self, mode: str, label: str, root: Path, tail=(), *, expected=0, extra=None) -> bytes:
        return self.command([self.client, mode, root / "responder", *tail], label,
                            expected=expected, extra=extra)

    def inject(self, target: Path, receipt: Path, cut: int, side: str) -> dict:
        return {"DYLD_INSERT_LIBRARIES" if os.uname().sysname == "Darwin" else "LD_PRELOAD": str(self.probe),
                "QPC_TEST_SYNC_TARGET": str(target), "QPC_TEST_SYNC_LOG": str(receipt),
                "QPC_TEST_SYNC_CUT": str(cut), "QPC_TEST_SYNC_SIDE": side}

    def receipt(self, label: str) -> Path:
        return self.output / f"c-fault-{self.profile}-{label}.events"

    def prepare(self, label: str) -> tuple[Path, dict]:
        root = self.outside / label
        self.native("prepare_fault_case", label + "-prepare", root)
        return root, plan(sdk.snapshot(root / "responder/fault-plan.json").data)

    def send(self, root: Path, original: dict, label: str, cut: int, side: str) -> int:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        receipt = self.receipt(label)
        stdout = self.c("uncertain-send", label + "-send", root,
                        [f"127.0.0.1:{port}", original["session"], original["message"]],
                        expected=86 if cut else 0,
                        extra=self.inject(root / "responder/journal.redb", receipt, cut, side))
        sdk.require(stdout == (b"" if cut else b"delivery-unknown-committed\n"), "fault sender outcome differs")
        return events(sdk.snapshot(receipt).data, cut, side)

    def disposition_and_revoke(self, root: Path, original: dict, label: str) -> int:
        raw = self.c("status", label + "-status", root, [original["session"], original["message"]])
        sdk.require(raw in (b"0\n", b"1\n", b"2\n"), "faulted message has an unexpected C disposition")
        status = int(raw)
        self.native("observe_fault_case", label + "-observe", root)
        sdk.require(sdk.snapshot(root / "responder/fault-native-status").data
                    == (b"absent\n", b"reserved\n", b"committed\n")[status], "native and C dispositions differ")
        self.native("revoke_fault_case", label + "-revoke", root)
        sdk.require(self.c("reject-open", label + "-denied", root) == b"rejected:603\n",
                    "fault recovery did not deny operational SDK admission")
        return status

    def loss(self, root: Path, original: dict, status: int) -> tuple[bytes, str]:
        data = sdk.snapshot(root / "responder/c-loss-report").data
        wire = sdk.snapshot(root / "responder/fault-wire").data if status == 2 else None
        identity = loss_report(data, original, status, wire)
        archive = sdk.snapshot(root / "responder/c-closure-archive").data
        sdk.require(len(archive) == 362 and archive.startswith(b"QPCSCA01")
                    and archive == sdk.snapshot(root / "responder/native-closure-archive").data,
                    "fault cleanup changed the original native archive")
        return data, identity

    def finish(self, root: Path, original: dict, label: str, data: bytes, *, closed=False) -> None:
        if not closed:
            sdk.require(self.c("recover-ack-crash", label + "-ack", root, [original["session"]], expected=77) == b"",
                        "fault report acknowledgement exit differs")
        sdk.require(self.c("recover-finish", label + "-finish", root, [original["session"]])
                    == b"original-report-closed-retired\n", "fault cleanup did not reconcile its original report")
        sdk.require(self.c("recover-archive", label + "-archive", root) == b"archive-closed-metadata-only\n",
                    "fault cleanup archive restored authority")
        sdk.require(self.c("recover-list", label + "-list", root) == b"catalogue:0\n", "fault catalogue not retired")
        self.native("verify_closed_fault_case", label + "-closed", root)
        sdk.require(sdk.snapshot(root / "responder/c-loss-report").data == data, "fault cleanup replaced host accounting")

    def record(self, root: Path, original: dict, data: bytes, report: str, **fields) -> None:
        public = {"responder/" + leaf: sdk.snapshot(root / "responder" / leaf).sha256
                  for leaf in ("fault-plan.json", "fault-native-status", "c-loss-report",
                               "c-closure-archive", "native-closure-archive")}
        if fields.get("status") == 2:
            public["responder/fault-wire"] = sdk.snapshot(root / "responder/fault-wire").sha256
        if fields.get("phase") != "send":
            public["responder/fault-closure-phase"] = sdk.snapshot(root / "responder/fault-closure-phase").sha256
        self.results.append(dict(original, **fields, report=report, root=str(root), public_readbacks=public,
                                 completed=True, loss_report_sha256=hashlib.sha256(data).hexdigest()))

    def send_case(self, cut: int, side: str) -> int:
        label = f"send-{cut}-{side}"
        root, original = self.prepare(label)
        count = self.send(root, original, label, cut, side)
        status = self.disposition_and_revoke(root, original, label)
        sdk.require(self.c("recover-freeze", label + "-freeze", root, [original["session"]], expected=77) == b"",
                    "fault freeze did not durably report before exit")
        data, report = self.loss(root, original, status)
        self.finish(root, original, label, data)
        self.record(root, original, data, report, phase="send", cut=cut, side=side, syncs=count, status=status)
        return count

    def closure_case(self, phase: str, cut: int, side: str, reserved_cut: int) -> int:
        label = f"{phase}-{cut}-{side}"
        root, original = self.prepare(label)
        self.send(root, original, label + "-reserve", reserved_cut, "after")
        sdk.require(self.disposition_and_revoke(root, original, label) == 1, "closure cut has no original reservation")
        prior = None
        if phase == "ack":
            sdk.require(self.c("recover-freeze", label + "-initial-freeze", root, [original["session"]], expected=77) == b"",
                        "initial reservation report was not retained")
            prior = sdk.snapshot(root / "responder/c-loss-report").data
        receipt = self.receipt(label)
        sdk.require(self.c("recover-freeze" if phase == "begin" else "recover-ack-crash",
                           label + "-fault", root, [original["session"]], expected=86 if cut else 77,
                           extra=self.inject(root / "responder/journal.redb", receipt, cut, side)) == b"",
                    "closure cut outcome differs")
        count = events(sdk.snapshot(receipt).data, cut, side)
        self.native("inspect_closure_fault_case", label + "-inspect", root)
        raw = sdk.snapshot(root / "responder/fault-closure-phase").data.decode("ascii")
        match = re.fullmatch(r"(open|pending|closed) ([0-9a-f]{64}|)\n", raw)
        sdk.require(match is not None, "invalid observed closure phase")
        state, observed = match.groups()
        sdk.require(state in ({"open", "pending"} if phase == "begin" else {"pending", "closed"})
                    and ((state == "open") == (observed == "")), "closure cut crossed an impossible phase")
        if phase == "begin":
            sdk.require(self.c("recover-freeze", label + "-freeze-retry", root, [original["session"]], expected=77) == b"",
                        "interrupted closure did not recover its complete report")
        data, report = self.loss(root, original, 1)
        sdk.require((not observed or observed == report) and (prior is None or prior == data),
                    "closure cut replaced the original report")
        self.finish(root, original, label, data, closed=state == "closed")
        self.record(root, original, data, report, phase=phase, cut=cut, side=side,
                    syncs=count, status=1, observed_phase=state)
        return count

    def probe_check(self) -> None:
        for cut, side in ((0, "before"), (1, "before"), (1, "after"), (2, "before"), (2, "after")):
            label = f"probe-{cut}-{side}"
            root = self.outside / label
            root.mkdir(mode=0o700)
            for leaf in ("target", "control"):
                fd = os.open(root / leaf, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.close(fd)
            receipt = self.receipt(label)
            stdout = self.command([self.smoke, root / "target", root / "control"], label,
                                  expected=86 if cut else 0, extra=self.inject(root / "target", receipt, cut, side))
            sdk.require(stdout == b"" and sdk.snapshot(root / "control").data == b"control",
                        "sync probe changed an unrelated inode")
            sdk.require(events(sdk.snapshot(receipt).data, cut, side) == (cut or 2), "probe sync count differs")
            sdk.require(sdk.snapshot(root / "target").data == (b"one" if cut == 1 else b"onetwo"),
                        "sync cut did not interrupt the intended operation")

    def execute(self) -> dict:
        result = {"completed": False, "scope": SCOPE, "release_claim_eligible": False,
                  "binary_sha256": self.identities, "profile": self.profile, "outside": str(self.outside)}
        started = time.monotonic()
        try:
            listing = self.command([self.helper, "--list"], "helper-inventory").decode()
            names = re.findall(r"^([^\n]+): test$", listing, re.MULTILINE)
            sdk.require(len(names) == 7 and set(names) == HELPERS | FIXTURE_TESTS, "fault helper inventory changed")
            self.probe_check()
            count = self.send_case(0, "before")
            for cut in range(1, count + 1):
                for side in ("before", "after"):
                    self.send_case(cut, side)
            sdk.require({r["status"] for r in self.results} == {0, 1, 2}, "fault matrix omitted a send disposition")
            reserved = [r["cut"] for r in self.results if r["status"] == 1 and r["side"] == "after"]
            sdk.require(bool(reserved), "no real post-sync uncommitted reservation was observed")
            for phase in ("begin", "ack"):
                count = self.closure_case(phase, 0, "before", reserved[0])
                for cut in range(1, count + 1):
                    for side in ("before", "after"):
                        self.closure_case(phase, cut, side, reserved[0])
                sdk.require({r["observed_phase"] for r in self.results if r["phase"] == phase}
                            == ({"open", "pending"} if phase == "begin" else {"pending", "closed"}),
                            "fault matrix omitted a cleanup commit outcome")
            sdk.require(self.identities == {p: sdk.snapshot(Path(p), maximum=256 * 1024**2).sha256
                                            for p in self.identities}, "fault-matrix binaries changed")
            result["coverage"] = coverage(self.results)
            result["completed"] = True
        finally:
            result.update(cases=self.results, commands=self.command_records,
                          elapsed_seconds=round(time.monotonic() - started, 3))
            sdk.write_json(self.output / f"C_SYNC_FAULTS_{self.profile.upper()}.json", result)
        return result
