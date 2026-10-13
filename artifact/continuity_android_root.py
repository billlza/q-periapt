"""Original-operation linkage for Android account-root qualification.

Native execution authenticates receipts and private report MACs. This reader checks
public bindings and exact child-process results, including expected process cuts.
"""
from pathlib import Path
import hashlib
import continuity_android_contract as contract
import rust_sdk_profile as sdk

ROUTES = {"original": (34, 6), "transition": (36, 6), "bound-transition": (37, 7),
          "adoption": (33, 5), "noncommit": (41, 7)}
TESTS = {route: "android_root_owned::" + route.replace("-", "_") + "_account_root_replacement"
         for route in ROUTES}

def _records(read, route, count):
    def same(*names):
        value = read(names[0])
        sdk.require(all(read(name) == value for name in names[1:]), "root records differ: " + ", ".join(names))
        return value

    def code(name, expected, width=4):
        sdk.require(read(name) == expected.to_bytes(width, "big"), "root result: " + name)

    code("process-count", count, 8)
    sdk.require(read("inputs/root-route") == route.encode(), "root route identity")
    request = same("original.request", "activated.request")
    sdk.require(len(request) == len(read("root-target.request")) == 5506, "enrollment request framing")
    prepared, target_prepared, identity = read("prepared"), read("root-target.prepared"), read("original.identity")
    sdk.require(len(prepared) == len(target_prepared) == 164 and len(identity) == 64
                and prepared[:4] == target_prepared[:4] == (2).to_bytes(4, "big")
                and prepared[4:36] == identity[32:] != target_prepared[4:36], "original/successor journal binding")
    same("root-begun", "root-preparing")
    code("root-begun", 1)
    if route != "adoption":
        bound = same("root-bound", "root-bound-replayed")
        sdk.require(bound.startswith((b"QPARPL01", b"QPARPL02")), "bound proposal framing")
        code("root-bad-freeze", 102)
    if route != "original":
        original = same("inputs/root-original-target-account", "inputs/root-original-target/trusted-account")
        sdk.require(original != read("inputs/root-target-account"), "alternative reused original target account")
        sdk.require(read("root-original-target.request") != read("root-target.request"), "alternative reused target request")
        sdk.require(read("inputs/root-original-target/enrollment-root") != read("inputs/root-target/enrollment-root"),
                    "alternative reused target root")
    checkpoint = same("root-retained", "root-retained-replayed")
    sdk.require(len(checkpoint) == 72 and checkpoint[:32] == read("inputs/authority-application")
                and checkpoint[32:40] == (2).to_bytes(8, "big"), "retained application checkpoint")
    target = same("inputs/root-target/trusted-account", "inputs/root-target-account")
    sdk.require(checkpoint[40:] == target and target != read("inputs/trusted-account"), "successor account checkpoint")
    sdk.require(read("inputs/root-target/enrollment-root") != read("inputs/enrollment-root"), "successor root unchanged")
    session, old_session = read("root-connected"), read("roster-connected")
    pending = same("root-unknown", "root-acknowledged")
    sdk.require(len(session) == len(old_session) == 32 and session != old_session
                and len(pending) == 64 and pending[:32] == session, "successor session/message binding")
    effect = same("root-effect-before", "root-effect-after")
    sdk.require(effect == pending + b"persisted before process exit", "successor business effect binding")
    code("root-effect-count", 2, 8)
    same("roster-effect-before", "root-original-effect-after")
    report = same("root-complete-report", "root-verified")
    inventory = read("root-inventory")
    sdk.require(len(inventory) == 313 and report.startswith((b"QPRDMD01", b"QPRDMD02", b"QPRDMD03"))
                and report[8:321] == inventory, "complete original report inventory")
    proposal = same("root-report-proposal", "root-report-unknown", "root-ack-proposal",
                    "root-journal-unknown", "root-signer-unknown")
    sdk.require(len(proposal) == 353 and proposal[8:321] == inventory, "original report proposal")
    for name, value in (("root-close-revoked", 202), ("root-activation-unknown", 218),
                        ("root-tampered-report", 208), ("root-wrong-purpose", 102)):
        code(name, value)


def steps(route: str) -> tuple[tuple[str, str, bool], ...]:
    before = [("original.request", "policy-create"), ("authority-created", "authority-create"),
              ("prepared", "policy-prepare"), ("activated.request", "policy-activate"),
              ("original.identity", "policy-identity"),
              ("roster-peer-unassociated", "roster-witness-peer-unassociated"),
              ("roster-peer-associated", "authority-peer-associate"),
              ("roster-connected", "roster-witness-peer-connect"),
              ("roster-unknown", "roster-witness-peer-uncertain"),
              ("root-target.request", "root-target-create"), ("root-target.prepared", "root-target-prepare")]
    if route != "original": before += [("root-original-target.request", "root-original-target-create"),
                                       ("root-original-target.prepared", "root-original-target-prepare")]
    values = [(label, mode, False) for label, mode in before]
    values += [("root-begun", "root-begin-unknown", True), ("root-preparing", "root-state", False)]
    if route == "noncommit": values += [("root-preparation-cancelled", "root-cancel-preparing", False)]
    if route == "adoption":
        values += [("root-retained", "root-adopt-unknown", True), ("root-retained-replayed", "root-adopt-replay", False)]
    else:
        values += [("root-bad-freeze", "root-freeze-bad", False)]
        if route == "bound-transition": values += [("root-original-bound", "root-freeze-original", True)]
        if route == "noncommit": values += [("root-bad-noncommit", "root-noncommit-bad", False),
            ("root-noncommit-retained", "root-noncommit-unknown", True), ("root-noncommit-replayed", "root-noncommit-replay", False)]
        prefix = "freeze" if route == "original" else "transition"
        values += [("root-bound", "root-" + prefix + "-unknown", True),
                   ("root-bound-replayed", "root-" + prefix + "-replay", False),
                   ("root-retained", "root-retain-unknown", True), ("root-retained-replayed", "root-retain-replay", False)]
    values += [("root-activation-unknown", "root-activate-unknown", False), ("root-activated", "root-activate", False),
               ("root-connected", "root-peer-connect", False), ("root-unknown", "root-peer-uncertain", False),
               ("root-acknowledged", "root-peer-retry", False)]
    if route == "noncommit": values += [("root-successor-cancelled", "root-cancel-successor", False)]
    values += [("root-" + label, "root-" + mode, cut) for label, mode, cut in (
        ("inventory", "inventory", False), ("report-proposal", "prepare-report", False),
        ("report-unknown", "report-unknown", True), ("complete-report", "report-reopen", False),
        ("tampered-report", "ack-tampered", False), ("ack-proposal", "prepare-ack", False),
        ("wrong-purpose", "erase-wrong-purpose", False), ("journal-unknown", "journal-unknown", True),
        ("signer-unknown", "signer-unknown", True), ("verified", "verify", False), ("close-revoked", "close-revokes", False))]
    return tuple(values)


def verify_records(directory: Path, trust: str, route: str) -> dict:
    sdk.require(trust in ("fixed", "recoverable") and route in ROUTES, "unknown Android root route/trust")
    count, cuts = ROUTES[route]
    public = {}
    def read(name):
        value = sdk.snapshot(directory / name, maximum=8 * 1024 * 1024)
        public[name] = {"sha256": value.sha256, "bytes": value.size}
        return value.data
    _records(read, route, count)
    if route == "noncommit":
        sdk.require(read("root-preparation-cancelled") == read("root-successor-cancelled") == (302).to_bytes(4, "big"), "controller cancellation")
        sdk.require(read("root-bad-noncommit") == (102).to_bytes(4, "big"), "noncommit signature rejection")
        sdk.require(read("root-noncommit-retained") == read("root-noncommit-replayed") == (4).to_bytes(4, "big"), "noncommit terminal persistence")
    approvals = ["root-plan", "root-retirement", "root-inventory-receipt", "root-report-receipt", "root-ack"]
    if route != "original": approvals += ["root-noncommit"]
    if route in ("transition", "bound-transition", "noncommit"): approvals += ["root-next-plan"]
    approvals += ["root-winner"] if route == "adoption" else ["root-freeze"]
    for name in approvals:
        sdk.require(bool(read("inputs/" + name)), "missing original approval")
    expected = steps(route)
    sdk.require(len(expected) == count and sum(cut for _, _, cut in expected) == cuts, "root step definition differs")
    for label, mode, cut in expected:
        sdk.require(read(label + ".stdout") == (b"" if cut else f"{trust}:{mode}:passed\n".encode())
                    and read(label + ".stderr") == b"", "root process outcome: " + label)
    return {"foreign_processes": count, "process_cuts": cuts,
            "report_sha256": hashlib.sha256(read("root-verified")).hexdigest(),
            "original_report_preserved": True, "total_counterparty_effects": 2, "public_readbacks": public}


def verify_execution(stdout: bytes, directory: Path, route: str, *, catalog=contract.TESTS) -> dict:
    sdk.require(route in ROUTES, "unknown Android root route")
    contract.verify_single(stdout, TESTS[route], catalog=catalog)
    count, cuts = ROUTES[route]
    result = {}
    for trust in ("fixed", "recoverable"):
        marker = f"qualified Android account-root {route} {trust}: {count} Java processes; {cuts} process cuts; original report, new root traffic and controller-close revocation"
        sdk.require(stdout.decode().splitlines().count(marker) == 1, "root route missing or duplicated")
        result[trust] = verify_records(directory / ("signed-" + trust), trust, route)
    return result


def qualify(binary: Path, consumer: Path, installed: Path, output: Path, profile: str, runtime: dict, run) -> dict:
    outcomes = {}
    for route, test in TESTS.items():
        cases = installed / ("root-" + route + "-cases")
        stdout = run([str(binary), "--exact", test, "--nocapture"], profile + "-root-" + route,
                     consumer, dict(runtime, QPC_ANDROID_CASES=str(cases)))
        result = verify_execution(stdout, cases, route)
        exported = output / ("android-jni-" + profile + "-root-" + route)
        for trust, record in result.items():
            for name in record["public_readbacks"]:
                sdk.copy(cases / ("signed-" + trust) / name, exported / ("signed-" + trust) / name)
        sdk.require(verify_execution(stdout, exported, route) == result, "root public export differs")
        outcomes[route] = result
    return outcomes
