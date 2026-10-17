"""Exact original witnessed-roster outcomes; public linkage is not fresh authority."""
from pathlib import Path
import continuity_android_contract as contract
import continuity_android_roster as local
import rust_sdk_profile as sdk

TEST = "android_roster_witness::original_terminal_recovery"


def steps(closed: bool, selected: bool = False) -> tuple:
    prefix = "roster-" if selected else ""
    mode = "roster-witness-selected-" if selected else "roster-witness-"
    result = []
    refusals = [("bad-roster", "prepare-bad"), ("cancelled", "prepare-cancelled"), ("no-policy-fallback", "prepare-unselected")]
    if selected: refusals += [("original-expired", "prepare-original-expired")]
    for name, action in refusals:
        result += [(prefix + name, mode + action), (prefix + name + "-absent", mode + "progress")]
    result += [(prefix + name, mode + action) for name, action in (
        ("proposal", "prepare"), ("proposal-replayed", "prepare"), ("proposal-recovered", "recover"),
        ("reserved", "progress"), ("unavailable", "reconcile"), ("no-local-abandon", "abandon-refused"),
        ("substitution-refused", "substitute"), ("prepared-at-witness", "reconcile"),
        ("unknown", "close-unknown" if closed else "commit-unknown"),
        ("historical-unmanaged", "history-unmanaged"), ("reconciled", "reconcile"),
        ("close-exact", "close"), ("commit-exact", "commit"), ("retired", "progress"),
        ("no-local-resolve", "resolve-local"), ("registry-required", "activate-unmanaged"))]
    result += [("roster-renewed-identity", "policy-activate-renewed")] if selected else [("active-original-request", "policy-activate")]
    return tuple(result)


def cases(closed: bool) -> tuple:
    return (("original.request", "policy-create"), ("authority-created", "authority-create"),
            ("prepared", "policy-prepare"), ("activated.request", "policy-activate"), ("original.identity", "policy-identity"),
            ("roster-peer-unassociated", "roster-witness-peer-unassociated"), ("roster-peer-associated", "authority-peer-associate"),
            ("roster-connected", "roster-witness-peer-connect"), ("roster-unknown", "roster-witness-peer-uncertain")) + steps(closed) + (
            ("roster-acknowledged", "roster-witness-peer-retry"), ("final.identity", "policy-identity"))


def verify_records(base: Path, closed: bool, *, selected: bool = False) -> None:
    prefix = "roster-" if selected else ""
    def read(name): return sdk.snapshot(base / name).data
    def result(name): return read(prefix + name)
    proposal = result("proposal"); prepared = read("prepared")
    sdk.require(len(proposal) == 417 and proposal[:8] == b"QPRWNP01"
                and proposal == result("proposal-replayed") == result("proposal-recovered") == read("inputs/roster-proposal")
                and len(prepared) == 164 and proposal[40:136] == prepared[36:132]
                and proposal[136:168] == read("inputs/roster-operation"), "roster original proposal/subject changed")
    sdk.require(proposal[168:208] == read("inputs/trusted-roster-version") + read("inputs/trusted-roster-digest")
                and proposal[208:248] == read("inputs/renewal-version") + read("inputs/renewal-digest"), "roster proposal checkpoints changed")
    policy = "inputs/policy-target/" if selected else "inputs/"
    sdk.require(proposal[248:288] == read(policy + "policy-version") + read(policy + "policy-digest")
                and proposal[288:321] == (b"\x01" + read("inputs/renewal-statement") if selected else bytes(33)),
                "roster proposal policy authorization changed")
    scope = proposal[136:288] + proposal[289:321] + int(selected).to_bytes(4, "big") + bytes(4)
    sdk.require(result("reserved") == (2).to_bytes(4, "big") + bytes(4) + scope + proposal + bytes(7), "roster reservation changed")
    phase, state, kind = (4, 3, 18) if closed else (3, 2, 16)
    sdk.require(result("retired") == phase.to_bytes(4, "big") + (1).to_bytes(4, "big") + scope + proposal + bytes(7),
                "roster terminal retirement differs")
    for name in ("historical-unmanaged", "reconciled", "close-exact", "commit-exact"):
        sdk.require(result(name) == state.to_bytes(4, "big"), "exact original roster terminal changed")
    refusals = [("bad-roster", 102), ("cancelled", 302), ("no-policy-fallback", 1)]
    if selected: refusals += [("original-expired", 104)]
    for name, code in refusals:
        sdk.require(result(name) == code.to_bytes(4, "big") and result(name + "-absent") == bytes(624), "refused roster changed pending state")
    for name, code in (("unavailable", 5), ("no-local-abandon", 211), ("substitution-refused", 211),
                       ("prepared-at-witness", 1), ("unknown", 218), ("no-local-resolve", 216), ("registry-required", 211)):
        sdk.require(result(name) == code.to_bytes(4, "big"), "roster authority/uncertainty result differs")
    request, reply = result("lost-terminal-request"), result("lost-terminal-reply")
    sdk.require(len(request) == 3674 and request[204] == kind and len(reply) == 3659, "lost roster terminal exchange missing")
    trace = result("historical-transcript")
    sdk.require(0 < len(trace) <= 128 * 7334 and len(trace) % 7334 == 0, "roster history transcript bound")
    for offset in range(0, len(trace), 7334):
        sdk.require(trace[offset] == 1 and trace[offset + 205] not in (16, 18), "history dispatched another roster Commit/Close")
    if selected:
        sdk.require(read("roster-terminal") == state.to_bytes(4, "big") and read("roster-renewed-identity") == read("original.identity"), "renewed roster changed identity")
    else: sdk.require(read("active-original-request") == read("original.request"), "roster activation replaced original request")


def verify_execution(stdout: bytes, directory: Path) -> dict:
    contract.verify_single(stdout, TEST); records = {}
    for carrier in ("signed", "tls"):
        for profile in ("fixed", "recoverable"):
            for terminal in ("applied", "closed"):
                label = carrier + "-" + profile + "-" + terminal; base = directory / label; closed = terminal == "closed"
                selected = cases(closed); sdk.require(len(selected) == 34, "witness roster census definition")
                marker = f"qualified roster witness {label}: 34 Java processes; original R terminal and original session message with one effect"
                sdk.require(stdout.decode().splitlines().count(marker) == 1, "witness roster outcome missing/duplicated")
                local.check_processes(base, profile, selected); verify_records(base, closed)
                sdk.require(sdk.snapshot(base / "process-count").data == (34).to_bytes(8, "big"), "witness roster process count differs")
                records[label] = dict(local.traffic(base, witnessed=True), foreign_processes=34, terminal=terminal)
    return records


def public(closed: bool, *, selected: bool = False) -> tuple:
    prefix = "roster-" if selected else ""; calls = steps(closed, True) if selected else cases(closed)
    files = tuple(name for name, _ in calls) + tuple(name + "." + suffix for name, _ in calls for suffix in ("stdout", "stderr"))
    files += tuple(prefix + name for name in ("lost-terminal-request", "lost-terminal-reply", "historical-transcript"))
    files += tuple("inputs/" + name for name in ("roster-operation", "roster-proposal", "trusted-roster-version", "trusted-roster-digest",
        "renewal-version", "renewal-digest", "policy-version", "policy-digest"))
    if selected: files += ("roster-terminal",)
    else:
        files += ("process-count", "roster-effect-before", "roster-effect-after", "roster-peer-admitted.stdout", "roster-peer-admitted.stderr",
                  "inputs/enrollment-intent", "inputs/enrollment-root")
    return files
