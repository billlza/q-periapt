"""Composition of actual P0 expiry, independent P2 and original roster operations."""
from pathlib import Path
import continuity_android_contract as contract
import continuity_android_policy_renewal as policy
import continuity_android_roster as local
import continuity_android_roster_witness as witness
import rust_sdk_profile as sdk

TESTS = frozenset(name for name in contract.TESTS if name.startswith("android_policy_renewal::roster_"))


def routes() -> tuple:
    return tuple((carrier, profile, outcome) for carrier in ("local", "signed", "tls")
                 for profile in ("fixed", "recoverable")
                 for outcome in (("applied",) if carrier == "local" else ("applied", "closed")))


def local_steps() -> tuple:
    steps = []
    for label, mode in (("original-expired", "original-expired"), ("no-policy-fallback", "unselected"),
                        ("bad-signature", "refused"), ("cancelled", "cancelled")):
        steps += [("roster-" + label, "roster-selected-" + mode),
                  ("roster-" + label + "-identity", "roster-selected-identity")]
    return tuple(steps + [("roster-refreshed", "roster-selected-refresh"), ("roster-refreshed-replayed", "roster-selected-refresh"),
                         ("roster-pending-resolution", "roster-selected-resolve-pending"), ("roster-activated-identity", "roster-selected-activate")])


def verify_local_records(base: Path) -> None:
    def read(name): return sdk.snapshot(base / name).data
    identity = read("original.identity")
    for name, code in (("original-expired", 104), ("no-policy-fallback", 1), ("bad-signature", 102), ("cancelled", 302)):
        sdk.require(read("roster-" + name) == code.to_bytes(4, "big") and read("roster-" + name + "-identity") == identity,
                    "selected local roster refusal changed identity")
    refreshed = read("roster-refreshed")
    sdk.require(len(refreshed) == 148 and refreshed == read("roster-refreshed-replayed")
                and refreshed[:4] == (6).to_bytes(4, "big") and refreshed[4:68] == identity
                and refreshed[68:108] == read("inputs/trusted-roster-version") + read("inputs/trusted-roster-digest")
                and refreshed[108:] == read("inputs/renewal-version") + read("inputs/renewal-digest"),
                "selected roster staging/checkpoints differ")
    sdk.require(read("roster-pending-resolution") == (215).to_bytes(4, "big")
                and read("roster-activated-identity") == identity and read("roster-local-completed") == (2).to_bytes(8, "big"),
                "selected roster staging became a commit receipt or replaced identity")


def verify_execution(stdout: bytes, directory: Path) -> dict:
    contract.verify_batch(stdout, TESTS); records = {}
    for carrier, profile, terminal in routes():
        label = carrier + "-" + profile + "-" + terminal; route = directory / label
        base = route / (carrier + "-" + profile)
        record = policy.verify_route(route, profile, carrier, with_roster=True)
        count = 43 if carrier == "local" else 68
        # Applied/Closed share the policy prefix; require both outcomes rather than
        # treating one matching carrier marker as proof of two completed tests.
        marker = f"qualified policy renewal {carrier}/{profile}: {count} foreign processes; expired P0, independent P2, original identity session message and one effect"
        sdk.require(stdout.decode().splitlines().count(marker) == (1 if carrier == "local" else 2), "policy-roster carrier outcomes missing/duplicated")
        calls = local_steps() if carrier == "local" else witness.steps(terminal == "closed", True)
        local.check_processes(base, profile, calls)
        if carrier == "local": verify_local_records(base)
        else: witness.verify_records(base, terminal == "closed", selected=True)
        sdk.require(sdk.snapshot(base / "roster-peer-admitted.stdout").data == b"peer-roster-admitted\n"
                    and sdk.snapshot(base / "roster-peer-admitted.stderr").data == b"", "continued native peer admission missing")
        records[label] = dict(record, terminal=terminal)
    return records


def public(carrier: str, terminal: str) -> tuple:
    files = policy.public(carrier)
    if carrier == "local":
        steps = local_steps()
        files += tuple(name for name, _ in steps) + tuple(name + "." + suffix for name, _ in steps for suffix in ("stdout", "stderr"))
        files += ("roster-local-completed", "inputs/trusted-roster-version", "inputs/trusted-roster-digest", "inputs/renewal-version", "inputs/renewal-digest")
    else: files += witness.public(terminal == "closed", selected=True)
    return tuple(dict.fromkeys(files + ("roster-peer-admitted.stdout", "roster-peer-admitted.stderr")))
