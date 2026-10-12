"""Exact installed Android harness inventory and complete execution receipts."""
from __future__ import annotations

import re
import rust_sdk_profile as sdk

ROSTER_TESTS = frozenset({
    "android_lifecycle",
    "android_roster_local::original_roster_advance",
    "android_roster_local::remote_roster_advance",
    "android_roster_witness::original_terminal_recovery",
    "android_witness::managed_credential_renewal",
    "android_witness::managed_first_registration",
    "android_witness::required_witness_registration",
    "fixture::owned_services_connect_restart_rekey_and_reconcile_unknown_delivery",
    "fixture::reopen::public_session_reopen_after_expiry_reconciles_unknown_commit_over_real_tls",
    "fixture::service_peer_process",
} | {
    module + "::" + profile
    for module in ("android_policy_expiry", "android_policy_renewal")
    for profile in ("fixed", "recoverable")
} | {
    "android_policy_renewal::roster_local_" + profile
    for profile in ("fixed", "recoverable")
} | {
    "android_policy_renewal::roster_" + carrier + "_" + profile + "_" + outcome
    for carrier in ("signed", "tls") for profile in ("fixed", "recoverable")
    for outcome in ("applied", "closed")
})
TESTS = ROSTER_TESTS | {"android_retirement::original_android_retirement"}


def verify_catalog(stdout: bytes) -> None:
    text = stdout.decode()
    names = re.findall(r"^(\S+): test$", text, re.M)
    sdk.require(len(names) == len(TESTS) and set(names) == TESTS
                and text.splitlines().count(f"{len(TESTS)} tests, 0 benchmarks") == 1,
                "installed Android harness test inventory differs")


def verify_single(stdout: bytes, test: str, *, catalog: frozenset[str] = TESTS) -> None:
    # Historical roster captures explicitly retain their previous complete catalog.
    # Live qualification always verifies TESTS first and uses this default.
    sdk.require(catalog in (ROSTER_TESTS, TESTS) and test in catalog, "unknown installed Android test/catalog")
    text = stdout.decode()
    expected = f"test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; {len(catalog)-1} filtered out;"
    sdk.require(re.findall(r"^test (\S+) \.\.\. ok$", text, re.M) == [test]
                and len(re.findall("^" + re.escape(expected), text, re.M)) == 1,
                "installed Android test did not execute completely")


def verify_batch(stdout: bytes, tests: frozenset[str]) -> None:
    sdk.require(tests and tests <= TESTS, "unknown installed Android test batch")
    text = stdout.decode()
    names = re.findall(r"^test (\S+) \.\.\. ok$", text, re.M)
    expected = (f"test result: ok. {len(tests)} passed; 0 failed; 0 ignored; 0 measured; "
                f"{len(TESTS)-len(tests)} filtered out;")
    sdk.require(len(names) == len(tests) and set(names) == tests
                and len(re.findall("^" + re.escape(expected), text, re.M)) == 1,
                "installed Android test batch did not execute completely")
