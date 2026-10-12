"""Original aggregate identities and exact foreign-process account outcomes."""
from pathlib import Path
import continuity_android_contract as contract
import rust_sdk_profile as sdk

TEST = "android_account::original_account_delivery"
MARKER = ("complete two-recipient original operation; receiver exit 77, exact retry, retained zero-exchange outcomes, "
          "omission and input conflict refused; active parent/member busy, member cancellation and original-operation recovery")
CASES = (("request", "enrollment-create"), ("activated", "enrollment-activate"), ("sessions", "account-connect"),
         ("original-operation", "account-next"), ("absent-before", "account-status")) + tuple(
    item for label, mode in (("omit", "account-omit"), ("duplicate-peer", "account-duplicate-peer"),
                            ("duplicate-session", "account-duplicate-session"), ("cancelled-peer", "account-cancelled-peer"))
    for item in ((label, mode), ("absent-" + label, "account-status"))) + (
    ("unknown", "account-unknown"), ("committed-after-unknown", "account-status"), ("changed", "account-changed"),
    ("omit-retained", "account-omit-retained"), ("delivered-0", "account-send"), ("retained-0", "account-reversed"),
    ("delivered-1", "account-send"), ("retained-1", "account-reversed"), ("committed-final", "account-status"),
    ("cancel-operation", "account-next"), ("concurrent-cancel", "account-concurrent"), ("cancel-committed", "account-status"),
    ("cancel-resumed-0", "account-send"), ("cancel-resumed-1", "account-send"))
PUBLIC = tuple(name for name, _ in CASES) + ("effect-before-retry", "effect-0", "effect-1") + tuple(
    name + "." + suffix for name, _ in CASES for suffix in ("stdout", "stderr"))


def verify_execution(stdout: bytes, cases: Path) -> dict:
    contract.verify_single(stdout, TEST)
    results = {}
    for trust in ("fixed", "recoverable"):
        sdk.require(stdout.decode().splitlines().count(f"qualified account {trust}: {MARKER}") == 1, "missing account workload")
        def read(name): return sdk.snapshot(cases / trust / name).data
        for name, mode in CASES:
            sdk.require(read(name + ".stdout") == f"{trust}:{mode}:passed\n".encode() and read(name + ".stderr") == b"",
                        "account child outcome/diagnostic differs")
        sdk.require(len(read("request")) == 5506 and read("request") == read("activated"), "account enrollment changed")
        sessions = read("sessions")
        sdk.require(len(sessions) == 64 and any(sessions[:32]) and any(sessions[32:]) and sessions[:32] != sessions[32:],
                    "account sessions differ")
        original, cancelled = read("original-operation"), read("cancel-operation")
        sdk.require(len(original) == len(cancelled) == 32 and any(original) and any(cancelled) and original != cancelled,
                    "account operation identities differ")
        for label, code in (("omit",106), ("duplicate-peer",1), ("duplicate-session",1), ("cancelled-peer",302),
                            ("unknown",311), ("changed",211), ("omit-retained",211), ("concurrent-cancel",302)):
            sdk.require(read(label) == code.to_bytes(4,"big"), "account refusal changed: " + label)
        for label in ("absent-before", "absent-omit", "absent-duplicate-peer", "absent-duplicate-session", "absent-cancelled-peer"):
            sdk.require(read(label) == bytes(33), "rejected input committed an account operation")
        for label in ("committed-after-unknown", "committed-final", "cancel-committed"):
            sdk.require(read(label) == b"\x02" + bytes(32), "aggregate commitment changed")
        delivered = []
        for index in (0,1):
            result, retained, resumed = (read(f"{prefix}-{index}") for prefix in ("delivered", "retained", "cancel-resumed"))
            sdk.require(len(result) == len(retained) == len(resumed) == 88 and any(result[:16]) and any(result[48:80]),
                        "account delivery framing")
            sdk.require(result[16:48] == sessions[index*32:(index+1)*32] and result[80:] == b"\0\0\0\x01" * 2,
                        "account member identity/outcome")
            sdk.require(retained[:84] == result[:84] and retained[84:] == bytes(4), "retained account member changed")
            sdk.require(resumed[:48] == result[:48] and any(resumed[48:80]) and resumed[48:80] != result[48:80]
                        and resumed[80:] == result[80:], "cancelled original operation did not resume")
            sdk.require(read(f"effect-{index}") == result[16:80] + b"persisted before process exit", "account business effect differs")
            delivered.append(result)
        sdk.require(delivered[0][:16] != delivered[1][:16] and delivered[0][48:80] != delivered[1][48:80]
                    and read("effect-before-retry") == read("effect-0"), "distinct recipient/original effect changed")
        results[trust] = {"foreign_processes":len(CASES), "original_operation":original.hex(), "cancelled_operation":cancelled.hex(),
                          "recipients":2, "receiver_exit_77_cuts":1, "concurrent_close_busy_and_member_cancel":True}
    return results
