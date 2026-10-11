"""Read JNI witness outcomes; native execution verifies signatures and authorization."""
from pathlib import Path
import re

import rust_sdk_profile as sdk

TEST = "android_witness::required_witness_registration"
BASE_CASES = (
    ("original.request", "witness-create"), ("wrong-pin", "witness-wrong"),
    ("resumed.request", "witness-resume"), ("genesis", "witness-prepare"),
    ("missing", "witness-missing"), ("activated.request", "witness-activate"),
    ("active-reopened.request", "witness-active-reopen"),
)


def cases(carrier: str, *, managed: bool = False) -> tuple:
    sdk.require(carrier in {"signed", "tls"}, "unknown witness carrier")
    selected = BASE_CASES + ((("bad-receipt", "witness-bad-receipt"),) if carrier == "signed" else ())
    if managed:
        selected = tuple((name, "managed-" + mode) for name, mode in selected) + (
            ("authority-created", "authority-create"), ("authority-reopened", "authority-reopen"),
            ("unselected", "managed-unselected"), ("closed-registry", "managed-closed-registry"),
            ("cancelled-registry", "managed-cancelled-registry"))
    return selected


def verify_execution(stdout: bytes, directory: Path, *, managed: bool = False, test: str | None = None) -> dict:
    text = stdout.decode()
    test = test or ("android_witness::managed_first_registration" if managed else TEST)
    sdk.require(re.findall(r"^test (\S+) \.\.\. ok$", text, re.MULTILINE) == [test]
                and len(re.findall(r"^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 6 filtered out;", text, re.MULTILINE)) == 1,
                "Android required-witness test was not executed completely")
    records = {}
    for carrier in ("signed", "tls"):
        for trust in ("fixed", "recoverable"):
            label = carrier + "-" + trust; base = directory / label
            marker = f"qualified witness {carrier}/{trust}: original registration, independent genesis, refused missing or wrong trust, authenticated activation and reopen"
            if managed:
                marker = f"qualified managed witness {carrier}/{trust}: independent registry, original association, checkpoint refusal, cancelled registry retains admission, closed registry revokes admission, authenticated activation and reopen"
            sdk.require(text.splitlines().count(marker) == 1, "Android witness profile missing or duplicated")
            for name, operation in cases(carrier, managed=managed):
                sdk.require(sdk.snapshot(base / (name + ".stderr")).data == b"" and
                            sdk.snapshot(base / (name + ".stdout")).data == f"{trust}:{operation}:passed\n".encode(),
                            "Android witness process omitted an outcome or reported diagnostics")
            if managed:
                checkpoint = sdk.snapshot(base / "authority-created").data
                sdk.require(len(checkpoint) == 72 and any(checkpoint[:32]) and any(checkpoint[40:])
                            and checkpoint[32:40] == (1).to_bytes(8, "big")
                            and sdk.snapshot(base / "authority-reopened").data == checkpoint,
                            "original authority association changed or failed to reopen")
            original = sdk.snapshot(base / "original.request").data
            replay = ("resumed.request", "missing", "activated.request", "active-reopened.request")
            if carrier == "signed": replay += ("bad-receipt",)
            if managed: replay += ("unselected", "closed-registry", "cancelled-registry")
            sdk.require(len(original) == 5506 and all(sdk.snapshot(base / name).data == original for name in replay),
                        "Android witnessed enrollment substituted its original request")
            sdk.require(sdk.snapshot(base / "wrong-pin").data == b"\x01", "wrong witness pin was not refused")
            genesis = sdk.snapshot(base / "genesis").data
            sdk.require(len(genesis) == 164 and genesis[:4] == (2).to_bytes(4, "big")
                        and genesis[4:36] == genesis[36:68] and all(any(genesis[a:a+32]) for a in (4, 68, 100, 132)),
                        "Android witness genesis changed or lost its device scope")
            transcript = sdk.snapshot(base / "signed-witness-transcript").data.decode().splitlines()
            sdk.require(0 < len(transcript) <= 4096, "witness transcript missing or exceeds its bound")
            for line in transcript:
                fields = line.split(" ")
                sdk.require(len(fields) == 3 and fields[2] in {"true", "false"}
                            and re.fullmatch(r"[0-9a-f]{7348}", fields[0]) is not None
                            and re.fullmatch(r"[0-9a-f]{7318}", fields[1]) is not None,
                            "witness transcript has malformed public frames")
            records[label] = {"foreign_processes": len(cases(carrier, managed=managed)), "journal": genesis[4:36].hex(),
                              "genesis_sha256": sdk.snapshot(base / "genesis").sha256,
                              "transcript_sha256": sdk.snapshot(base / "signed-witness-transcript").sha256}
    return records
