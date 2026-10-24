"""Read JNI witness outcomes; native execution verifies signatures and authorization."""
from pathlib import Path
from collections.abc import Callable
import re
import tempfile

import continuity_android_contract as contract
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


def public(carrier: str, *, managed: bool = False) -> tuple[str, ...]:
    """Complete public result and process-record closure of the witness reader."""
    selected = cases(carrier, managed=managed)
    return (tuple(name for name, _ in selected)
            + tuple(name + "." + stream for name, _ in selected for stream in ("stdout", "stderr"))
            + ("signed-witness-transcript",))


def export_public(stdout: bytes, directory: Path, output: Path, prefix: str, outcomes: dict,
                  *, managed: bool = False, extra_public: tuple[str, ...] = (),
                  verifier: Callable[[bytes, Path], dict]) -> None:
    """Replay the retained flat archive bytes through the original full reader."""
    sdk.require(re.fullmatch(r"android-jni-(debug|release)-(witness|authority|credential)-", prefix)
                is not None, "invalid witness public export prefix")
    sdk.require(set(outcomes) == {carrier + "-" + trust for carrier in ("signed", "tls")
                                 for trust in ("fixed", "recoverable")}, "incomplete witness export routes")
    with tempfile.TemporaryDirectory(prefix="witness-export-readback-", dir=output) as temporary:
        readback = Path(temporary)
        for label in outcomes:
            carrier = label.split("-", 1)[0]
            # The inventory is a union: a repeated declaration refers to the
            # same original public file, not a second output to overwrite.
            names = dict.fromkeys(public(carrier, managed=managed) + extra_public)
            for name in names:
                relative = Path(name)
                sdk.require(name and not relative.is_absolute() and ".." not in relative.parts
                            and relative.as_posix() == name, "invalid witness public member")
                retained = output / (prefix + label + "-" + name + ".public")
                sdk.copy(directory / label / relative, retained)
                sdk.copy(retained, readback / label / relative)
        sdk.require(verifier(stdout, readback) == outcomes, "witness public export differs")


def verify_execution(stdout: bytes, directory: Path, *, managed: bool = False, test: str | None = None) -> dict:
    text = stdout.decode()
    test = test or ("android_witness::managed_first_registration" if managed else TEST)
    contract.verify_single(stdout, test)
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
