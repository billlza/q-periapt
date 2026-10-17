"""Original local roster and independently admitted peer-roster linkage."""
from pathlib import Path
import continuity_android_contract as contract
import continuity_first_configuration as first
import rust_sdk_profile as sdk

LOCAL_TEST = "android_roster_local::original_roster_advance"
PEER_TEST = "android_roster_local::remote_roster_advance"


def local_cases(remote: bool = False) -> tuple:
    steps = [("original.request", "policy-create"), ("prepared", "policy-prepare"),
             ("activated.request", "policy-activate"), ("original.identity", "policy-identity"),
             ("roster-connected", "roster-peer-connect"), ("roster-unknown", "roster-peer-uncertain")]
    if remote:
        steps += [("remote-roster-" + label, "roster-peer-roster-" + mode) for label, mode in
                  (("bad", "bad"), ("checkpoint", "checkpoint"), ("cancelled", "cancelled"),
                   ("admitted", "admit"), ("reopened", "reopen"))]
    steps += [("bad-signature", "roster-refused"), ("bad-signature-identity", "roster-identity"),
              ("cancelled", "roster-cancelled"), ("cancelled-identity", "roster-identity"),
              ("refreshed", "roster-refresh"), ("refreshed-replay", "roster-refresh"),
              ("pending-resolution", "roster-resolve-pending"), ("activated.identity", "roster-activate"),
              ("roster-acknowledged", "roster-peer-retry")]
    if remote:
        steps += [("remote-roster-revoked", "roster-peer-roster-revoke"),
                  ("remote-roster-revoked-reopened", "roster-peer-roster-revoked-reopen")]
    return tuple(steps + [("final.identity", "roster-identity")])


def check_processes(base: Path, profile: str, steps: tuple) -> None:
    for name, mode in steps:
        sdk.require(sdk.snapshot(base / (name + ".stdout")).data == f"{profile}:{mode}:passed\n".encode()
                    and sdk.snapshot(base / (name + ".stderr")).data == b"", "roster process outcome missing: " + name)


def traffic(base: Path, *, witnessed: bool = False) -> dict:
    def read(name): return sdk.snapshot(base / name).data
    prepared, identity = read("prepared"), read("original.identity")
    sdk.require(len(prepared) == 164 and len(identity) == 64 and identity[32:] == prepared[4:36]
                and read("final.identity") == identity, "roster changed original identity/journal")
    if not witnessed:
        sdk.require(prepared[:4] == (1).to_bytes(4, "big") and prepared[36:] == bytes(128), "local protection changed")
    data = {"request.bin": read("original.request"), "replayed.bin": read("activated.request"),
            "intent.bin": read("inputs/enrollment-intent"), "root.bin": read("inputs/enrollment-root"),
            "session.bin": read("roster-connected"), "unknown.bin": read("roster-unknown"),
            "acknowledged.bin": read("roster-acknowledged"), "effect.bin": read("roster-effect-before"),
            "after-traffic.bin": read("final.identity")}
    if witnessed: data["genesis.bin"] = prepared
    _, _, _, request_sha = first.verify_original(data, after_traffic="identity",
        identity_journal=None if witnessed else prepared[4:36])
    sdk.require(read("roster-effect-after") == data["effect.bin"], "roster retry repeated the business effect")
    sdk.require(read("roster-peer-admitted.stdout") == b"peer-roster-admitted\n"
                and read("roster-peer-admitted.stderr") == b"", "native peer roster admission missing")
    return {"original_request_sha256": request_sha, "original_session": data["session.bin"].hex(),
            "original_message": data["unknown.bin"][32:].hex(), "business_effects": 1}


def verify_peer(base: Path) -> None:
    def read(name): return sdk.snapshot(base / name).data
    for name, code in (("bad", 102), ("checkpoint", 105), ("cancelled", 302)):
        sdk.require(read("remote-roster-" + name) == code.to_bytes(4, "big"), "remote roster refusal changed")
    admitted = read("remote-roster-admitted")
    target = read("inputs/remote-roster-version") + read("inputs/remote-roster-digest")
    revoked = read("inputs/remote-roster-revoked-version") + read("inputs/remote-roster-revoked-digest")
    sdk.require(len(admitted) == 72 and admitted == read("remote-roster-reopened")
                and admitted[:40] == target and admitted[40:] == read("inputs/remote-roster-next")
                and any(admitted[40:]), "remote roster replaced the original next slot")
    sdk.require(len(target) == len(revoked) == 40
                and int.from_bytes(read("inputs/peer/responder-roster-version"), "big")
                < int.from_bytes(target[:8], "big") < int.from_bytes(revoked[:8], "big")
                and read("remote-roster-revoked") == read("remote-roster-revoked-reopened") == revoked,
                "remote roster advancement/revocation linkage differs")


def verify_local(stdout: bytes, directory: Path, *, remote: bool = False, catalog=contract.TESTS) -> dict:
    contract.verify_single(stdout, PEER_TEST if remote else LOCAL_TEST, catalog=catalog)
    steps = local_cases(remote); count = 23 if remote else 16
    sdk.require(len(steps) == count, "local roster census definition")
    results = {}
    for profile in ("fixed", "recoverable"):
        marker = f"qualified local roster adapter {profile}: {count} Java processes; original identity journal session message and one effect across local R2 advancement"
        sdk.require(stdout.decode().splitlines().count(marker) == 1, "local roster outcome missing/duplicated")
        base = directory / profile; check_processes(base, profile, steps)
        def read(name): return sdk.snapshot(base / name).data
        record = traffic(base)
        refreshed = read("refreshed"); identity = read("original.identity")
        sdk.require(len(refreshed) == 148 and refreshed == read("refreshed-replay")
                    and refreshed[:4] == (6).to_bytes(4, "big") and refreshed[4:68] == identity
                    and refreshed[68:108] == read("inputs/trusted-roster-version") + read("inputs/trusted-roster-digest")
                    and refreshed[108:] == read("inputs/renewal-version") + read("inputs/renewal-digest"),
                    "local roster staging identity/checkpoints differ")
        sdk.require(read("pending-resolution") == (215).to_bytes(4, "big")
                    and read("activated.identity") == identity, "staging became a commit receipt or changed identity")
        for name, code in (("bad-signature", 102), ("cancelled", 302)):
            sdk.require(read(name) == code.to_bytes(4, "big") and read(name + "-identity") == identity,
                        "rejected roster changed original identity")
        if remote: verify_peer(base)
        results[profile] = dict(record, foreign_processes=count, remote_roster=remote)
    return results


def local_public(remote: bool = False) -> tuple:
    steps = local_cases(remote)
    files = tuple(name for name, _ in steps) + tuple(name + "." + suffix for name, _ in steps for suffix in ("stdout", "stderr"))
    files += ("roster-effect-before", "roster-effect-after", "roster-peer-admitted.stdout", "roster-peer-admitted.stderr",
              "inputs/enrollment-intent", "inputs/enrollment-root", "inputs/trusted-roster-version", "inputs/trusted-roster-digest",
              "inputs/renewal-version", "inputs/renewal-digest")
    if remote:
        files += tuple("inputs/" + name for name in ("remote-roster", "remote-roster-version", "remote-roster-digest",
            "remote-roster-next", "remote-roster-revoked", "remote-roster-revoked-version", "remote-roster-revoked-digest",
            "peer/responder-roster-version", "peer/responder-root", "peer/responder-account", "peer/bootstrap.bundle", "family"))
    return files
