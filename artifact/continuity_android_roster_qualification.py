"""Installed Android roster workloads and their bounded public export closure."""
from pathlib import Path
import continuity_android_roster as local
import continuity_android_roster_witness as witness
import continuity_android_policy_roster as policy
import rust_sdk_profile as sdk


def qualify(binary: Path, consumer: Path, installed: Path, output: Path, profile: str,
            runtime: dict, run) -> dict:
    results = {}
    for lane, test, remote in (("roster-local", local.LOCAL_TEST, False), ("roster-peer", local.PEER_TEST, True)):
        cases = installed / (lane + "-cases")
        stdout = run([str(binary), "--exact", test, "--nocapture"], profile + "-" + lane,
                     consumer, dict(runtime, QPC_ANDROID_CASES=str(cases)))
        records = local.verify_local(stdout, cases, remote=remote); results[lane] = records
        exported = output / ("android-jni-" + profile + "-" + lane)
        for label in records:
            for name in local.local_public(remote): sdk.copy(cases / label / name, exported / label / name)
        sdk.require(local.verify_local(stdout, exported, remote=remote) == records, "local roster public export differs")
    cases = installed / "roster-witness-cases"
    stdout = run([str(binary), "--exact", witness.TEST, "--nocapture"], profile + "-roster-witness",
                 consumer, dict(runtime, QPC_ANDROID_CASES=str(cases)))
    records = witness.verify_execution(stdout, cases); results["roster-witness"] = records
    exported = output / ("android-jni-" + profile + "-roster-witness")
    for label in records:
        for name in witness.public(label.endswith("-closed")): sdk.copy(cases / label / name, exported / label / name)
    sdk.require(witness.verify_execution(stdout, exported) == records, "witness roster public export differs")
    # Each test owns a distinct directory, identity, journal and witness. Three
    # independent real-expiry routes run at once within the command time bound.
    cases = installed / "policy-roster-cases"; cases.mkdir(mode=0o700)
    stdout = run([str(binary), "android_policy_renewal::roster_", "--test-threads=3", "--show-output"],
                 profile + "-policy-roster", consumer, dict(runtime, QPC_ANDROID_CASES=str(cases)))
    records = policy.verify_execution(stdout, cases); results["policy-roster"] = records
    exported = output / ("android-jni-" + profile + "-policy-roster")
    for carrier, trust, terminal in policy.routes():
        label = carrier + "-" + trust + "-" + terminal; relative = Path(label) / (carrier + "-" + trust)
        for name in policy.public(carrier, terminal): sdk.copy(cases / relative / name, exported / relative / name)
    sdk.require(policy.verify_execution(stdout, exported) == records, "policy-roster public export differs")
    return results
