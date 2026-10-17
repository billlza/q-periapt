"""Installed Kotlin root recovery and observed registry Cleaner revocation."""
from pathlib import Path

import continuity_c_root as driver
from continuity_c_consumer import MAX_BINARY
from continuity_c_witness import export_selected
import rust_sdk_profile as sdk

SCOPE = ("Installed Kotlin public root controller and C peer on the same host and shared Rust engine; "
         "original approvals, retired cleanup, signed witness query loss, mutual TLS, epoch-1 rekey and "
         "bidirectional original-message recovery. Bounded observed registry Cleaner revocation with a "
         "still-live successor under the selected Serial/G1 collector. JVM stack size is not measured or "
         "overridden. ROOT_C_* markers identify shared fixture wire formats. Not independent-implementation, "
         "all-JVM GC, automatic cancellation, power-loss or full release qualification.")


def verify_execution(stdout: bytes, directory: Path, *, variant: str, collector: str) -> dict:
    sdk.require(collector in {"Serial", "G1"}, "unsupported root GC collector")
    result = driver.verify_execution(stdout, directory, darwin=False, variant=variant, cut_ready=True)
    for name, expected in (("client-language", b"Kotlin"), ("root-gc-collector", collector.encode()),
                           ("gc-revokes-successor", (1).to_bytes(8, "big"))):
        value = sdk.snapshot(directory / "public" / name, maximum=8)
        sdk.require(value.data == expected, "root JVM language, collector or Cleaner revocation differs")
        result["public_readbacks"]["public/" + name] = value.sha256
    count = sdk.snapshot(directory / "public/gc-collections", maximum=8)
    sdk.require(len(count.data) == 8 and 1 <= int.from_bytes(count.data, "big") <= 4096,
                "root Cleaner observation has no bounded actual GC progress")
    result["public_readbacks"]["public/gc-collections"] = count.sha256
    for observation in (result, result["application_traffic"], result["application_traffic"]["reverse"]):
        sdk.require(not observation.pop("default_thread_stacks"), "JVM root receipt claims pthread stack measurements")
    result.update(scope=SCOPE, client_language="Kotlin", route=variant, collector=collector,
                  observed_collections=int.from_bytes(count.data, "big"), final_cleaner_revokes_successor=True)
    return result


def qualify(outside: Path, output: Path, profile: str, runtime: dict, clients: dict[str, Path],
            native: dict, library: Path, run) -> dict:
    sdk.require(set(clients) == {"Serial", "G1"}, "root Kotlin lane requires both garbage collectors")
    selected = {}
    for name in ("driver", "peer"):
        row = native[name]; path = Path(row["path"])
        sdk.require(sdk.snapshot(path, maximum=MAX_BINARY).sha256 == row["sha256"], "native root fixture changed")
        selected[name] = path
    identities = {path: sdk.snapshot(path, maximum=MAX_BINARY).sha256 for path in (*clients.values(), library, *selected.values())}
    sdk.require(identities[library] == native["binaries"][library.name], "Kotlin root library differs from the installed C engine")
    result = {"completed": False, "scope": SCOPE, "release_claim_eligible": False, "collectors": {}}
    for collector, client in clients.items():
        routes = {}
        for variant in ("original", *driver.alternatives.VARIANTS):
            label = profile + "-" + collector.lower() + "-" + variant
            evidence = outside / ("kotlin-root-" + label)
            env = dict(runtime, QPC_ROOT_CLIENT=str(client), QPC_ROOT_CLIENT_LANGUAGE="Kotlin", QPC_ROOT_VARIANT=variant,
                       QPC_ROOT_EVIDENCE=str(evidence), QPERIAPT_C_CLIENT=str(selected["peer"]))
            env.pop("QPERIAPT_PUBLIC_SERVICE_EVIDENCE", None)
            stdout = run([str(selected["driver"]), "--exact", driver.TEST, "--nocapture"], "root-" + label, runtime=env)
            checked = verify_execution(stdout, evidence, variant=variant, collector=collector)
            checked["exported_public_files"] = export_selected(checked, evidence, output / "kotlin-root-public" / label, SCOPE,
                replay=lambda path: verify_execution(stdout, path, variant=variant, collector=collector))
            routes[variant] = checked
        result["collectors"][collector] = routes
    sdk.require(all(sdk.snapshot(path, maximum=MAX_BINARY).sha256 == digest for path, digest in identities.items()),
                "root Kotlin/native binaries changed during qualification")
    result["binary_sha256"] = {str(path): digest for path, digest in identities.items()}
    result["completed"] = True
    return result
