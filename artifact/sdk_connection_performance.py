#!/usr/bin/env python3
"""Source-bound Swift/Rust loopback connection timing; no release performance claim."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil

from bounded_process import capture_stdout
from evidence_io import parse_strict_json_bytes
from sdk_connection_interop import freeze, policy_files, run_boundary, verify_client_load
from sdk_path_performance import quantiles, source_map
from standard_tls_interop import MAX_LOG, Peer, ROOT, identity, read_log, require

BLOCKS = 5
PAYLOADS = [0, 1, 65536]
SAMPLE_FIELDS = {"schema", "kind", "index", "phase", "connect_ns", "payload_bytes", "request_ns", "shutdown_ns"}
MARKER = b"SWIFT_CONNECTION_PROBE_OK measure"


def parse_samples(raw: bytes, reconnects: int) -> dict:
    require(type(reconnects) is int and 200 <= reconnects <= 1000, "invalid reconnect budget")
    require(len(raw) <= MAX_LOG, "connection timing log exceeds its bound")
    lines = raw.splitlines()
    require(len(lines) == reconnects + 3 and lines[-1] == MARKER, "connection timing capture is incomplete")
    setup = parse_strict_json_bytes(lines[0], label="connection setup timing")
    require(isinstance(setup, dict) and set(setup) == {"schema", "kind", "elapsed_ns"}, "setup timing shape differs")
    require(type(setup["schema"]) is int and setup["schema"] == 1 and setup["kind"] == "setup", "setup identity differs")
    valid_time = lambda value: type(value) is int and 0 < value < 120_000_000_000
    require(valid_time(setup["elapsed_ns"]), "invalid setup elapsed time")
    samples = []
    for index, line in enumerate(lines[1:-1]):
        sample = parse_strict_json_bytes(line, label="connection timing sample")
        require(isinstance(sample, dict) and set(sample) == SAMPLE_FIELDS, "sample timing shape differs")
        require(type(sample["schema"]) is int and sample["schema"] == 1 and sample["kind"] == "connection", "sample identity differs")
        require(type(sample["index"]) is int and sample["index"] == index and
                sample["phase"] == ("first" if index == 0 else "reconnect"), "sample order/phase differs")
        require(sample["payload_bytes"] == PAYLOADS and all(type(value) is int for value in sample["payload_bytes"]),
                "request payload matrix differs")
        require(isinstance(sample["request_ns"], list) and len(sample["request_ns"]) == len(PAYLOADS) and
                all(valid_time(value) for value in sample["request_ns"]) and
                valid_time(sample["connect_ns"]) and valid_time(sample["shutdown_ns"]), "invalid connection elapsed time")
        samples.append(sample)
    return {"setup": setup, "samples": samples}


def summarize(parsed: dict) -> dict:
    rows = parsed["samples"][1:]
    values = {"connect": [row["connect_ns"] for row in rows], "shutdown": [row["shutdown_ns"] for row in rows]}
    values.update({f"request_{size}": [row["request_ns"][index] for row in rows] for index, size in enumerate(PAYLOADS)})
    return {"setup_ns": parsed["setup"]["elapsed_ns"], "first": parsed["samples"][0],
            "reconnect_quantiles_ns": {name: quantiles(samples) for name, samples in values.items()}}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--reconnects", type=int, default=200)
    args = parser.parse_args()
    require(os.uname().sysname == "Darwin", "connection timing requires the native macOS Swift adapter")
    require(200 <= args.reconnects <= 1000, "reconnects must be 200..1000")
    require(shutil.disk_usage(ROOT).free >= 2 * 1024**3, "connection timing build needs at least 2 GiB free")
    output = args.output.resolve()
    require(output.is_relative_to(ROOT / "target"), "output must be fresh and inside target/")
    output.mkdir(mode=0o700)
    binary = output / "bin"; binary.mkdir(mode=0o700)
    os.chdir(ROOT)
    before = source_map()
    records: list[dict] = []
    manifest = {"kind": "qperiapt.connection_path_timing", "completed": False, "release_claim_eligible": False,
                "started_utc": datetime.now(timezone.utc).isoformat(), "source_files_sha256": before,
                "source_manifest_sha256": hashlib.sha256(json.dumps(before, sort_keys=True).encode()).hexdigest(),
                "platform": os.uname().sysname, "machine": os.uname().machine, "network": "IPv4 loopback",
                "blocks": BLOCKS, "reconnects_per_block": args.reconnects, "commands": records, "observations": [],
                "clock": "DispatchTime.now().uptimeNanoseconds", "quantiles": "nearest rank per block",
                "security_contract": "fresh TLS 1.3/X25519MLKEM768, mutual pinned certificates, qperiapt-sdk/1 policy/context confirmation; no resumption/0-RTT/classic fallback",
                "included": ["Swift actor/FFI/Network transport", "TCP/TLS/authentication/policy confirmation in connect", "complete authenticated echo in request", "close_notify and disposal in shutdown", "reference server deadline-bounded socket readiness waiting"],
                "setup_scope": "fixture reads, signed-policy provisioning/durable commit and client endpoint construction; before first connect",
                "excluded": ["process launch from latency intervals", "payload construction and reply comparison", "JSON output", "server setup before LISTEN", "CPU/allocation/energy", "installed packages", "native Linux"],
                "first_connection_scope": "one first call per fresh Swift process after endpoint setup; five raw observations, no first-connect tail claim",
                "host_controls": "uncontrolled; no power settings or other applications changed"}

    def command(argv: list[str], name: str, *, environment=None, timeout=900) -> bytes:
        record = {"argv": argv, "name": name, "returncode": None}; records.append(record)
        with (output / f"{name}.stdout").open("xb") as stdout, (output / f"{name}.stderr").open("xb") as stderr:
            result = capture_stdout(argv, timeout_seconds=timeout, maximum_bytes=MAX_LOG,
                                    stderr=stderr.fileno(), environment=environment, output_sink=stdout.write)
        record["returncode"] = result.returncode
        error_log = read_log(output / f"{name}.stderr")
        require(result.returncode == 0, f"connection timing command failed: {name}")
        require(re.search(rb"(?im)(?:^|[^a-z])(warning|error):", result.stdout + error_log) is None,
                f"connection timing command emitted warnings/errors: {name}")
        return result.stdout

    try:
        for tool in ("rustc", "cargo", "swift", "cc"):
            command([tool, "--version"], tool + "-version")
        command(["sysctl", "machdep.cpu.brand_string", "hw.logicalcpu"], "host-cpu")
        command(["cargo", "build", "--locked", "--release", "-p", "q-periapt-ffi", "--lib"], "native-build")
        command(["cargo", "build", "--locked", "--release", "-p", "q-periapt-rustls", "--examples", "--features", "reference-connection"], "peer-build")
        metadata = parse_strict_json_bytes(command(["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"], "metadata"), label="Cargo target metadata")
        target = Path(metadata["target_directory"])
        library = freeze(target / "release/libq_periapt_ffi_abi2.dylib", binary / "libq_periapt_ffi_abi2.dylib")
        server = freeze(target / "release/examples/connection_peer", binary / "connection_peer")
        fixtures_program = freeze(target / "release/examples/standard_peer", binary / "standard_peer")
        build = ["swift", "build", "--package-path", "bindings/swift", "--configuration", "release",
                 "--product", "QPeriaptConnectionProbe", "--scratch-path", str(output / "swift-build"),
                 "-Xlinker", f"-L{binary}", "-Xswiftc", "-strict-concurrency=complete", "-Xswiftc", "-warnings-as-errors"]
        command(build, "swift-build")
        swift_bin = Path(command(build + ["--show-bin-path"], "swift-bin").decode().strip())
        client = freeze(swift_bin / "QPeriaptConnectionProbe", binary / "QPeriaptConnectionProbe")
        identities = {name: identity(path) for name, path in (("client", client), ("server", server), ("library", library), ("fixtures", fixtures_program))}
        manifest["binaries"] = identities
        require(source_map() == before, "source changed during connection build")
        # The unchanged negative paths must still run with the same executables
        # before any timing row is admitted as a completed capture.
        boundary = run_boundary(output / "boundary", swift=client, server=server, library=library, fixtures_binary=fixtures_program)
        require(boundary["completed"] and len(boundary["observations"]) == 12, "connection acceptance did not complete")
        manifest["acceptance_manifest"] = identity(output / "boundary/manifest.json")
        environment = {key: value for key, value in os.environ.items() if not key.startswith(("DYLD_", "LD_"))}
        environment.update(DYLD_LIBRARY_PATH=str(binary), DYLD_PRINT_LIBRARIES="1")
        policy = parse_strict_json_bytes((ROOT / "bindings/signed-policy-vectors.json").read_bytes(), label="signed policy fixture")
        manifest["load_before"] = os.getloadavg()
        for block in range(BLOCKS):
            folder = output / f"fixtures-{block}"
            command([str(fixtures_program), "fixtures", str(folder)], f"fixtures-{block}", timeout=30)
            policy_files(folder, policy, create=True)
            peer = Peer([str(server), str(folder), "measure", str(args.reconnects + 1), "provision"], output, f"block-{block}-server", records)
            try:
                address = peer.ready(b"LISTEN")
                name = f"block-{block}-client"
                load = os.getloadavg()
                raw = command([str(client), str(folder), address.rsplit(":", 1)[1], "measure", "localhost", "provision", str(args.reconnects)], name, environment=environment, timeout=120)
                require(peer.finish() == 0, "measurement server did not finish")
                require(read_log(peer.stdout) == f"LISTEN {address}\nCONNECTION_PEER_DONE requests={3 * (args.reconnects + 1)}\n".encode(), "server request count or logging mode differs")
                require(read_log(peer.stderr) == b"", "measurement server emitted diagnostics")
                verify_client_load(read_log(output / f"{name}.stderr"), client, library, static=False)
                parsed = parse_samples(raw, args.reconnects)
                manifest["observations"].append({"block": block, "load_before": load, "raw": name + ".stdout", **summarize(parsed)})
            finally:
                peer.close()
        manifest["load_after"] = os.getloadavg()
        require(source_map() == before, "source changed during connection measurement")
        require({name: identity(Path(row["path"])) for name, row in identities.items()} == identities, "frozen executable/library changed")
        manifest["completed"] = True
    except BaseException as error:
        manifest["failure"] = {"kind": type(error).__name__, "message": str(error)}
        raise
    finally:
        manifest["finished_utc"] = datetime.now(timezone.utc).isoformat()
        manifest["evidence_sha256"] = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(output.iterdir()) if path.is_file()}
        with (output / "manifest.json").open("x") as stream:
            json.dump(manifest, stream, indent=2, sort_keys=True); stream.write("\n")
    print(f"SDK_CONNECTION_TIMING_PASS blocks={BLOCKS} reconnects_per_block={args.reconnects} output={output}")


if __name__ == "__main__":
    main()
