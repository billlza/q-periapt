#!/usr/bin/env python3
"""Actual Swift/Rust TCP boundary diagnostic; not installed-package qualification."""
import argparse
from dataclasses import dataclass
import re
import json
import os
from pathlib import Path
import time

from standard_tls_interop import MAX_IDENTITY_BYTES, Peer, ROOT, identity, read_log, require, run
from evidence_io import load_json_object_snapshot, read_regular_snapshot


def freeze(source: Path, destination: Path) -> Path:
    snapshot = read_regular_snapshot(source, maximum=MAX_IDENTITY_BYTES, label="connection input")
    with destination.open("xb") as writer:
        require(writer.write(snapshot.data) == snapshot.size, "connection input copy was incomplete")
    destination.chmod(0o500)
    return destination


def policy_files(fixtures: Path, document: dict, *, create: bool) -> None:
    # These are driver-owned test inputs. No process is using them while a new
    # signed configuration is installed; the server's store is never overwritten.
    for name, value in [("policy.toml", document["policy_toml"].encode()),
                        ("policy.sig", bytes.fromhex(document["signature"])),
                        ("policy.vk", bytes.fromhex(document["verification_key"]))]:
        with (fixtures / name).open("xb" if create else "wb") as stream:
            stream.write(value)
        (fixtures / name).chmod(0o600)


@dataclass(frozen=True)
class StaticClientLinkage:
    """Inputs supplied only after the installed-package caller validates its ZIPs."""
    library: Path
    library_sha256: str
    link_map: Path
    architecture: str


def verify_static_linkage(client: Path, linkage: StaticClientLinkage) -> dict:
    from apple_sdk_profile import verify_link_map
    require(re.fullmatch(r"[0-9a-f]{64}", linkage.library_sha256) is not None,
            "static client requires an exact expected archive digest")
    require(identity(linkage.library)["sha256"] == linkage.library_sha256,
            "static client archive differs from the selected package")
    return {"kind": "static", "library_sha256": linkage.library_sha256,
            "link_map": verify_link_map(linkage.link_map, linkage.library, client, linkage.architecture)}


def verify_client_load(log: bytes, client: Path, library: Path, *, static: bool) -> None:
    # Only complete dyld image records establish identity. A matching substring
    # in another path or an ordinary diagnostic is not a load observation.
    image_record = re.compile(
        rb"dyld\[[1-9][0-9]*\]: <[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}> (/[^\r\n]+)"
    )
    transition_record = re.compile(
        rb"dyld\[[1-9][0-9]*\]: move (?:loaded to delayed|delayed to loaded): ([A-Za-z0-9_.+-]+)"
    )
    images, transitions = [], []
    for line in log.splitlines():
        if line.startswith(b"dyld["):
            record = image_record.fullmatch(line)
            if record is not None:
                images.append(record[1])
            else:
                transition = transition_record.fullmatch(line)
                require(transition is not None, "unsupported dyld image record")
                transitions.append(transition[1])
    expected = client if static else library
    require(images.count(str(expected).encode()) == 1,
            "dyld must identify the exact frozen client" if static else
            "dyld must identify the exact frozen ABI 2 library")
    sdk_name = re.compile(rb"(?i)(?:q_periapt|qperiapt).*\.(?:dylib|so)(?:\.[0-9]+)*$")
    sdk_images = [path for path in images if sdk_name.search(path.rsplit(b"/", 1)[-1])]
    sdk_transitions = [name for name in transitions if sdk_name.search(name)]
    if static:
        require(not sdk_images and not sdk_transitions,
                "installed static client loaded a separate Q-Periapt library")
    else:
        require(all(path == str(library).encode() for path in sdk_images) and
                all(name == library.name.encode() for name in sdk_transitions),
                "dynamic client loaded another Q-Periapt library")


def run_controlled_client(command: list[str], output: Path, name: str, records: list[dict],
                          server: Peer, markers: tuple[bytes, ...], environment: dict[str, str]) -> int:
    """Authorize cancellation/revocation only after the peer observes real I/O."""
    client = Peer(command, output, name, records, environment=environment, control_input=True)
    client.record["control_observations"] = []
    try:
        for marker in markers:
            deadline = time.monotonic() + 2
            while marker not in read_log(server.stdout).splitlines():
                require(server.process.poll() is None and client.process.poll() is None,
                        "peer exited before the controlled operation was observed")
                if time.monotonic() >= deadline:
                    raise TimeoutError(f"peer observation deadline expired: {name}")
                time.sleep(0.005)
            require(server.process.poll() is None, "observed peer already exited before interruption")
            require(client.process.stdin is not None, "diagnostic control pipe is missing")
            require(client.process.stdin.write(b"\n") == 1, "diagnostic control write was incomplete")
            client.record["control_observations"].append(marker.decode("ascii"))
        client.process.stdin.close()
        return client.finish()
    finally:
        client.close()


def run_boundary(output: Path, *, swift: Path, server: Path, fixtures_binary: Path,
                 library: Path | None = None, static_linkage: StaticClientLinkage | None = None) -> dict:
    require(os.uname().sysname == "Darwin", "this boundary driver requires a native macOS Swift client")
    require((library is None) != (static_linkage is None), "select exactly one checked client linkage")
    linkage = ({"kind": "dynamic"} if static_linkage is None
               else verify_static_linkage(swift, static_linkage))
    selected_library = library if static_linkage is None else static_linkage.library
    output = output.resolve()
    output.mkdir(mode=0o700)
    binary = output / "bin"
    binary.mkdir(mode=0o700)
    sources = {"client": swift, "library": selected_library, "server": server, "fixtures": fixtures_binary}
    frozen = {name: freeze(path.resolve(strict=True), binary / path.name) for name, path in sources.items()}
    identities = {name: identity(path) for name, path in frozen.items()}
    records: list[dict] = []
    observations: list[dict] = []
    manifest = {"completed": False, "release_claim_eligible": False, "platform": os.uname().sysname,
                "network": "loopback", "abi_major": 2, "binaries": identities, "commands": records,
                "observations": observations, "scope": "real local TCP and persistent policy on both peers; " +
                ("checked static Swift client" if static_linkage is not None else "local dynamic source build"),
                "source_paths": {name: str(path.resolve()) for name, path in sources.items()},
                "client_linkage": linkage}
    try:
        fixtures = output / "fixtures"
        require(run([str(frozen["fixtures"]), "fixtures", str(fixtures)], output, "fixtures", records) == 0,
                "certificate fixture generation failed")
        policy = load_json_object_snapshot(ROOT / "bindings/signed-policy-vectors.json", label="initial policy fixture").value
        policy_files(fixtures, policy, create=True)
        environment = {key: value for key, value in os.environ.items() if not key.startswith(("DYLD_", "LD_"))}
        environment["DYLD_PRINT_LIBRARIES"] = "1"
        if static_linkage is None:
            environment["DYLD_LIBRARY_PATH"] = str(binary)
        def check_load(label: str) -> None:
            verify_client_load(read_log(output / f"{label}.stderr"), frozen["client"], frozen["library"],
                               static=static_linkage is not None)
        for index, (case, mode, connections, hostname) in enumerate([
            ("roundtrip", "echo", 2, "localhost"),
            ("concurrent", "delay", 1, "localhost"),
            ("timeout", "stall", 1, "localhost"),
            ("cancel", "stall", 2, "localhost"),
            ("request-timeout", "hold", 1, "localhost"),
            ("request-cancel", "hold", 1, "localhost"),
            ("runtime-revoke", "hold", 1, "localhost"),
            ("mismatch", "mismatch", 1, "localhost"),
            ("hostname", "echo", 1, "wrong.test"),
        ]):
            server = Peer([str(frozen["server"]), str(fixtures), mode, str(connections),
                           "provision" if index == 0 else "open"],
                          output, case + "-server", records)
            try:
                address = server.ready(b"LISTEN")
                started = time.monotonic()
                command = [str(frozen["client"]), str(fixtures), address.rsplit(":", 1)[1], case, hostname,
                           "provision" if index == 0 else "open"]
                markers = {"cancel": (b"ACCEPTED 1", b"ACCEPTED 2"),
                           "request-cancel": (b"REQUEST 1 1",), "runtime-revoke": (b"REQUEST 1 1",)}
                if case in markers:
                    status = run_controlled_client([*command, "observed-io"], output, case + "-swift", records,
                                                   server, markers[case], environment)
                else:
                    status = run(command, output, case + "-swift", records, environment=environment)
                elapsed = time.monotonic() - started
                server_status = server.finish()
                require(status == 0, f"Swift boundary case failed: {case}")
                require(f"SWIFT_CONNECTION_PROBE_OK {case}\n".encode() in read_log(output / f"{case}-swift.stdout"),
                        f"Swift completion marker missing: {case}")
                check_load(case + "-swift")
                server_output = read_log(server.stdout)
                if case in ("mismatch", "hostname"):
                    require(server_status != 0 and b"POLICY_CONFIRMED" not in server_output,
                            f"forbidden peer reached confirmed application use: {case}")
                    if case == "mismatch":
                        require(b"BindingMismatch" in read_log(server.stderr), "missing context-binding rejection")
                elif case in ("request-timeout", "request-cancel", "runtime-revoke"):
                    require(server_status != 0 and server_output.count(b"REQUEST 1 1\n") == 1,
                            "cancelled/expired/revoked request was not observed exactly once")
                    require(elapsed < 3, "request cancellation/revocation exceeded the diagnostic bound")
                else:
                    require(server_status == 0, f"Rust boundary case failed: {case}")
                if case == "roundtrip":
                    require(server_output.count(b"POLICY_CONFIRMED\n") == 2 and
                            b"CONNECTION_PEER_DONE requests=6\n" in server_output, "reconnect/echo counts differ")
                elif case == "concurrent":
                    require(b"CONNECTION_PEER_DONE requests=2\n" in server_output,
                            "busy rejection cancelled/duplicated the admitted request")
                elif case in ("timeout", "cancel"):
                    require(elapsed < 3 and b"POLICY_CONFIRMED" not in server_output,
                            "silent peer did not terminate within the diagnostic bound")
                observations.append({"case": case, "passed": True, "client_elapsed_seconds": elapsed})
            finally:
                server.close()
        # Revoke the supported suite in a newer signed policy, then try the old
        # configured policy after process restart. Neither may open a listener.
        # If the revocation had merely failed signature verification without
        # persisting, the old policy would listen and this check would fail.
        revoked = load_json_object_snapshot(ROOT / "bindings/sdk-policy-revocation-vectors.json", label="revocation policy fixture").value
        require(revoked["verification_key"] == policy["verification_key"], "revocation fixture changed the root")
        for case, document in [("persist-revocation", revoked), ("reject-restart-rollback", policy)]:
            policy_files(fixtures, document, create=False)
            status = run([str(frozen["server"]), str(fixtures), "echo", "1", "open"],
                         output, case, records)
            require(status != 0 and b"LISTEN" not in read_log(output / f"{case}.stdout") and
                    b"PolicyDenied" in read_log(output / f"{case}.stderr"),
                    f"persisted revocation/rollback did not fail closed: {case}")
            client_case = "store-disabled" if case == "persist-revocation" else "store-rollback"
            client_status = run([str(frozen["client"]), str(fixtures), "0", client_case, "localhost", "open"],
                                output, case + "-swift", records, environment=environment)
            require(client_status == 0 and
                    f"SWIFT_CONNECTION_PROBE_OK {client_case}\n".encode() in read_log(output / f"{case}-swift.stdout"),
                    f"Swift persisted policy did not enforce {client_case}")
            check_load(case + "-swift")
            observations.append({"case": case, "passed": True, "persistent_peers": ["swift-client", "rust-server"]})
        enabled = load_json_object_snapshot(ROOT / "bindings/sdk-policy-update-vectors.json", label="re-enabling policy fixture").value
        require(enabled["verification_key"] == policy["verification_key"], "re-enable fixture changed the root")
        policy_files(fixtures, enabled, create=False)
        server = Peer([str(frozen["server"]), str(fixtures), "echo", "2", "open"],
                      output, "re-enable-server", records)
        try:
            address = server.ready(b"LISTEN")
            status = run([str(frozen["client"]), str(fixtures), address.rsplit(":", 1)[1], "roundtrip", "localhost", "open"],
                         output, "re-enable-swift", records, environment=environment)
            require(status == 0 and server.finish() == 0 and
                    b"SWIFT_CONNECTION_PROBE_OK roundtrip\n" in read_log(output / "re-enable-swift.stdout") and
                    b"CONNECTION_PEER_DONE requests=6\n" in read_log(server.stdout),
                    "newer signed policy did not re-enable the reopened server and client")
            check_load("re-enable-swift")
            observations.append({"case": "persist-re-enable-and-reconnect", "passed": True})
        finally:
            server.close()
        manifest["final_server_policy_database"] = identity(fixtures / "server.policy.redb")
        manifest["final_client_policy_database"] = identity(fixtures / "client.policy.redb")
        require({name: identity(path) for name, path in frozen.items()} == identities,
                "a frozen binary changed during the run")
        if static_linkage is not None:
            require(verify_static_linkage(swift, static_linkage) == linkage,
                    "installed client linkage changed during the boundary run")
        manifest["completed"] = True
    finally:
        (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"Swift/Rust connection boundary: {len(observations)} cases passed; {output / 'manifest.json'}")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--swift", type=Path, required=True)
    parser.add_argument("--library", type=Path, default=ROOT / "target/release/libq_periapt_ffi_abi2.dylib")
    parser.add_argument("--server", type=Path, default=ROOT / "target/debug/examples/connection_peer")
    parser.add_argument("--fixtures", type=Path, default=ROOT / "target/debug/examples/standard_peer")
    args = parser.parse_args()
    run_boundary(args.output, swift=args.swift, library=args.library, server=args.server, fixtures_binary=args.fixtures)


if __name__ == "__main__":
    main()
