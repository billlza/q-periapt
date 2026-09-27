"""Bounded loopback interoperability with an independent OpenSSL 3.5+ endpoint.

Build standard_peer with --features standard-tls first. No public network,
installation, secret logging, mocked crypto or success-through-skip path.
Generated test credentials stay in the mode-0700 output directory. This is a
diagnostic harness, not the Swift/macOS-to-Rust/Linux reference application.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parent.parent
MAX_LOG = 1_048_576


def read_log(path: Path) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(MAX_LOG + 1)
    if len(data) > MAX_LOG:
        raise ValueError(f"diagnostic log exceeds {MAX_LOG} bytes: {path.name}")
    return data


class Peer:
    def __init__(self, command: list[str], output: Path, name: str, records: list[dict]):
        self.stdout = output / f"{name}.stdout"
        self.stderr = output / f"{name}.stderr"
        self.record = {"command": command, "name": name, "returncode": None}
        records.append(self.record)
        with self.stdout.open("xb") as stdout, self.stderr.open("xb") as stderr:
            self.process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)

    def ready(self, prefix: bytes) -> str:
        deadline = time.monotonic() + 10
        pattern = re.compile(prefix + rb" (127\.0\.0\.1:[0-9]+)\r?\n")
        while time.monotonic() < deadline:
            match = pattern.search(read_log(self.stdout))
            if match is not None:
                return match.group(1).decode("ascii")
            if self.process.poll() is not None:
                raise RuntimeError(f"peer exited before readiness: {self.record['name']}")
            time.sleep(0.02)
        raise TimeoutError(f"peer readiness timeout: {self.record['name']}")

    def finish(self) -> int:
        status = self.process.wait(timeout=10)
        self.record["returncode"] = status
        read_log(self.stdout)
        read_log(self.stderr)
        return status

    def close(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)
        self.record["returncode"] = self.process.returncode


def run(command: list[str], output: Path, name: str, records: list[dict], data: bytes | None = None,
        *, environment: dict[str, str] | None = None) -> int:
    record = {"command": command, "name": name, "returncode": None}
    records.append(record)
    with (output / f"{name}.stdout").open("xb") as stdout, (output / f"{name}.stderr").open("xb") as stderr:
        result = subprocess.run(command, input=data, stdout=stdout, stderr=stderr, timeout=20, check=False,
                                env=environment)
    record["returncode"] = result.returncode
    read_log(output / f"{name}.stdout")
    read_log(output / f"{name}.stderr")
    return result.returncode


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def identity(path: Path) -> dict:
    return {"path": str(path.resolve()), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def seal_peer(source: Path, output: Path) -> Path:
    """Run one immutable executable even if Cargo rebuilds the source path."""
    folder = output / "bin"
    folder.mkdir(mode=0o700)
    destination = folder / "standard_peer"
    with source.open("rb") as reader, destination.open("xb") as writer:
        before = os.fstat(reader.fileno())
        shutil.copyfileobj(reader, writer)
        after = os.fstat(reader.fileno())
        require((before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_size, after.st_mtime_ns, after.st_ctime_ns), "peer executable changed while sealing")
    destination.chmod(0o500)
    return destination


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--openssl", default=shutil.which("openssl"))
    parser.add_argument("--peer", type=Path, default=ROOT / "target/debug/examples/standard_peer")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    require(os.name == "posix", "this loopback diagnostic requires Unix permission semantics")
    require(args.openssl is not None, "OpenSSL is required, not skipped")
    openssl, peer_source = Path(args.openssl).resolve(strict=True), args.peer.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(mode=0o700)  # never overwrite a previous run
    peer = seal_peer(peer_source, output)
    records: list[dict] = []
    observations: list[dict] = []
    manifest = {"openssl": identity(openssl), "rust_peer": identity(peer), "peer_source_path": str(peer_source), "observations": observations,
                "commands": records, "completed": False, "release_claim_eligible": False,
                "platform": os.uname().sysname, "network": "loopback", "independent_tls_implementation": "OpenSSL",
                "scope": "fresh standard hybrid TLS 1.3 with certificate authentication; no Q-Periapt policy agreement"}
    try:
        require(run([str(openssl), "version", "-a"], output, "openssl-version", records) == 0, "OpenSSL version failed")
        require(run([str(openssl), "list", "-tls-groups", "-tls1_3"], output, "openssl-groups", records) == 0, "OpenSSL group query failed")
        require(b"X25519MLKEM768" in read_log(output / "openssl-groups.stdout"), "OpenSSL lacks the required standard group")
        fixtures = output / "fixtures"
        require(run([str(peer), "fixtures", str(fixtures)], output, "fixtures", records) == 0, "test fixture generation failed")
        for case, group, hostname, authenticated, protocol in [
            ("accepted", "X25519MLKEM768", "localhost", True, "-tls1_3"),
            ("wrong-hostname", "X25519MLKEM768", "wrong.test", True, "-tls1_3"),
            ("anonymous", "X25519MLKEM768", "localhost", False, "-tls1_3"),
            ("classic-only", "X25519", "localhost", True, "-tls1_3"),
            ("tls12", "X25519", "localhost", True, "-tls1_2"),
        ]:
            name = f"rust-server-{case}"
            server = Peer([str(peer), "server", str(fixtures)], output, name, records)
            try:
                address = server.ready(b"LISTEN")
                command = [str(openssl), "s_client", "-connect", address, protocol, "-groups", group,
                           "-verify_return_error", "-verify_hostname", hostname, "-servername", hostname,
                           "-CAfile", str(fixtures / "server.pem"), "-quiet"]
                if authenticated:
                    command += ["-cert", str(fixtures / "client.pem"), "-key", str(fixtures / "client.key.pem")]
                status = run(command, output, name + "-openssl", records, b"PING\n")
                server_status = server.finish()
                if case == "accepted":
                    require(status == 0 and server_status == 0, "OpenSSL client / Rust server did not complete")
                    require(read_log(output / f"{name}-openssl.stdout") == b"QPERIAPT_STANDARD_TLS_OK\n", "authenticated response mismatch")
                    require(b"TLS_STANDARD_PEER_OK" in read_log(server.stdout), "Rust server lacks negotiated contract evidence")
                else:
                    require(status != 0 and server_status != 0, f"forbidden peer completed: {case}")
                    require(b"TLS_STANDARD_PEER_OK" not in read_log(server.stdout), f"forbidden peer reached application data: {case}")
                    # A transport failure is not evidence of the intended rejection.
                    client_error = read_log(output / f"{name}-openssl.stderr")
                    server_error = read_log(server.stderr)
                    reason = {
                        "wrong-hostname": b"verify error:num=62" in client_error,
                        "anonymous": b"NoCertificatesPresented" in server_error,
                        "classic-only": b"NoKxGroupsInCommon" in server_error,
                        "tls12": any(value in server_error for value in
                                     (b"SupportedVersionsExtensionRequired", b"Tls12NotOfferedOrEnabled")),
                    }[case]
                    require(reason, f"peer failed for an unexpected reason: {case}")
                observations.append({"direction": "openssl-client/rust-server", "case": case, "passed": True})
            finally:
                server.close()
        for case, group, hostname in [("accepted", "X25519MLKEM768", "localhost"),
                                     ("wrong-hostname", "X25519MLKEM768", "wrong.test"),
                                     ("classic-only", "X25519", "localhost")]:
            name = f"rust-client-{case}"
            command = [str(openssl), "s_server", "-accept", "127.0.0.1:0", "-tls1_3", "-groups", group,
                       "-cert", str(fixtures / "server.pem"), "-key", str(fixtures / "server.key.pem"),
                       "-CAfile", str(fixtures / "client.pem"), "-Verify", "1", "-verify_return_error",
                       "-no_ticket", "-num_tickets", "0", "-www", "-naccept", "1"]
            server = Peer(command, output, name + "-openssl", records)
            try:
                address = server.ready(b"ACCEPT")
                status = run([str(peer), "client", str(fixtures), address, hostname], output, name, records)
                server_status = server.finish()
                if case == "accepted":
                    require(status == 0 and server_status == 0, "Rust client / OpenSSL server did not complete")
                    require(b"TLS_STANDARD_PEER_OK" in read_log(output / f"{name}.stdout"), "Rust client lacks negotiated contract evidence")
                else:
                    # s_server can exit zero after reporting a rejected single connection.
                    require(status != 0, f"Rust client accepted forbidden peer: {case}")
                    require(b"TLS_STANDARD_PEER_OK" not in read_log(output / f"{name}.stdout"), "forbidden peer reached application data")
                    client_error = read_log(output / f"{name}.stderr")
                    if case == "wrong-hostname":
                        require(b"InvalidCertificate(NotValidForName" in client_error, "missing hostname rejection")
                    else:
                        require(b"AlertReceived(HandshakeFailure)" in client_error and
                                b"no suitable key share" in read_log(server.stderr), "missing no-common-group rejection")
                observations.append({"direction": "rust-client/openssl-server", "case": case, "passed": True})
            finally:
                server.close()
        require(identity(peer) == manifest["rust_peer"], "sealed peer executable changed during observation")
        require(identity(openssl) == manifest["openssl"], "OpenSSL executable changed during observation")
        manifest["completed"] = True
    finally:
        manifest["logs"] = {p.name: identity(p) for p in output.iterdir() if p.is_file()}
        (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"STANDARD_TLS_OPENSSL_INTEROP_PASS cases={len(observations)} output={output}")


if __name__ == "__main__":
    main()
