"""Independent OpenSSL TLS carrier qualification; witness state/signatures stay native.

Public readbacks validate runtime receipts, framing and effects. They are neither
an independent signature engine nor a proof of general TLS/protocol security.
"""
from pathlib import Path
import re

import rust_sdk_profile as sdk
from continuity_c_witness import commit, export_selected
from continuity_c_witness_tls import verify_owner_readbacks
from evidence_io import parse_strict_json_bytes

SCOPE = "installed C owners and OpenSSL TLS reference peer in both directions; shared native witness engine; same host"
TESTS = {
    "server": "openssl::native_c_owners_and_openssl_witness_reconcile_revoked_cleanup",
    "client": "openssl::openssl_client_and_native_witness_exchange_exact_signed_frames",
    "rejections": "openssl::openssl_rejects_scope_trailing_data_missing_end_and_wrong_protocol_before_store",
}
REPORTS = {"server": "c-witness-openssl-public-result.json", "client": "openssl-client-public-result.json",
           "rejections": "openssl-rejections-public-result.json"}
REJECTIONS = {"wrong-subject": "certificate/subject admission", "trailing-data": "trailing TLS application bytes",
              "missing-end": "missing authenticated TLS end", "wrong-protocol": "TLS handshake"}
MAX_BINARY = 256 * 1024**2


def verify_versions(cli: str, identity: str) -> str:
    match = re.fullmatch(r"OPENSSL_HEADER (OpenSSL [^\n]+)\nOPENSSL_RUNTIME (OpenSSL [^\n]+)\n", identity)
    sdk.require(match is not None and match[1] == match[2], "OpenSSL headers and linked runtime differ")
    version = match[1]
    sdk.require(cli in (version, f"{version} (Library: {version})"), "OpenSSL CLI and peer library differ")
    return version


def negotiated(text: bytes, role: str, count: int) -> None:
    expected = "".join(f"OPENSSL_WITNESS_OK role={role} tls=1.3 group=X25519MLKEM768 "
                       f"alpn=q-periapt-anchor/1 exchange={i}\n" for i in range(1, count + 1))
    sdk.require(text == expected.encode(), "independent TLS negotiation receipt differs")


def verify_execution(kind: str, stdout: bytes, directory: Path) -> dict:
    sdk.require(kind in TESTS, "unknown OpenSSL witness workload")
    text = stdout.decode()
    sdk.require(re.findall(r"^test ([a-z_:]+) \.\.\. ok$", text, re.MULTILINE) == [TESTS[kind]]
                and re.search(r"^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; 6 filtered out;", text, re.MULTILINE),
                "OpenSSL witness workload did not execute completely")
    public = {}

    def read(name, maximum=1048576):
        value = sdk.snapshot(directory / name, maximum=maximum)
        public[name] = value.sha256
        return value.data

    report = parse_strict_json_bytes(read(REPORTS[kind]), label="OpenSSL witness result")
    common = {"completed", "independent_tls_implementation", "independent_witness_engine", "release_claim_eligible"}
    extra = {"server": {"session", "message", "witness_exchanges"}, "client": {"exchanges", "outcomes"},
             "rejections": {"cases", "store_calls"}}
    sdk.require(isinstance(report, dict) and set(report) == common | extra[kind], "OpenSSL result fields differ")
    sdk.require(report["completed"] is True and report["independent_tls_implementation"] is True
                and report["independent_witness_engine"] is False and report["release_claim_eligible"] is False,
                "OpenSSL qualification scope differs")
    logs = {}
    if kind == "server":
        sdk.require(type(report["witness_exchanges"]) is int and report["witness_exchanges"] == 142,
                    "OpenSSL server exchange census differs")
        for name in ("session", "message"):
            sdk.require(type(report[name]) is str and re.fullmatch(r"[0-9a-f]{64}", report[name])
                        and report[name] != "0" * 64, "OpenSSL C identity differs")
        session, message = report["session"], report["message"]
        expected = {
            "initiator/openssl-kind": "operational-owner-not-recovery\n",
            "initiator/openssl-bootstrap-client": session + "\n", "responder/openssl-next": message + "\n",
            "responder/openssl-send": "consumed\n", "responder/openssl-revoked": "rejected:603\n",
            "responder/openssl-cancel": "cancelled-cleanup-not-frozen\n", "responder/openssl-freeze": "",
            "responder/openssl-ack": "", "responder/openssl-retire": "original-report-closed-retired\n",
            "responder/openssl-archive": "archive-closed-metadata-only\n",
        }
        servers = {"responder/openssl-bootstrap-server": f"served:1:0:0:0\n{session}\n{'0' * 64}\n",
                   "initiator/openssl-message-server": f"served:2:0:1:1\n{session}\n{message}\n"}
        logs = verify_owner_readbacks(read, directory, session, message, expected, servers)
        negotiated(read("openssl-witness-server.stderr", 65536), "server", 142)
    elif kind == "client":
        sdk.require(type(report["exchanges"]) is int and report["exchanges"] == 2
                    and report["outcomes"] == [1, 2] and all(type(n) is int for n in report["outcomes"]),
                    "OpenSSL client exchange outcomes differ")
        prior = None
        for label, kind, outcome in (("query", 1, 1), ("advance", 2, 2)):
            negotiated(read(f"initiator/openssl-{label}.stderr", 65536), "client", 1)
            request = read(f"initiator/openssl-{label}.request", 3674)
            wire = read(f"initiator/openssl-{label}.reply", 3663)
            sdk.require(len(request) == 3674 and request[:4] == (297).to_bytes(4, "big")
                        and len(wire) == 3663 and wire[:8] == (3659).to_bytes(4, "big") + (282).to_bytes(4, "big"),
                        "OpenSSL signed envelope framing differs")
            rq, rs = request[4:301], wire[8:290]
            sdk.require(rq[:8] == b"QPANRQ01" and rs[:8] == b"QPANRS01" and rq[8:136] == rs[8:136]
                        and rq[200] == kind and rs[200] == outcome
                        and rq[136:168] == rs[168:200] == commit(b"Q-PERIAPT-CONTINUITY-ANCHOR-COMMAND/v1", rq[8:136] + rq[200:])
                        and rs[136:168] == commit(b"Q-PERIAPT-CONTINUITY-ANCHOR-REQUEST/v1", rq),
                        "OpenSSL signed command/attempt binding differs")
            if prior is None:
                sdk.require(rq[201:] == bytes(96), "OpenSSL query contains a transition")
            else:
                sdk.require(rq[8:136] == prior[0] and rq[168:200] != prior[1]
                            and rq[201:249] == prior[2] and rq[249:297] == rs[201:249]
                            and rs[201:209] == prior[2][:8]
                            and int.from_bytes(rs[209:217], "big") == int.from_bytes(prior[2][8:16], "big") + 1
                            and rs[217:249] == bytes([47]) * 32,
                            "OpenSSL advance did not follow its exact observed head")
            prior = (rq[8:136], rq[168:200], rs[201:249])
    else:
        sdk.require(report["cases"] == list(REJECTIONS) and type(report["store_calls"]) is int
                    and report["store_calls"] == 0, "OpenSSL pre-store rejection census differs")
        for case, reason in REJECTIONS.items():
            text = read(f"{case}/openssl-witness-server.stderr", 65536)
            sdk.require(text.startswith(f"OPENSSL_WITNESS_ERROR {reason}\n".encode())
                        and b"OPENSSL_WITNESS_OK" not in text, "OpenSSL rejection diagnostic differs")
    return dict(report, scope=SCOPE, public_readbacks=public, command_logs=logs,
                full_tls_fault_matrix_qualified=False, cross_host_qualified=False)


def export_public(kind: str, stdout: bytes, directory: Path, destination: Path) -> dict:
    return export_selected(verify_execution(kind, stdout, directory), directory, destination, SCOPE)


def build_peer(prefix: Path, cc: Path, platform_flags: list[str], consumer: Path,
               installed: Path, run, *, darwin: bool, profile: str) -> tuple[Path, dict]:
    prefix = prefix.resolve(strict=True)
    openssl = (prefix / "bin/openssl").resolve(strict=True)
    sdk.require(openssl.is_relative_to(prefix), "OpenSSL executable escaped selected installation")
    headers = sorted((prefix / "include/openssl").glob("*.h"))
    sdk.require(headers and (prefix / "include/openssl/ssl.h") in headers, "OpenSSL development headers missing")
    inputs = [openssl, *headers]
    sdk.require(all(p.resolve(strict=True).is_relative_to(prefix) for p in inputs),
                "OpenSSL headers escaped selected installation")
    identities = {str(p.resolve(strict=True)): sdk.snapshot(p.resolve(strict=True), maximum=MAX_BINARY).sha256 for p in inputs}
    executable = installed / "witness-tls-peer"
    run([str(cc), *platform_flags, "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wpedantic",
         *(["-O2"] if profile == "release" else ["-O0", "-g"]), str(consumer / "witness_tls_peer.c"),
         "-I", str(prefix / "include"), "-L", str(prefix / "lib"), "-lssl", "-lcrypto",
         "-Wl,-rpath," + str(prefix / "lib"), "-o", str(executable)], "witness-openssl-compile-" + profile)
    cli_version = run([str(openssl), "version"], "witness-openssl-version-" + profile).decode().strip()
    identity = run([str(executable), "identity"], "witness-openssl-identity-" + profile).decode()
    version = verify_versions(cli_version, identity)
    linked = run((["/usr/bin/otool", "-L"] if darwin else ["/usr/bin/ldd"]) + [str(executable)],
                 "witness-openssl-linked-" + profile).decode()
    pattern = r"^\s*(/\S+/lib(?:ssl|crypto)\.3\.dylib) \(" if darwin else r"^\s*lib(?:ssl|crypto)\.so\.3 => (/\S+) \("
    libraries = [Path(p).resolve(strict=True) for p in re.findall(pattern, linked, re.MULTILINE)]
    sdk.require(len(libraries) == 2 and len(set(libraries)) == 2
                and all(p.is_relative_to(prefix) for p in libraries), "OpenSSL linked library identity differs")
    for path in libraries:
        identities[str(path)] = sdk.snapshot(path, maximum=MAX_BINARY).sha256
    peer = sdk.snapshot(executable, maximum=MAX_BINARY)
    identities[str(executable)] = peer.sha256
    verify_dependencies(identities)
    return executable, {"path": str(executable), "sha256": peer.sha256, "bytes": peer.size,
                        "version": version, "dependency_files": identities}


def verify_dependencies(identities: dict) -> None:
    for path, expected in identities.items():
        sdk.require(sdk.snapshot(Path(path), maximum=MAX_BINARY).sha256 == expected,
                    "OpenSSL peer or dependency changed during qualification")
