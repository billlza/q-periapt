#!/usr/bin/env python3
"""Exercise the materialized uploader's bounded, credential-free diagnostics."""

from __future__ import annotations

import contextlib
import dataclasses
import datetime as dt
import http.client
import http.server
import importlib.util
import io
import json
import pathlib
import select
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from importlib.machinery import SourceFileLoader
from unittest import mock

import crates_io_uploader_build as build
from crates_io_upload_diagnostic import parse_upload_diagnostic
from test_crates_io_uploader_build import TEMPLATE, VERSION, _crate_bytes, _write_cohort


@dataclasses.dataclass
class ConnectExchange:
    connect_headers: bytes = b""
    encrypted_client_bytes: bytearray = dataclasses.field(default_factory=bytearray)
    server_names: list[str | None] = dataclasses.field(default_factory=list)
    request_line: bytes = b""
    request_headers: dict[str, str] = dataclasses.field(default_factory=dict)
    request_body: bytes = b""
    tls_errors: list[ssl.SSLError] = dataclasses.field(default_factory=list)
    relay_disconnects: list[ConnectionResetError | BrokenPipeError] = dataclasses.field(default_factory=list)
    connections: int = 0


class UploaderDiagnosticTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = pathlib.Path(temporary.name)
        self.root = root
        handoff = _write_cohort(root)
        output = root / "uploader"
        build.build(handoff, TEMPLATE, output, crate_dir=root, cargo_version="1.99.0")
        loader = SourceFileLoader("uploader_diagnostics_under_test", str(output))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        self.assertIsNotNone(spec)
        self.module = importlib.util.module_from_spec(spec)
        sys.modules[loader.name] = self.module
        self.addCleanup(sys.modules.pop, loader.name, None)
        loader.exec_module(self.module)
        self.name = "q-periapt-core"
        self.payload = _crate_bytes(self.name, VERSION)
        self.contract = self.module.COHORT_CONTRACTS[self.name]
        self.secret = "cio_private_diagnostic_sentinel_123456789"
        self.arguments = [
            "--crate-stdin", "--name", self.name, "--version", VERSION,
            "--size", str(self.contract.size), "--sha256", self.contract.sha256,
        ]

    def invoke(
        self,
        *,
        upload_url: str = "http://127.0.0.1:12345/api/v1/crates/new",
        arguments: list[str] | None = None,
        timeout_seconds: float = 240.0,
    ) -> tuple[int, dict[str, object], str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        result = self.module.main(
            self.arguments if arguments is None else arguments,
            stdin=io.BytesIO(self.payload),
            environment={"CARGO_REGISTRY_TOKEN": self.secret},
            stdout=stdout,
            stderr=stderr,
            upload_url=upload_url,
            allow_loopback_test=True,
            timeout_seconds=timeout_seconds,
        )
        self.assertEqual(1, len(stdout.getvalue().splitlines()))
        self.assertLess(len(stdout.getvalue()), 1024)
        self.assertNotIn(self.secret, stdout.getvalue() + stderr.getvalue())
        diagnostic = json.loads(stdout.getvalue())
        parsed = parse_upload_diagnostic(
            stdout.getvalue().encode("utf-8"), credential=self.secret, returncode=result
        )
        self.assertEqual(diagnostic, parsed.to_document())
        self.assertEqual(
            {
                "schema_version", "stage", "category", "http_status",
                "sent_body_bytes_lower_bound", "elapsed_ms", "retry_after_seconds",
            },
            set(diagnostic),
        )
        self.assertEqual(1, diagnostic["schema_version"])
        self.assertIs(type(diagnostic["elapsed_ms"]), int)
        self.assertGreaterEqual(diagnostic["elapsed_ms"], 0)
        return result, diagnostic, stderr.getvalue()

    @contextlib.contextmanager
    def registry(self, *, status=200, retry_after=None, body=b"{}", stall_response=False):
        requests: list[bytes] = []
        release_response = threading.Event()

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_PUT(handler) -> None:
                length = int(handler.headers["Content-Length"])
                requests.append(handler.rfile.read(length))
                if stall_response:
                    release_response.wait(timeout=3)
                    return
                handler.send_response(status)
                if retry_after is not None:
                    handler.send_header("Retry-After", retry_after)
                handler.send_header("Content-Length", str(len(body)))
                handler.end_headers()
                handler.wfile.write(body)

            def log_message(self, format, *args) -> None:
                del format, args

        with http.server.HTTPServer(("127.0.0.1", 0), Handler) as server:
            server.timeout = 3
            thread = threading.Thread(target=server.handle_request)
            thread.start()
            try:
                yield f"http://127.0.0.1:{server.server_port}/api/v1/crates/new", requests
            finally:
                release_response.set()
                thread.join(timeout=4)
                self.assertFalse(thread.is_alive(), "registry request thread did not exit")

    def test_real_upload_success_reports_complete_body_without_external_content(self) -> None:
        with self.registry(body=b'{"warnings":{"other":[]}}') as (url, requests):
            result, diagnostic, stderr = self.invoke(upload_url=url)
        self.assertEqual(0, result)
        self.assertEqual("", stderr)
        self.assertEqual("complete", diagnostic["stage"])
        self.assertEqual("ok", diagnostic["category"])
        self.assertEqual(200, diagnostic["http_status"])
        self.assertIsNone(diagnostic["retry_after_seconds"])
        self.assertEqual(1, len(requests))
        self.assertEqual(len(requests[0]), diagnostic["sent_body_bytes_lower_bound"])
        self.assertTrue(requests[0].endswith(self.payload))

    def test_http_rejection_preserves_status_and_safe_retry_hint_without_body(self) -> None:
        body = json.dumps({"errors": [{"detail": self.secret}]}).encode()
        with self.registry(status=429, retry_after="17", body=body) as (url, requests):
            result, diagnostic, stderr = self.invoke(upload_url=url)
        self.assertEqual(1, result)
        self.assertEqual("response_body", diagnostic["stage"])
        self.assertEqual("response", diagnostic["category"])
        self.assertEqual(429, diagnostic["http_status"])
        self.assertEqual(17, diagnostic["retry_after_seconds"])
        self.assertEqual(len(requests[0]), diagnostic["sent_body_bytes_lower_bound"])
        self.assertIn("failed safely: response", stderr)

    def test_200_error_document_is_nonzero_and_never_replays_detail(self) -> None:
        body = json.dumps({"errors": [{"detail": self.secret}]}).encode()
        with self.registry(body=body) as (url, _requests):
            result, diagnostic, _stderr = self.invoke(upload_url=url)
        self.assertEqual(1, result)
        self.assertEqual("response", diagnostic["category"])
        self.assertEqual(200, diagnostic["http_status"])

    def test_untrusted_retry_header_is_never_replayed(self) -> None:
        with self.registry(status=503, retry_after=self.secret) as (url, _requests):
            result, diagnostic, _stderr = self.invoke(upload_url=url)
        self.assertEqual(1, result)
        self.assertEqual(503, diagnostic["http_status"])
        self.assertIsNone(diagnostic["retry_after_seconds"])

    def test_redirect_is_not_followed(self) -> None:
        with self.registry(status=307) as (url, requests):
            result, diagnostic, _stderr = self.invoke(upload_url=url)
        self.assertEqual(1, result)
        self.assertEqual("redirect", diagnostic["category"])
        self.assertEqual(307, diagnostic["http_status"])
        self.assertEqual(1, len(requests))

    def test_preflight_failure_does_not_open_network(self) -> None:
        with mock.patch.object(self.module.http.client, "HTTPConnection") as connection:
            result, diagnostic, _stderr = self.invoke(arguments=[self.secret])
        self.assertEqual(1, result)
        self.assertEqual("preflight", diagnostic["stage"])
        self.assertEqual("protocol", diagnostic["category"])
        self.assertEqual(0, diagnostic["sent_body_bytes_lower_bound"])
        self.assertIsNone(diagnostic["http_status"])
        connection.assert_not_called()

    def test_connection_exceptions_are_fixed_classes_without_exception_text(self) -> None:
        cases = (
            (TimeoutError(self.secret), "timeout"),
            (socket.gaierror(self.secret), "dns"),
            (ssl.SSLError(self.secret), "tls"),
            (ConnectionResetError(self.secret), "connection"),
            (http.client.BadStatusLine(self.secret), "http_protocol"),
            (OSError(self.secret), "transport"),
            (RuntimeError(self.secret), "internal"),
        )
        for error, category in cases:
            with self.subTest(category=category):
                with mock.patch.object(self.module.http.client, "HTTPConnection") as factory:
                    factory.return_value.connect.side_effect = error
                    result, diagnostic, _stderr = self.invoke()
                self.assertEqual(1, result)
                self.assertEqual("connect", diagnostic["stage"])
                self.assertEqual(category, diagnostic["category"])
                self.assertEqual(0, diagnostic["sent_body_bytes_lower_bound"])
                self.assertIsNone(diagnostic["http_status"])

    def test_partial_send_failure_records_only_completed_body_calls(self) -> None:
        with mock.patch.object(self.module.http.client, "HTTPConnection") as factory:
            factory.return_value.send.side_effect = [None, BrokenPipeError(self.secret)]
            result, diagnostic, _stderr = self.invoke()
        self.assertEqual(1, result)
        self.assertEqual("archive", diagnostic["stage"])
        self.assertEqual("connection", diagnostic["category"])
        self.assertEqual(8 + len(self.contract.metadata_json), diagnostic["sent_body_bytes_lower_bound"])
        self.assertIsNone(diagnostic["http_status"])

    def test_response_header_timeout_keeps_full_send_count_and_unknown_status(self) -> None:
        with mock.patch.object(self.module.http.client, "HTTPConnection") as factory:
            factory.return_value.response_class.return_value.begin.side_effect = TimeoutError(self.secret)
            result, diagnostic, _stderr = self.invoke()
        self.assertEqual(1, result)
        self.assertEqual("response_headers", diagnostic["stage"])
        self.assertEqual("timeout", diagnostic["category"])
        self.assertEqual(8 + len(self.contract.metadata_json) + self.contract.size,
                         diagnostic["sent_body_bytes_lower_bound"])
        self.assertIsNone(diagnostic["http_status"])

    def test_real_response_stall_times_out_once_and_disarms_deadline(self) -> None:
        before = self.module.signal.getitimer(self.module.signal.ITIMER_REAL)
        with self.registry(stall_response=True) as (url, requests):
            result, diagnostic, _stderr = self.invoke(upload_url=url, timeout_seconds=0.15)
        self.assertEqual(1, result)
        self.assertEqual("response_headers", diagnostic["stage"])
        self.assertEqual("timeout", diagnostic["category"])
        self.assertEqual(1, len(requests))
        self.assertEqual(len(requests[0]), diagnostic["sent_body_bytes_lower_bound"])
        self.assertIsNone(diagnostic["http_status"])
        self.assertEqual(before, self.module.signal.getitimer(self.module.signal.ITIMER_REAL))

    def test_cleanup_failure_cannot_report_success(self) -> None:
        with mock.patch.object(self.module.http.client, "HTTPConnection") as factory:
            response = factory.return_value.response_class.return_value
            response.status = 200
            response.getheader.return_value = None
            response.read1.return_value = b""
            factory.return_value.close.side_effect = OSError(self.secret)
            result, diagnostic, _stderr = self.invoke()
        self.assertEqual(1, result)
        self.assertEqual("cleanup", diagnostic["stage"])
        self.assertEqual("transport", diagnostic["category"])

    def test_response_body_timeout_keeps_status_and_retry_hint(self) -> None:
        with mock.patch.object(self.module.http.client, "HTTPConnection") as factory:
            response = factory.return_value.response_class.return_value
            response.status = 429
            response.getheader.return_value = "19"
            response.read1.side_effect = TimeoutError(self.secret)
            result, diagnostic, _stderr = self.invoke()
        self.assertEqual(1, result)
        self.assertEqual("response_body", diagnostic["stage"])
        self.assertEqual("timeout", diagnostic["category"])
        self.assertEqual(429, diagnostic["http_status"])
        self.assertEqual(19, diagnostic["retry_after_seconds"])

    def test_retry_after_accepts_only_bounded_canonical_hints(self) -> None:
        now = dt.datetime(2026, 9, 5, 0, 0, tzinfo=dt.UTC)
        cases = (
            (None, None), ("0", 0), ("0017", 17), ("86400", 86400),
            ("86401", None), ("1" * 129, None), ("-1", None), ("1.5", None),
            (self.secret, None), ("17\n" + self.secret, None), ("12, 13", None),
            ("Sat, 05 Sep 2026 00:00:03 GMT", 3),
            ("Fri, 04 Sep 2026 23:59:59 GMT", 0),
            ("Mon, 07 Sep 2026 00:00:00 GMT", None),
            ("Sun, 05 Sep 2026 00:00:03 GMT", None),
        )
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertEqual(expected, self.module._retry_after_seconds(value, now=now))

    def test_output_write_failure_is_nonzero_without_raw_exception(self) -> None:
        stdout = mock.Mock()
        stdout.write.side_effect = BrokenPipeError(self.secret)
        stderr = io.StringIO()
        result = self.module.main(
            [self.secret], stdin=io.BytesIO(self.payload), environment={},
            stdout=stdout, stderr=stderr,
        )
        self.assertEqual(1, result)
        self.assertEqual("error: q-periapt uploader diagnostic output failed\n", stderr.getvalue())
        self.assertNotIn(self.secret, stderr.getvalue())

    def tls_contexts(self, hostname: str) -> tuple[ssl.SSLContext, ssl.SSLContext]:
        """Make a short-lived local test CA without relaxing TLS verification."""

        openssl = shutil.which("openssl")
        self.assertIsNotNone(openssl, "real TLS boundary tests require the repository's OpenSSL CLI")
        certificate = self.root / "test-server.pem"
        key = self.root / "test-server.key"
        configuration = self.root / "test-server.cnf"
        configuration.write_text(
            "[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=extensions\n"
            f"[dn]\nCN={hostname}\n[extensions]\nsubjectAltName=DNS:{hostname}\n"
            "basicConstraints=critical,CA:TRUE\n"
            "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign\n"
            "extendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\n",
            encoding="ascii",
        )
        result = subprocess.run(
            [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "1",
             "-config", str(configuration), "-keyout", str(key), "-out", str(certificate)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=15, check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr.decode("utf-8", errors="replace"))
        server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server.load_cert_chain(certificate, key)
        client = ssl.create_default_context(cafile=str(certificate))
        self.assertTrue(client.check_hostname)
        self.assertEqual(ssl.CERT_REQUIRED, client.verify_mode)
        return server, client

    @contextlib.contextmanager
    def connect_proxy(self, server_context: ssl.SSLContext | None = None, *, outcome: str = "accept"):
        """Run a real byte-forwarding proxy and an optional local TLS origin."""

        exchange = ConnectExchange()
        failures: list[BaseException] = []
        release_connect = threading.Event()
        with socket.socket() as proxy, socket.socket() as origin:
            for listener in (proxy, origin):
                listener.bind(("127.0.0.1", 0))
                listener.listen(1)
                listener.settimeout(3)
            if server_context is not None:
                def server_name(_socket, name, _context):
                    exchange.server_names.append(name)
                server_context.set_servername_callback(server_name)

            def serve_origin() -> None:
                self.assertIsNotNone(server_context)
                with origin.accept()[0] as raw:
                    raw.settimeout(3)
                    try:
                        secured = server_context.wrap_socket(raw, server_side=True)
                    except ssl.SSLError as exc:
                        exchange.tls_errors.append(exc)
                        return
                    with secured, secured.makefile("rb") as stream:
                        exchange.request_line = stream.readline(4097)
                        headers = http.client.parse_headers(stream)
                        exchange.request_headers = dict(headers.items())
                        length = int(headers["Content-Length"])
                        self.assertLess(length, 1024 * 1024)
                        exchange.request_body = stream.read(length)
                        self.assertEqual(length, len(exchange.request_body))
                        secured.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")

            def serve_proxy() -> None:
                with proxy.accept()[0] as client:
                    exchange.connections += 1
                    client.settimeout(3)
                    request = bytearray()
                    while not request.endswith(b"\r\n\r\n"):
                        byte = client.recv(1)
                        self.assertTrue(byte, "CONNECT request ended before its headers")
                        request.extend(byte)
                        self.assertLess(len(request), 4096)
                    exchange.connect_headers = bytes(request)
                    if outcome == "reject":
                        client.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
                        return
                    if outcome == "stall":
                        self.assertTrue(release_connect.wait(timeout=3), "stalled CONNECT was not released")
                        return
                    self.assertEqual("accept", outcome)
                    with socket.create_connection(origin.getsockname(), timeout=3) as upstream:
                        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        peers = {client: upstream, upstream: client}
                        while True:
                            readable, _, _ = select.select(list(peers), [], [], 3)
                            self.assertTrue(readable, "CONNECT forwarding made no progress")
                            for source in readable:
                                try:
                                    payload = source.recv(64 * 1024)
                                except ConnectionResetError as exc:
                                    exchange.relay_disconnects.append(exc)
                                    return
                                if not payload:
                                    return
                                if source is client:
                                    exchange.encrypted_client_bytes.extend(payload)
                                try:
                                    peers[source].sendall(payload)
                                except (ConnectionResetError, BrokenPipeError) as exc:
                                    exchange.relay_disconnects.append(exc)
                                    return

            def checked(target) -> None:
                try:
                    target()
                except BaseException as exc:
                    failures.append(exc)

            targets = [serve_proxy]
            if server_context is not None:
                self.assertEqual("accept", outcome)
                targets.append(serve_origin)
            threads = [threading.Thread(target=checked, args=(target,)) for target in targets]
            for thread in threads:
                thread.start()
            try:
                yield f"http://127.0.0.1:{proxy.getsockname()[1]}", exchange
            finally:
                release_connect.set()
                for thread in threads:
                    thread.join(timeout=4)
                    self.assertFalse(thread.is_alive(), "CONNECT test thread did not exit")
                if failures:
                    raise failures[0]

    def assert_plaintext_connect_is_credential_free(self, exchange: ConnectExchange) -> None:
        self.assertEqual(1, exchange.connections)
        lines = exchange.connect_headers.split(b"\r\n")
        self.assertRegex(lines[0], rb"\ACONNECT crates\.io:443 HTTP/1\.[01]\Z")
        headers = http.client.parse_headers(io.BytesIO(b"\r\n".join(lines[1:])))
        self.assertLessEqual(set(name.lower() for name in headers), {"host"})
        if "Host" in headers:
            self.assertEqual("crates.io:443", headers["Host"])
        for payload in (exchange.connect_headers, bytes(exchange.encrypted_client_bytes)):
            self.assertNotIn(self.secret.encode(), payload)
            self.assertNotIn(b"Authorization:", payload)
            self.assertNotIn(self.payload, payload)

    def test_explicit_proxy_url_boundary_rejects_before_credentials_or_network(self) -> None:
        accepted = {
            "http://127.0.0.1:1": ("127.0.0.1", 1),
            "http://127.255.255.255:65535": ("127.255.255.255", 65535),
            "http://[::1]:7890": ("::1", 7890),
        }
        for value, expected in accepted.items():
            self.assertEqual(expected, self.module._parse_http_connect_proxy(value))
        invalid = (
            "http://localhost:7890", "http://192.168.0.1:7890", "https://127.0.0.1:7890",
            "http://user:password@127.0.0.1:7890", "http://127.0.0.1:7890/",
            "http://127.0.0.1:7890?", "http://127.0.0.1:7890#", "http://127.0.0.1:7890\n",
            "http://127.0.0.1:\t7890", "http://127.00.0.1:7890", "http://127.256.0.1:7890",
            "http://127.0.0.1:0", "http://127.0.0.1:01", "http://127.0.0.1:65536",
            "http://[::ffff:127.0.0.1]:7890",
        )
        for value in invalid:
            with (
                self.subTest(proxy=value),
                mock.patch.object(self.module, "_credential") as credential,
                mock.patch.object(self.module.socket, "create_connection") as connection,
            ):
                result, diagnostic, _ = self.invoke(arguments=[*self.arguments, "--http-connect-proxy", value])
            self.assertEqual(1, result)
            self.assertEqual("preflight", diagnostic["stage"])
            self.assertEqual("endpoint", diagnostic["category"])
            self.assertEqual(0, diagnostic["sent_body_bytes_lower_bound"])
            credential.assert_not_called()
            connection.assert_not_called()

    def test_explicit_proxy_cannot_change_fixed_registry_endpoint(self) -> None:
        with mock.patch.object(self.module.socket, "create_connection") as connection:
            result, diagnostic, _ = self.invoke(arguments=[
                *self.arguments, "--http-connect-proxy", "http://127.0.0.1:7890",
            ])
        self.assertEqual(1, result)
        self.assertEqual("endpoint", diagnostic["category"])
        self.assertEqual(0, diagnostic["sent_body_bytes_lower_bound"])
        connection.assert_not_called()

    def test_real_connect_tunnel_keeps_credentials_inside_registry_tls(self) -> None:
        server, client = self.tls_contexts("crates.io")
        with self.connect_proxy(server) as (proxy, exchange):
            with mock.patch.object(self.module.ssl, "create_default_context", return_value=client):
                result, diagnostic, stderr = self.invoke(
                    upload_url=self.module.PRODUCTION_UPLOAD_URL,
                    arguments=[*self.arguments, "--http-connect-proxy", proxy],
                )
        self.assertEqual(0, result)
        self.assertEqual("", stderr)
        self.assertEqual("complete", diagnostic["stage"])
        self.assertEqual(200, diagnostic["http_status"])
        self.assertEqual([], exchange.tls_errors)
        self.assertEqual([], exchange.relay_disconnects)
        self.assertEqual(["crates.io"], exchange.server_names)
        self.assertEqual(b"PUT /api/v1/crates/new HTTP/1.1\r\n", exchange.request_line)
        self.assertEqual("crates.io", exchange.request_headers["Host"])
        self.assertEqual(self.secret, exchange.request_headers["Authorization"])
        expected_body = (struct.pack("<I", len(self.contract.metadata_json)) + self.contract.metadata_json
                         + struct.pack("<I", self.contract.size) + self.payload)
        self.assertEqual(expected_body, exchange.request_body)
        self.assertEqual(len(expected_body), diagnostic["sent_body_bytes_lower_bound"])
        self.assertTrue(client.check_hostname)
        self.assertEqual(ssl.CERT_REQUIRED, client.verify_mode)
        self.assert_plaintext_connect_is_credential_free(exchange)

    def test_real_connect_rejects_wrong_tls_hostname_before_upload(self) -> None:
        server, client = self.tls_contexts("wrong-registry.invalid")
        with self.connect_proxy(server) as (proxy, exchange):
            with mock.patch.object(self.module.ssl, "create_default_context", return_value=client):
                result, diagnostic, _ = self.invoke(
                    upload_url=self.module.PRODUCTION_UPLOAD_URL,
                    arguments=[*self.arguments, "--http-connect-proxy", proxy],
                )
        self.assertEqual(1, result)
        self.assertEqual("connect", diagnostic["stage"])
        self.assertEqual("tls", diagnostic["category"])
        self.assertEqual(0, diagnostic["sent_body_bytes_lower_bound"])
        self.assertIsNone(diagnostic["http_status"])
        self.assertEqual(["crates.io"], exchange.server_names)
        self.assertEqual(1, len(exchange.tls_errors))
        # A failed TLS client may close with EOF or reset its TCP connection.
        # Both still require the independent TLS rejection and zero HTTP bytes.
        self.assertLessEqual(len(exchange.relay_disconnects), 1)
        self.assertEqual(b"", exchange.request_line)
        self.assertEqual(b"", exchange.request_body)
        self.assert_plaintext_connect_is_credential_free(exchange)

    def test_real_connect_rejection_and_stall_do_not_send_or_retry_upload(self) -> None:
        before = self.module.signal.getitimer(self.module.signal.ITIMER_REAL)
        for outcome, category in (("reject", "transport"), ("stall", "timeout")):
            with self.subTest(outcome=outcome), self.connect_proxy(outcome=outcome) as (proxy, exchange):
                result, diagnostic, _ = self.invoke(
                    upload_url=self.module.PRODUCTION_UPLOAD_URL,
                    arguments=[*self.arguments, "--http-connect-proxy", proxy],
                    timeout_seconds=0.2,
                )
            self.assertEqual(1, result)
            self.assertEqual("connect", diagnostic["stage"])
            self.assertEqual(category, diagnostic["category"])
            self.assertEqual(0, diagnostic["sent_body_bytes_lower_bound"])
            self.assertIsNone(diagnostic["http_status"])
            self.assertEqual(b"", exchange.request_body)
            self.assertEqual(bytearray(), exchange.encrypted_client_bytes)
            self.assert_plaintext_connect_is_credential_free(exchange)
            self.assertEqual(before, self.module.signal.getitimer(self.module.signal.ITIMER_REAL))


if __name__ == "__main__":
    unittest.main()
