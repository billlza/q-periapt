"""Exact route grammar tests shared by the registry and GitHub boundaries."""

from __future__ import annotations

import unittest

from http_connect_proxy import HttpConnectProxyError, validate_http_connect_proxy


class HttpConnectProxyTests(unittest.TestCase):
    def test_accepts_canonical_loopback_host_and_bounded_port(self) -> None:
        for value in (
            "http://127.0.0.1:1",
            "http://127.255.255.255:65535",
            "http://[::1]:7890",
        ):
            with self.subTest(value=value):
                self.assertEqual(value, validate_http_connect_proxy(value))

    def test_rejects_every_route_extension_without_echoing_input(self) -> None:
        for value in (
            "http://localhost:7890",
            "http://192.168.0.1:7890",
            "https://127.0.0.1:7890",
            "socks5://127.0.0.1:7890",
            "http://user:secret@127.0.0.1:7890",
            "http://127.0.0.1:7890/",
            "http://127.0.0.1:7890?",
            "http://127.0.0.1:7890#",
            "http://127.0.0.1:7890\n",
            "http://127.0.0.1:\t7890",
            " http://127.0.0.1:7890",
            "http://127.00.0.1:7890",
            "http://127.256.0.1:7890",
            "http://127.0.0.1:0",
            "http://127.0.0.1:01",
            "http://127.0.0.1:65536",
            "http://[0:0:0:0:0:0:0:1]:7890",
            "http://[::ffff:127.0.0.1]:7890",
        ):
            with self.subTest(value=value):
                with self.assertRaises(HttpConnectProxyError) as caught:
                    validate_http_connect_proxy(value)
                self.assertNotIn(value, str(caught.exception))
                self.assertNotIn("secret", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
