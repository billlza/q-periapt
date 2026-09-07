"""Canonical loopback HTTP CONNECT route validation for publication tools."""

from __future__ import annotations

import ipaddress
import re


class HttpConnectProxyError(ValueError):
    """An explicit proxy URL violates the local CONNECT route contract."""


def validate_http_connect_proxy(value: str) -> str:
    """Accept an exact loopback HTTP host and port without URL credentials.

    An exact grammar rejects parser normalization of control characters, empty
    query/fragment markers and noncanonical addresses. This selects a route;
    callers retain the destination's normal TLS certificate and hostname checks.
    """

    match = (
        re.fullmatch(
            r"http://(127(?:\.[0-9]{1,3}){3}|\[::1\]):([1-9][0-9]{0,4})", value
        )
        if type(value) is str
        else None
    )
    if match is None:
        raise HttpConnectProxyError(
            "HTTP CONNECT proxy must be a canonical loopback HTTP host and port"
        )
    host = match.group(1).strip("[]")
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise HttpConnectProxyError("HTTP CONNECT proxy address is malformed") from exc
    if not (
        address.is_loopback and str(address) == host and int(match.group(2)) <= 65535
    ):
        raise HttpConnectProxyError(
            "HTTP CONNECT proxy address or port differs from the loopback contract"
        )
    return value
