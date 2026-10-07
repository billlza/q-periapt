#!/usr/bin/env python3
"""Reproducibly verify selected public-reference content hashes."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import pathlib
import re
import urllib.parse
import urllib.request
from typing import Any

from evidence_io import EvidenceIOError, load_json_object_snapshot


SCHEMA_VERSION = 3
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
RAW_SHA256 = "raw_sha256_v1"
SIGNAL_CFEMAIL_SHA256 = "signal_cfemail_normalized_sha256_v1"
CFEMAIL_ATTRIBUTE = re.compile(br'data-cfemail="[0-9A-Fa-f]+"')
CFEMAIL_FRAGMENT = re.compile(br"/cdn-cgi/l/email-protection#[0-9A-Fa-f]+")


class BaselineError(ValueError):
    """A baseline or retrieved response violates the verification contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise BaselineError(message)


def load_baseline(path: pathlib.Path) -> dict[str, Any]:
    try:
        data = load_json_object_snapshot(
            path,
            maximum=4 * 1024 * 1024,
            label="reference baseline",
        ).value
    except EvidenceIOError as exc:
        raise BaselineError(f"cannot load reference baseline {path}: {exc}") from exc
    require(data.get("schema_version") == SCHEMA_VERSION, "unsupported baseline schema")
    components = data.get("components")
    require(isinstance(components, list) and components, "baseline components must be non-empty")
    ids: list[str] = []
    for component in components:
        require(isinstance(component, dict), "every baseline component must be an object")
        component_id = component.get("id")
        require(isinstance(component_id, str) and component_id, "component id is missing")
        ids.append(component_id)
    require(len(ids) == len(set(ids)), "baseline component ids must be unique")
    return data


def find_component(baseline: dict[str, Any], component_id: str) -> dict[str, Any]:
    matches = [item for item in baseline["components"] if item.get("id") == component_id]
    require(len(matches) == 1, f"unknown or duplicate component id: {component_id}")
    return matches[0]


def normalize_content(component: dict[str, Any], content: bytes) -> bytes:
    content_hash = component.get("content_hash")
    require(isinstance(content_hash, dict), f"{component['id']} has no content-hash contract")
    method = content_hash.get("method")
    if method == RAW_SHA256:
        return content
    if method == SIGNAL_CFEMAIL_SHA256:
        hostname = urllib.parse.urlparse(component.get("url", "")).hostname
        require(hostname == "signal.org", "Signal normalization is restricted to signal.org")
        normalized = CFEMAIL_ATTRIBUTE.sub(b'data-cfemail="<normalized>"', content)
        return CFEMAIL_FRAGMENT.sub(
            b"/cdn-cgi/l/email-protection#<normalized>", normalized
        )
    raise BaselineError(f"unsupported content hash method for {component['id']}: {method}")


def verify_content(component: dict[str, Any], content: bytes) -> tuple[str, str]:
    require(len(content) <= MAX_RESPONSE_BYTES, f"{component['id']} response exceeds size limit")
    content_hash = component.get("content_hash")
    require(isinstance(content_hash, dict), f"{component['id']} has no content-hash contract")
    method = content_hash.get("method")
    expected = content_hash.get("sha256")
    require(
        isinstance(expected, str) and re.fullmatch(r"[0-9a-f]{64}", expected) is not None,
        f"{component['id']} has an invalid expected SHA-256",
    )
    normalized = normalize_content(component, content)
    actual = hashlib.sha256(normalized).hexdigest()
    require(actual == expected, f"{component['id']} content hash mismatch: got {actual}")
    return method, actual


def fetch(url: str, timeout_seconds: float) -> bytes:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "q-periapt-reference-baseline/1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            content = response.read(MAX_RESPONSE_BYTES + 1)
    except (OSError, http.client.HTTPException) as exc:
        raise BaselineError(f"cannot retrieve {url}: {exc}") from exc
    require(len(content) <= MAX_RESPONSE_BYTES, f"response exceeds {MAX_RESPONSE_BYTES} bytes")
    return content


def verify_file(args: argparse.Namespace) -> None:
    baseline = load_baseline(args.baseline.resolve())
    component = find_component(baseline, args.component)
    try:
        content = args.input.resolve().read_bytes()
    except OSError as exc:
        raise BaselineError(f"cannot read response file {args.input}: {exc}") from exc
    method, digest = verify_content(component, content)
    print(f"REFERENCE_BASELINE_FILE_PASS component={args.component} method={method} sha256={digest}")


def verify_url(args: argparse.Namespace) -> None:
    baseline = load_baseline(args.baseline.resolve())
    component = find_component(baseline, args.component)
    url = component.get("url")
    require(isinstance(url, str) and url.startswith("https://"), "component URL must use HTTPS")
    first = fetch(url, args.timeout_seconds)
    second = fetch(url, args.timeout_seconds)
    method, digest = verify_content(component, first)
    verify_content(component, second)
    require(
        normalize_content(component, first) == normalize_content(component, second),
        f"{args.component} remained nondeterministic after declared normalization",
    )
    print(f"REFERENCE_BASELINE_URL_PASS component={args.component} method={method} sha256={digest}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--baseline",
        type=pathlib.Path,
        default=pathlib.Path("docs/continuity/reference-baseline.json"),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    file_parser = subparsers.add_parser("verify-file")
    file_parser.add_argument("--component", required=True)
    file_parser.add_argument("--input", type=pathlib.Path, required=True)
    file_parser.set_defaults(handler=verify_file)

    url_parser = subparsers.add_parser("verify-url")
    url_parser.add_argument("--component", required=True)
    url_parser.add_argument("--timeout-seconds", type=float, default=30.0)
    url_parser.set_defaults(handler=verify_url)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    require(0 < getattr(args, "timeout_seconds", 1.0) <= 120, "timeout must be in (0, 120]")
    args.handler(args)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BaselineError as exc:
        raise SystemExit(f"error: {exc}") from exc
