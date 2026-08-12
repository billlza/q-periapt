#!/usr/bin/env python3
"""Verify that Rust CodeQL sees the exact clean GitHub checkout bytes."""

from __future__ import annotations

import os

from codeql_rust_quality import CodeQLRustQualityError, require_clean_checkout


def main() -> None:
    expected_commit = os.environ.get("CODEQL_EXPECTED_COMMIT", "")
    if not expected_commit:
        raise SystemExit("error: expected checkout commit is missing")
    try:
        require_clean_checkout(expected_commit)
    except CodeQLRustQualityError as exc:
        raise SystemExit(f"error: {exc}") from exc
    print(f"CODEQL_RUST_CHECKOUT_PASS commit={expected_commit}")


if __name__ == "__main__":
    main()
