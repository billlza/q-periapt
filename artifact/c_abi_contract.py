#!/usr/bin/env python3
"""Verify the frozen Q-Periapt C ABI 2 header and packaged runtime identity.

For a dynamic library the contract compares every named, defined export against
the nine-symbol allowlist. Toolchain support or internal bridge symbols are not
permitted to escape merely because they use another namespace. For a static
archive, the reserved public ``q_periapt_*`` namespace must contain exactly the
same nine definitions; other static implementation symbols remain outside the
public contract.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import pathlib
import re
import secrets
import stat
import subprocess
import tempfile
import threading
from dataclasses import dataclass
from typing import Any, BinaryIO, Callable, Iterator, NoReturn

from evidence_io import (
    EvidenceIOError,
    FileSnapshot,
    load_json_object_snapshot,
    read_regular_snapshot,
)


CONTRACT_SCHEMA = 1
CONTRACT_KIND = "qperiapt.c_abi_contract"
ABI_MAJOR = 2
PACKAGE_SEMVER = "0.1.0-alpha.2"
HEADER_GUARD = "Q_PERIAPT_ABI2_H"
MAX_CONTRACT_BYTES = 1024 * 1024
MAX_HEADER_BYTES = 2 * 1024 * 1024
MAX_STATIC_LIBRARY_BYTES = 512 * 1024 * 1024
MAX_INSPECTOR_STDOUT_BYTES = 16 * 1024 * 1024
MAX_INSPECTOR_STDERR_BYTES = 1024 * 1024
MAX_LLVM_NM_ROW_CHARS = 16 * 1024
MAX_LLVM_NM_MEMBER_CHARS = 8 * 1024
MAX_LLVM_NM_SYMBOL_CHARS = 8 * 1024
MAX_DYNAMIC_ROW_CHARS = 16 * 1024
MAX_DYNAMIC_EXPORT_CHARS = 8 * 1024
INSPECTOR_TIMEOUT_SECONDS = 120.0
INSPECTOR_TERMINATION_SECONDS = 5.0
INSPECTOR_READER_JOIN_SECONDS = 5.0
INSPECTOR_PIPE_CHUNK_BYTES = 64 * 1024

EXPECTED_STATUS_CODES = {
    "Q_PERIAPT_OK": 0,
    "Q_PERIAPT_ERR_NULL": -1,
    "Q_PERIAPT_ERR_LENGTH": -2,
    "Q_PERIAPT_ERR_POLICY": -3,
    "Q_PERIAPT_ERR_PANIC": -4,
    "Q_PERIAPT_ERR_INTERNAL": -5,
    "Q_PERIAPT_ERR_INVALID_KEYSHARE": -6,
    "Q_PERIAPT_ERR_ALIASING": -7,
    "Q_PERIAPT_ERR_ENTROPY": -8,
}

EXPECTED_MACROS = {
    "Q_PERIAPT_ABI_VERSION": 2,
    "Q_PERIAPT_MAX_SIGNED_POLICY_BYTES": 65536,
    "Q_PERIAPT_MAX_APPLICATION_CONTEXT_BYTES": 65536,
    **EXPECTED_STATUS_CODES,
    "Q_PERIAPT_PROFILE_CONTEXT_BOUND": 2,
    "Q_PERIAPT_POLICY_DECISION_VERSION": 1,
    "Q_PERIAPT_TRUSTED_POLICY_STATE_LEN": 36,
    "Q_PERIAPT_POLICY_DECISION_LEN": 40,
    "Q_PERIAPT_SUITE_MLKEM768_X25519": 1,
    "Q_PERIAPT_KEY_FORMAT_EXPANDED": 1,
    "Q_PERIAPT_MLKEM768_SK_LEN": 2400,
    "Q_PERIAPT_MLKEM768_PK_LEN": 1184,
    "Q_PERIAPT_MLKEM768_CT_LEN": 1088,
    "Q_PERIAPT_X25519_LEN": 32,
    "Q_PERIAPT_SECRET_LEN": 32,
}

EXPECTED_EXPORTS = (
    (
        "q_periapt_abi_version",
        "metadata",
        "uint32_t q_periapt_abi_version(void);",
    ),
    (
        "q_periapt_version",
        "metadata",
        "const char *q_periapt_version(void);",
    ),
    (
        "q_periapt_fixed_suite_id",
        "metadata",
        "const char *q_periapt_fixed_suite_id(void);",
    ),
    (
        "q_periapt_fixed_suite_id_len",
        "metadata",
        "uintptr_t q_periapt_fixed_suite_id_len(void);",
    ),
    (
        "q_periapt_status_name",
        "metadata",
        "const char *q_periapt_status_name(int32_t code);",
    ),
    (
        "q_periapt_decision_from_signed_policy",
        "policy",
        "int32_t q_periapt_decision_from_signed_policy(const uint8_t *toml, "
        "uintptr_t toml_len, const uint8_t *signature, uintptr_t signature_len, "
        "const uint8_t *vk, uintptr_t vk_len, const uint8_t *last_trusted_state, "
        "uintptr_t last_trusted_state_len, uint8_t *out_decision, "
        "uintptr_t out_decision_len);",
    ),
    (
        "q_periapt_generate_keypair",
        "key_management",
        "int32_t q_periapt_generate_keypair(const uint8_t *decision, "
        "uintptr_t decision_len, uint8_t *out_sk_pq, uintptr_t out_sk_pq_len, "
        "uint8_t *out_pk_pq, uintptr_t out_pk_pq_len, uint8_t *out_sk_trad, "
        "uintptr_t out_sk_trad_len, uint8_t *out_pk_trad, uintptr_t out_pk_trad_len);",
    ),
    (
        "q_periapt_encapsulate",
        "operation",
        "int32_t q_periapt_encapsulate(const uint8_t *decision, uintptr_t decision_len, "
        "const uint8_t *pk_pq, uintptr_t pk_pq_len, const uint8_t *pk_trad, "
        "uintptr_t pk_trad_len, const uint8_t *application_context, "
        "uintptr_t application_context_len, uint8_t *out_ct_pq, "
        "uintptr_t out_ct_pq_len, uint8_t *out_ct_trad, uintptr_t out_ct_trad_len, "
        "uint8_t *out_secret, uintptr_t out_secret_len);",
    ),
    (
        "q_periapt_decapsulate",
        "operation",
        "int32_t q_periapt_decapsulate(const uint8_t *decision, uintptr_t decision_len, "
        "const uint8_t *sk_pq, uintptr_t sk_pq_len, const uint8_t *ct_pq, "
        "uintptr_t ct_pq_len, const uint8_t *pk_pq, uintptr_t pk_pq_len, "
        "const uint8_t *sk_trad, uintptr_t sk_trad_len, const uint8_t *ct_trad, "
        "uintptr_t ct_trad_len, const uint8_t *pk_trad, uintptr_t pk_trad_len, "
        "const uint8_t *application_context, uintptr_t application_context_len, "
        "uint8_t *out_secret, uintptr_t out_secret_len);",
    ),
)

FORBIDDEN_EXPORTS = (
    "q_periapt_combine",
    "q_periapt_hybrid_decapsulate",
    "q_periapt_hybrid_decapsulate_with_decision",
    "q_periapt_hybrid_encapsulate",
    "q_periapt_hybrid_encapsulate_with_decision",
    "q_periapt_mlkem768_keypair",
    "q_periapt_mlkem768_xwing_keypair",
    "q_periapt_x25519_keypair",
)

EXPECTED_LAYOUTS = {
    "policy_decision": {
        "bytes": 40,
        "fields": [
            {
                "name": "decision_version",
                "offset": 0,
                "bytes": 1,
                "encoding": "u8_constant",
            },
            {
                "name": "suite_code",
                "offset": 1,
                "bytes": 1,
                "encoding": "u8_enum",
            },
            {
                "name": "profile_code",
                "offset": 2,
                "bytes": 1,
                "encoding": "u8_enum",
            },
            {
                "name": "key_format_code",
                "offset": 3,
                "bytes": 1,
                "encoding": "u8_enum",
            },
            {
                "name": "policy_version",
                "offset": 4,
                "bytes": 4,
                "encoding": "u32_be_nonzero",
            },
            {
                "name": "policy_digest",
                "offset": 8,
                "bytes": 32,
                "encoding": "sha3_256_exact_policy",
            },
        ],
    },
    "trusted_policy_state": {
        "bytes": 36,
        "fields": [
            {
                "name": "policy_version",
                "offset": 0,
                "bytes": 4,
                "encoding": "u32_be_nonzero",
            },
            {
                "name": "policy_digest",
                "offset": 4,
                "bytes": 32,
                "encoding": "sha3_256_exact_policy",
            },
        ],
    },
}

EXPECTED_PACKAGE = {
    "abi_major": 2,
    "archive_prefix": "q-periapt-c-abi2",
    "rust_library_name": "q_periapt_ffi_abi2",
    "semver": PACKAGE_SEMVER,
    "platforms": {
        "macos": {
            "shared_filename": "libq_periapt_ffi.2.dylib",
            "install_name": "@rpath/libq_periapt_ffi.2.dylib",
            "current_version": "2.0.0",
            "compatibility_version": "2.0.0",
            "static_filename": "libq_periapt_ffi_abi2.a",
        },
        "linux": {
            "shared_filename": "libq_periapt_ffi.so.2",
            "soname": "libq_periapt_ffi.so.2",
            "static_filename": "libq_periapt_ffi_abi2.a",
        },
        "windows": {
            "shared_filename": "q_periapt_ffi_abi2.dll",
            "import_library_filename": "q_periapt_ffi_abi2.lib",
            "static_filename": "q_periapt_ffi_abi2_static.lib",
        },
    },
    "pkg_config": {
        "dynamic_module": "qperiapt-abi2",
        "static_module": "qperiapt-abi2-static",
    },
    "cmake": {
        "package": "QPeriaptABI2",
        "config_directory": "lib/cmake/QPeriaptABI2",
        "abi_compatibility_version": "2.0.0",
        "version_match": "exact",
        "release_semver_variable": "QPeriaptABI2_RELEASE_VERSION",
        "shared_target": "QPeriaptABI2::qperiapt",
        "static_target": "QPeriaptABI2::qperiapt_static",
    },
}

EXPECTED_MIGRATION = {
    "abi1_state_bytes": 4,
    "automatic_migration": False,
    "migration_exports": [],
    "required_action": "explicit_host_authorized_reenrollment_or_reset",
}

_COMMENT_RE = re.compile(r"/\*.*?\*/|//[^\r\n]*", re.DOTALL)
_DEFINE_RE = re.compile(
    r"^\s*#\s*define\s+(Q_PERIAPT_[A-Za-z0-9_]+)"
    r"(?:(?P<function>\([^)]*\))(?:\s+(?P<function_value>.*?))?"
    r"|(?:\s+(?P<value>.*?)))?\s*$"
)
_INTEGER_RE = re.compile(r"-?(?:0|[1-9][0-9]*)")
_DECLARATION_RE = re.compile(
    r"\b(?P<return>const\s+char\s*\*|uint32_t|uintptr_t|int32_t)\s*"
    r"(?P<name>q_periapt_[A-Za-z0-9_]+)\s*"
    r"\((?P<parameters>[^;{}]*)\)\s*;",
    re.DOTALL,
)
_FUNCTION_TOKEN_RE = re.compile(r"\b(q_periapt_[A-Za-z0-9_]+)\s*\(")
_VERSION_RE = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")
class CAbiContractError(ValueError):
    """The contract, header, or packaged library violates the frozen ABI."""


@dataclass(frozen=True, slots=True)
class CAbiContract:
    """A validated contract tied to the exact bytes read from disk."""

    path: pathlib.Path
    sha256: str
    document: dict[str, Any]

    @property
    def export_names(self) -> frozenset[str]:
        return frozenset(item["name"] for item in self.document["abi"]["exports"])

    @property
    def declarations(self) -> dict[str, str]:
        return {
            item["name"]: item["declaration"]
            for item in self.document["abi"]["exports"]
        }


CommandRunner = Callable[[list[str]], str]


def _fail(message: str) -> NoReturn:
    raise CAbiContractError(message)


def _require_exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        _fail(f"{label} keys differ: missing={missing}, extra={extra}")


def _typed_equal(value: Any, expected: Any) -> bool:
    """JSON equality that does not treat booleans as integers."""

    if type(value) is not type(expected):
        return False
    if isinstance(expected, dict):
        return set(value) == set(expected) and all(
            _typed_equal(value[key], expected[key]) for key in expected
        )
    if isinstance(expected, list):
        return len(value) == len(expected) and all(
            _typed_equal(actual, wanted) for actual, wanted in zip(value, expected)
        )
    if isinstance(expected, tuple):
        return len(value) == len(expected) and all(
            _typed_equal(actual, wanted) for actual, wanted in zip(value, expected)
        )
    return value == expected


def _require_exact(value: Any, expected: Any, label: str) -> None:
    if not _typed_equal(value, expected):
        _fail(f"{label} differs from frozen ABI 2 contract")


def _validate_layout(name: str, layout: Any) -> None:
    if not isinstance(layout, dict):
        _fail(f"ABI layout {name} must be an object")
    _require_exact_keys(layout, {"bytes", "fields"}, f"ABI layout {name}")
    size = layout["bytes"]
    fields = layout["fields"]
    if type(size) is not int or size <= 0:
        _fail(f"ABI layout {name} bytes must be a positive integer")
    if not isinstance(fields, list) or not fields:
        _fail(f"ABI layout {name} fields must be a non-empty array")
    cursor = 0
    names: set[str] = set()
    for index, field in enumerate(fields):
        if not isinstance(field, dict):
            _fail(f"ABI layout {name} field {index} must be an object")
        _require_exact_keys(
            field,
            {"name", "offset", "bytes", "encoding"},
            f"ABI layout {name} field {index}",
        )
        field_name = field["name"]
        offset = field["offset"]
        field_bytes = field["bytes"]
        encoding = field["encoding"]
        if not isinstance(field_name, str) or not field_name or field_name in names:
            _fail(f"ABI layout {name} field {index} has an invalid or duplicate name")
        if type(offset) is not int or type(field_bytes) is not int or field_bytes <= 0:
            _fail(f"ABI layout {name} field {field_name} has an invalid extent")
        if not isinstance(encoding, str) or not encoding:
            _fail(f"ABI layout {name} field {field_name} has no encoding")
        if offset != cursor:
            _fail(f"ABI layout {name} has a gap or overlap at {field_name}")
        names.add(field_name)
        cursor += field_bytes
    if cursor != size:
        _fail(f"ABI layout {name} fields cover {cursor} bytes, expected {size}")


def _validate_contract_document(document: dict[str, Any]) -> None:
    _require_exact_keys(
        document,
        {"schema", "kind", "abi", "migration", "package"},
        "contract root",
    )
    _require_exact(document["schema"], CONTRACT_SCHEMA, "contract schema")
    _require_exact(document["kind"], CONTRACT_KIND, "contract kind")

    abi = document["abi"]
    if not isinstance(abi, dict):
        _fail("contract abi must be an object")
    _require_exact_keys(
        abi,
        {"major", "macros", "status_codes", "layouts", "exports", "forbidden_exports"},
        "contract abi",
    )
    _require_exact(abi["major"], ABI_MAJOR, "ABI major")
    _require_exact(abi["macros"], EXPECTED_MACROS, "ABI macros")
    _require_exact(abi["status_codes"], EXPECTED_STATUS_CODES, "ABI status codes")
    if not isinstance(abi["layouts"], dict):
        _fail("ABI layouts must be an object")
    for name, layout in abi["layouts"].items():
        _validate_layout(name, layout)
    _require_exact(abi["layouts"], EXPECTED_LAYOUTS, "ABI layouts")

    exports = abi["exports"]
    if not isinstance(exports, list):
        _fail("ABI exports must be an array")
    normalized_exports: list[tuple[str, str, str]] = []
    for index, item in enumerate(exports):
        if not isinstance(item, dict):
            _fail(f"ABI export {index} must be an object")
        _require_exact_keys(item, {"name", "role", "declaration"}, f"ABI export {index}")
        values = (item["name"], item["role"], item["declaration"])
        if not all(isinstance(value, str) and value for value in values):
            _fail(f"ABI export {index} fields must be non-empty strings")
        normalized_exports.append(values)
    _require_exact(tuple(normalized_exports), EXPECTED_EXPORTS, "ABI exports")
    forbidden_exports = abi["forbidden_exports"]
    if not isinstance(forbidden_exports, list) or not all(
        isinstance(name, str) and name for name in forbidden_exports
    ):
        _fail("forbidden exports must be an array of non-empty strings")
    _require_exact(tuple(forbidden_exports), FORBIDDEN_EXPORTS, "forbidden exports")
    if set(abi["forbidden_exports"]) & {item[0] for item in EXPECTED_EXPORTS}:
        _fail("an ABI symbol is both exported and forbidden")

    _require_exact(document["migration"], EXPECTED_MIGRATION, "ABI migration policy")
    _require_exact(document["package"], EXPECTED_PACKAGE, "ABI package identity")


def load_contract(path: pathlib.Path) -> CAbiContract:
    """Load one strict, bounded contract snapshot and validate every frozen field."""

    try:
        snapshot = load_json_object_snapshot(
            pathlib.Path(path), maximum=MAX_CONTRACT_BYTES, label="C ABI contract"
        )
    except EvidenceIOError as exc:
        raise CAbiContractError(str(exc)) from exc
    _validate_contract_document(snapshot.value)
    return CAbiContract(
        path=snapshot.file.path,
        sha256=snapshot.file.sha256,
        document=snapshot.value,
    )


def _without_comments(text: str, label: str) -> str:
    stripped = _COMMENT_RE.sub(" ", text)
    if "/*" in stripped or "*/" in stripped:
        _fail(f"{label} contains an unterminated C comment")
    return stripped


def _parse_header_macros(text: str) -> dict[str, int]:
    macros: dict[str, int] = {}
    for line_number, line in enumerate(text.splitlines(), start=1):
        match = _DEFINE_RE.match(line)
        if match is None:
            continue
        name = match.group(1)
        function = match.group("function")
        raw_value = match.group("value")
        if name == HEADER_GUARD and function is None and raw_value is None:
            continue
        if function is not None:
            _fail(f"header macro {name} at line {line_number} must not be function-like")
        if raw_value is None or _INTEGER_RE.fullmatch(raw_value) is None:
            _fail(f"header macro {name} at line {line_number} is not a canonical integer")
        if name in macros:
            _fail(f"header defines {name} more than once")
        macros[name] = int(raw_value, 10)
    return macros


def _normalize_fragment(value: str) -> str:
    value = re.sub(r"\s+", " ", value.strip())
    value = re.sub(r"\s*\*\s*", " *", value)
    value = re.sub(r"\s*,\s*", ", ", value)
    return value


def _parse_header_declarations(text: str) -> dict[str, str]:
    without_preprocessor = "\n".join(
        "" if line.lstrip().startswith("#") else line for line in text.splitlines()
    )
    declarations: dict[str, str] = {}
    for match in _DECLARATION_RE.finditer(without_preprocessor):
        return_type = _normalize_fragment(match.group("return"))
        name = match.group("name")
        parameters = _normalize_fragment(match.group("parameters"))
        separator = "" if return_type.endswith("*") else " "
        declaration = f"{return_type}{separator}{name}({parameters});"
        if name in declarations:
            _fail(f"header declares {name} more than once")
        declarations[name] = declaration

    tokens = _FUNCTION_TOKEN_RE.findall(without_preprocessor)
    if len(tokens) != len(set(tokens)):
        _fail("header contains duplicate q_periapt function tokens")
    missed = sorted(set(tokens) - set(declarations))
    if missed:
        _fail(f"header contains unparseable q_periapt declarations: {missed}")
    return declarations


def verify_header(contract: CAbiContract, header_path: pathlib.Path) -> None:
    """Require exact numeric macros and exact normalized function declarations."""

    try:
        snapshot = read_regular_snapshot(
            pathlib.Path(header_path), maximum=MAX_HEADER_BYTES, label="C ABI header"
        )
        text = snapshot.data.decode("utf-8")
    except (EvidenceIOError, UnicodeDecodeError) as exc:
        raise CAbiContractError(f"cannot read strict UTF-8 C ABI header: {exc}") from exc
    stripped = _without_comments(text, "C ABI header")
    if len(re.findall(rf"^\s*#\s*ifndef\s+{HEADER_GUARD}\s*$", stripped, re.MULTILINE)) != 1:
        _fail(f"header must have exactly one #ifndef {HEADER_GUARD}")
    macros = _parse_header_macros(stripped)
    expected_macros = contract.document["abi"]["macros"]
    if macros != expected_macros:
        missing = sorted(set(expected_macros) - set(macros))
        extra = sorted(set(macros) - set(expected_macros))
        changed = sorted(
            name
            for name in set(macros) & set(expected_macros)
            if macros[name] != expected_macros[name]
        )
        _fail(
            "header macros differ from contract: "
            f"missing={missing}, extra={extra}, changed={changed}"
        )

    declarations = _parse_header_declarations(stripped)
    expected_declarations = contract.declarations
    if declarations != expected_declarations:
        missing = sorted(set(expected_declarations) - set(declarations))
        extra = sorted(set(declarations) - set(expected_declarations))
        changed = sorted(
            name
            for name in set(declarations) & set(expected_declarations)
            if declarations[name] != expected_declarations[name]
        )
        forbidden = sorted(set(declarations) & set(contract.document["abi"]["forbidden_exports"]))
        _fail(
            "header declarations differ from contract: "
            f"missing={missing}, extra={extra}, changed={changed}, forbidden={forbidden}"
        )


@dataclass(slots=True)
class _BoundedPipeCapture:
    label: str
    limit: int
    data: bytearray
    overflow: bool = False
    error_type: str | None = None


def _capture_inspector_pipe(
    stream: BinaryIO,
    capture: _BoundedPipeCapture,
    request_kill: Callable[[], None],
) -> None:
    """Drain one child pipe without allowing output-driven memory growth."""

    try:
        while True:
            read_size = min(
                INSPECTOR_PIPE_CHUNK_BYTES,
                capture.limit + 1 - len(capture.data),
            )
            chunk = stream.read(max(1, read_size))
            if not chunk:
                break
            available = capture.limit - len(capture.data)
            if len(chunk) > available:
                if available > 0:
                    capture.data.extend(chunk[:available])
                capture.overflow = True
                request_kill()
                break
            capture.data.extend(chunk)
    except (OSError, ValueError) as exc:
        capture.error_type = type(exc).__name__
        request_kill()
    finally:
        try:
            stream.close()
        except (OSError, ValueError) as exc:
            if capture.error_type is None:
                capture.error_type = type(exc).__name__
                request_kill()


def _capture_descriptor(capture: _BoundedPipeCapture) -> str:
    return (
        f"{capture.label}_bytes={len(capture.data)}, "
        f"{capture.label}_sha256={hashlib.sha256(capture.data).hexdigest()}"
    )


def _default_runner(command: list[str]) -> str:
    """Run an ABI inspector with hard time, output, and diagnostic bounds."""

    if not command or not command[0]:
        _fail("cannot inspect ABI library: inspection command is empty")
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )
    except (OSError, ValueError) as exc:
        raise CAbiContractError(
            "cannot inspect ABI library: inspection process could not start "
            f"({type(exc).__name__})"
        ) from None

    if process.stdout is None or process.stderr is None:
        with contextlib.suppress(OSError):
            process.kill()
        with contextlib.suppress(OSError, subprocess.TimeoutExpired):
            process.wait(timeout=INSPECTOR_TERMINATION_SECONDS)
        _fail("cannot inspect ABI library: inspection pipes were not created")

    termination_errors: list[str] = []
    termination_lock = threading.Lock()

    def request_kill() -> None:
        try:
            process.kill()
        except OSError as exc:
            if process.poll() is None:
                with termination_lock:
                    termination_errors.append(type(exc).__name__)

    captures = (
        _BoundedPipeCapture(
            "stdout",
            MAX_INSPECTOR_STDOUT_BYTES,
            bytearray(),
        ),
        _BoundedPipeCapture(
            "stderr",
            MAX_INSPECTOR_STDERR_BYTES,
            bytearray(),
        ),
    )
    streams = (process.stdout, process.stderr)
    threads = [
        threading.Thread(
            target=_capture_inspector_pipe,
            args=(stream, capture, request_kill),
            name=f"qperiapt-inspector-{capture.label}",
            daemon=True,
        )
        for stream, capture in zip(streams, captures, strict=True)
    ]
    started_threads: list[threading.Thread] = []
    thread_start_error: str | None = None
    for thread in threads:
        try:
            thread.start()
            started_threads.append(thread)
        except RuntimeError as exc:
            thread_start_error = type(exc).__name__
            request_kill()
            break

    timed_out = False
    wait_error: str | None = None
    try:
        process.wait(
            timeout=(
                INSPECTOR_TERMINATION_SECONDS
                if thread_start_error is not None
                else INSPECTOR_TIMEOUT_SECONDS
            )
        )
    except subprocess.TimeoutExpired:
        timed_out = thread_start_error is None
        request_kill()
        try:
            process.wait(timeout=INSPECTOR_TERMINATION_SECONDS)
        except (OSError, subprocess.TimeoutExpired) as exc:
            wait_error = type(exc).__name__
    except OSError as exc:
        wait_error = type(exc).__name__
        request_kill()

    for thread in started_threads:
        thread.join(INSPECTOR_READER_JOIN_SECONDS)
    reader_stuck = any(thread.is_alive() for thread in started_threads)
    if reader_stuck:
        request_kill()
        for stream in streams:
            with contextlib.suppress(OSError, ValueError):
                stream.close()
        for thread in started_threads:
            thread.join(INSPECTOR_TERMINATION_SECONDS)

    for thread, stream in zip(threads, streams, strict=True):
        if thread not in started_threads:
            with contextlib.suppress(OSError, ValueError):
                stream.close()

    stdout_capture, stderr_capture = captures
    if thread_start_error is not None:
        _fail(
            "cannot inspect ABI library: output reader could not start "
            f"({thread_start_error})"
        )
    if reader_stuck or any(thread.is_alive() for thread in started_threads):
        _fail("cannot inspect ABI library: output reader did not terminate")
    if wait_error is not None:
        _fail(
            "cannot inspect ABI library: inspection process did not terminate "
            f"({wait_error})"
        )
    if termination_errors:
        _fail(
            "cannot inspect ABI library: inspection process termination failed "
            f"({','.join(sorted(set(termination_errors)))})"
        )
    if timed_out:
        _fail(
            "cannot inspect ABI library: inspection process exceeded "
            f"{INSPECTOR_TIMEOUT_SECONDS:g}-second timeout"
        )
    for capture in captures:
        if capture.error_type is not None:
            _fail(
                f"cannot inspect ABI library: {capture.label} reader failed "
                f"({capture.error_type})"
            )
        if capture.overflow:
            _fail(
                f"cannot inspect ABI library: {capture.label} exceeded "
                f"{capture.limit}-byte limit"
            )
    if process.returncode != 0:
        _fail(
            "cannot inspect ABI library: inspection process failed: "
            f"exit_code={process.returncode}, "
            f"{_capture_descriptor(stdout_capture)}, "
            f"{_capture_descriptor(stderr_capture)}"
        )
    if stderr_capture.data:
        _fail(
            "cannot inspect ABI library: inspection process emitted diagnostics: "
            f"{_capture_descriptor(stderr_capture)}"
        )
    try:
        return bytes(stdout_capture.data).decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        invalid_offset = exc.start
        raise CAbiContractError(
            "cannot inspect ABI library: stdout is not strict UTF-8: "
            f"offset={invalid_offset}, {_capture_descriptor(stdout_capture)}"
        ) from None


def _require_regular_library(path: pathlib.Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise CAbiContractError(f"cannot stat ABI library {path}: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        _fail(f"ABI library must be a non-symlink regular file: {path}")


def _read_static_library_snapshot(
    path: pathlib.Path, label: str
) -> FileSnapshot:
    try:
        return read_regular_snapshot(
            path,
            maximum=MAX_STATIC_LIBRARY_BYTES,
            label=label,
        )
    except EvidenceIOError as exc:
        raise CAbiContractError(str(exc)) from exc


def _write_private_snapshot(path: pathlib.Path, data: bytes) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = os.open(path, flags, 0o600)
    primary_error: BaseException | None = None
    try:
        if os.name != "nt":
            os.fchmod(descriptor, 0o600)
        remaining = memoryview(data)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("private static-library snapshot write made no progress")
            remaining = remaining[written:]
        os.fsync(descriptor)
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        try:
            os.close(descriptor)
        except BaseException as cleanup_error:
            if primary_error is not None:
                primary_error.add_note(
                    f"closing the private static-library snapshot also failed: {cleanup_error}"
                )
            else:
                raise


def _require_matching_static_snapshot(
    reference_size: int,
    reference_sha256: str,
    observed: FileSnapshot,
    label: str,
) -> None:
    if (
        observed.size != reference_size
        or observed.sha256 != reference_sha256
    ):
        _fail(f"{label} changed during static-library verification")


@contextlib.contextmanager
def _authenticated_static_archive(
    path: pathlib.Path,
) -> Iterator[pathlib.Path]:
    """Yield an unpredictable byte-identical path that authenticates nm rows.

    llvm-nm does not escape newlines in archive member or symbol names. A
    256-bit path generated only after the source bytes are snapshotted prevents
    those fixed archive bytes from pre-forging a second accepted prefix. The
    llvm-nm executable and same-user host environment remain trusted.
    """

    original = _read_static_library_snapshot(path, "static ABI library")
    reference_size = original.size
    reference_sha256 = original.sha256
    original_data = original.data
    del original
    token = secrets.token_hex(32)
    body_error: BaseException | None = None
    try:
        with tempfile.TemporaryDirectory(prefix="qperiapt-c-abi-") as temporary:
            private_root = pathlib.Path(temporary)
            os.chmod(private_root, 0o700)
            root_metadata = private_root.lstat()
            if (
                stat.S_ISLNK(root_metadata.st_mode)
                or not stat.S_ISDIR(root_metadata.st_mode)
                or (
                    os.name != "nt"
                    and stat.S_IMODE(root_metadata.st_mode) & 0o077
                )
            ):
                _fail("private static-library inspection directory is not isolated")
            authenticated = private_root / f"archive-{token}{path.suffix}"
            _write_private_snapshot(authenticated, original_data)
            original_data = b""
            copied = _read_static_library_snapshot(
                authenticated, "private static ABI library snapshot"
            )
            _require_matching_static_snapshot(
                reference_size,
                reference_sha256,
                copied,
                "private static ABI library snapshot",
            )
            del copied
            try:
                yield authenticated
            except BaseException as exc:
                body_error = exc
                raise
            finally:
                try:
                    copied_after = _read_static_library_snapshot(
                        authenticated, "private static ABI library snapshot"
                    )
                    _require_matching_static_snapshot(
                        reference_size,
                        reference_sha256,
                        copied_after,
                        "private static ABI library snapshot",
                    )
                    del copied_after
                except BaseException as verification_error:
                    if body_error is not None:
                        body_error.add_note(
                            "post-inspection private snapshot verification also failed: "
                            f"{verification_error}"
                        )
                    else:
                        raise
    except (OSError, EvidenceIOError) as exc:
        raise CAbiContractError(
            f"cannot prepare authenticated static-library inspection: {exc}"
        ) from exc
    finally:
        original_data = b""
        try:
            original_after = _read_static_library_snapshot(
                path, "static ABI library"
            )
            _require_matching_static_snapshot(
                reference_size,
                reference_sha256,
                original_after,
                "static ABI library",
            )
            del original_after
        except BaseException as verification_error:
            if body_error is not None:
                body_error.add_note(
                    "post-inspection source snapshot verification also failed: "
                    f"{verification_error}"
                )
            else:
                raise


def _row_descriptor(line_number: int, raw_line: str) -> str:
    encoded = raw_line.encode("utf-8", errors="surrogatepass")
    return (
        f"row={line_number}, chars={len(raw_line)}, "
        f"sha256={hashlib.sha256(encoded).hexdigest()}"
    )


def _bounded_row_descriptor(
    label: str,
    line_number: int,
    raw_line: str,
    maximum: int,
) -> str:
    descriptor = _row_descriptor(line_number, raw_line)
    if len(raw_line) > maximum:
        _fail(
            f"{label} row exceeds the character limit: "
            f"{descriptor}, limit={maximum}"
        )
    return descriptor


def _ordered_text_sha256(values: list[str]) -> str:
    digest = hashlib.sha256()
    for value in values:
        encoded = value.encode("utf-8", errors="surrogatepass")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _dynamic_exports(output: str, platform: str) -> frozenset[str]:
    """Parse every defined dynamic export emitted by the platform tool."""

    names: set[str] = set()

    def record(name: str, descriptor: str) -> None:
        if (
            not name
            or "\x00" in name
            or len(name) > MAX_DYNAMIC_EXPORT_CHARS
        ):
            _fail(f"cannot parse dynamic-export symbol: {descriptor}")
        if name in names:
            _fail(
                "dynamic library defines export more than once: "
                f"{descriptor}"
            )
        names.add(name)

    if platform == "macos":
        for line_number, line in enumerate(output.splitlines(), start=1):
            if not line.strip():
                continue
            descriptor = _bounded_row_descriptor(
                "nm dynamic-export",
                line_number,
                line,
                MAX_DYNAMIC_ROW_CHARS,
            )
            candidate = line.strip()
            if len(candidate.split()) != 1:
                _fail(f"cannot parse nm dynamic-export row: {descriptor}")
            record(
                candidate[1:] if candidate.startswith("_") else candidate,
                descriptor,
            )
    elif platform == "linux":
        for line_number, line in enumerate(output.splitlines(), start=1):
            if not line.strip():
                continue
            descriptor = _bounded_row_descriptor(
                "nm dynamic-export",
                line_number,
                line,
                MAX_DYNAMIC_ROW_CHARS,
            )
            fields = line.split()
            if len(fields) not in {3, 4} or len(fields[1]) != 1:
                _fail(f"cannot parse nm dynamic-export row: {descriptor}")
            record(fields[0], descriptor)
    elif platform == "windows":
        lines = output.splitlines()
        for line_number, line in enumerate(lines, start=1):
            _bounded_row_descriptor(
                "dumpbin",
                line_number,
                line,
                MAX_DYNAMIC_ROW_CHARS,
            )
        headers = [
            (index, match)
            for index, line in enumerate(lines)
            if (
                match := re.fullmatch(
                    r"(?P<leading>\s*)(?P<ordinal>ordinal)(?P<gap1>\s+)"
                    r"(?P<hint>hint)(?P<gap2>\s+)(?P<rva>rva)"
                    r"(?P<gap3>\s+)(?P<name>name)\s*",
                    line,
                    re.IGNORECASE,
                )
            )
            is not None
        ]
        if not headers:
            _fail("cannot locate dumpbin export-table header")
        if len(headers) != 1:
            _fail("dumpbin output contains more than one export-table header")
        header_index, header_match = headers[0]

        def declared_decimal(label: str) -> int:
            matches = [
                match
                for line in lines[:header_index]
                if (
                    match := re.fullmatch(
                        rf"\s*([0-9]+)\s+{label}\s*",
                        line,
                        re.IGNORECASE,
                    )
                )
                is not None
            ]
            if len(matches) != 1:
                _fail(f"dumpbin output must declare {label} exactly once")
            decimal = matches[0].group(1)
            if len(decimal) > 5:
                _fail(f"dumpbin {label} exceeds the supported integer range")
            return int(decimal, 10)

        ordinal_base = declared_decimal("ordinal base")
        number_of_functions = declared_decimal("number of functions")
        number_of_names = declared_decimal("number of names")
        if number_of_names > number_of_functions:
            _fail("dumpbin named-export count exceeds its function count")
        if not 1 <= ordinal_base <= 65535:
            _fail(f"dumpbin export ordinal base is out of range: {ordinal_base}")
        ordinal_limit = ordinal_base + number_of_functions
        if ordinal_limit > 65536:
            _fail(
                "dumpbin export function table exceeds the ordinal range: "
                f"base={ordinal_base}, functions={number_of_functions}"
            )

        summaries = [
            index
            for index, line in enumerate(lines[header_index + 1 :], header_index + 1)
            if re.fullmatch(r"\s*Summary\s*", line, re.IGNORECASE) is not None
        ]
        if len(summaries) != 1:
            _fail("dumpbin output must terminate the export table with one Summary")
        summary_index = summaries[0]

        ordinal_start = header_match.start("ordinal")
        hint_start = header_match.start("hint")
        rva_start = header_match.start("rva")
        name_start = header_match.start("name")
        hints: set[int] = set()
        row_count = 0
        for line_index in range(header_index + 1, summary_index):
            line = lines[line_index]
            if not line.strip():
                continue
            descriptor = _row_descriptor(line_index + 1, line)
            padded = line.ljust(name_start)
            if padded[:ordinal_start].strip():
                _fail(f"cannot parse dumpbin export row: {descriptor}")
            ordinal_text = padded[ordinal_start:hint_start].strip()
            hint_text = padded[hint_start:rva_start].strip()
            rva_text = padded[rva_start:name_start].strip()
            payload = padded[name_start:].strip()
            if (
                re.fullmatch(r"[0-9]{1,5}", ordinal_text) is None
                or not payload
            ):
                _fail(f"cannot parse dumpbin export row: {descriptor}")
            ordinal = int(ordinal_text, 10)
            if not ordinal_base <= ordinal < ordinal_limit:
                _fail(
                    "dumpbin export ordinal is outside the declared function table: "
                    f"ordinal={ordinal}, base={ordinal_base}, "
                    f"functions={number_of_functions}, {descriptor}"
                )

            public_name = payload.split(maxsplit=1)[0]
            if public_name == "[NONAME]":
                _fail(
                    "dynamic library contains an ordinal-only export: "
                    f"{descriptor}"
                )
            if re.fullmatch(r"[0-9A-Fa-f]{1,4}", hint_text) is None:
                _fail(f"cannot parse dumpbin export row: {descriptor}")
            hint = int(hint_text, 16)
            if hint in hints:
                _fail(
                    "dynamic library defines export hint more than once: "
                    f"hint={hint:X}, {descriptor}"
                )
            hints.add(hint)

            if not rva_text:
                forwarder = re.fullmatch(
                    r"(?P<name>\S+)\s+\(forwarded\s+to\s+"
                    r"(?P<target>[^\s()]+\.[^\s()]+)\)",
                    payload,
                    re.IGNORECASE,
                )
                if forwarder is not None:
                    _fail(
                        "dynamic library contains a forwarded export: "
                        f"{descriptor}"
                    )
                _fail(f"cannot parse dumpbin export row: {descriptor}")
            if (
                re.fullmatch(r"[0-9A-Fa-f]{8}", rva_text) is None
                or int(rva_text, 16) == 0
            ):
                _fail(f"cannot parse dumpbin export row: {descriptor}")
            if re.search(r"\(forwarded\s+to\b", payload, re.IGNORECASE) is not None:
                _fail(f"cannot parse dumpbin export row: {descriptor}")
            direct = re.fullmatch(
                r"(?P<name>\S+)(?:\s+=\s+(?P<internal>\S+)"
                r"(?:\s+\([^\r\n]*\))?)?",
                payload,
            )
            if direct is None:
                _fail(f"cannot parse dumpbin export row: {descriptor}")
            name = direct.group("name")
            record(name, descriptor)
            row_count += 1

        if row_count != number_of_names:
            _fail(
                "dumpbin named-export count differs from its table: "
                f"rows={row_count}, declared={number_of_names}"
            )
        if hints and (min(hints) != 0 or max(hints) != number_of_names - 1):
            _fail("dumpbin export hints do not cover the declared name table")
    else:
        _fail(f"unknown dynamic-library platform: {platform}")
    return frozenset(names)


def _static_reserved_exports(
    output: str, platform: str, archive_argument: str
) -> frozenset[str]:
    """Parse the defined external ``q_periapt_*`` namespace from llvm-nm.

    ``--print-file-name --just-symbol-name`` emits one line per symbol as
    ``<archive>:<member>: <symbol>``. The archive argument contains a 256-bit
    value generated after the inspected bytes were snapshotted, so member or
    symbol newlines cannot forge a second authenticated row. Split on the first
    ``: `` after that exact prefix so a crafted symbol containing the delimiter
    cannot be mistaken for member provenance. Every symbol must be one
    whitespace-free token. Mach-O must use exactly one leading underscore for
    reserved exports. Linux and Windows must use the undecorated canonical
    spelling; because this verifier has no architecture input, decorated 32-bit
    COFF spellings fail closed and are outside this ABI 2 release scope.
    """

    archive_prefix = f"{archive_argument}:"
    names: set[str] = set()
    for line_number, raw_line in enumerate(output.splitlines(), start=1):
        descriptor = _bounded_row_descriptor(
            "llvm-nm static reserved-symbol",
            line_number,
            raw_line,
            MAX_LLVM_NM_ROW_CHARS,
        )
        if not raw_line.startswith(archive_prefix):
            _fail(f"cannot parse llvm-nm static reserved-symbol row: {descriptor}")
        member_name, separator, candidate = raw_line[len(archive_prefix) :].partition(
            ": "
        )
        if (
            separator == ""
            or member_name == ""
            or len(member_name) > MAX_LLVM_NM_MEMBER_CHARS
            or len(candidate) > MAX_LLVM_NM_SYMBOL_CHARS
            or "\x00" in member_name
            or re.fullmatch(r"\S+", candidate) is None
        ):
            _fail(f"cannot parse llvm-nm static reserved-symbol row: {descriptor}")
        if platform == "macos":
            if candidate.startswith("q_periapt_"):
                _fail(
                    "static library contains an undecorated reserved symbol on macos; "
                    f"Mach-O requires _q_periapt_* spelling: {descriptor}"
                )
            normalized = (
                candidate[1:] if candidate.startswith("_q_periapt_") else candidate
            )
        else:
            if candidate.startswith("_q_periapt_"):
                _fail(
                    f"static library contains a decorated reserved symbol on {platform}; "
                    "this verifier requires canonical undecorated q_periapt_* spelling "
                    f"and excludes 32-bit COFF: {descriptor}"
                )
            normalized = candidate
        if not normalized.startswith("q_periapt_"):
            continue
        if re.fullmatch(r"q_periapt_[a-z0-9_]+", normalized) is None:
            _fail(f"cannot parse llvm-nm static reserved-symbol row: {descriptor}")
        if normalized in names:
            _fail(
                "static library defines reserved symbol more than once: "
                f"{descriptor}"
            )
        names.add(normalized)
    return frozenset(names)


def _symbol_set_sha256(names: set[str] | frozenset[str]) -> str:
    canonical = b"\x00".join(name.encode("utf-8") for name in sorted(names))
    return hashlib.sha256(canonical).hexdigest()


def _verify_macos_identity(
    path: pathlib.Path, identity: dict[str, Any], runner: CommandRunner
) -> None:
    install_output = runner(["otool", "-D", str(path)])
    install_names = [line.strip() for line in install_output.splitlines()[1:] if line.strip()]
    if install_names != [identity["install_name"]]:
        _fail(
            "macOS install name differs: "
            f"observed_count={len(install_names)}, "
            f"observed_sha256={_ordered_text_sha256(install_names)}"
        )

    linkage_output = runner(["otool", "-L", str(path)])
    escaped_name = re.escape(identity["install_name"])
    pattern = re.compile(
        rf"^\s*{escaped_name}\s+\(compatibility version\s+"
        rf"({_VERSION_RE.pattern}),\s+current version\s+({_VERSION_RE.pattern})\)\s*$"
    )
    identities = [
        match.groups()
        for line in linkage_output.splitlines()[1:]
        if (match := pattern.match(line)) is not None
    ]
    expected = [(identity["compatibility_version"], identity["current_version"])]
    if identities != expected:
        observed_versions = ["\x00".join(pair) for pair in identities]
        _fail(
            "macOS compatibility/current versions differ: "
            f"observed_count={len(observed_versions)}, "
            f"observed_sha256={_ordered_text_sha256(observed_versions)}"
        )


def _verify_linux_identity(
    path: pathlib.Path, identity: dict[str, Any], runner: CommandRunner
) -> None:
    dynamic = runner(["readelf", "-d", str(path)])
    sonames = re.findall(r"\(SONAME\).*?\[([^\]]+)\]", dynamic)
    if sonames != [identity["soname"]]:
        _fail(
            "Linux SONAME differs: "
            f"observed_count={len(sonames)}, "
            f"observed_sha256={_ordered_text_sha256(sonames)}"
        )


def verify_dynamic_library(
    contract: CAbiContract,
    library_path: pathlib.Path,
    platform: str,
    *,
    runner: CommandRunner = _default_runner,
) -> None:
    """Verify exact project exports and platform ABI-major runtime identity."""

    if platform not in {"macos", "linux", "windows"}:
        _fail(f"unknown dynamic-library platform: {platform}")
    path = pathlib.Path(library_path)
    _require_regular_library(path)
    identity = contract.document["package"]["platforms"][platform]
    if path.name != identity["shared_filename"]:
        _fail(
            f"{platform} shared-library filename differs: "
            f"{path.name} != {identity['shared_filename']}"
        )

    if platform == "macos":
        exports_output = runner(["nm", "-gUj", str(path)])
        _verify_macos_identity(path, identity, runner)
    elif platform == "linux":
        exports_output = runner(["nm", "-D", "--defined-only", "-P", str(path)])
        _verify_linux_identity(path, identity, runner)
    else:
        exports_output = runner(["dumpbin", "/nologo", "/exports", str(path)])

    exports = _dynamic_exports(exports_output, platform)
    if exports != contract.export_names:
        missing = sorted(contract.export_names - exports)
        extra = exports - contract.export_names
        forbidden = exports & set(contract.document["abi"]["forbidden_exports"])
        _fail(
            "dynamic-library exports differ from contract: "
            f"missing={missing}, "
            f"extra_count={len(extra)}, extra_sha256={_symbol_set_sha256(extra)}, "
            f"forbidden_count={len(forbidden)}, "
            f"forbidden_sha256={_symbol_set_sha256(forbidden)}"
        )


def verify_static_library(
    contract: CAbiContract,
    library_path: pathlib.Path,
    platform: str,
    llvm_nm: pathlib.Path,
    *,
    runner: CommandRunner = _default_runner,
) -> None:
    """Verify the exact reserved public namespace of one static archive."""

    if platform not in {"macos", "linux", "windows"}:
        _fail(f"unknown static-library platform: {platform}")
    path = pathlib.Path(library_path)
    _require_regular_library(path)
    identity = contract.document["package"]["platforms"][platform]
    if path.name != identity["static_filename"]:
        _fail(
            f"{platform} static-library filename differs: "
            f"{path.name} != {identity['static_filename']}"
        )

    nm_path = pathlib.Path(llvm_nm)
    if not nm_path.is_absolute():
        _fail(f"llvm-nm path must be absolute: {nm_path}")
    _require_regular_library(nm_path)
    with _authenticated_static_archive(path) as authenticated_archive:
        archive_argument = str(authenticated_archive)
        output = runner(
            [
                str(nm_path),
                "--defined-only",
                "--extern-only",
                "--no-demangle",
                "--quiet",
                "--print-file-name",
                "--just-symbol-name",
                archive_argument,
            ]
        )
        exports = _static_reserved_exports(output, platform, archive_argument)
    if exports != contract.export_names:
        missing = sorted(contract.export_names - exports)
        extra = exports - contract.export_names
        forbidden = exports & set(contract.document["abi"]["forbidden_exports"])
        _fail(
            "static-library reserved exports differ from contract: "
            f"missing={missing}, "
            f"extra_count={len(extra)}, extra_sha256={_symbol_set_sha256(extra)}, "
            f"forbidden_count={len(forbidden)}, "
            f"forbidden_sha256={_symbol_set_sha256(forbidden)}"
        )


def _repository_root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parent.parent


def _parse_args() -> argparse.Namespace:
    root = _repository_root()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--contract",
        type=pathlib.Path,
        default=root / "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json",
    )
    parser.add_argument(
        "--header",
        type=pathlib.Path,
        default=root / "crates/q-periapt-ffi/include/q_periapt.h",
    )
    parser.add_argument("--library", type=pathlib.Path)
    parser.add_argument("--static-library", type=pathlib.Path)
    parser.add_argument("--llvm-nm", type=pathlib.Path)
    parser.add_argument("--platform", choices=("macos", "linux", "windows"))
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    has_library = args.library is not None or args.static_library is not None
    if has_library != (args.platform is not None):
        raise SystemExit(
            "error: --platform must be supplied exactly when a library is supplied"
        )
    if (args.static_library is None) != (args.llvm_nm is None):
        raise SystemExit(
            "error: --static-library and --llvm-nm must be supplied together"
        )
    try:
        contract = load_contract(args.contract)
        verify_header(contract, args.header)
        if args.library is not None:
            verify_dynamic_library(contract, args.library, args.platform)
        if args.static_library is not None:
            verify_static_library(
                contract,
                args.static_library,
                args.platform,
                args.llvm_nm,
            )
    except CAbiContractError as exc:
        raise SystemExit(f"error: {exc}") from exc
    result = {
        "abi_major": ABI_MAJOR,
        "contract_sha256": contract.sha256,
        "exports": len(contract.export_names),
        "header": str(args.header),
        "library": str(args.library) if args.library is not None else None,
        "static_library": (
            str(args.static_library) if args.static_library is not None else None
        ),
        "package_semver": PACKAGE_SEMVER,
        "platform": args.platform,
        "status": "pass",
    }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
