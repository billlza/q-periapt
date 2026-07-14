#!/usr/bin/env python3
"""Fail-closed evidence for a signed, static-only Apple XCFramework release."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import pathlib
import posixpath
import re
import stat
import struct
import subprocess
import sys
import tempfile
import zipfile
import zlib
from typing import Any, NoReturn

from evidence_io import EvidenceIOError, load_json_object_snapshot, read_regular_snapshot


MAX_TEXT_BYTES = 256 * 1024
MAX_CERTIFICATE_BYTES = 1024 * 1024
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_ENTRY_BYTES = 64 * 1024 * 1024
MAX_COMPRESSION_RATIO = 100
EXPECTED_IDENTITY_CLASS = "Developer ID Application"
BUILD_PATH_HYGIENE_POLICY = "qperiapt.apple_static_archive_build_paths.v1"
SYNTHETIC_BUILD_PATH_PREFIX = "/__qperiapt__/"
EXPECTED_XCFRAMEWORK_LIBRARIES = frozenset(
    {
        "ios-arm64/libq_periapt_ffi_abi2.a",
        "ios-arm64_x86_64-simulator/libq_periapt_ffi_abi2.a",
        "macos-arm64_x86_64/libq_periapt_ffi_abi2.a",
    }
)
EXPECTED_XCFRAMEWORK_DIRECTORIES = frozenset(
    {
        "CQPeriapt.xcframework/",
        "CQPeriapt.xcframework/ios-arm64/",
        "CQPeriapt.xcframework/ios-arm64/Headers/",
        "CQPeriapt.xcframework/ios-arm64_x86_64-simulator/",
        "CQPeriapt.xcframework/ios-arm64_x86_64-simulator/Headers/",
        "CQPeriapt.xcframework/macos-arm64_x86_64/",
        "CQPeriapt.xcframework/macos-arm64_x86_64/Headers/",
    }
)
EXPECTED_XCFRAMEWORK_FILES = frozenset(
    {
        "CQPeriapt.xcframework/Info.plist",
        *(
            f"CQPeriapt.xcframework/{slice_name}/Headers/{header}"
            for slice_name in (
                "ios-arm64",
                "ios-arm64_x86_64-simulator",
                "macos-arm64_x86_64",
            )
            for header in ("module.modulemap", "q_periapt.h")
        ),
        *(
            f"CQPeriapt.xcframework/{library}"
            for library in EXPECTED_XCFRAMEWORK_LIBRARIES
        ),
    }
)
EXPECTED_SIGNATURE_DIRECTORIES = frozenset(
    {"CQPeriapt.xcframework/_CodeSignature/"}
)
EXPECTED_SIGNATURE_FILES = frozenset(
    {
        "CQPeriapt.xcframework/_CodeSignature/CodeDirectory",
        "CQPeriapt.xcframework/_CodeSignature/CodeRequirements",
        "CQPeriapt.xcframework/_CodeSignature/CodeResources",
        "CQPeriapt.xcframework/_CodeSignature/CodeSignature",
    }
)
HEX_40 = re.compile(r"^[0-9A-Fa-f]{40}$")
HEX_64 = re.compile(r"^[0-9A-Fa-f]{64}$")
TEAM_ID = re.compile(r"^[A-Z0-9]{10}$")
GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")
FAT_MAGIC = b"\xca\xfe\xba\xbe"
AR_MAGIC = b"!<arch>\n"
AR_MEMBER_HEADER_BYTES = 60
ZIP_LOCAL_FILE_HEADER = struct.Struct("<IHHHHHIIIHH")
ZIP_CENTRAL_DIRECTORY_HEADER = struct.Struct("<IHHHHHHIIIHHHHHII")
ZIP_END_OF_CENTRAL_DIRECTORY = struct.Struct("<IHHHHIIH")
ZIP_LOCAL_FILE_SIGNATURE = 0x04034B50
ZIP_CENTRAL_DIRECTORY_SIGNATURE = 0x02014B50
ZIP_END_OF_CENTRAL_DIRECTORY_SIGNATURE = 0x06054B50
_ALLOWED_RUST_DISTRIBUTION_BUILD_PATHS = (
    re.compile(
        rb"/Users/runner/work/rust/rust/build/aarch64-apple-darwin/"
        rb"stage1-std/aarch64-apple-darwin/dist/build/"
        rb"compiler_builtins-7be819c9f191cb18/out"
        rb"(?:/lse_[A-Za-z0-9_]+\.S)?(?=[\x00\r\n\t ]|$)"
    ),
    re.compile(
        rb"/Users/runner/work/rust/rust/library/compiler-builtins/"
        rb"compiler-builtins(?=[\x00\r\n\t ]|$)"
    ),
)
_ALLOWED_RUST_DISTRIBUTION_MEMBER_NAMES = (
    re.compile(rb"4134eb5fb31f69b6-lse_[A-Za-z0-9_]+\.o"),
    re.compile(rb"f3c5cc7ab326d4d0-[A-Za-z0-9_]+\.o"),
    re.compile(rb"ad3ac4dcdcbf93cb-aarch64\.o"),
)
_PRIVATE_BUILD_PATH_PATTERNS = (
    (
        "macos_user_home",
        re.compile(rb"(?:file://)?/Users/[-A-Za-z0-9_.+ ]{1,128}/"),
    ),
    (
        "linux_user_home",
        re.compile(
            rb"(?:file://)?/(?:home/[-A-Za-z0-9_.+ ]{1,128}|root)/"
        ),
    ),
    (
        "macos_temporary_directory",
        re.compile(rb"(?:file://)?/(?:private/)?var/folders/"),
    ),
    (
        "temporary_directory",
        re.compile(rb"(?:file://)?/(?:private/)?(?:tmp|var/tmp)/"),
    ),
    (
        "ci_workspace",
        re.compile(rb"(?:file://)?/(?:github/workspace|workspace|builds)/"),
    ),
    (
        "windows_drive_absolute_path",
        re.compile(
            rb"(?i)(?:file:///)?(?:\\\\\?\\)?[A-Z]:[\\/]"
            rb"[-A-Za-z0-9_.+@$ ]{2,128}[\\/]"
            rb"[-A-Za-z0-9_.+@$ ]{2,128}"
            rb"(?=[\\/\x00\r\n\t ]|$)"
        ),
    ),
    (
        "windows_extended_unc_share",
        re.compile(
            rb"(?i)\\\\\?\\UNC\\[-A-Za-z0-9_.+@$ ]{2,128}"
            rb"\\[-A-Za-z0-9_.+@$ ]{2,128}"
            rb"(?=[\\\x00\r\n\t ]|$)"
        ),
    ),
    (
        "windows_unc_share",
        re.compile(
            rb"\\\\[-A-Za-z0-9_.+@$ ]{2,128}"
            rb"\\[-A-Za-z0-9_.+@$ ]{2,128}"
            rb"(?=[\\\x00\r\n\t ]|$)"
        ),
    ),
    (
        "windows_posix_unc_share",
        re.compile(
            rb"//[-A-Za-z0-9_.+@$ ]{2,128}"
            rb"/[-A-Za-z0-9_.+@$ ]{2,128}"
            rb"(?=[/\x00\r\n\t ]|$)"
        ),
    ),
    (
        "msys_drive_absolute_path",
        re.compile(
            rb"/[a-z]/[-A-Za-z0-9_.+@$]{2,128}/"
            rb"[-A-Za-z0-9_.+@$]{2,128}(?=[/\x00\r\n\t ]|$)"
        ),
    ),
)
_UTF16_PRIVATE_PREFIXES = (
    ("utf16_macos_user_home", "/Users/"),
    ("utf16_linux_user_home", "/home/"),
    ("utf16_root_home", "/root/"),
    ("utf16_macos_temporary_directory", "/private/var/folders/"),
    ("utf16_temporary_directory", "/tmp/"),
    ("utf16_windows_user_home", ":\\Users\\"),
    ("utf16_windows_user_home", ":/Users/"),
)
_UTF16_PRIVATE_PATH_PATTERNS = (
    (
        "utf16_windows_drive_absolute_path",
        re.compile(
            rb"(?i)(?:file:///)?[A-Z]:[\\/]"
            rb"[-A-Za-z0-9_.+@$ ]{2,128}[\\/]"
            rb"[-A-Za-z0-9_.+@$ ]{2,128}"
            rb"(?=[\\/\x00\r\n\t ]|$)"
        ),
    ),
    (
        "utf16_windows_extended_unc_share",
        re.compile(
            rb"(?i)\\\\\?\\UNC\\[-A-Za-z0-9_.+@$ ]{2,128}"
            rb"\\[-A-Za-z0-9_.+@$ ]{2,128}"
            rb"(?=[\\\x00\r\n\t ]|$)"
        ),
    ),
    (
        "utf16_windows_unc_share",
        re.compile(
            rb"\\\\[-A-Za-z0-9_.+@$ ]{2,128}"
            rb"\\[-A-Za-z0-9_.+@$ ]{2,128}"
            rb"(?=[\\\x00\r\n\t ]|$)"
        ),
    ),
    (
        "utf16_windows_posix_unc_share",
        re.compile(
            rb"//[-A-Za-z0-9_.+@$ ]{2,128}"
            rb"/[-A-Za-z0-9_.+@$ ]{2,128}"
            rb"(?=[/\x00\r\n\t ]|$)"
        ),
    ),
    (
        "utf16_msys_drive_absolute_path",
        re.compile(
            rb"/[a-z]/[-A-Za-z0-9_.+@$]{2,128}/"
            rb"[-A-Za-z0-9_.+@$]{2,128}(?=[/\x00\r\n\t ]|$)"
        ),
    ),
)


class AppleDistributionError(ValueError):
    """Apple distribution evidence violates the release contract."""


def _fail(message: str) -> NoReturn:
    raise AppleDistributionError(message)


def _require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        _fail(f"{label} must be a non-empty string")
    return value


def _require_sha256(value: Any, label: str) -> str:
    text = _require_string(value, label)
    if not HEX_64.fullmatch(text):
        _fail(f"{label} must be a 64-digit SHA-256 hex digest")
    return text.lower()


def _require_git_commit(value: Any, label: str) -> str:
    text = _require_string(value, label)
    if not GIT_COMMIT.fullmatch(text):
        _fail(f"{label} must be a lowercase 40-digit Git commit")
    return text


def _require_exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        _fail(
            f"{label} fields differ from the release schema: "
            f"missing={sorted(expected - actual)} unknown={sorted(actual - expected)}"
        )


def _json_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _write_new_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    """Atomically publish a new public evidence file without replacing a path."""

    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        raise FileExistsError(path)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.tmp.", dir=path.parent
    )
    temporary = pathlib.Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(_json_bytes(value))
            stream.flush()
            os.fchmod(stream.fileno(), 0o644)
            os.fsync(stream.fileno())
        os.link(temporary, path, follow_symlinks=False)
        directory = os.open(
            path.parent,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _stream_sha256_regular_file(
    path: pathlib.Path, *, maximum: int, label: str
) -> tuple[int, str]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            _fail(f"{label} is not a regular file: {path}")
        if before.st_size > maximum:
            _fail(f"{label} exceeds {maximum} bytes: {path}")
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > maximum:
                _fail(f"{label} exceeds {maximum} bytes while being read: {path}")
            digest.update(chunk)
        after = os.fstat(descriptor)
        identity = lambda value: (
            value.st_dev,
            value.st_ino,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )
        if identity(before) != identity(after) or size != before.st_size:
            _fail(f"{label} changed while it was hashed: {path}")
        return size, digest.hexdigest()
    finally:
        os.close(descriptor)


def _single_field(fields: dict[str, list[str]], key: str) -> str:
    values = fields.get(key, [])
    if len(values) != 1 or not values[0]:
        _fail(f"codesign display must contain exactly one non-empty {key} field")
    return values[0]


def parse_codesign_display(text: str, *, expected_team_id: str) -> dict[str, Any]:
    """Parse the stable subset of ``codesign --display --verbose=4``."""

    if not TEAM_ID.fullmatch(expected_team_id):
        _fail("expected Team ID must be ten uppercase alphanumeric characters")
    fields: dict[str, list[str]] = {}
    for raw_line in text.splitlines():
        if "=" not in raw_line:
            continue
        key, value = raw_line.split("=", 1)
        fields.setdefault(key, []).append(value)

    authorities = fields.get("Authority", [])
    if len(authorities) < 3 or any(not authority for authority in authorities):
        _fail("codesign display must contain a complete non-empty authority chain")
    identity = authorities[0]
    if not identity.startswith(f"{EXPECTED_IDENTITY_CLASS}:"):
        _fail(f"unexpected leaf signing authority: {identity}")
    if "Developer ID Certification Authority" not in authorities[1:]:
        _fail("codesign authority chain lacks Developer ID Certification Authority")
    if "Apple Root CA" not in authorities[1:]:
        _fail("codesign authority chain lacks Apple Root CA")
    team_id = _single_field(fields, "TeamIdentifier")
    if team_id != expected_team_id:
        _fail(f"codesign TeamIdentifier {team_id} does not match {expected_team_id}")
    if fields.get("Signature") == ["adhoc"]:
        _fail("ad-hoc signatures are forbidden for Apple distribution")
    if "Runtime Version" in fields:
        _fail("static XCFramework signature unexpectedly enables hardened runtime")
    signature_size = _single_field(fields, "Signature size")
    if not signature_size.isdecimal() or int(signature_size) <= 0:
        _fail("codesign Signature size must be a positive integer")
    code_directories = re.findall(
        r"^CodeDirectory\b.*\bflags=0x([0-9A-Fa-f]+)\(([^)]*)\)",
        text,
        flags=re.MULTILINE,
    )
    if code_directories != [("0", "none")]:
        _fail(
            "static XCFramework CodeDirectory flags are not exactly none: "
            f"{code_directories}"
        )
    cdhash = _single_field(fields, "CDHash")
    if not HEX_40.fullmatch(cdhash):
        _fail("codesign CDHash must be a 40-digit hex digest")
    display_format = _single_field(fields, "Format")
    if not display_format.startswith("bundle"):
        _fail(f"codesign format is not a bundle: {display_format}")
    return {
        "identity_class": EXPECTED_IDENTITY_CLASS,
        "authority": identity,
        "authority_chain": authorities,
        "team_id": team_id,
        "identifier": _single_field(fields, "Identifier"),
        "format": "bundle",
        "secure_timestamp": _single_field(fields, "Timestamp"),
        "cdhash": cdhash.lower(),
        "hardened_runtime": False,
        "code_directory_flags": "none",
        "strict_verification": True,
    }


def _openssl_certificate_metadata(certificate: bytes) -> dict[str, str]:
    try:
        completed = subprocess.run(
            [
                "openssl",
                "x509",
                "-inform",
                "DER",
                "-noout",
                "-subject",
                "-issuer",
                "-serial",
                "-dates",
            ],
            input=certificate,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise AppleDistributionError(
            f"cannot inspect leaf signing certificate: {exc}"
        ) from exc
    try:
        text = completed.stdout.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AppleDistributionError("openssl certificate metadata is not UTF-8") from exc
    metadata: dict[str, str] = {}
    for line in text.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            metadata[key.strip()] = value.strip()
    required = ("subject", "issuer", "serial", "notBefore", "notAfter")
    for key in required:
        _require_string(metadata.get(key), f"certificate {key}")
    if EXPECTED_IDENTITY_CLASS not in metadata["subject"]:
        _fail("leaf certificate subject is not a Developer ID Application identity")
    return {key: metadata[key] for key in required}


def _expected_archive_entries(require_signature: bool) -> frozenset[str]:
    entries = set(EXPECTED_XCFRAMEWORK_DIRECTORIES | EXPECTED_XCFRAMEWORK_FILES)
    if require_signature:
        entries.update(EXPECTED_SIGNATURE_DIRECTORIES)
        entries.update(EXPECTED_SIGNATURE_FILES)
    return frozenset(entries)


def _allowed_rust_distribution_path_at(
    data: bytes, offset: int, *, allow_upstream_toolchain_paths: bool
) -> bool:
    return allow_upstream_toolchain_paths and any(
        pattern.match(data, offset) is not None
        for pattern in _ALLOWED_RUST_DISTRIBUTION_BUILD_PATHS
    )


def _path_match_failure(*, category: str, label: str, offset: int) -> NoReturn:
    _fail(
        "static archive contains a forbidden private build path: "
        f"category={category} artifact={label} offset={offset}"
    )


def _validated_forbidden_build_prefixes(prefixes: tuple[str, ...]) -> tuple[bytes, ...]:
    validated: list[bytes] = []
    for prefix in prefixes:
        if (
            not isinstance(prefix, str)
            or not prefix.startswith("/")
            or prefix == "/"
            or posixpath.normpath(prefix) != prefix
            or "=" in prefix
            or any(ord(character) < 32 or ord(character) == 127 for character in prefix)
        ):
            _fail("forbidden build path prefixes must be absolute canonical POSIX paths")
        encoded = prefix.rstrip("/").encode("utf-8")
        if encoded not in validated:
            validated.append(encoded)
    return tuple(validated)


def _has_path_boundary(data: bytes, *, offset: int, matched_length: int) -> bool:
    end = offset + matched_length
    return end == len(data) or data[end : end + 1] in {b"/", b"\\", b"\x00"}


def _has_utf16_path_boundary(
    data: bytes, *, offset: int, matched_length: int, encoding: str
) -> bool:
    end = offset + matched_length
    if end == len(data):
        return True
    return data[end : end + 2] in {
        character.encode(encoding) for character in ("/", "\\", "\x00")
    }


def _ascii_utf16_view(data: bytes, *, encoding: str, alignment: int) -> bytes:
    """Project only correctly aligned ASCII UTF-16 code units into a byte view."""

    view = bytearray()
    for offset in range(alignment, len(data) - 1, 2):
        first, second = data[offset], data[offset + 1]
        code_unit, zero = (first, second) if encoding == "utf-16-le" else (second, first)
        view.append(code_unit if zero == 0 and code_unit < 0x80 else 0)
    return bytes(view)


def _utf16_public_web_url_at(data: bytes, *, reported_slash_offset: int) -> bool:
    """Recognize only a complete HTTP(S) UTF-16 scheme at the same separator."""

    for slash_offset in range(
        max(0, reported_slash_offset - 1),
        min(len(data), reported_slash_offset + 1) + 1,
    ):
        for encoding in ("utf-16-le", "utf-16-be"):
            separator = "//".encode(encoding)
            if data[slash_offset : slash_offset + len(separator)] != separator:
                continue
            for scheme in ("http:", "https:"):
                encoded_scheme = scheme.encode(encoding)
                scheme_start = slash_offset - len(encoded_scheme)
                if scheme_start >= 0 and data[
                    scheme_start:slash_offset
                ].lower() == encoded_scheme:
                    return True
    return False


def _validate_build_path_hygiene(
    data: bytes,
    *,
    label: str,
    forbidden_build_prefixes: tuple[str, ...] = (),
    allow_upstream_toolchain_paths: bool = False,
) -> None:
    """Reject private build paths without disclosing their raw value in diagnostics."""

    for prefix in _validated_forbidden_build_prefixes(forbidden_build_prefixes):
        start = 0
        while True:
            offset = data.find(prefix, start)
            if offset < 0:
                break
            if _has_path_boundary(
                data, offset=offset, matched_length=len(prefix)
            ) and not _allowed_rust_distribution_path_at(
                data,
                offset,
                allow_upstream_toolchain_paths=allow_upstream_toolchain_paths,
            ):
                _path_match_failure(
                    category="exact_build_prefix",
                    label=label,
                    offset=offset,
                )
            start = offset + 1
        for encoding in ("utf-16-le", "utf-16-be"):
            encoded = prefix.decode("utf-8").encode(encoding)
            start = 0
            while True:
                offset = data.find(encoded, start)
                if offset < 0:
                    break
                if _has_utf16_path_boundary(
                    data,
                    offset=offset,
                    matched_length=len(encoded),
                    encoding=encoding,
                ):
                    _path_match_failure(
                        category=f"exact_build_prefix_{encoding}",
                        label=label,
                        offset=offset,
                    )
                start = offset + 2

    for category, pattern in _PRIVATE_BUILD_PATH_PATTERNS:
        for match in pattern.finditer(data):
            if category == "windows_posix_unc_share" and data[
                max(0, match.start() - 6) : match.start()
            ].lower().endswith((b"http:", b"https:")):
                continue
            if category == "macos_user_home" and _allowed_rust_distribution_path_at(
                data,
                match.start(),
                allow_upstream_toolchain_paths=allow_upstream_toolchain_paths,
            ):
                continue
            _path_match_failure(
                category=category,
                label=label,
                offset=match.start(),
            )

    for category, prefix in _UTF16_PRIVATE_PREFIXES:
        for encoding in ("utf-16-le", "utf-16-be"):
            encoded = prefix.encode(encoding)
            offset = data.find(encoded)
            if offset >= 0:
                _path_match_failure(
                    category=category,
                    label=label,
                    offset=offset,
                )

    for encoding in ("utf-16-le", "utf-16-be"):
        # Inspect each alignment independently because an object member need not
        # place a UTF-16 string at an even archive offset.
        for alignment in (0, 1):
            decoded = _ascii_utf16_view(
                data, encoding=encoding, alignment=alignment
            )
            for category, pattern in _UTF16_PRIVATE_PATH_PATTERNS:
                for match in pattern.finditer(decoded):
                    raw_offset = alignment + match.start() * 2
                    if category == "utf16_windows_posix_unc_share" and (
                        _utf16_public_web_url_at(
                            data, reported_slash_offset=raw_offset
                        )
                    ):
                        continue
                    _path_match_failure(
                        category=category,
                        label=label,
                        offset=raw_offset,
                    )


def _parse_ar_member_name(
    raw_name: bytes, payload: bytes, *, label: str
) -> tuple[bytes, bytes]:
    field = raw_name.rstrip(b" ")
    if field.startswith(b"#1/"):
        length_text = field.removeprefix(b"#1/")
        if not length_text.isdigit():
            _fail(f"static archive has an invalid extended member name: {label}")
        length = int(length_text)
        if length <= 0 or length > len(payload):
            _fail(f"static archive extended member name is out of bounds: {label}")
        name = payload[:length].rstrip(b"\x00")
        content = payload[length:]
    else:
        name = field
        content = payload
        if name.endswith(b"/") and name not in {b"/", b"//"}:
            name = name[:-1]
    if not name or any(byte < 32 or byte == 127 for byte in name):
        _fail(f"static archive has an invalid member name: {label}")
    return name, content


def _is_pinned_rust_distribution_member(name: bytes) -> bool:
    return any(
        pattern.fullmatch(name) is not None
        for pattern in _ALLOWED_RUST_DISTRIBUTION_MEMBER_NAMES
    )


def _validate_ar_archive(
    data: bytes, *, label: str, forbidden_build_prefixes: tuple[str, ...]
) -> None:
    if not data.startswith(AR_MAGIC):
        _fail(f"fat archive slice is not an ar archive: {label}")
    offset = len(AR_MAGIC)
    member_index = 0
    while offset < len(data):
        header_end = offset + AR_MEMBER_HEADER_BYTES
        if header_end > len(data):
            _fail(f"static archive member header is truncated: {label}")
        header = data[offset:header_end]
        if header[58:60] != b"`\n":
            _fail(f"static archive member header terminator is invalid: {label}")
        for field_name, field, digits in (
            ("timestamp", header[16:28], b"0123456789"),
            ("owner", header[28:34], b"0123456789"),
            ("group", header[34:40], b"0123456789"),
            ("mode", header[40:48], b"01234567"),
        ):
            value = field.strip(b" ")
            if not value or any(byte not in digits for byte in value):
                _fail(
                    f"static archive member {field_name} is invalid: {label}"
                )
        size_text = header[48:58].strip(b" ")
        if not size_text or not size_text.isdigit():
            _fail(f"static archive member size is invalid: {label}")
        member_size = int(size_text)
        payload_end = header_end + member_size
        if payload_end > len(data):
            _fail(f"static archive member payload is out of bounds: {label}")
        raw_payload = data[header_end:payload_end]
        member_name, member_payload = _parse_ar_member_name(
            header[:16], raw_payload, label=label
        )
        member_label = f"{label}:member[{member_index}]"
        _validate_build_path_hygiene(
            header,
            label=member_label,
            forbidden_build_prefixes=forbidden_build_prefixes,
        )
        _validate_build_path_hygiene(
            member_name,
            label=member_label,
            forbidden_build_prefixes=forbidden_build_prefixes,
        )
        _validate_build_path_hygiene(
            member_payload,
            label=member_label,
            forbidden_build_prefixes=forbidden_build_prefixes,
            allow_upstream_toolchain_paths=_is_pinned_rust_distribution_member(
                member_name
            ),
        )
        offset = payload_end
        if member_size % 2:
            if offset >= len(data) or data[offset : offset + 1] != b"\n":
                _fail(f"static archive member padding is invalid: {label}")
            offset += 1
        member_index += 1
    if member_index == 0:
        _fail(f"static archive contains no members: {label}")


def _validate_static_archive(
    data: bytes, *, label: str, forbidden_build_prefixes: tuple[str, ...] = ()
) -> None:
    if data.startswith(AR_MAGIC):
        _validate_ar_archive(
            data,
            label=label,
            forbidden_build_prefixes=forbidden_build_prefixes,
        )
    elif not data.startswith(FAT_MAGIC) or len(data) < 8:
        _fail(f"XCFramework library is not a static archive or fat static archive: {label}")
    else:
        architecture_count = struct.unpack_from(">I", data, 4)[0]
        if architecture_count != 2:
            _fail(f"fat static archive must contain exactly two architectures: {label}")
        header_size = 8 + architecture_count * 20
        if len(data) < header_size:
            _fail(f"fat static archive header is truncated: {label}")
        _validate_build_path_hygiene(
            data[:header_size],
            label=f"{label}:fat-header",
            forbidden_build_prefixes=forbidden_build_prefixes,
        )
        seen_ranges: list[tuple[int, int]] = []
        for index in range(architecture_count):
            _, _, offset, size, _ = struct.unpack_from(">IIIII", data, 8 + index * 20)
            end = offset + size
            if offset < header_size or end > len(data) or size < len(AR_MAGIC):
                _fail(f"fat static archive slice is out of bounds: {label}")
            if data[offset : offset + len(AR_MAGIC)] != AR_MAGIC:
                _fail(f"fat archive slice is not an ar archive: {label}")
            if any(
                offset < other_end and other_offset < end
                for other_offset, other_end in seen_ranges
            ):
                _fail(f"fat static archive slices overlap: {label}")
            seen_ranges.append((offset, end))
            _validate_ar_archive(
                data[offset:end],
                label=f"{label}:slice[{index}]",
                forbidden_build_prefixes=forbidden_build_prefixes,
            )
        cursor = header_size
        for offset, end in sorted(seen_ranges):
            _validate_build_path_hygiene(
                data[cursor:offset],
                label=f"{label}:fat-padding",
                forbidden_build_prefixes=forbidden_build_prefixes,
            )
            cursor = end
        _validate_build_path_hygiene(
            data[cursor:],
            label=f"{label}:fat-trailing",
            forbidden_build_prefixes=forbidden_build_prefixes,
        )


def _validate_zip_container_structure(
    data: bytes, infos: list[zipfile.ZipInfo]
) -> list[bytes]:
    """Bind every central-directory entry to one contiguous local record."""

    eocd_offset = len(data) - ZIP_END_OF_CENTRAL_DIRECTORY.size
    if eocd_offset < 0:
        _fail("XCFramework ZIP end-of-central-directory record is missing")
    (
        signature,
        disk_number,
        central_disk,
        disk_entry_count,
        total_entry_count,
        central_size,
        central_offset,
        comment_length,
    ) = ZIP_END_OF_CENTRAL_DIRECTORY.unpack_from(data, eocd_offset)
    if signature != ZIP_END_OF_CENTRAL_DIRECTORY_SIGNATURE:
        _fail("XCFramework ZIP has prefixed, trailing, or missing container data")
    if (
        disk_number != 0
        or central_disk != 0
        or disk_entry_count != total_entry_count
        or total_entry_count != len(infos)
        or total_entry_count == 0xFFFF
        or central_size == 0xFFFFFFFF
        or central_offset == 0xFFFFFFFF
        or comment_length != 0
    ):
        _fail("XCFramework ZIP must be one non-ZIP64 disk with exact entry counts")
    if central_offset + central_size != eocd_offset:
        _fail("XCFramework ZIP central directory has a gap or invalid bounds")

    central_cursor = central_offset
    local_records: list[
        tuple[int, int, zipfile.ZipInfo, tuple[int, ...], bytes]
    ] = []
    for index, info in enumerate(infos):
        header_end = central_cursor + ZIP_CENTRAL_DIRECTORY_HEADER.size
        if header_end > eocd_offset:
            _fail("XCFramework ZIP central directory header is truncated")
        fields = ZIP_CENTRAL_DIRECTORY_HEADER.unpack_from(data, central_cursor)
        (
            central_signature,
            version_made_by,
            version_needed,
            flags,
            compression,
            modified_time,
            modified_date,
            crc32,
            compressed_size,
            uncompressed_size,
            name_length,
            extra_length,
            entry_comment_length,
            disk_start,
            internal_attributes,
            external_attributes,
            local_offset,
        ) = fields
        variable_end = (
            header_end + name_length + extra_length + entry_comment_length
        )
        if (
            central_signature != ZIP_CENTRAL_DIRECTORY_SIGNATURE
            or variable_end > eocd_offset
        ):
            _fail("XCFramework ZIP central directory record is invalid")
        raw_name = data[header_end : header_end + name_length]
        try:
            decoded_name = raw_name.decode("ascii")
        except UnicodeDecodeError as exc:
            raise AppleDistributionError(
                "XCFramework ZIP entry names must be canonical ASCII"
            ) from exc
        if (
            decoded_name != info.filename
            or info.orig_filename != info.filename
            or version_made_by >> 8 != info.create_system
            or flags != info.flag_bits
            or compression != info.compress_type
            or crc32 != info.CRC
            or compressed_size != info.compress_size
            or uncompressed_size != info.file_size
            or extra_length != 0
            or entry_comment_length != 0
            or disk_start != 0
            or internal_attributes != info.internal_attr
            or external_attributes != info.external_attr
            or local_offset != info.header_offset
            or compressed_size == 0xFFFFFFFF
            or uncompressed_size == 0xFFFFFFFF
            or local_offset == 0xFFFFFFFF
        ):
            _fail(
                "XCFramework ZIP central directory metadata differs from its "
                f"canonical entry: index={index}"
            )
        local_records.append(
            (
                local_offset,
                index,
                info,
                (
                    version_needed,
                    flags,
                    compression,
                    modified_time,
                    modified_date,
                    crc32,
                    compressed_size,
                    uncompressed_size,
                ),
                raw_name,
            )
        )
        central_cursor = variable_end
    if central_cursor != eocd_offset:
        _fail("XCFramework ZIP central directory length is noncanonical")

    local_cursor = 0
    decoded_entries = [b""] * len(infos)
    for local_offset, index, info, expected_fields, expected_name in sorted(
        local_records, key=lambda record: record[0]
    ):
        if local_offset != local_cursor:
            _fail("XCFramework ZIP local records contain prefixed data or a gap")
        header_end = local_offset + ZIP_LOCAL_FILE_HEADER.size
        if header_end > central_offset:
            _fail("XCFramework ZIP local file header is truncated")
        (
            local_signature,
            version_needed,
            flags,
            compression,
            modified_time,
            modified_date,
            crc32,
            compressed_size,
            uncompressed_size,
            name_length,
            extra_length,
        ) = ZIP_LOCAL_FILE_HEADER.unpack_from(data, local_offset)
        name_end = header_end + name_length
        payload_start = name_end + extra_length
        payload_end = payload_start + compressed_size
        if (
            local_signature != ZIP_LOCAL_FILE_SIGNATURE
            or payload_end > central_offset
            or data[header_end:name_end] != expected_name
            or name_length != len(expected_name)
            or extra_length != 0
            or (
                version_needed,
                flags,
                compression,
                modified_time,
                modified_date,
                crc32,
                compressed_size,
                uncompressed_size,
            )
            != expected_fields
            or flags != 0
            or info.header_offset != local_offset
        ):
            _fail(
                "XCFramework ZIP local header differs from its central directory "
                f"entry: {info.filename}"
            )
        compressed_payload = data[payload_start:payload_end]
        if compression == zipfile.ZIP_STORED:
            if compressed_size != uncompressed_size:
                _fail(
                    "stored XCFramework ZIP entry has different compressed and "
                    f"uncompressed sizes: {info.filename}"
                )
            decoded = compressed_payload
        elif compression == zipfile.ZIP_DEFLATED:
            if uncompressed_size > MAX_ARCHIVE_ENTRY_BYTES:
                _fail(f"XCFramework ZIP entry exceeds size limit: {info.filename}")
            decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
            try:
                decoded = decompressor.decompress(
                    compressed_payload, uncompressed_size + 1
                )
            except zlib.error as exc:
                raise AppleDistributionError(
                    f"XCFramework ZIP deflate stream is invalid: {info.filename}"
                ) from exc
            if (
                not decompressor.eof
                or decompressor.unused_data
                or decompressor.unconsumed_tail
            ):
                _fail(
                    "XCFramework ZIP deflate stream has trailing or unconsumed "
                    f"data: {info.filename}"
                )
            decoded += decompressor.flush()
        else:
            _fail(f"unsupported XCFramework ZIP compression method: {info.filename}")
        if (
            len(decoded) != uncompressed_size
            or zlib.crc32(decoded) & 0xFFFFFFFF != crc32
        ):
            _fail(
                f"XCFramework ZIP decompressed size or CRC differs: {info.filename}"
            )
        decoded_entries[index] = decoded
        local_cursor = payload_end
    if local_cursor != central_offset:
        _fail("XCFramework ZIP local records do not end at the central directory")
    return decoded_entries


def _validate_xcframework_zip_bytes(
    data: bytes,
    *,
    require_signature: bool,
    forbidden_build_prefixes: tuple[str, ...] = (),
) -> None:
    if not data:
        _fail("XCFramework ZIP is empty")
    expected = _expected_archive_entries(require_signature)
    seen: set[str] = set()
    total_uncompressed = 0
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            if archive.comment:
                _fail("XCFramework ZIP comment is forbidden")
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if len(names) != len(set(names)):
                _fail("duplicate XCFramework ZIP entry")
            if len(infos) != len(expected):
                _fail(
                    "XCFramework ZIP entry count differs from the exact static-only "
                    "layout"
                )
            if any(info.file_size > MAX_ARCHIVE_ENTRY_BYTES for info in infos) or sum(
                info.file_size for info in infos
            ) > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                _fail("XCFramework ZIP uncompressed size exceeds release limits")
            decoded_entries = _validate_zip_container_structure(data, infos)
            entry_payloads: dict[str, bytes] = {}
            for info, entry_data in zip(infos, decoded_entries, strict=True):
                name = info.filename
                if name in seen:
                    _fail(f"duplicate XCFramework ZIP entry: {name}")
                seen.add(name)
                entry_payloads[name] = entry_data
                pure = pathlib.PurePosixPath(name)
                if (
                    not name
                    or name.startswith("/")
                    or "\\" in name
                    or ".." in pure.parts
                    or not pure.parts
                    or pure.parts[0] != "CQPeriapt.xcframework"
                ):
                    _fail(f"unsafe or unexpected XCFramework ZIP entry: {name}")
                if info.comment or info.extra or info.flag_bits != 0:
                    _fail(
                        "commented, extended, encrypted, or flagged XCFramework ZIP "
                        f"entry is forbidden: {name}"
                    )
                if info.create_system != 3:
                    _fail(f"XCFramework ZIP entry is not Unix-origin metadata: {name}")
                if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                    _fail(f"unsupported XCFramework ZIP compression method: {name}")
                mode = (info.external_attr >> 16) & 0o177777
                kind = stat.S_IFMT(mode)
                if name.endswith("/"):
                    if (
                        kind != stat.S_IFDIR
                        or stat.S_IMODE(mode) != 0o755
                        or info.file_size != 0
                    ):
                        _fail(f"XCFramework ZIP directory entry has invalid type or size: {name}")
                else:
                    if kind != stat.S_IFREG:
                        _fail(f"unsupported XCFramework ZIP entry type: {name}")
                    if stat.S_IMODE(mode) != 0o644:
                        _fail(f"XCFramework ZIP regular file mode is not exactly 0644: {name}")
                    if info.file_size > MAX_ARCHIVE_ENTRY_BYTES:
                        _fail(f"XCFramework ZIP entry exceeds size limit: {name}")
                    if info.file_size and info.file_size > max(info.compress_size, 1) * MAX_COMPRESSION_RATIO:
                        _fail(f"XCFramework ZIP entry has an unsafe compression ratio: {name}")
                    total_uncompressed += info.file_size
                    if total_uncompressed > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                        _fail("XCFramework ZIP exceeds the total uncompressed size limit")
            if seen != expected:
                _fail(
                    "XCFramework ZIP entries differ from the exact static-only layout: "
                    f"missing={sorted(expected - seen)} unknown={sorted(seen - expected)}"
                )
            library_names = {
                f"CQPeriapt.xcframework/{relative}"
                for relative in EXPECTED_XCFRAMEWORK_LIBRARIES
            }
            for name in sorted(seen):
                if name.endswith("/"):
                    continue
                entry_data = entry_payloads[name]
                if name in library_names:
                    _validate_static_archive(
                        entry_data,
                        label=name,
                        forbidden_build_prefixes=forbidden_build_prefixes,
                    )
                else:
                    _validate_build_path_hygiene(
                        entry_data,
                        label=name,
                        forbidden_build_prefixes=forbidden_build_prefixes,
                    )
            bad_crc = archive.testzip()
            if bad_crc is not None:
                _fail(f"XCFramework ZIP CRC check failed: {bad_crc}")
    except zipfile.BadZipFile as exc:
        raise AppleDistributionError("invalid XCFramework ZIP") from exc


def validate_xcframework_zip(
    path: pathlib.Path,
    *,
    require_signature: bool,
    forbidden_build_prefixes: tuple[str, ...] = (),
) -> None:
    """Validate one immutable snapshot before any extractor sees the archive."""

    snapshot = read_regular_snapshot(
        path, maximum=MAX_ARTIFACT_BYTES, label="XCFramework ZIP"
    )
    _validate_xcframework_zip_bytes(
        snapshot.data,
        require_signature=require_signature,
        forbidden_build_prefixes=forbidden_build_prefixes,
    )


def _local_xcframework_files(xcframework: pathlib.Path) -> frozenset[str]:
    try:
        root_state = os.lstat(xcframework)
    except OSError as exc:
        raise AppleDistributionError(f"cannot inspect XCFramework path: {xcframework}: {exc}") from exc
    if (
        xcframework.name != "CQPeriapt.xcframework"
        or not stat.S_ISDIR(root_state.st_mode)
        or stat.S_IMODE(root_state.st_mode) != 0o755
    ):
        _fail(f"unexpected XCFramework path: {xcframework}")
    files: set[str] = set()
    directories: set[str] = {"CQPeriapt.xcframework/"}
    for root, dir_names, file_names in os.walk(xcframework, followlinks=False):
        root_path = pathlib.Path(root)
        for name in dir_names:
            child = root_path / name
            state = os.lstat(child)
            if (
                not stat.S_ISDIR(state.st_mode)
                or stat.S_IMODE(state.st_mode) != 0o755
            ):
                _fail(f"XCFramework directory mode/type is not exactly 0755: {child}")
            directories.add(
                "CQPeriapt.xcframework/"
                + child.relative_to(xcframework).as_posix()
                + "/"
            )
        for name in file_names:
            child = root_path / name
            state = os.lstat(child)
            if (
                not stat.S_ISREG(state.st_mode)
                or stat.S_IMODE(state.st_mode) != 0o644
            ):
                _fail(f"XCFramework regular file mode/type is not exactly 0644: {child}")
            files.add(
                "CQPeriapt.xcframework/"
                + child.relative_to(xcframework).as_posix()
            )
    actual = frozenset(files | directories)
    expected = _expected_archive_entries(True)
    if actual != expected:
        _fail(
            "signed XCFramework entries differ from the exact static-only layout: "
            f"missing={sorted(expected - actual)} unknown={sorted(actual - expected)}"
        )
    return actual


def build_signing_evidence(
    *,
    xcframework: pathlib.Path,
    codesign_display: pathlib.Path,
    certificate: pathlib.Path,
    expected_team_id: str,
    expected_identity_sha1: str,
    expected_certificate_sha256: str,
) -> dict[str, Any]:
    if not HEX_40.fullmatch(expected_identity_sha1):
        _fail("expected identity SHA-1 must contain 40 hex digits")
    expected_certificate_sha256 = _require_sha256(
        expected_certificate_sha256, "expected certificate SHA-256"
    )
    display_snapshot = read_regular_snapshot(
        codesign_display, maximum=MAX_TEXT_BYTES, label="codesign display"
    )
    try:
        display_text = display_snapshot.data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AppleDistributionError("codesign display is not UTF-8") from exc
    signature = parse_codesign_display(display_text, expected_team_id=expected_team_id)
    certificate_snapshot = read_regular_snapshot(
        certificate, maximum=MAX_CERTIFICATE_BYTES, label="leaf signing certificate"
    )
    certificate_sha1 = hashlib.sha1(
        certificate_snapshot.data, usedforsecurity=False
    ).hexdigest()
    if certificate_sha1 != expected_identity_sha1.lower():
        _fail("embedded leaf certificate SHA-1 does not match the pinned signing identity")
    if certificate_snapshot.sha256 != expected_certificate_sha256:
        _fail("embedded leaf certificate SHA-256 does not match the pinned certificate")
    certificate_metadata = _openssl_certificate_metadata(certificate_snapshot.data)

    xcframework = pathlib.Path(xcframework)
    _local_xcframework_files(xcframework)
    libraries: dict[str, str] = {}
    for relative in sorted(EXPECTED_XCFRAMEWORK_LIBRARIES):
        library = xcframework / relative
        snapshot = read_regular_snapshot(
            library,
            maximum=MAX_ARCHIVE_ENTRY_BYTES,
            label=f"XCFramework slice {relative}",
        )
        if not snapshot.data:
            _fail(f"XCFramework static slice is empty: {relative}")
        _validate_static_archive(snapshot.data, label=relative)
        libraries[relative] = snapshot.sha256
    code_resources = xcframework / "_CodeSignature" / "CodeResources"
    _, code_resources_sha256 = _stream_sha256_regular_file(
        code_resources, maximum=MAX_TEXT_BYTES, label="XCFramework CodeResources"
    )
    return {
        "schema_version": 1,
        "kind": "qperiapt.apple_xcframework_signature",
        "signature": signature,
        "certificate": {
            "sha1": certificate_sha1,
            "sha256": certificate_snapshot.sha256,
            **certificate_metadata,
        },
        "sealed_resources": {
            "code_resources_sha256": code_resources_sha256,
            "static_libraries": libraries,
        },
    }


def _validate_signing_evidence(evidence: dict[str, Any]) -> None:
    _require_exact_keys(
        evidence,
        {"schema_version", "kind", "signature", "certificate", "sealed_resources"},
        "signing evidence",
    )
    if evidence["schema_version"] != 1 or evidence["kind"] != "qperiapt.apple_xcframework_signature":
        _fail("signing evidence has the wrong schema or kind")
    signature = evidence["signature"]
    certificate = evidence["certificate"]
    sealed = evidence["sealed_resources"]
    if not isinstance(signature, dict) or not isinstance(certificate, dict) or not isinstance(sealed, dict):
        _fail("signing evidence objects are malformed")
    _require_exact_keys(
        signature,
        {
            "identity_class",
            "authority",
            "authority_chain",
            "team_id",
            "identifier",
            "format",
            "secure_timestamp",
            "cdhash",
            "hardened_runtime",
            "code_directory_flags",
            "strict_verification",
        },
        "signature evidence",
    )
    if signature["identity_class"] != EXPECTED_IDENTITY_CLASS:
        _fail("signature identity class is not Developer ID Application")
    if not TEAM_ID.fullmatch(_require_string(signature["team_id"], "signature Team ID")):
        _fail("signature Team ID is invalid")
    if not HEX_40.fullmatch(_require_string(signature["cdhash"], "signature CDHash")):
        _fail("signature CDHash is invalid")
    if signature["hardened_runtime"] is not False or signature["code_directory_flags"] != "none" or signature["strict_verification"] is not True:
        _fail("static XCFramework signature flags are not the exact verified form")
    _require_exact_keys(
        certificate,
        {"sha1", "sha256", "subject", "issuer", "serial", "notBefore", "notAfter"},
        "certificate evidence",
    )
    _require_sha256(certificate["sha256"], "certificate SHA-256")
    _require_exact_keys(
        sealed, {"code_resources_sha256", "static_libraries"}, "sealed resources"
    )
    _require_sha256(sealed["code_resources_sha256"], "CodeResources SHA-256")
    libraries = sealed["static_libraries"]
    if not isinstance(libraries, dict) or frozenset(libraries) != EXPECTED_XCFRAMEWORK_LIBRARIES:
        _fail("signing evidence has the wrong static library set")
    for relative, digest in libraries.items():
        _require_sha256(digest, f"sealed static library SHA-256 for {relative}")


def _zip_static_library_hashes(data: bytes) -> dict[str, str]:
    hashes: dict[str, str] = {}
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for relative in sorted(EXPECTED_XCFRAMEWORK_LIBRARIES):
            data = archive.read(f"CQPeriapt.xcframework/{relative}")
            hashes[relative] = hashlib.sha256(data).hexdigest()
    return hashes


def build_static_xcframework_distribution_evidence(
    *,
    artifact: pathlib.Path,
    source_commit: str,
    swiftpm_checksum: str,
    signing_evidence: dict[str, Any],
    forbidden_build_prefixes: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Bind one final signed ZIP to its honest static-SDK distribution claims."""

    source_commit = _require_git_commit(source_commit, "Apple release source commit")
    swiftpm_checksum = _require_sha256(swiftpm_checksum, "SwiftPM checksum")
    artifact_snapshot = read_regular_snapshot(
        artifact, maximum=MAX_ARTIFACT_BYTES, label="signed XCFramework ZIP"
    )
    _validate_xcframework_zip_bytes(
        artifact_snapshot.data,
        require_signature=True,
        forbidden_build_prefixes=forbidden_build_prefixes,
    )
    _validate_signing_evidence(signing_evidence)
    artifact_size = len(artifact_snapshot.data)
    artifact_sha256 = artifact_snapshot.sha256
    if swiftpm_checksum != artifact_sha256:
        _fail("SwiftPM checksum does not match the signed XCFramework ZIP SHA-256")
    zip_libraries = _zip_static_library_hashes(artifact_snapshot.data)
    sealed_libraries = signing_evidence["sealed_resources"]["static_libraries"]
    if zip_libraries != sealed_libraries:
        _fail("signed ZIP static library hashes differ from signing evidence")
    return {
        "schema_version": 2,
        "kind": "qperiapt.apple_static_xcframework_distribution",
        "source_commit": source_commit,
        "artifact": {
            "path": pathlib.Path(artifact).name,
            "size": artifact_size,
            "sha256": artifact_sha256,
            "swiftpm_checksum": swiftpm_checksum,
        },
        "format": {
            "container": "xcframework",
            "distribution": "swiftpm_remote_binary_target",
            "linkage": "static",
            "archive_entry_count": len(_expected_archive_entries(True)),
            "static_archive_count": len(EXPECTED_XCFRAMEWORK_LIBRARIES),
            "standalone_executable_count": 0,
        },
        "path_hygiene": {
            "policy": BUILD_PATH_HYGIENE_POLICY,
            "artifact_scan": {
                "scope": "all_decompressed_regular_zip_entries",
                "forbidden_match_count": 0,
            },
            "synthetic_build_path_prefix": SYNTHETIC_BUILD_PATH_PREFIX,
            "allowed_upstream_toolchain_path_rules": [
                "rust_distributed_compiler_builtins_members_v1"
            ],
        },
        "origin_signature": signing_evidence,
        "notarization": {
            "applicability": "not_applicable_static_sdk_payload",
            "submission_performed": False,
            "ticket_expected": False,
            "ticket_generated": False,
            "notarized": False,
            "stapled": False,
            "reason_code": "static_xcframework_contains_no_standalone_executable_or_notarizable_bundle",
        },
        "consumer_responsibilities": {
            "macos_final_product": ["sign", "notarize"],
            "ios_final_product": ["sign", "provision"],
        },
    }


def _command_validate_zip(args: argparse.Namespace) -> None:
    validate_xcframework_zip(
        args.artifact,
        require_signature=args.require_signature,
        forbidden_build_prefixes=tuple(args.forbidden_build_prefix),
    )
    print("SWIFT_XCFRAMEWORK_STATIC_ZIP_PASS")


def _command_validate_static_archive(args: argparse.Namespace) -> None:
    snapshot = read_regular_snapshot(
        args.artifact,
        maximum=MAX_ARCHIVE_ENTRY_BYTES,
        label="Apple static archive",
    )
    _validate_static_archive(
        snapshot.data,
        label=args.artifact.name,
        forbidden_build_prefixes=tuple(args.forbidden_build_prefix),
    )
    print("APPLE_STATIC_ARCHIVE_PATH_HYGIENE_PASS")


def _command_signing_evidence(args: argparse.Namespace) -> None:
    evidence = build_signing_evidence(
        xcframework=args.xcframework,
        codesign_display=args.codesign_display,
        certificate=args.certificate,
        expected_team_id=args.expected_team_id,
        expected_identity_sha1=args.expected_identity_sha1,
        expected_certificate_sha256=args.expected_certificate_sha256,
    )
    _write_new_json(args.output, evidence)


def _command_distribution_evidence(args: argparse.Namespace) -> None:
    snapshot = load_json_object_snapshot(
        args.signing_evidence,
        maximum=MAX_TEXT_BYTES,
        label="Apple signing evidence",
    )
    evidence = build_static_xcframework_distribution_evidence(
        artifact=args.artifact,
        source_commit=args.source_commit,
        swiftpm_checksum=args.swiftpm_checksum,
        signing_evidence=snapshot.value,
        forbidden_build_prefixes=tuple(args.forbidden_build_prefix),
    )
    _write_new_json(args.output, evidence)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate-zip")
    validate.add_argument("--artifact", type=pathlib.Path, required=True)
    validate.add_argument("--require-signature", action="store_true")
    validate.add_argument("--forbidden-build-prefix", action="append", default=[])
    validate.set_defaults(handler=_command_validate_zip)

    static_archive = subparsers.add_parser("validate-static-archive")
    static_archive.add_argument("--artifact", type=pathlib.Path, required=True)
    static_archive.add_argument(
        "--forbidden-build-prefix", action="append", default=[]
    )
    static_archive.set_defaults(handler=_command_validate_static_archive)

    signing = subparsers.add_parser("signing-evidence")
    signing.add_argument("--xcframework", type=pathlib.Path, required=True)
    signing.add_argument("--codesign-display", type=pathlib.Path, required=True)
    signing.add_argument("--certificate", type=pathlib.Path, required=True)
    signing.add_argument("--expected-team-id", required=True)
    signing.add_argument("--expected-identity-sha1", required=True)
    signing.add_argument("--expected-certificate-sha256", required=True)
    signing.add_argument("--output", type=pathlib.Path, required=True)
    signing.set_defaults(handler=_command_signing_evidence)

    distribution = subparsers.add_parser("apple-distribution-evidence")
    distribution.add_argument("--artifact", type=pathlib.Path, required=True)
    distribution.add_argument("--source-commit", required=True)
    distribution.add_argument("--swiftpm-checksum", required=True)
    distribution.add_argument("--signing-evidence", type=pathlib.Path, required=True)
    distribution.add_argument(
        "--forbidden-build-prefix", action="append", default=[]
    )
    distribution.add_argument("--output", type=pathlib.Path, required=True)
    distribution.set_defaults(handler=_command_distribution_evidence)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        args.handler(args)
    except (AppleDistributionError, EvidenceIOError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
