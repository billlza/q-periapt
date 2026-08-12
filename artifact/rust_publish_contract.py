#!/usr/bin/env python3

"""Fail-closed checks for the packaged Rust/C build surface."""

from __future__ import annotations

import hashlib
import os
import pathlib
import re
import secrets
import stat
from collections.abc import Iterable


class RustPublishContractError(RuntimeError):
    """The packaged Rust/C build surface violates the package contract."""


_OWNED_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_OWNED_TEMP_PREFIX = re.compile(r"qperiapt-package-(?:verification|inspection)\.$")
_OWNED_TEMP_NAME = re.compile(
    r"qperiapt-package-(?:verification|inspection)\.[0-9a-f]{24}$"
)


def _require_owned_directory_apis() -> None:
    if (
        os.open not in os.supports_dir_fd
        or os.mkdir not in os.supports_dir_fd
        or os.stat not in os.supports_dir_fd
        or os.unlink not in os.supports_dir_fd
        or os.rmdir not in os.supports_dir_fd
        or not hasattr(os, "O_DIRECTORY")
        or not hasattr(os, "O_NOFOLLOW")
    ):
        raise RustPublishContractError(
            "owned package directories require POSIX openat no-follow APIs"
        )


def _temporary_parent() -> pathlib.Path:
    try:
        parent = pathlib.Path("/tmp").resolve(strict=True)
        metadata = parent.lstat()
    except OSError as exc:
        raise RustPublishContractError(
            f"cannot resolve the package temporary parent: {exc}"
        ) from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise RustPublishContractError(
            f"package temporary parent must resolve to a real directory: {parent}"
        )
    return parent


def _directory_identity(metadata: os.stat_result, label: pathlib.Path) -> tuple[int, int]:
    if not stat.S_ISDIR(metadata.st_mode):
        raise RustPublishContractError(f"owned package path is not a directory: {label}")
    return metadata.st_dev, metadata.st_ino


def _validate_owned_root_metadata(
    metadata: os.stat_result,
    path: pathlib.Path,
) -> tuple[int, int]:
    identity = _directory_identity(metadata, path)
    if metadata.st_uid != os.getuid():
        raise RustPublishContractError(
            f"owned package directory has the wrong owner: {path}"
        )
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise RustPublishContractError(
            f"owned package directory must have mode 0700: {path}"
        )
    return identity


def create_owned_package_directory(prefix: str) -> tuple[pathlib.Path, int, int]:
    """Create a private package target relative to an anchored temporary parent."""

    _require_owned_directory_apis()
    if _OWNED_TEMP_PREFIX.fullmatch(prefix) is None:
        raise RustPublishContractError("owned package directory prefix is malformed")
    parent = _temporary_parent()
    try:
        parent_fd = os.open(parent, _OWNED_DIRECTORY_FLAGS)
    except OSError as exc:
        raise RustPublishContractError(
            f"cannot open the package temporary parent: {parent}: {exc}"
        ) from exc
    try:
        for _ in range(128):
            name = prefix + secrets.token_hex(12)
            try:
                os.mkdir(name, mode=0o700, dir_fd=parent_fd)
            except FileExistsError:
                continue
            path = parent / name
            try:
                directory_fd = os.open(name, _OWNED_DIRECTORY_FLAGS, dir_fd=parent_fd)
            except OSError as exc:
                raise RustPublishContractError(
                    f"cannot anchor the new package directory: {path}: {exc}"
                ) from exc
            try:
                descriptor_identity = _validate_owned_root_metadata(
                    os.fstat(directory_fd), path
                )
                named_identity = _validate_owned_root_metadata(
                    os.stat(name, dir_fd=parent_fd, follow_symlinks=False), path
                )
                if named_identity != descriptor_identity:
                    raise RustPublishContractError(
                        f"new package directory was replaced during creation: {path}"
                    )
                return path, descriptor_identity[0], descriptor_identity[1]
            finally:
                os.close(directory_fd)
        raise RustPublishContractError(
            "cannot allocate a unique owned package directory after 128 attempts"
        )
    finally:
        os.close(parent_fd)


def _clear_owned_package_directory(directory_fd: int, path: pathlib.Path) -> None:
    try:
        with os.scandir(directory_fd) as entries:
            names = [entry.name for entry in entries]
    except OSError as exc:
        raise RustPublishContractError(
            f"cannot list owned package directory: {path}: {exc}"
        ) from exc

    for name in names:
        child_path = path / name
        try:
            observed = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as exc:
            raise RustPublishContractError(
                f"cannot inspect owned package entry: {child_path}: {exc}"
            ) from exc
        if not stat.S_ISDIR(observed.st_mode):
            try:
                os.unlink(name, dir_fd=directory_fd)
            except OSError as exc:
                raise RustPublishContractError(
                    f"cannot unlink owned package entry: {child_path}: {exc}"
                ) from exc
            continue

        observed_identity = _directory_identity(observed, child_path)
        try:
            child_fd = os.open(name, _OWNED_DIRECTORY_FLAGS, dir_fd=directory_fd)
        except OSError as exc:
            raise RustPublishContractError(
                f"cannot anchor owned package subdirectory: {child_path}: {exc}"
            ) from exc
        try:
            descriptor_identity = _directory_identity(os.fstat(child_fd), child_path)
            if descriptor_identity != observed_identity:
                raise RustPublishContractError(
                    f"owned package subdirectory was replaced before cleanup: {child_path}"
                )
            _clear_owned_package_directory(child_fd, child_path)
            try:
                final_identity = _directory_identity(
                    os.stat(name, dir_fd=directory_fd, follow_symlinks=False),
                    child_path,
                )
            except OSError as exc:
                raise RustPublishContractError(
                    f"cannot revalidate owned package subdirectory: {child_path}: {exc}"
                ) from exc
            if final_identity != descriptor_identity:
                raise RustPublishContractError(
                    f"owned package subdirectory was replaced during cleanup: {child_path}"
                )
            try:
                os.rmdir(name, dir_fd=directory_fd)
            except OSError as exc:
                raise RustPublishContractError(
                    f"cannot remove owned package subdirectory: {child_path}: {exc}"
                ) from exc
        finally:
            os.close(child_fd)


def remove_owned_package_directory(
    path: pathlib.Path,
    expected_device: int,
    expected_inode: int,
) -> None:
    """Remove only the identity captured for a package target, using anchored paths."""

    _require_owned_directory_apis()
    path = pathlib.Path(path)
    parent = _temporary_parent()
    if (
        not path.is_absolute()
        or path.parent != parent
        or _OWNED_TEMP_NAME.fullmatch(path.name) is None
        or expected_device < 0
        or expected_inode <= 0
    ):
        raise RustPublishContractError(
            f"owned package directory cleanup request is malformed: {path}"
        )
    expected_identity = expected_device, expected_inode
    try:
        parent_fd = os.open(parent, _OWNED_DIRECTORY_FLAGS)
    except OSError as exc:
        raise RustPublishContractError(
            f"cannot open the package temporary parent: {parent}: {exc}"
        ) from exc
    try:
        try:
            observed = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as exc:
            raise RustPublishContractError(
                f"cannot inspect owned package directory before cleanup: {path}: {exc}"
            ) from exc
        observed_identity = _validate_owned_root_metadata(observed, path)
        if observed_identity != expected_identity:
            raise RustPublishContractError(
                f"owned package directory identity changed before cleanup: {path}"
            )
        try:
            directory_fd = os.open(path.name, _OWNED_DIRECTORY_FLAGS, dir_fd=parent_fd)
        except OSError as exc:
            raise RustPublishContractError(
                f"cannot anchor owned package directory for cleanup: {path}: {exc}"
            ) from exc
        try:
            descriptor_identity = _validate_owned_root_metadata(
                os.fstat(directory_fd), path
            )
            if descriptor_identity != expected_identity:
                raise RustPublishContractError(
                    f"owned package directory was replaced before cleanup: {path}"
                )
            _clear_owned_package_directory(directory_fd, path)
            final_identity = _validate_owned_root_metadata(
                os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False), path
            )
            if final_identity != descriptor_identity:
                raise RustPublishContractError(
                    f"owned package directory was replaced during cleanup: {path}"
                )
            try:
                os.rmdir(path.name, dir_fd=parent_fd)
            except OSError as exc:
                raise RustPublishContractError(
                    f"cannot remove owned package directory: {path}: {exc}"
                ) from exc
        finally:
            os.close(directory_fd)
    finally:
        os.close(parent_fd)


def validate_cargo_output(label: str, streams: Iterable[str]) -> None:
    """Reject every Cargo warning without hiding any other diagnostic."""

    if not label or any(character in label for character in "\r\n"):
        raise RustPublishContractError("Cargo command label is malformed")
    for stream in streams:
        for line in stream.splitlines():
            if "warning:" in line.casefold():
                raise RustPublishContractError(
                    f"{label} emitted a warning: {line}"
                )


def validate_cargo_package_completion(
    crate: str,
    streams: Iterable[str],
) -> None:
    """Require Cargo's complete package and rebuilt-archive verification phases."""

    if re.fullmatch(r"[a-z0-9][a-z0-9-]*", crate) is None:
        raise RustPublishContractError("Cargo package name is malformed")
    output = "\n".join(streams)
    required = (
        f"Packaging {crate} ",
        "Packaged ",
        f"Verifying {crate} ",
        "Finished `dev` profile",
    )
    missing = [marker for marker in required if marker not in output]
    if missing:
        raise RustPublishContractError(
            f"Cargo package verification log for {crate} is incomplete: {missing}"
        )


_ALLOWED_BUILD_MODULE = '#[path = "src/build_support.rs"]\nmod build_support;'
_EXPECTED_BUILD_SURFACE_SHA256 = {
    "build.rs": "762ca28ec0f738e5165c2f2b8c9efa20bc1870ca997bcbedeffee19847e3928a",
    "src/build_support.rs": "aede04be9ca74fc58b4c0e2cf26503fde702598075c55b95f0d8c50369c70d63",
    "src/mlkem_bridge.c": "a05b807108685a33ac03b42cad4eb5c9b9c26c850030aa3d2de503e7f97fb93e",
    "src/mlkem_bridge.h": "b8c286379f0f6444c91b3ae66b9aa3dcc412b62a727cd480c610b7e8d19722a2",
    "src/mlkem_config.h": "a6a1eb47cd506dc8db14e08c7dbe1a245386db252cab3ca3821565b83eef27e4",
}
_EXPECTED_LOCAL_SOURCE_FILES = frozenset(
    {
        "src/build_support.rs",
        "src/build_support_tests.rs",
        "src/lib.rs",
        "src/mlkem_bridge.c",
        "src/mlkem_bridge.h",
        "src/mlkem_config.h",
        "src/raw.rs",
        "src/tests.rs",
    }
)
_CONFIG_SELECTION = re.compile(
    r'\.define\(\s*"MLK_CONFIG_FILE"\s*,\s*'
    r'Some\(\s*"\\"mlkem_config\.h\\""\s*\)\s*\)'
)
_INCLUDE_SOURCE_TOKEN = re.compile(r"(?<!\.)\binclude(?:_bytes|_str)?\b")
_C_INCLUDE_DIRECTIVE = re.compile(
    r"(?m)^[ \t]*(?:#|%:|\?\?=)[ \t]*(?:include|include_next|import)\b[^\r\n]*$"
)
_C_LITERAL_INCLUDE = re.compile(
    r'(?m)^[ \t]*#[ \t]*include[ \t]*(?P<target>"[^"\r\n]+"|<[^>\r\n]+>)[ \t]*$'
)
_EXPECTED_C_INCLUDES = {
    "src/mlkem_bridge.c": (
        '"mlkem_bridge.h"',
        '"mlkem_native.c"',
        '"mlkem_native.c"',
        '"mlkem_native.c"',
    ),
    "src/mlkem_bridge.h": ("<stdint.h>", '"mlkem_native.h"'),
    "src/mlkem_config.h": (
        "<stddef.h>",
        "<stdint.h>",
        '"src/sys.h"',
        "<stddef.h>",
        "<stdint.h>",
        '"src/sys.h"',
    ),
}
_PORTABLE_CONFIG_PREFIX = (
    "/* SPDX-License-Identifier: Apache-2.0 OR MIT */\n"
    "#if defined(MLK_CONFIG_USE_NATIVE_BACKEND_ARITH) || \\\n"
    "    defined(MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202) || \\\n"
    "    defined(MLK_CONFIG_ARITH_BACKEND_FILE) || \\\n"
    "    defined(MLK_CONFIG_FIPS202_BACKEND_FILE) || \\\n"
    "    defined(MLK_CONFIG_FIPS202_CUSTOM_HEADER) || \\\n"
    "    defined(MLK_CONFIG_FIPS202X4_CUSTOM_HEADER)\n"
    "#error External or native mlkem-native backends are not supported by this portable-only crate\n"
    "#endif\n\n"
    "#ifndef QPN_MLKEM_CONFIG_H\n"
    "#define QPN_MLKEM_CONFIG_H\n"
)
_REQUIRED_GUARD_TOKENS = {
    "MLK_CONFIG_USE_NATIVE_BACKEND_ARITH",
    "MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202",
    "MLK_CONFIG_ARITH_BACKEND_FILE",
    "MLK_CONFIG_FIPS202_BACKEND_FILE",
    "MLK_CONFIG_FIPS202_CUSTOM_HEADER",
    "MLK_CONFIG_FIPS202X4_CUSTOM_HEADER",
}
_NATIVE_ENABLE_PATTERNS = {
    "C #define MLK_CONFIG_USE_NATIVE_BACKEND_*": re.compile(
        r"(?m)^\s*#\s*define\s+MLK_CONFIG_USE_NATIVE_BACKEND_(?:ARITH|FIPS202)(?:\s|$)"
    ),
    "cc::Build::define MLK_CONFIG_USE_NATIVE_BACKEND_*": re.compile(
        r'\.define\(\s*"MLK_CONFIG_USE_NATIVE_BACKEND_(?:ARITH|FIPS202)"'
    ),
    "C #define MLK_CONFIG_*_BACKEND_FILE": re.compile(
        r"(?m)^\s*#\s*define\s+MLK_CONFIG_(?:ARITH|FIPS202)_BACKEND_FILE(?:\s|$)"
    ),
    "cc::Build::define MLK_CONFIG_*_BACKEND_FILE": re.compile(
        r'\.define\(\s*"MLK_CONFIG_(?:ARITH|FIPS202)_BACKEND_FILE"'
    ),
    "assembly translation unit": re.compile(
        r'(?i)#\s*include\s*[<"][^>"]+\.S[>"]|'
        r"\.files?\([^\n)]*\.S|mlkem_native_asm\.S"
    ),
    "prebuilt object": re.compile(r"\.objects?\b"),
    "native assembly symbol": re.compile(r"(?i)\b[a-z_][a-z0-9_]*_asm\s*\("),
}


def validate_packaged_mlkem_native_local_sources(source_files: set[str]) -> None:
    """Reject local package files outside the reviewed sys-crate source set."""

    missing = sorted(_EXPECTED_LOCAL_SOURCE_FILES - source_files)
    extra = sorted(source_files - _EXPECTED_LOCAL_SOURCE_FILES)
    if missing or extra:
        raise RustPublishContractError(
            "sys crate packaged local source set differs from the audited allowlist: "
            f"missing={missing} extra={extra}"
        )


def _validate_c_include_graph(name: str, source: str) -> None:
    directives = _C_INCLUDE_DIRECTIVE.findall(source)
    literal_targets = tuple(
        match.group("target") for match in _C_LITERAL_INCLUDE.finditer(source)
    )
    expected_targets = _EXPECTED_C_INCLUDES[name]
    if len(directives) != len(literal_targets) or literal_targets != expected_targets:
        raise RustPublishContractError(
            "portable C include graph differs from the audited allowlist: "
            f"file={name} directives={len(directives)} "
            f"literal_targets={list(literal_targets)} "
            f"expected={list(expected_targets)}"
        )


def validate_mlkem_native_build_surface(
    *,
    build_rs: str,
    build_support: str,
    bridge_c: str,
    bridge_h: str,
    local_config: str,
) -> None:
    """Validate the complete packaged build-script and portable C surface.

    The semantic checks are intentionally lexical and conservative. The final
    whole-file digest allowlist closes equivalent Rust and C spellings without
    pretending that these checks are complete language parsers.
    """

    build_rust_surface = "\n".join((build_rs, build_support))
    build_surface = "\n".join(
        (build_rust_surface, bridge_c, bridge_h, local_config)
    )

    allowed_build_module_count = build_rs.count(_ALLOWED_BUILD_MODULE)
    remaining_build_rs = build_rs.replace(_ALLOWED_BUILD_MODULE, "", 1)
    unapproved_mod_sources = sorted(
        name
        for name, rust_source in (
            ("build.rs", remaining_build_rs),
            ("src/build_support.rs", build_support),
        )
        if re.search(r"\bmod\b", rust_source)
    )
    included_sources = sorted(
        name
        for name, rust_source in (
            ("build.rs", build_rs),
            ("src/build_support.rs", build_support),
        )
        if _INCLUDE_SOURCE_TOKEN.search(rust_source)
    )
    if (
        allowed_build_module_count != 1
        or unapproved_mod_sources
        or included_sources
    ):
        raise RustPublishContractError(
            "sys crate build-script module graph differs from the audited surface: "
            f"allowed_count={allowed_build_module_count} "
            f"unapproved_mod_sources={unapproved_mod_sources} "
            f"include_macros={included_sources}"
        )

    config_selections = _CONFIG_SELECTION.findall(build_rust_surface)
    if len(config_selections) != 1:
        raise RustPublishContractError(
            "portable build must select packaged mlkem_config.h exactly once: "
            f"matches={len(config_selections)}"
        )

    source_files = re.findall(r'\.file\(\s*"([^"]+)"', build_rust_surface)
    file_call_count = len(re.findall(r"\.file\b", build_rust_surface))
    files_call_count = len(re.findall(r"\.files\b", build_rust_surface))
    if (
        source_files != ["src/mlkem_bridge.c"]
        or file_call_count != 1
        or files_call_count != 0
    ):
        raise RustPublishContractError(
            "sys crate must compile exactly the single portable bridge translation unit: "
            f"literal_files={source_files} file_calls={file_call_count} "
            f"files_calls={files_call_count}"
        )

    define_names = re.findall(r'\.define\(\s*"([^"]+)"', build_rust_surface)
    define_call_count = len(re.findall(r"\.define\b", build_rust_surface))
    expected_define_names = ["MLK_CONFIG_FILE", "QPN_MLKEM_FREESTANDING"]
    try_compile_count = len(re.findall(r"\.try_compile\b", build_rust_surface))
    forbidden_build_tokens = sorted(
        token for token in _REQUIRED_GUARD_TOKENS if token in build_rust_surface
    )
    if (
        define_names != expected_define_names
        or define_call_count != len(expected_define_names)
        or try_compile_count != 1
        or forbidden_build_tokens
    ):
        raise RustPublishContractError(
            "sys crate build-script API surface differs from the portable allowlist: "
            f"defines={define_names} define_calls={define_call_count} "
            f"try_compile_calls={try_compile_count} "
            f"forbidden_tokens={forbidden_build_tokens}"
        )

    for name, source in (
        ("src/mlkem_bridge.c", bridge_c),
        ("src/mlkem_bridge.h", bridge_h),
        ("src/mlkem_config.h", local_config),
    ):
        _validate_c_include_graph(name, source)

    guard_token_counts = {
        token: local_config.count(token) for token in sorted(_REQUIRED_GUARD_TOKENS)
    }
    error_directive_count = len(
        re.findall(r"(?m)^[ \t]*#[ \t]*error\b", local_config)
    )
    if (
        not local_config.startswith(_PORTABLE_CONFIG_PREFIX)
        or any(count != 1 for count in guard_token_counts.values())
        or error_directive_count != 1
    ):
        raise RustPublishContractError(
            "portable config lacks the active fail-fast native-backend guard prefix: "
            f"token_counts={guard_token_counts} "
            f"error_directives={error_directive_count}"
        )

    enabled_native_shapes = sorted(
        label
        for label, pattern in _NATIVE_ENABLE_PATTERNS.items()
        if pattern.search(build_surface)
    )
    if enabled_native_shapes:
        raise RustPublishContractError(
            "sys crate release build is not portable-only: "
            f"{enabled_native_shapes}"
        )

    packaged_sources = {
        "build.rs": build_rs,
        "src/build_support.rs": build_support,
        "src/mlkem_bridge.c": bridge_c,
        "src/mlkem_bridge.h": bridge_h,
        "src/mlkem_config.h": local_config,
    }
    actual_digests = {
        name: hashlib.sha256(source.encode("utf-8")).hexdigest()
        for name, source in packaged_sources.items()
    }
    mismatches = {
        name: {
            "expected": _EXPECTED_BUILD_SURFACE_SHA256[name],
            "actual": actual_digests[name],
        }
        for name in packaged_sources
        if actual_digests[name] != _EXPECTED_BUILD_SURFACE_SHA256[name]
    }
    if mismatches:
        raise RustPublishContractError(
            "packaged build-surface bytes differ from the audited allowlist: "
            f"{mismatches}"
        )
