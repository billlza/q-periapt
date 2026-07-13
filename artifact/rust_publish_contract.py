#!/usr/bin/env python3

"""Fail-closed checks for the packaged Rust/C build surface."""

from __future__ import annotations

import hashlib
import re


class RustPublishContractError(RuntimeError):
    """The packaged Rust/C build surface violates the release contract."""


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
