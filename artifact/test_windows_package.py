from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time
import tomllib
import unittest
from unittest import mock

import third_party_licenses
import windows_package
from windows_package import WindowsPackageError


def _dumpbin_output(*dependencies: str) -> bytes:
    dependency_lines = b"".join(
        f"    {dependency}\r\n".encode("ascii") for dependency in dependencies
    )
    return (
        b"Microsoft (R) COFF/PE Dumper Version 14.44.35211.0\r\n"
        b"Copyright (C) Microsoft Corporation.  All rights reserved.\r\n"
        b"\r\n"
        b"Dump of file q_periapt_ffi_abi2.dll\r\n"
        b"\r\n"
        b"File Type: DLL\r\n"
        b"\r\n"
        b"  Image has the following dependencies:\r\n"
        b"\r\n"
        + dependency_lines
        + b"\r\n"
        b"  Summary\r\n"
        b"\r\n"
        b"        1000 .data\r\n"
    )


def _native_static_libraries_output(
    *tokens: str, newline: bytes = b"\n"
) -> bytes:
    return newline.join(
        (
            b"note: link against the following native artifacts when linking against this static library.",
            b"",
            b"note: native-static-libs: "
            + " ".join(tokens).encode("ascii"),
            b"",
        )
    )


def _rustc_link_arguments_output(
    *,
    program: str = r"C:\Program Files\Microsoft Visual Studio\VC\Tools\MSVC\14.50.12345\bin\Hostx64\x64\link.exe",
    arguments: tuple[str, ...] = (
        "/NOLOGO",
        "/Brepro",
        "/WX",
        r"/OUT:C:\build\q_periapt_ffi_abi2.dll",
    ),
) -> bytes:
    prefix = (
        'env -u LIBRARY_PATH LC_ALL="C" '
        'PATH="C:\\\\Program Files\\\\Microsoft Visual Studio" '
        'VSLANG="1033" '
    )
    command = prefix + json.dumps(program)
    if arguments:
        command += " " + " ".join(json.dumps(value) for value in arguments)
    return (command + "\n").encode("utf-8")


def _windows_pe_fixture(*, hash_payload: bool = False) -> bytes:
    """Build an independent minimal x64 PE32+ DLL fixture for parser tests."""

    data = bytearray(0x400)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into(
        "<HHIIIHH",
        data,
        0x84,
        0x8664,
        1,
        0x11223344,
        0,
        0,
        0xF0,
        0x2022,
    )
    struct.pack_into("<H", data, 0x98, 0x20B)
    struct.pack_into("<I", data, 0x98 + 32, 0x1000)
    struct.pack_into("<I", data, 0x98 + 36, 0x200)
    struct.pack_into("<I", data, 0x98 + 56, 0x2000)
    struct.pack_into("<I", data, 0x98 + 60, 0x200)
    struct.pack_into("<H", data, 0x98 + 68, 3)
    struct.pack_into("<H", data, 0x98 + 70, 0x0160)
    struct.pack_into("<I", data, 0x98 + 108, 16)
    struct.pack_into("<II", data, 0x98 + 152, 0x1080, 12)
    struct.pack_into("<II", data, 0x98 + 160, 0x1000, 28)
    struct.pack_into(
        "<8sIIIIIIHHI",
        data,
        0x188,
        b".rdata\0\0",
        0x200,
        0x1000,
        0x200,
        0x200,
        0,
        0,
        0,
        0,
        0x40000040,
    )
    struct.pack_into("<IIHH", data, 0x280, 0x1000, 12, 0xA100, 0)
    if hash_payload:
        struct.pack_into(
            "<IIHHIIII",
            data,
            0x200,
            0,
            0x55667788,
            0,
            0,
            16,
            36,
            0x1040,
            0x240,
        )
        struct.pack_into("<I", data, 0x240, 32)
        data[0x244:0x264] = bytes(range(32))
    else:
        struct.pack_into(
            "<IIHHIIII",
            data,
            0x200,
            0,
            0x55667788,
            0,
            0,
            16,
            0,
            0,
            0,
        )
    return bytes(data)


def _pack_pe(data: bytes, offset: int, format_: str, *values: int) -> bytes:
    changed = bytearray(data)
    struct.pack_into(format_, changed, offset, *values)
    return bytes(changed)


INHERITING_DESCENDANT_SCRIPT = """
import os
import pathlib
import sys
import time

os.write(1, b"descendant-stdout\\n")
os.write(2, b"descendant-stderr\\n")
marker = pathlib.Path(sys.argv[1])
temporary_marker = marker.with_name(f".{marker.name}.{os.getpid()}.tmp")
temporary_marker.write_text(str(os.getpid()), encoding="ascii")
os.replace(temporary_marker, marker)
time.sleep(30)
"""

INHERITING_PARENT_SCRIPT = """
import pathlib
import subprocess
import sys
import time

marker = pathlib.Path(sys.argv[1])
subprocess.Popen(
    [sys.executable, "-I", "-S", "-c", sys.argv[2], str(marker)],
    stdout=sys.stdout.buffer,
    stderr=sys.stderr.buffer,
)
deadline = time.monotonic() + 5
while not marker.is_file():
    if time.monotonic() >= deadline:
        raise SystemExit(3)
    time.sleep(0.01)
if sys.argv[3] == "hold":
    time.sleep(30)
elif sys.argv[3] != "exit":
    raise SystemExit(4)
"""


def _wait_for_process_exit(process_id: int, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while True:
        try:
            os.kill(process_id, 0)
        except ProcessLookupError:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.05)


def _kill_process_if_present(process_id: int) -> None:
    try:
        os.kill(process_id, signal.SIGKILL)
    except ProcessLookupError:
        pass


class WindowsPeEvidenceTests(unittest.TestCase):
    def test_accepts_only_the_two_explicit_repro_payload_shapes(self) -> None:
        expected_common = {
            "authenticode_certificate_directory_present": False,
            "hardening": {
                "machine": "x86_64",
                "dynamic_base": True,
                "nx_compatible": True,
                "high_entropy_va": True,
                "base_relocations": {
                    "directory_present": True,
                    "dir64_count": 1,
                },
                "debug_directory": {
                    "entry_count": 1,
                    "entry_type": "IMAGE_DEBUG_TYPE_REPRO",
                    "payload_kind": "empty",
                    "hash_bytes": 0,
                },
            },
        }
        self.assertEqual(
            windows_package.parse_windows_pe_evidence(_windows_pe_fixture()),
            expected_common,
        )

        hashed = json.loads(json.dumps(expected_common))
        hashed["hardening"]["debug_directory"].update(
            {"payload_kind": "length_prefixed_hash", "hash_bytes": 32}
        )
        self.assertEqual(
            windows_package.parse_windows_pe_evidence(
                _windows_pe_fixture(hash_payload=True)
            ),
            hashed,
        )

    def test_rejects_truncated_headers_directories_sections_and_payloads(self) -> None:
        empty = _windows_pe_fixture()
        hashed = _windows_pe_fixture(hash_payload=True)
        cases = {
            "DOS": empty[:1],
            "PE offset": empty[:0x3F],
            "COFF": empty[:0x90],
            "optional header": empty[:0x180],
            "section table": empty[:0x1A0],
            "debug entry": empty[:0x21B],
            "section raw data": empty[:-1],
            "hash payload": hashed[:0x263],
        }
        for label, data in cases.items():
            with self.subTest(label=label), self.assertRaises(WindowsPackageError):
                windows_package.parse_windows_pe_evidence(data)

    def test_rejects_invalid_pe_identity_and_header_contracts(self) -> None:
        valid = _windows_pe_fixture()
        bad_mz = bytearray(valid)
        bad_mz[:2] = b"NZ"
        bad_signature = bytearray(valid)
        bad_signature[0x80:0x84] = b"PX\0\0"
        cases = {
            "DOS signature": bytes(bad_mz),
            "PE header before DOS header": _pack_pe(valid, 0x3C, "<I", 0x20),
            "PE header outside file": _pack_pe(valid, 0x3C, "<I", 0xFFFFFFFC),
            "PE signature": bytes(bad_signature),
            "machine": _pack_pe(valid, 0x84, "<H", 0x014C),
            "zero sections": _pack_pe(valid, 0x86, "<H", 0),
            "too many sections": _pack_pe(valid, 0x86, "<H", 97),
            "COFF symbols pointer": _pack_pe(valid, 0x8C, "<I", 0x300),
            "COFF symbols count": _pack_pe(valid, 0x90, "<I", 1),
            "optional header too short": _pack_pe(valid, 0x94, "<H", 0xA0),
            "not PE32+": _pack_pe(valid, 0x98, "<H", 0x10B),
            "not executable": _pack_pe(valid, 0x96, "<H", 0x2020),
            "not DLL": _pack_pe(valid, 0x96, "<H", 0x0022),
            "headers before section table": _pack_pe(valid, 0x98 + 60, "<I", 0x190),
            "headers outside file": _pack_pe(valid, 0x98 + 60, "<I", 0x600),
            "too few directories": _pack_pe(valid, 0x98 + 108, "<I", 6),
            "directories exceed optional header": _pack_pe(
                valid, 0x98 + 108, "<I", 17
            ),
        }
        for label, data in cases.items():
            with self.subTest(label=label), self.assertRaises(WindowsPackageError):
                windows_package.parse_windows_pe_evidence(data)

    def test_rejects_each_missing_hardening_bit_and_certificate_table(self) -> None:
        valid = _windows_pe_fixture()
        for label, value in (
            ("high entropy VA", 0x0140),
            ("dynamic base", 0x0120),
            ("NX", 0x0060),
        ):
            with self.subTest(label=label), self.assertRaises(WindowsPackageError):
                windows_package.parse_windows_pe_evidence(
                    _pack_pe(valid, 0x98 + 70, "<H", value)
                )
        for label, offset in (
            ("certificate pointer", 0x98 + 144),
            ("certificate size", 0x98 + 148),
        ):
            with self.subTest(label=label), self.assertRaises(WindowsPackageError):
                windows_package.parse_windows_pe_evidence(
                    _pack_pe(valid, offset, "<I", 8)
                )

    def test_rejects_missing_malformed_or_ineffective_base_relocations(self) -> None:
        valid = _windows_pe_fixture()
        oversized_entries = bytearray(valid)
        relocation_entry_count = 65_538
        relocation_block_size = 8 + relocation_entry_count * 2
        relocation_end = 0x280 + relocation_block_size
        oversized_entries.extend(b"\0" * (relocation_end - len(oversized_entries)))
        struct.pack_into("<I", oversized_entries, 0x188 + 8, len(oversized_entries) - 0x200)
        struct.pack_into("<I", oversized_entries, 0x188 + 16, len(oversized_entries) - 0x200)
        struct.pack_into("<I", oversized_entries, 0x98 + 156, relocation_block_size)
        struct.pack_into("<I", oversized_entries, 0x284, relocation_block_size)
        cases = {
            "relocations stripped": _pack_pe(valid, 0x96, "<H", 0x2023),
            "missing relocation RVA": _pack_pe(valid, 0x98 + 152, "<I", 0),
            "missing relocation size": _pack_pe(valid, 0x98 + 156, "<I", 0),
            "unmapped relocation directory": _pack_pe(
                valid, 0x98 + 152, "<I", 0x3000
            ),
            "oversized relocation directory": _pack_pe(
                valid, 0x98 + 156, "<I", 1024 * 1024 + 1
            ),
            "unaligned page": _pack_pe(valid, 0x280, "<I", 0x1001),
            "empty block": _pack_pe(valid, 0x284, "<I", 8),
            "misaligned block size": _pack_pe(valid, 0x284, "<I", 10),
            "block exceeds directory": _pack_pe(valid, 0x284, "<I", 16),
            "non-DIR64 relocation": _pack_pe(valid, 0x288, "<H", 0x3100),
            "noncanonical padding": _pack_pe(valid, 0x28A, "<H", 1),
            "DIR64 target outside section": _pack_pe(
                valid, 0x288, "<H", 0xAFFF
            ),
            "duplicate DIR64 target": _pack_pe(valid, 0x28A, "<H", 0xA100),
            "too many relocation entries": bytes(oversized_entries),
        }
        for label, data in cases.items():
            with self.subTest(label=label), self.assertRaises(WindowsPackageError):
                windows_package.parse_windows_pe_evidence(data)

    def test_rejects_non_repro_reserved_and_multiple_debug_entries(self) -> None:
        valid = _windows_pe_fixture()
        cases = {
            "missing debug directory": _pack_pe(valid, 0x98 + 164, "<I", 0),
            "two debug entries": _pack_pe(valid, 0x98 + 164, "<I", 56),
            "reserved field": _pack_pe(valid, 0x200, "<I", 1),
            "major version": _pack_pe(valid, 0x208, "<H", 1),
            "minor version": _pack_pe(valid, 0x20A, "<H", 1),
        }
        for debug_type in (0, 1, 2, 4, 17, 19, 20):
            cases[f"debug type {debug_type}"] = _pack_pe(
                valid, 0x20C, "<I", debug_type
            )
        for label, data in cases.items():
            with self.subTest(label=label), self.assertRaises(WindowsPackageError):
                windows_package.parse_windows_pe_evidence(data)

    def test_rejects_unmapped_ambiguous_or_non_file_backed_rvas(self) -> None:
        valid = _windows_pe_fixture()
        zero_filled = _pack_pe(valid, 0x188 + 8, "<I", 0x400)
        zero_filled = _pack_pe(zero_filled, 0x188 + 16, "<I", 0x100)
        zero_filled = _pack_pe(zero_filled, 0x98 + 160, "<I", 0x1180)

        ambiguous = bytearray(valid)
        ambiguous.extend(b"\0" * 0x200)
        struct.pack_into("<H", ambiguous, 0x86, 2)
        struct.pack_into(
            "<8sIIIIIIHHI",
            ambiguous,
            0x1B0,
            b".other\0\0",
            0x200,
            0x1000,
            0x200,
            0x400,
            0,
            0,
            0,
            0,
            0x40000040,
        )
        raw_overlap = bytearray(valid)
        struct.pack_into("<H", raw_overlap, 0x86, 2)
        struct.pack_into(
            "<8sIIIIIIHHI",
            raw_overlap,
            0x1B0,
            b".other\0\0",
            0x100,
            0x2000,
            0x100,
            0x300,
            0,
            0,
            0,
            0,
            0x40000040,
        )
        cases = {
            "unmapped directory": _pack_pe(valid, 0x98 + 160, "<I", 0x3000),
            "zero-filled directory": zero_filled,
            "directory crosses section": _pack_pe(
                valid, 0x98 + 160, "<I", 0x11F0
            ),
            "ambiguous sections": bytes(ambiguous),
            "section raw range outside file": _pack_pe(
                valid, 0x188 + 20, "<I", 0x300
            ),
            "section raw range starts in headers": _pack_pe(
                valid, 0x188 + 20, "<I", 0x100
            ),
            "section raw ranges overlap": bytes(raw_overlap),
            "section virtual overflow": _pack_pe(
                valid, 0x188 + 12, "<I", 0xFFFFFF80
            ),
            "debug RVA overflows 32 bits": _pack_pe(
                valid, 0x98 + 160, "<I", 0xFFFFFFF0
            ),
        }
        for label, data in cases.items():
            with self.subTest(label=label), self.assertRaises(WindowsPackageError):
                windows_package.parse_windows_pe_evidence(data)

    def test_rejects_malformed_or_inconsistent_repro_payloads(self) -> None:
        empty = _windows_pe_fixture()
        hashed = _windows_pe_fixture(hash_payload=True)
        overlap = _pack_pe(hashed, 0x214, "<I", 0x1010)
        overlap = _pack_pe(overlap, 0x218, "<I", 0x210)
        cases = {
            "empty entry with RVA": _pack_pe(empty, 0x214, "<I", 0x1040),
            "empty entry with pointer": _pack_pe(empty, 0x218, "<I", 0x240),
            "unexpected payload size": _pack_pe(hashed, 0x210, "<I", 35),
            "zero payload RVA": _pack_pe(hashed, 0x214, "<I", 0),
            "zero payload pointer": _pack_pe(hashed, 0x218, "<I", 0),
            "RVA/pointer mismatch": _pack_pe(hashed, 0x218, "<I", 0x244),
            "unmapped payload RVA": _pack_pe(hashed, 0x214, "<I", 0x3000),
            "payload pointer outside file": _pack_pe(hashed, 0x218, "<I", 0x500),
            "hash length": _pack_pe(hashed, 0x240, "<I", 31),
            "directory overlap": overlap,
        }
        for label, data in cases.items():
            with self.subTest(label=label), self.assertRaises(WindowsPackageError):
                windows_package.parse_windows_pe_evidence(data)


class RustcNativeStaticLibraryTests(unittest.TestCase):
    RAW_TOKENS = windows_package.EXPECTED_WINDOWS_NATIVE_STATIC_LIBRARY_TOKENS
    CANONICAL_LIBRARIES = list(
        windows_package.CANONICAL_WINDOWS_NATIVE_STATIC_LIBRARIES
    )

    def test_parser_accepts_only_the_exact_ordered_windows_contract(self) -> None:
        for newline in (b"\n", b"\r\n"):
            with self.subTest(newline=newline):
                self.assertEqual(
                    windows_package.parse_rustc_native_static_libraries(
                        _native_static_libraries_output(
                            *self.RAW_TOKENS, newline=newline
                        )
                    ),
                    self.CANONICAL_LIBRARIES,
                )

    def test_parser_rejects_unsafe_ambiguous_or_changed_contracts(self) -> None:
        exact = _native_static_libraries_output(*self.RAW_TOKENS)
        changed_contracts = {
            "missing marker": exact.replace(
                b"native-static-libs:", b"native libraries:"
            ),
            "duplicate marker": exact + exact,
            "missing token": _native_static_libraries_output(*self.RAW_TOKENS[:-1]),
            "extra token": _native_static_libraries_output(
                *self.RAW_TOKENS, "evil.lib"
            ),
            "reordered": _native_static_libraries_output(
                self.RAW_TOKENS[1], self.RAW_TOKENS[0], *self.RAW_TOKENS[2:]
            ),
            "case change": _native_static_libraries_output(
                "KERNEL32.lib", *self.RAW_TOKENS[1:]
            ),
            "defaultlib injection": _native_static_libraries_output(
                *self.RAW_TOKENS[:-1], "/defaultlib:evil"
            ),
            "whole archive": _native_static_libraries_output(
                *self.RAW_TOKENS[:-1], "/WHOLEARCHIVE:evil.lib"
            ),
            "path": _native_static_libraries_output(
                *self.RAW_TOKENS[:-1], r"C:\\evil.lib"
            ),
            "quoted": _native_static_libraries_output(
                *self.RAW_TOKENS[:-1], '"evil.lib"'
            ),
            "response file": _native_static_libraries_output(
                *self.RAW_TOKENS[:-1], "@evil.rsp"
            ),
            "Unix flags": _native_static_libraries_output(
                "-lkernel32", "-lntdll"
            ),
            "ANSI": exact.replace(b"note:", b"\x1b[92mnote\x1b[0m:", 1),
            "incomplete escape": exact + b"\x1b[",
            "NUL": exact + b"\0",
            "non-ASCII": exact + b"\xff",
            "oversized": b"x"
            * (windows_package.MAX_RUSTC_NATIVE_STATIC_LIBS_BYTES + 1),
        }
        for label, output in changed_contracts.items():
            with self.subTest(label=label):
                with self.assertRaises(WindowsPackageError):
                    windows_package.parse_rustc_native_static_libraries(output)

    def test_parser_cli_emits_only_the_canonical_json_array(self) -> None:
        repository = pathlib.Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory() as temporary:
            compiler_output = pathlib.Path(temporary) / "native-static-libraries.txt"
            compiler_output.write_bytes(
                _native_static_libraries_output(*self.RAW_TOKENS)
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-B",
                    "-W",
                    "error",
                    "artifact/python_bootstrap.py",
                    "artifact/windows_package.py",
                    "parse-native-static-libraries",
                    "--compiler-output",
                    str(compiler_output),
                ],
                cwd=repository,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, b"")
        self.assertEqual(json.loads(completed.stdout), self.CANONICAL_LIBRARIES)
        self.assertEqual(
            completed.stdout,
            (json.dumps(self.CANONICAL_LIBRARIES, separators=(",", ":")) + "\n").encode(
                "ascii"
            ),
        )


class RustcLinkerInvocationTests(unittest.TestCase):
    EXPECTED_LINKER = (
        r"C:\Program Files\Microsoft Visual Studio\VC\Tools\MSVC\14.50.12345"
        r"\bin\Hostx64\x64\link.exe"
    )

    def test_accepts_the_exact_default_msvc_linker_and_hardening_contract(self) -> None:
        arguments = windows_package.verify_rustc_linker_invocation(
            _rustc_link_arguments_output(),
            self.EXPECTED_LINKER.lower(),
        )
        self.assertEqual(
            arguments,
            [
                "/NOLOGO",
                "/Brepro",
                "/WX",
                r"/OUT:C:\build\q_periapt_ffi_abi2.dll",
            ],
        )

    def test_rejects_changed_program_command_shape_or_hardening(self) -> None:
        valid = _rustc_link_arguments_output()
        cases = {
            "different linker": _rustc_link_arguments_output(
                program=r"C:\Other\link.exe"
            ),
            "relative linker": _rustc_link_arguments_output(program="link.exe"),
            "wrong executable": _rustc_link_arguments_output(
                program=r"C:\Trusted\lld-link.exe"
            ),
            "missing Brepro": _rustc_link_arguments_output(
                arguments=("/NOLOGO", "/WX", "/OUT:output.dll")
            ),
            "duplicate WX": _rustc_link_arguments_output(
                arguments=("/NOLOGO", "/Brepro", "/WX", "/wx")
            ),
            "warnings disabled": _rustc_link_arguments_output(
                arguments=("/NOLOGO", "/Brepro", "/WX", "/WX:NO")
            ),
            "missing env": valid.removeprefix(b"env "),
            "CRLF": valid[:-1] + b"\r\n",
            "two commands": valid + valid,
            "NUL": valid[:-1] + b"\0\n",
            "invalid UTF-8": valid[:-1] + b"\xff\n",
            "unquoted program": valid.replace(
                json.dumps(self.EXPECTED_LINKER).encode("ascii"),
                b"link.exe",
                1,
            ),
            "unquoted argument": valid.replace(b'"/NOLOGO"', b"/NOLOGO", 1),
            "invalid environment name": valid.replace(
                b'LC_ALL="C"', b'LC-ALL="C"', 1
            ),
            "oversized": b"x"
            * (windows_package.MAX_RUSTC_LINK_ARGUMENTS_BYTES + 1),
        }
        for label, output in cases.items():
            with self.subTest(label=label), self.assertRaises(WindowsPackageError):
                windows_package.verify_rustc_linker_invocation(
                    output,
                    self.EXPECTED_LINKER,
                )

        with self.assertRaisesRegex(
            WindowsPackageError,
            "expected MSVC linker must be an absolute Windows drive path",
        ):
            windows_package.verify_rustc_linker_invocation(valid, "link.exe")

    def test_cli_verifies_one_regular_link_argument_snapshot(self) -> None:
        repository = pathlib.Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory() as temporary:
            link_arguments = pathlib.Path(temporary) / "link-arguments.txt"
            link_arguments.write_bytes(_rustc_link_arguments_output())
            completed = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-B",
                    "-W",
                    "error",
                    "artifact/python_bootstrap.py",
                    "artifact/windows_package.py",
                    "verify-linker-invocation",
                    "--link-arguments",
                    str(link_arguments),
                    "--expected-linker",
                    self.EXPECTED_LINKER,
                ],
                cwd=repository,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, b"")
        self.assertEqual(
            completed.stdout,
            b"WINDOWS_RUST_LINKER_INVOCATION_PASS\n",
        )


class DumpbinDependencyTests(unittest.TestCase):
    def test_parser_accepts_only_the_canonical_nonempty_dependency_block(self) -> None:
        self.assertEqual(
            windows_package.parse_dumpbin_dependents(
                _dumpbin_output("KERNEL32.dll", "bcrypt.dll")
            ),
            ["bcrypt.dll", "KERNEL32.dll"],
        )
        self.assertEqual(
            windows_package.parse_dumpbin_dependents(
                _dumpbin_output(
                    "WS2_32.dll",
                    "bcryptprimitives.dll",
                    "api-ms-win-core-synch-l1-2-0.dll",
                    "api-ms-win-crt-runtime-l1-1-0.dll",
                )
            ),
            [
                "api-ms-win-core-synch-l1-2-0.dll",
                "api-ms-win-crt-runtime-l1-1-0.dll",
                "bcryptprimitives.dll",
                "WS2_32.dll",
            ],
        )

    def test_ucrt_allowlist_is_the_exact_fifteen_contract_set(self) -> None:
        expected = {
            f"api-ms-win-crt-{family}-l1-1-0.dll"
            for family in (
                "conio",
                "convert",
                "environment",
                "filesystem",
                "heap",
                "locale",
                "math",
                "multibyte",
                "private",
                "process",
                "runtime",
                "stdio",
                "string",
                "time",
                "utility",
            )
        }
        actual = {
            name
            for name in windows_package.ALLOWED_DEPENDENCY_NAMES
            if name.startswith("api-ms-win-crt-")
        }
        self.assertEqual(actual, expected)

    def test_manifest_dependency_normalization_rejects_unicode_casefold_spoofs(
        self,
    ) -> None:
        for dependency in ("KERNEL32.dll", "UſERENV.dll"):
            with self.subTest(dependency=dependency):
                with self.assertRaises(WindowsPackageError):
                    windows_package._normalize_dependencies([dependency])

    def test_parser_rejects_missing_duplicate_or_ambiguous_sections(self) -> None:
        canonical = _dumpbin_output("KERNEL32.dll")
        cases = {
            "missing dependency header": canonical.replace(
                b"Image has the following dependencies:", b"Dependencies:"
            ),
            "duplicate dependency header": canonical.replace(
                b"  Summary",
                b"  Image has the following dependencies:\r\n\r\n  Summary",
            ),
            "delay-load section": canonical.replace(
                b"  Summary",
                b"  Image has the following delay load dependencies:\r\n\r\n"
                b"    USER32.dll\r\n\r\n  Summary",
            ),
            "missing summary": canonical.replace(b"  Summary", b"  Totals"),
            "duplicate summary": canonical.replace(
                b"  Summary", b"  Summary\r\n\r\n  Summary"
            ),
            "summary before dependency block": canonical.replace(
                b"  Image has the following dependencies:",
                b"  Summary\r\n\r\n  Image has the following dependencies:",
            ),
        }
        for label, output in cases.items():
            with self.subTest(label=label):
                with self.assertRaises(WindowsPackageError):
                    windows_package.parse_dumpbin_dependents(output)

    def test_parser_rejects_every_malformed_or_unapproved_import(self) -> None:
        cases = {
            "empty": _dumpbin_output(),
            "path": _dumpbin_output(r"C:\\evil.dll"),
            "space": _dumpbin_output("evil name.dll"),
            "punctuation": _dumpbin_output("evil!.dll"),
            "trailing data": _dumpbin_output("KERNEL32.dll extra"),
            "non-ascii": _dumpbin_output("KERNEL32.dll").replace(
                b"KERNEL32.dll", b"KERNEL32.d\xffll"
            ),
            "unknown": _dumpbin_output("evil.dll"),
            "unversioned API set": _dumpbin_output("api-ms-win-crt-evil.dll"),
            "well-shaped unknown API set": _dumpbin_output(
                "api-ms-win-crt-evil-l1-1-0.dll"
            ),
            "well-shaped fake API version": _dumpbin_output(
                "api-ms-win-crt-runtime-l1-1-1.dll"
            ),
            "well-shaped fake core API version": _dumpbin_output(
                "api-ms-win-core-synch-l1-2-1.dll"
            ),
            "well-shaped absurd API set": _dumpbin_output(
                "api-ms-win-crt----l999-999-999.dll"
            ),
            "API set underscore": _dumpbin_output(
                "api-ms-win-crt-bad_name-l1-1-0.dll"
            ),
            "API set dot": _dumpbin_output("api-ms-win-crt-bad.name-l1-1-0.dll"),
            "API set bad version": _dumpbin_output(
                "api-ms-win-crt-runtime-l1-1.dll"
            ),
            "duplicate": _dumpbin_output("KERNEL32.dll", "kernel32.DLL"),
            "unversioned legacy recursion": _dumpbin_output("q_periapt_ffi.dll"),
            "ABI1 legacy recursion": _dumpbin_output("q_periapt_ffi_abi1.dll"),
            "ABI2 recursion": _dumpbin_output("q_periapt_ffi_abi2.dll"),
            "nul": _dumpbin_output("KERNEL32.dll") + b"\0",
            "oversized": b"x" * (windows_package.MAX_DUMPBIN_OUTPUT_BYTES + 1),
        }
        for label, output in cases.items():
            with self.subTest(label=label):
                with self.assertRaises(WindowsPackageError):
                    windows_package.parse_dumpbin_dependents(output)

    def test_inspector_binds_exact_absolute_tool_dll_and_process_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            tool_root = root / "trusted-msvc"
            package_root = root / "package"
            tool_root.mkdir()
            package_root.mkdir()
            dumpbin = tool_root / "dumpbin.exe"
            library = package_root / "q_periapt_ffi_abi2.dll"
            dumpbin.write_bytes(b"fixture tool")
            library.write_bytes(b"fixture dll")
            calls: list[tuple[list[str], dict[str, object]]] = []

            def runner(
                arguments: list[str], **kwargs: object
            ) -> subprocess.CompletedProcess[bytes]:
                calls.append((arguments, kwargs))
                return subprocess.CompletedProcess(
                    arguments,
                    0,
                    _dumpbin_output("KERNEL32.dll", "bcrypt.dll"),
                    b"",
                )

            self.assertEqual(
                windows_package.inspect_dumpbin_dependencies(
                    dumpbin, library, runner=runner
                ),
                ["bcrypt.dll", "KERNEL32.dll"],
            )
            self.assertEqual(len(calls), 1)
            arguments, kwargs = calls[0]
            self.assertEqual(
                arguments,
                [
                    str(dumpbin),
                    "/nologo",
                    "/dependents",
                    str(library),
                ],
            )
            self.assertEqual(
                kwargs,
                {
                    "cwd": str(tool_root),
                    "stdin": subprocess.DEVNULL,
                    "stdout": subprocess.PIPE,
                    "stderr": subprocess.PIPE,
                    "check": False,
                    "timeout": 30,
                },
            )

    def test_process_capture_is_memory_bounded_while_draining_both_pipes(self) -> None:
        emitted = windows_package.MAX_DUMPBIN_OUTPUT_BYTES + 64 * 1024
        script = (
            "import os;"
            f"os.write(1, b'x' * {emitted});"
            f"os.write(2, b'y' * {emitted})"
        )
        completed = windows_package._run_bounded_process(
            [sys.executable, "-I", "-S", "-c", script],
            cwd=str(pathlib.Path.cwd()),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(
            len(completed.stdout), windows_package.MAX_DUMPBIN_OUTPUT_BYTES + 1
        )
        self.assertEqual(
            len(completed.stderr), windows_package.MAX_DUMPBIN_OUTPUT_BYTES + 1
        )

    def test_process_capture_reaps_a_timed_out_process_after_draining_pipes(self) -> None:
        script = (
            "import os,time;"
            "os.write(1,b'stdout-before-timeout');"
            "os.write(2,b'stderr-before-timeout');"
            "time.sleep(30)"
        )
        started = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            windows_package._run_bounded_process(
                [sys.executable, "-I", "-S", "-c", script],
                cwd=str(pathlib.Path.cwd()),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=1,
            )
        self.assertLess(time.monotonic() - started, 10)

    def test_process_capture_terminates_descendants_that_inherit_pipes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            marker = pathlib.Path(temporary) / "descendant.pid"
            child_pid: int | None = None
            try:
                started = time.monotonic()
                completed = windows_package._run_bounded_process(
                    [
                        sys.executable,
                        "-I",
                        "-S",
                        "-c",
                        INHERITING_PARENT_SCRIPT,
                        str(marker),
                        INHERITING_DESCENDANT_SCRIPT,
                        "exit",
                    ],
                    cwd=str(pathlib.Path.cwd()),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                    timeout=5,
                )
                self.assertEqual(completed.returncode, 0)
                self.assertEqual(completed.stdout, b"descendant-stdout\n")
                self.assertEqual(completed.stderr, b"descendant-stderr\n")
                self.assertLess(time.monotonic() - started, 10)
                child_pid = int(marker.read_text(encoding="ascii"))
                self.assertGreater(child_pid, 0)
                self.assertFalse(
                    marker.with_name(f".{marker.name}.{child_pid}.tmp").exists()
                )

                if os.name != "nt":
                    self.assertTrue(
                        _wait_for_process_exit(child_pid),
                        "descendant process survived process-group cleanup",
                    )
            finally:
                if os.name != "nt" and child_pid is not None:
                    _kill_process_if_present(child_pid)

    def test_process_capture_times_out_and_reaps_an_inheriting_descendant(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            marker = pathlib.Path(temporary) / "timed-out-descendant.pid"
            child_pid: int | None = None
            try:
                started = time.monotonic()
                with self.assertRaises(subprocess.TimeoutExpired):
                    windows_package._run_bounded_process(
                        [
                            sys.executable,
                            "-I",
                            "-S",
                            "-c",
                            INHERITING_PARENT_SCRIPT,
                            str(marker),
                            INHERITING_DESCENDANT_SCRIPT,
                            "hold",
                        ],
                        cwd=str(pathlib.Path.cwd()),
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=False,
                        timeout=1,
                    )
                self.assertLess(time.monotonic() - started, 10)
                child_pid = int(marker.read_text(encoding="ascii"))
                self.assertGreater(child_pid, 0)
                self.assertFalse(
                    marker.with_name(f".{marker.name}.{child_pid}.tmp").exists()
                )

                if os.name != "nt":
                    self.assertTrue(
                        _wait_for_process_exit(child_pid),
                        "timed-out descendant survived process-group cleanup",
                    )
            finally:
                if os.name != "nt" and child_pid is not None:
                    _kill_process_if_present(child_pid)

    def test_inspector_rejects_process_failures_and_malformed_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            dumpbin = root / "dumpbin.exe"
            library = root / "q_periapt_ffi_abi2.dll"
            dumpbin.write_bytes(b"fixture tool")
            library.write_bytes(b"fixture dll")
            valid = _dumpbin_output("KERNEL32.dll")
            completed_cases = {
                "nonzero": subprocess.CompletedProcess([], 1, valid, b"failed"),
                "stderr": subprocess.CompletedProcess([], 0, valid, b"diagnostic"),
                "boolean return code": subprocess.CompletedProcess([], True, valid, b""),
                "text stdout": subprocess.CompletedProcess([], 0, "text", b""),
                "text stderr": subprocess.CompletedProcess([], 0, valid, "text"),
                "oversized stdout": subprocess.CompletedProcess(
                    [],
                    0,
                    b"x" * (windows_package.MAX_DUMPBIN_OUTPUT_BYTES + 1),
                    b"",
                ),
                "oversized stderr": subprocess.CompletedProcess(
                    [],
                    0,
                    valid,
                    b"x" * (windows_package.MAX_DUMPBIN_OUTPUT_BYTES + 1),
                ),
            }
            for label, completed in completed_cases.items():
                with self.subTest(label=label):
                    with self.assertRaises(WindowsPackageError):
                        windows_package.inspect_dumpbin_dependencies(
                            dumpbin,
                            library,
                            runner=lambda *args, completed=completed, **kwargs: completed,
                        )

            def timeout_runner(
                *args: object, **kwargs: object
            ) -> subprocess.CompletedProcess[bytes]:
                raise subprocess.TimeoutExpired("dumpbin.exe", 30)

            def os_error_runner(
                *args: object, **kwargs: object
            ) -> subprocess.CompletedProcess[bytes]:
                raise OSError("cannot start")

            for label, runner in (
                ("timeout", timeout_runner),
                ("os error", os_error_runner),
            ):
                with self.subTest(label=label):
                    with self.assertRaises(WindowsPackageError):
                        windows_package.inspect_dumpbin_dependencies(
                            dumpbin, library, runner=runner
                        )

    def test_inspector_rejects_untrusted_tool_and_library_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            dumpbin = root / "dumpbin.exe"
            wrong_tool = root / "other.exe"
            library = root / "q_periapt_ffi_abi2.dll"
            wrong_library = root / "other.dll"
            for path in (dumpbin, wrong_tool, library, wrong_library):
                path.write_bytes(b"fixture")

            cases = (
                (pathlib.Path("dumpbin.exe"), library),
                (wrong_tool, library),
                (dumpbin, pathlib.Path("q_periapt_ffi_abi2.dll")),
                (dumpbin, wrong_library),
            )
            for tool_path, library_path in cases:
                with self.subTest(tool=tool_path, library=library_path):
                    with self.assertRaises(WindowsPackageError):
                        windows_package.inspect_dumpbin_dependencies(
                            tool_path, library_path
                        )

            tool_link = root / "tool-link" / "dumpbin.exe"
            library_link = root / "library-link" / "q_periapt_ffi_abi2.dll"
            tool_link.parent.mkdir()
            library_link.parent.mkdir()
            try:
                tool_link.symlink_to(dumpbin)
                library_link.symlink_to(library)
            except (OSError, NotImplementedError):
                self.skipTest("file symlinks unavailable")
            for tool_path, library_path in (
                (tool_link, library),
                (dumpbin, library_link),
            ):
                with self.subTest(tool=tool_path, library=library_path):
                    with self.assertRaises(WindowsPackageError):
                        windows_package.inspect_dumpbin_dependencies(
                            tool_path, library_path
                        )


class WindowsPackageManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repository_root = pathlib.Path(__file__).resolve().parent.parent

    def _package(
        self, root: pathlib.Path, *, hash_repro_payload: bool = False
    ) -> pathlib.Path:
        package = root / (
            "q-periapt-c-abi2-0.1.0-alpha.2-x86_64-pc-windows-msvc"
        )
        for relative in windows_package.EXPECTED_PAYLOAD_FILES:
            path = package / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            if relative == "bin/q_periapt_ffi_abi2.dll":
                path.write_bytes(
                    _windows_pe_fixture(hash_payload=hash_repro_payload)
                )
            else:
                path.write_bytes(f"fixture:{relative}\n".encode())
        license_relative = "THIRD_PARTY/rust/fixture-dependency-1.0.0/LICENSE"
        license_path = package / license_relative
        license_path.parent.mkdir(parents=True, exist_ok=True)
        license_path.write_text("fixture dependency license\n", encoding="utf-8")
        license_bytes = license_path.read_bytes()
        inventory = {
            "schema_version": third_party_licenses.SCHEMA_VERSION,
            "kind": third_party_licenses.KIND,
            "root_package": third_party_licenses.ROOT_PACKAGE,
            "target": windows_package.TARGET,
            "packages": [
                {
                    "checksum": "b" * 64,
                    "license_expression": "MIT",
                    "name": "fixture-dependency",
                    "source": "registry+https://github.com/rust-lang/crates.io-index",
                    "version": "1.0.0",
                    "license_files": [
                        {
                            "bytes": len(license_bytes),
                            "path": license_relative,
                            "sha256": hashlib.sha256(license_bytes).hexdigest(),
                        }
                    ],
                }
            ],
        }
        inventory_path = package / third_party_licenses.INVENTORY_RELATIVE
        inventory_path.write_bytes(third_party_licenses.canonical_json(inventory))
        shutil.copy2(
            self.repository_root
            / "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json",
            package / "share/q-periapt/abi/q-periapt-c-abi-v2.json",
        )
        crypto_components = []
        for name in sorted(windows_package.EXPECTED_CRYPTO_ASSETS):
            crypto_components.append(
                {
                    "type": "cryptographic-asset",
                    "bom-ref": f"crypto:{name}",
                    "name": name,
                    "cryptoProperties": {
                        "assetType": "algorithm",
                        "algorithmProperties": {
                            "primitive": "fixture",
                            "parameterSetIdentifier": name,
                            "cryptoFunctions": ["other"],
                            "nistQuantumSecurityLevel": 0,
                        },
                    },
                }
            )
        lock = tomllib.loads(
            (self.repository_root / "Cargo.lock").read_text(encoding="utf-8")
        )
        sbom_components = []
        for entry in lock["package"]:
            purl = f"pkg:cargo/{entry['name']}@{entry['version']}"
            sbom_components.append(
                {
                    "type": "library",
                    "bom-ref": purl,
                    "name": entry["name"],
                    "version": entry["version"],
                    "purl": purl,
                }
            )
        common = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "metadata": {"component": {"name": "q-periapt-hybrid-suite"}},
        }
        (package / "share/q-periapt/bom/cbom.cdx.json").write_text(
            json.dumps({**common, "components": crypto_components}, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        (package / "share/q-periapt/bom/sbom.cdx.json").write_text(
            json.dumps({**common, "components": sbom_components}, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        return package

    def _create(self, package: pathlib.Path) -> dict:
        return windows_package.create_manifest(
            package,
            self.repository_root,
            package_name=package.name,
            version="0.1.0-alpha.2",
            git_commit="a" * 40,
            git_tree="b" * 40,
            source_date_epoch=1_700_000_000,
            rustc="rustc fixture",
            cargo="cargo fixture",
            cl="Microsoft C/C++ fixture",
            dependencies=["KERNEL32.dll", "bcrypt.dll"],
        )

    def test_create_and_verify_are_deterministic_and_strict(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            package = self._package(pathlib.Path(temporary))
            first = self._create(package)
            first_manifest = (package / "MANIFEST.json").read_bytes()
            first_sums = (package / "SHA256SUMS").read_bytes()

            (package / "MANIFEST.json").unlink()
            (package / "SHA256SUMS").unlink()
            second = self._create(package)

            self.assertEqual(first, second)
            self.assertEqual(first_manifest, (package / "MANIFEST.json").read_bytes())
            self.assertEqual(first_sums, (package / "SHA256SUMS").read_bytes())
            verified = windows_package.verify_package(
                package, repository_root=self.repository_root
            )
            self.assertEqual(verified["target"], windows_package.TARGET)
            self.assertEqual(
                verified["release_class"], "unsigned_experimental_prerelease"
            )
            self.assertFalse(verified["authenticode"]["signed"])
            self.assertFalse(
                verified["authenticode"]["certificate_directory_present"]
            )
            self.assertEqual(
                verified["hardening"]["debug_directory"],
                {
                    "entry_count": 1,
                    "entry_type": "IMAGE_DEBUG_TYPE_REPRO",
                    "payload_kind": "empty",
                    "hash_bytes": 0,
                },
            )

    def test_hash_repro_payload_is_bound_through_create_and_verify(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            package = self._package(
                pathlib.Path(temporary), hash_repro_payload=True
            )
            created = self._create(package)
            expected_debug = {
                "entry_count": 1,
                "entry_type": "IMAGE_DEBUG_TYPE_REPRO",
                "payload_kind": "length_prefixed_hash",
                "hash_bytes": 32,
            }
            self.assertEqual(
                created["hardening"]["debug_directory"], expected_debug
            )
            verified = windows_package.verify_package(package)
            self.assertEqual(
                verified["hardening"]["debug_directory"], expected_debug
            )

            self._rewrite_manifest(
                package,
                lambda value: value["hardening"]["debug_directory"].__setitem__(
                    "hash_bytes", 31
                ),
            )
            with self.assertRaisesRegex(
                WindowsPackageError, "hardening evidence differs"
            ):
                windows_package.verify_package(package)

    def test_create_rejects_dll_replacement_between_inspection_and_hashing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            package = self._package(pathlib.Path(temporary))
            dll = package / "bin/q_periapt_ffi_abi2.dll"
            real_scan = windows_package.scan_release_file
            replaced = False
            resolved_dll = dll.resolve(strict=True)

            def replace_before_scan(path, **kwargs):
                nonlocal replaced
                if pathlib.Path(path).resolve(strict=True) == resolved_dll and not replaced:
                    replaced = True
                    dll.write_bytes(_windows_pe_fixture(hash_payload=True))
                return real_scan(path, **kwargs)

            with (
                mock.patch.object(
                    windows_package,
                    "scan_release_file",
                    side_effect=replace_before_scan,
                ),
                self.assertRaisesRegex(WindowsPackageError, "changed between"),
            ):
                self._create(package)

    def test_verify_rejects_dll_replacement_after_pe_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            package = self._package(pathlib.Path(temporary))
            self._create(package)
            dll = package / "bin/q_periapt_ffi_abi2.dll"
            replacement = _windows_pe_fixture(hash_payload=True)
            replacement_sha256 = hashlib.sha256(replacement).hexdigest()

            self._rewrite_manifest(
                package,
                lambda value: next(
                    entry
                    for entry in value["files"]
                    if entry["path"] == "bin/q_periapt_ffi_abi2.dll"
                ).__setitem__("sha256", replacement_sha256),
            )
            sums_path = package / "SHA256SUMS"
            sums_path.write_text(
                "".join(
                    f"{replacement_sha256 if relative == 'bin/q_periapt_ffi_abi2.dll' else digest}  {relative}\n"
                    for digest, relative in (
                        line.split("  ", 1)
                        for line in sums_path.read_text(encoding="ascii").splitlines()
                    )
                ),
                encoding="ascii",
            )

            real_sha256 = windows_package._sha256
            resolved_dll = dll.resolve(strict=True)
            replaced = False

            def replace_before_hash(path):
                nonlocal replaced
                if pathlib.Path(path).resolve(strict=True) == resolved_dll and not replaced:
                    replaced = True
                    dll.write_bytes(replacement)
                return real_sha256(path)

            with (
                mock.patch.object(
                    windows_package,
                    "_sha256",
                    side_effect=replace_before_hash,
                ),
                self.assertRaisesRegex(
                    WindowsPackageError, "inspection snapshot differs"
                ),
            ):
                windows_package.verify_package(package)

    def test_tampering_extra_files_and_symlinks_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            package = self._package(root)
            self._create(package)

            (package / "bin/q_periapt_ffi_abi2.dll").write_bytes(b"tampered")
            with self.assertRaises(WindowsPackageError):
                windows_package.verify_package(package)

            package = self._package(root / "extra")
            (package / "unexpected.txt").write_text("unexpected", encoding="utf-8")
            with self.assertRaisesRegex(WindowsPackageError, "file set differs"):
                self._create(package)

            package = self._package(root / "symlink")
            target = package / "LICENSE"
            target.unlink()
            target.symlink_to(self.repository_root / "LICENSE")
            with self.assertRaisesRegex(WindowsPackageError, "symlink"):
                self._create(package)

            real_package = self._package(root / "root-link-target")
            self._create(real_package)
            package_link = root / "package-root-link"
            try:
                package_link.symlink_to(real_package, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("directory symlinks unavailable")
            with self.assertRaisesRegex(WindowsPackageError, "root must be a non-symlink"):
                windows_package.verify_package(package_link)

    def test_invalid_dependencies_and_source_metadata_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            package = self._package(pathlib.Path(temporary))
            with self.assertRaisesRegex(WindowsPackageError, "invalid Windows"):
                windows_package.create_manifest(
                    package,
                    self.repository_root,
                    package_name=package.name,
                    version="0.1.0-alpha.2",
                    git_commit="a" * 40,
                    git_tree="b" * 40,
                    source_date_epoch=1_700_000_000,
                    rustc="rustc fixture",
                    cargo="cargo fixture",
                    cl="Microsoft C/C++ fixture",
                    dependencies=["..\\malicious.dll"],
                )
            with self.assertRaisesRegex(WindowsPackageError, "git commit"):
                windows_package.create_manifest(
                    package,
                    self.repository_root,
                    package_name=package.name,
                    version="0.1.0-alpha.2",
                    git_commit="not-a-commit",
                    git_tree="b" * 40,
                    source_date_epoch=1_700_000_000,
                    rustc="rustc fixture",
                    cargo="cargo fixture",
                    cl="Microsoft C/C++ fixture",
                    dependencies=["KERNEL32.dll"],
                )

    @staticmethod
    def _rewrite_manifest(package: pathlib.Path, mutate) -> None:
        manifest_path = package / "MANIFEST.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        mutate(manifest)
        manifest_path.write_bytes(windows_package._canonical_json(manifest))
        sums_path = package / "SHA256SUMS"
        lines = []
        for line in sums_path.read_text(encoding="ascii").splitlines():
            digest, relative = line.split("  ", 1)
            if relative == "MANIFEST.json":
                digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
            lines.append(f"{digest}  {relative}\n")
        sums_path.write_text("".join(lines), encoding="ascii")

    def test_manifest_identity_source_toolchain_and_schema_tampering_fail_closed(self) -> None:
        mutations = {
            "schema": lambda value: value.__setitem__("schema_version", 2),
            "package": lambda value: value.__setitem__("package", "unrelated-package"),
            "generated_at": lambda value: value.__setitem__("generated_at", "not-a-time"),
            "source_date_epoch": lambda value: value.__setitem__("source_date_epoch", False),
            "toolchain": lambda value: value.__setitem__("toolchain", {}),
            "source inputs": lambda value: value.__setitem__("source_inputs_sha256", {}),
            "fields": lambda value: value.__setitem__("unexpected", True),
            "dependency": lambda value: value.__setitem__("native_dependencies", ["evil.dll"]),
            "Unicode dependency spoof": lambda value: value.__setitem__(
                "native_dependencies", ["KERNEL32.dll"]
            ),
            "hardening entry type": lambda value: value["hardening"][
                "debug_directory"
            ].__setitem__("entry_type", "IMAGE_DEBUG_TYPE_CODEVIEW"),
            "hardening entry count": lambda value: value["hardening"][
                "debug_directory"
            ].__setitem__("entry_count", 2),
            "hardening payload": lambda value: value["hardening"][
                "debug_directory"
            ].__setitem__("payload_kind", "unverified"),
            "base relocation count": lambda value: value["hardening"][
                "base_relocations"
            ].__setitem__("dir64_count", 0),
            "certificate directory": lambda value: value["authenticode"].__setitem__(
                "certificate_directory_present", True
            ),
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            original = self._package(root / "original")
            self._create(original)
            for label, mutation in mutations.items():
                with self.subTest(label=label):
                    package = root / f"tampered-{label.replace(' ', '-')}" / original.name
                    shutil.copytree(original, package)
                    self._rewrite_manifest(package, mutation)
                    with self.assertRaises(WindowsPackageError):
                        windows_package.verify_package(
                            package, repository_root=self.repository_root
                        )

    def test_native_dependency_evidence_and_complete_sbom_are_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            package = self._package(root / "package")
            self._create(package)
            with self.assertRaisesRegex(
                WindowsPackageError, "dependencies differ from native dumpbin",
            ):
                windows_package.verify_package(
                    package,
                    repository_root=self.repository_root,
                    expected_dependencies=["KERNEL32.dll"],
                )

            invalid = self._package(root / "invalid-bom")
            sbom_path = invalid / "share/q-periapt/bom/sbom.cdx.json"
            sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
            sbom["components"].pop()
            sbom_path.write_text(json.dumps(sbom, sort_keys=True) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(
                WindowsPackageError, "SBOM components do not match Cargo.lock",
            ):
                self._create(invalid)

    def test_powershell_release_wiring_preserves_source_and_external_trust_roots(self) -> None:
        script = (self.repository_root / "artifact/windows-package.ps1").read_text(
            encoding="utf-8"
        )
        self.assertGreaterEqual(
            script.count(
                "Assert-SourceSnapshot -ExpectedCommit $GitCommit -ExpectedTree $GitTree"
            ),
            5,
        )
        for token in (
            "$ExpectedSha256",
            "$ExpectedManifestSha256",
            "$ExpectedContractSha256",
            "$ExpectedGitCommit",
            "$ExpectedGitTree",
            "function Assert-TrustedBuildEnvironment",
            "function Assert-NoAmbientCargoConfiguration",
            "function Resolve-TrustedToolchainFile",
            "function Resolve-TrustedCommandProcessor",
            "function Resolve-TrustedMsvcX64Tools",
            "function Set-TrustedMsvcPath",
            "[System.IO.FileAttributes]::ReparsePoint",
            "-SystemDirectory ([System.Environment]::SystemDirectory)",
            "$environmentLines = & $commandProcessor",
            "$MsvcInstallation = Initialize-MsvcEnvironment",
            '$env:VSCMD_ARG_HOST_ARCH -cne "x64"',
            '$env:VSCMD_ARG_TGT_ARCH -cne "x64"',
            "$env:VSINSTALLDIR",
            "$env:VCINSTALLDIR",
            "$env:VCToolsInstallDir",
            '"bin/Hostx64/x64"',
            '-ExpectedName "cl.exe"',
            '-ExpectedName "link.exe"',
            '-ExpectedName "dumpbin.exe"',
            '-ExpectedName "lib.exe"',
            "$MsvcTools = Resolve-TrustedMsvcX64Tools",
            "$Cl = $MsvcTools.Cl",
            "$Dumpbin = $MsvcTools.Dumpbin",
            "$Librarian = $MsvcTools.Librarian",
            "$Linker = $MsvcTools.Linker",
            "Set-TrustedMsvcPath -TrustedBin $MsvcTools.Bin -Linker $Linker",
            '$env:RUSTFLAGS = "-D warnings"',
            '$env:CARGO_INCREMENTAL = "0"',
            '"-DQPeriaptABI2_DIR=$Extracted/lib/cmake/QPeriaptABI2"',
            '"--dumpbin", $Dumpbin',
            '"--sha256", $ExpectedArchiveSha256',
            '$savedCargoTermColor = $env:CARGO_TERM_COLOR',
            '$savedRustFlags = $env:RUSTFLAGS',
            '$savedCargoIncremental = $env:CARGO_INCREMENTAL',
            '$savedBomRustFlags = $env:RUSTFLAGS',
            '$savedBomCargoIncremental = $env:CARGO_INCREMENTAL',
            '$env:CARGO_TERM_COLOR = "never"',
            '$env:CARGO_TERM_COLOR = $savedCargoTermColor',
            '$env:RUSTFLAGS = $savedRustFlags',
            '$env:CARGO_INCREMENTAL = $savedCargoIncremental',
            '$env:RUSTFLAGS = $savedBomRustFlags',
            '$env:CARGO_INCREMENTAL = $savedBomCargoIncremental',
            "$env:CC = $Cl",
            "$env:CC = $savedCc",
            '$env:CFLAGS = "/experimental:deterministic /pathmap:$Root=qperiapt-source"',
            "$env:AR = $Librarian",
            "$env:AR = $savedAr",
            '"--print", "link-args=$linkArgumentsLog"',
            '"-Clink-arg=/Brepro"',
            '"-Clink-arg=/WX"',
            '"-Dlinker-messages"',
            '"verify-linker-invocation"',
            '"--link-arguments", $linkArgumentsLog',
            '"--expected-linker", $Linker',
            "Invoke-PythonChecked -Arguments $manifestArguments",
            "Invoke-PythonChecked -Arguments $manifestVerificationArguments",
            '"parse-native-static-libraries"',
            '"--compiler-output", $nativeStaticLibrariesLog',
            "ConvertFrom-Json `",
            "-InputObject $nativeLibrariesJson `",
            "-NoEnumerate",
            "$decodedNativeStaticLibraries -isnot [System.Array]",
            "$decodedNativeStaticLibraries.Count -ne $expectedNativeStaticLibraries.Count",
            "$library -isnot [string]",
            "[System.StringComparison]::Ordinal",
            "$NativeStaticLibraries = [string[]] $decodedNativeStaticLibraries",
        ):
            self.assertIn(token, script)
        for forbidden in (
            "function Get-DllDependencies",
            "function Get-NativeStaticLibraries",
            "function Assert-PeHardening",
            '"/headers"',
            '"-Clink-arg=/WX:NO"',
            "/WX:NO",
            "-Clinker=",
            "Resolve-TrustedRustLinkerCommand",
            "$RustLinkerCommand",
            '"-A", "linker-messages"',
            '"-Alinker-messages"',
            '"--cap-lints"',
            '"--dependency"',
            '"--expected-dependency"',
            '$Linker = Resolve-TrustedToolchainFile',
            '$Dumpbin = Resolve-TrustedToolchainFile',
            "function Resolve-TrustedToolchainCommand",
            '(Get-Command "link.exe"',
            '(Get-Command "dumpbin.exe"',
            '(Get-Command "cl.exe"',
            '-FilePath "cl.exe"',
            "Select-Object -First",
            '"CFLAGS_x86_64-pc-windows-msvc"',
            '"CFLAGS_x86_64_pc_windows_msvc"',
        ):
            self.assertNotIn(forbidden, script)
        self.assertNotIn(
            "debug_directory_absent",
            (self.repository_root / "artifact/windows_package.py").read_text(
                encoding="utf-8"
            ),
        )
        self.assertLess(
            script.index('"-Clink-arg=/Brepro"'),
            script.index('"-Clink-arg=/WX"'),
        )
        self.assertLess(
            script.index('"link-args=$linkArgumentsLog"'),
            script.index('"verify-linker-invocation"'),
        )
        copied_dll = script.index("Copy-Item -LiteralPath $dynamicDll")
        created_manifest = script.index(
            "Invoke-PythonChecked -Arguments $manifestArguments"
        )
        created_archive = script.index(
            '"artifact/deterministic_archive.py", "create-zip"'
        )
        self.assertLess(copied_dll, created_manifest)
        self.assertLess(created_manifest, created_archive)
        verification_arguments = script.index("$manifestVerificationArguments = @(")
        invoked_verification = script.index(
            "Invoke-PythonChecked -Arguments $manifestVerificationArguments"
        )
        self.assertLess(verification_arguments, invoked_verification)
        environment_guard = re.search(
            r"function Assert-TrustedBuildEnvironment \{(?P<body>.*?)\n\}"
            r"\n\nfunction Assert-NoAmbientCargoConfiguration",
            script,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(environment_guard)
        assert environment_guard is not None
        environment_guard_body = environment_guard.group("body")
        for name in (
            '"CL"',
            '"_CL_"',
            '"LINK"',
            '"RUSTC"',
            '"RUSTC_WRAPPER"',
            '"RUSTC_WORKSPACE_WRAPPER"',
            '"CARGO_BUILD_RUSTC"',
            '"CARGO_BUILD_RUSTC_WRAPPER"',
            '"CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER"',
            '"CARGO_BUILD_INCREMENTAL"',
            '"CARGO_ENCODED_RUSTFLAGS"',
            '"CMAKE_C_COMPILER_LAUNCHER"',
            '"CMAKE_C_LINKER_LAUNCHER"',
            '"CMAKE_CROSSCOMPILING_EMULATOR"',
            '"CMAKE_PROJECT_INCLUDE"',
            '"CMAKE_TEST_LAUNCHER"',
            '"QPeriaptABI2_ROOT"',
            '"GIT_DIR"',
        ):
            self.assertIn(name, environment_guard_body)
        self.assertIn('^CARGO_PROFILE_.+$', environment_guard_body)
        self.assertIn(
            '^CARGO_TARGET_.+_(?:AR|LINKER|RUNNER|RUSTDOCFLAGS|RUSTFLAGS)$',
            environment_guard_body,
        )
        self.assertEqual(
            2,
            len(re.findall(r"(?m)^Assert-TrustedBuildEnvironment$", script)),
        )
        self.assertLess(
            script.index("Assert-TrustedBuildEnvironment"),
            script.index("$MsvcInstallation = Initialize-MsvcEnvironment"),
        )
        cargo_configuration_guard = re.search(
            r"function Assert-NoAmbientCargoConfiguration \{(?P<body>.*?)\n\}"
            r"\n\nfunction Resolve-TrustedToolchainFile",
            script,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(cargo_configuration_guard)
        assert cargo_configuration_guard is not None
        cargo_configuration_body = cargo_configuration_guard.group("body")
        self.assertIn('$env:CARGO_HOME', cargo_configuration_body)
        self.assertIn('@("config", "config.toml")', cargo_configuration_body)
        self.assertIn('Join-Path $directory.FullName ".cargo/$name"', cargo_configuration_body)
        self.assertIn("Test-Path -LiteralPath $candidate", cargo_configuration_body)
        self.assertLess(
            script.index("Assert-NoAmbientCargoConfiguration -SourceRoot $Root"),
            script.index("$MsvcInstallation = Initialize-MsvcEnvironment"),
        )
        resolver = re.search(
            r"function Resolve-TrustedMsvcX64Tools \{(?P<body>.*?)\n\}"
            r"\n\nfunction Set-TrustedMsvcPath",
            script,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(resolver)
        assert resolver is not None
        resolver_body = resolver.group("body")
        self.assertEqual(4, resolver_body.count("Resolve-TrustedToolchainFile `"))
        self.assertIn("$vcToolsParent.FullName.Equals(", resolver_body)
        self.assertIn("$vsInstallation.Equals(", resolver_body)
        self.assertIn("$vcInstallation.Equals(", resolver_body)
        self.assertIn("[System.StringComparison]::OrdinalIgnoreCase", resolver_body)
        self.assertIn("$vcToolsVersion -cnotmatch", resolver_body)
        for tool in ("cl.exe", "link.exe", "dumpbin.exe", "lib.exe"):
            self.assertIn(f'-Path (Join-Path $bin "{tool}")', resolver_body)
        path_binding = re.search(
            r"function Set-TrustedMsvcPath \{(?P<body>.*?)\n\}"
            r"\n\nfunction Initialize-MsvcEnvironment",
            script,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(path_binding)
        assert path_binding is not None
        path_binding_body = path_binding.group("body")
        self.assertIn("other link.exe provider is removed", path_binding_body)
        self.assertIn("$linkerCandidates.Count -ne 1", path_binding_body)
        self.assertIn("controlled PATH does not resolve only", path_binding_body)
        self.assertGreaterEqual(script.count("-Cl $Cl `"), 3)
        self.assertEqual(2, script.count("Invoke-Checked -FilePath $Cl"))
        toolchain_test = (
            self.repository_root / "artifact/windows-toolchain-tests.ps1"
        ).read_text(encoding="utf-8")
        self.assertIn("WINDOWS_MSVC_TOOLCHAIN_RESOLVER_PASS", toolchain_test)
        self.assertIn("Assert-RejectsEnvironmentOverride", toolchain_test)
        self.assertIn("Resolve-TrustedCommandProcessor", toolchain_test)
        self.assertIn("Set-TrustedMsvcPath", toolchain_test)
        self.assertIn("different Visual Studio installation", toolchain_test)
        self.assertIn("non-file PATH linker", toolchain_test)
        for name in (
            '"CL"',
            '"LINK"',
            '"RUSTC_WRAPPER"',
            '"CARGO_BUILD_RUSTC_WRAPPER"',
            '"CARGO_BUILD_INCREMENTAL"',
            '"CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_AR"',
            '"CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER"',
            '"CARGO_PROFILE_RELEASE_LTO"',
            '"CMAKE_C_COMPILER_LAUNCHER"',
            '"CMAKE_CROSSCOMPILING_EMULATOR"',
            '"CMAKE_PROJECT_INCLUDE"',
            '"CMAKE_TEST_LAUNCHER"',
            '"QPeriaptABI2_ROOT"',
            '"GIT_DIR"',
        ):
            self.assertIn(name, toolchain_test)
        for workflow in (
            ".github/workflows/ci.yml",
            ".github/workflows/abi2-platform-candidate.yml",
        ):
            self.assertIn(
                "./windows-toolchain-tests.ps1",
                (self.repository_root / workflow).read_text(encoding="utf-8"),
            )
        native_library_contract = re.search(
            r"\$expectedNativeStaticLibraries\s*=\s*\[string\[\]\]\s*@\("
            r"(?P<libraries>.*?)\n\s*\)",
            script,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(native_library_contract)
        assert native_library_contract is not None
        self.assertEqual(
            re.findall(r'"([^"]+)"', native_library_contract.group("libraries")),
            list(windows_package.CANONICAL_WINDOWS_NATIVE_STATIC_LIBRARIES),
        )
        self.assertRegex(
            script,
            re.compile(
                r"\$vswhereCandidates\s*=\s*@\(\s*@\(.*?\)\s*\|\s*"
                r"Where-Object\s*\{.*?\}\s*\)",
                re.DOTALL,
            ),
        )
        stdout_read = script.index("$process.StandardOutput.ReadToEndAsync()")
        stderr_read = script.index("$process.StandardError.ReadToEndAsync()")
        wait = script.index("$process.WaitForExit()")
        self.assertLess(stdout_read, wait)
        self.assertLess(stderr_read, wait)


if __name__ == "__main__":
    unittest.main()
