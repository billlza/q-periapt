from __future__ import annotations

import copy
import hashlib
import json
import os
import pathlib
import re
import sys
import tempfile
import time
import traceback
import unittest
from collections.abc import Callable
from unittest import mock

import c_abi_contract
from c_abi_contract import CAbiContractError


class CAbiContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = pathlib.Path(__file__).resolve().parent.parent
        cls.contract_path = (
            cls.root / "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json"
        )
        cls.contract = c_abi_contract.load_contract(cls.contract_path)

    def _assert_redacted_error(
        self,
        operation: Callable[[], object],
        expected: str,
        secret: str,
    ) -> str:
        with self.assertRaises(CAbiContractError) as captured:
            operation()
        message = str(captured.exception)
        rendered = "".join(
            traceback.format_exception(
                type(captured.exception),
                captured.exception,
                captured.exception.__traceback__,
            )
        )
        self.assertIn(expected, message)
        self.assertNotIn(secret, rendered)
        return message

    def _header_text(self) -> str:
        macros = self.contract.document["abi"]["macros"]
        declarations = self.contract.declarations
        lines = ["#ifndef Q_PERIAPT_ABI2_H", "#define Q_PERIAPT_ABI2_H", ""]
        lines.extend(f"#define {name} {value}" for name, value in macros.items())
        lines.extend(
            [
                "",
                "/* Whitespace and line wrapping are intentionally non-canonical. */",
            ]
        )
        for declaration in declarations.values():
            lines.append(declaration.replace(", ", ",\n    "))
        lines.extend(["", "#endif"])
        return "\n".join(lines) + "\n"

    def _write_header(self, root: pathlib.Path, text: str | None = None) -> pathlib.Path:
        header = root / "q_periapt.h"
        header.write_text(self._header_text() if text is None else text, encoding="utf-8")
        return header

    def _write_contract(self, root: pathlib.Path, document: dict) -> pathlib.Path:
        path = root / "contract.json"
        path.write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return path

    def _library(self, root: pathlib.Path, platform: str) -> pathlib.Path:
        filename = self.contract.document["package"]["platforms"][platform][
            "shared_filename"
        ]
        library = root / filename
        library.write_bytes(b"fixture")
        return library

    def _static_library(self, root: pathlib.Path, platform: str) -> pathlib.Path:
        filename = self.contract.document["package"]["platforms"][platform][
            "static_filename"
        ]
        library = root / filename
        library.write_bytes(b"fixture")
        return library

    def _llvm_nm(self, root: pathlib.Path) -> pathlib.Path:
        llvm_nm = root / "llvm-nm"
        llvm_nm.write_bytes(b"fixture")
        return llvm_nm

    def _nm_exports(self, *, underscore: bool = False, omit: str | None = None) -> str:
        names = sorted(self.contract.export_names - ({omit} if omit else set()))
        prefix = "_" if underscore else ""
        return "".join(f"{prefix}{name}\n" for name in names)

    def test_contract_and_normalized_header_pass(self) -> None:
        self.assertEqual(self.contract.document["abi"]["major"], 2)
        self.assertEqual(self.contract.document["package"]["semver"], "0.1.0-alpha.2")
        self.assertEqual(len(self.contract.export_names), 9)
        with tempfile.TemporaryDirectory() as temporary:
            header = self._write_header(pathlib.Path(temporary))
            c_abi_contract.verify_header(self.contract, header)

    def test_changed_extra_and_noncanonical_macros_are_rejected(self) -> None:
        original = self._header_text()
        cases = (
            (
                original.replace(
                    "#define Q_PERIAPT_POLICY_DECISION_LEN 40",
                    "#define Q_PERIAPT_POLICY_DECISION_LEN 41",
                ),
                "changed=.*Q_PERIAPT_POLICY_DECISION_LEN",
            ),
            (
                original.replace(
                    "#define Q_PERIAPT_SECRET_LEN 32",
                    "#define Q_PERIAPT_SECRET_LEN 32\n#define Q_PERIAPT_SURPRISE 7",
                ),
                "extra=.*Q_PERIAPT_SURPRISE",
            ),
            (
                original.replace(
                    "#define Q_PERIAPT_ABI_VERSION 2",
                    "#define Q_PERIAPT_ABI_VERSION (2)",
                ),
                "not a canonical integer",
            ),
            (
                original.replace(
                    "#define Q_PERIAPT_SECRET_LEN 32",
                    "#define Q_PERIAPT_SECRET_LEN 32\n#define Q_PERIAPT_bad 1",
                ),
                "extra=.*Q_PERIAPT_bad",
            ),
            (
                original.replace(
                    "#define Q_PERIAPT_SECRET_LEN 32",
                    "#define Q_PERIAPT_SECRET_LEN 32\n#define Q_PERIAPT_VALUE(x) (x)",
                ),
                "must not be function-like",
            ),
            (
                original.replace("Q_PERIAPT_ABI2_H", "Q_PERIAPT_H"),
                "exactly one #ifndef Q_PERIAPT_ABI2_H",
            ),
        )
        for header_text, message in cases:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as temporary:
                header = self._write_header(pathlib.Path(temporary), header_text)
                with self.assertRaisesRegex(CAbiContractError, message):
                    c_abi_contract.verify_header(self.contract, header)

    def test_missing_extra_forbidden_and_changed_declarations_are_rejected(self) -> None:
        original = self._header_text()
        missing_declaration = self.contract.declarations["q_periapt_generate_keypair"]
        cases = (
            (
                original.replace(missing_declaration.replace(", ", ",\n    ") + "\n", ""),
                "missing=.*q_periapt_generate_keypair",
            ),
            (
                original.replace(
                    "\n#endif",
                    "\nint32_t q_periapt_surprise(void);\n#endif",
                ),
                "extra=.*q_periapt_surprise",
            ),
            (
                original.replace(
                    "\n#endif",
                    "\nint32_t q_periapt_combine(void);\n#endif",
                ),
                "forbidden=.*q_periapt_combine",
            ),
            (
                original.replace(
                    "const uint8_t *toml",
                    "uint8_t *toml",
                    1,
                ),
                "changed=.*q_periapt_decision_from_signed_policy",
            ),
        )
        for header_text, message in cases:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as temporary:
                header = self._write_header(pathlib.Path(temporary), header_text)
                with self.assertRaisesRegex(CAbiContractError, message):
                    c_abi_contract.verify_header(self.contract, header)

    def test_contract_package_identity_and_export_allowlist_are_frozen(self) -> None:
        cases: list[tuple[dict, str]] = []

        wrong_identity = copy.deepcopy(self.contract.document)
        wrong_identity["package"]["platforms"]["linux"]["soname"] = (
            "libq_periapt_ffi.so"
        )
        cases.append((wrong_identity, "package identity"))

        extra_export = copy.deepcopy(self.contract.document)
        extra_export["abi"]["exports"].append(
            {
                "name": "q_periapt_surprise",
                "role": "operation",
                "declaration": "int32_t q_periapt_surprise(void);",
            }
        )
        cases.append((extra_export, "ABI exports"))

        migrates_abi1 = copy.deepcopy(self.contract.document)
        migrates_abi1["migration"]["automatic_migration"] = True
        cases.append((migrates_abi1, "migration policy"))

        boolean_integer = copy.deepcopy(self.contract.document)
        boolean_integer["abi"]["macros"]["Q_PERIAPT_ABI_VERSION"] = True
        cases.append((boolean_integer, "ABI macros"))

        for document, message in cases:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as temporary:
                path = self._write_contract(pathlib.Path(temporary), document)
                with self.assertRaisesRegex(CAbiContractError, message):
                    c_abi_contract.load_contract(path)

    def test_duplicate_contract_key_is_rejected_by_strict_json_loader(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "contract.json"
            path.write_text(
                '{"schema":1,"schema":1,"kind":"qperiapt.c_abi_contract"}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(CAbiContractError, "duplicate JSON key"):
                c_abi_contract.load_contract(path)

    def test_macos_library_exports_and_runtime_identity_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            library = self._library(pathlib.Path(temporary), "macos")
            identity = self.contract.document["package"]["platforms"]["macos"]

            def runner(command: list[str]) -> str:
                if command[:2] == ["nm", "-gUj"]:
                    return self._nm_exports(underscore=True)
                if command[:2] == ["otool", "-D"]:
                    return f"{library}:\n{identity['install_name']}\n"
                if command[:2] == ["otool", "-L"]:
                    return (
                        f"{library}:\n"
                        f"\t{identity['install_name']} "
                        f"(compatibility version {identity['compatibility_version']}, "
                        f"current version {identity['current_version']})\n"
                    )
                self.fail(f"unexpected command: {command}")

            c_abi_contract.verify_dynamic_library(
                self.contract, library, "macos", runner=runner
            )

            def extra_export(command: list[str]) -> str:
                if command[:2] == ["nm", "-gUj"]:
                    return self._nm_exports(underscore=True) + "_qpn_mlkem_bridge_leak\n"
                return runner(command)

            with self.assertRaisesRegex(CAbiContractError, "extra_count=1"):
                c_abi_contract.verify_dynamic_library(
                    self.contract, library, "macos", runner=extra_export
                )

            def generic_extra(command: list[str]) -> str:
                if command[:2] == ["nm", "-gUj"]:
                    return self._nm_exports(underscore=True) + "_unexpected_export\n"
                return runner(command)

            with self.assertRaisesRegex(CAbiContractError, "extra_count=1"):
                c_abi_contract.verify_dynamic_library(
                    self.contract, library, "macos", runner=generic_extra
                )

            def duplicate_export(command: list[str]) -> str:
                if command[:2] == ["nm", "-gUj"]:
                    return self._nm_exports(underscore=True) + "_q_periapt_version\n"
                return runner(command)

            with self.assertRaisesRegex(CAbiContractError, "defines export more than once"):
                c_abi_contract.verify_dynamic_library(
                    self.contract, library, "macos", runner=duplicate_export
                )

            def malformed_export(command: list[str]) -> str:
                if command[:2] == ["nm", "-gUj"]:
                    return self._nm_exports(underscore=True) + "not one symbol\n"
                return runner(command)

            with self.assertRaisesRegex(CAbiContractError, "cannot parse nm"):
                c_abi_contract.verify_dynamic_library(
                    self.contract, library, "macos", runner=malformed_export
                )

    def test_macos_wrong_install_name_or_version_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            library = self._library(pathlib.Path(temporary), "macos")
            identity = self.contract.document["package"]["platforms"]["macos"]

            def wrong_install_name(command: list[str]) -> str:
                if command[0] == "nm":
                    return self._nm_exports(underscore=True)
                if command[:2] == ["otool", "-D"]:
                    return f"{library}:\n@rpath/libq_periapt_ffi.dylib\n"
                return ""

            with self.assertRaisesRegex(CAbiContractError, "install name differs"):
                c_abi_contract.verify_dynamic_library(
                    self.contract, library, "macos", runner=wrong_install_name
                )

            def wrong_current_version(command: list[str]) -> str:
                if command[0] == "nm":
                    return self._nm_exports(underscore=True)
                if command[:2] == ["otool", "-D"]:
                    return f"{library}:\n{identity['install_name']}\n"
                if command[:2] == ["otool", "-L"]:
                    return (
                        f"{library}:\n\t{identity['install_name']} "
                        "(compatibility version 2.0.0, current version 2.1.0)\n"
                    )
                self.fail(f"unexpected command: {command}")

            with self.assertRaisesRegex(CAbiContractError, "versions differ"):
                c_abi_contract.verify_dynamic_library(
                    self.contract, library, "macos", runner=wrong_current_version
                )

    def test_linux_library_passes_and_wrong_soname_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            library = self._library(pathlib.Path(temporary), "linux")
            identity = self.contract.document["package"]["platforms"]["linux"]

            def runner(command: list[str]) -> str:
                if command[0] == "nm":
                    return "".join(
                        f"{name} T 0 0\n" for name in sorted(self.contract.export_names)
                    )
                if command[0] == "readelf":
                    return (
                        " 0x000000000000000e (SONAME)             Library soname: "
                        f"[{identity['soname']}]\n"
                    )
                self.fail(f"unexpected command: {command}")

            c_abi_contract.verify_dynamic_library(
                self.contract, library, "linux", runner=runner
            )

            def extra_export(command: list[str]) -> str:
                if command[0] == "nm":
                    return runner(command) + "qpn_mlkem_bridge_leak T 0 0\n"
                return runner(command)

            with self.assertRaisesRegex(CAbiContractError, "extra_count=1"):
                c_abi_contract.verify_dynamic_library(
                    self.contract, library, "linux", runner=extra_export
                )

            def duplicate_export(command: list[str]) -> str:
                if command[0] == "nm":
                    return runner(command) + "q_periapt_version T 0 0\n"
                return runner(command)

            with self.assertRaisesRegex(CAbiContractError, "defines export more than once"):
                c_abi_contract.verify_dynamic_library(
                    self.contract, library, "linux", runner=duplicate_export
                )

            def malformed_export(command: list[str]) -> str:
                if command[0] == "nm":
                    return runner(command) + "malformed\n"
                return runner(command)

            with self.assertRaisesRegex(CAbiContractError, "cannot parse nm"):
                c_abi_contract.verify_dynamic_library(
                    self.contract, library, "linux", runner=malformed_export
                )

            def wrong_soname(command: list[str]) -> str:
                if command[0] == "nm":
                    return runner(command)
                return (
                    " 0x000000000000000e (SONAME) Library soname: "
                    "[libq_periapt_ffi.so]\n"
                )

            with self.assertRaisesRegex(CAbiContractError, "SONAME differs"):
                c_abi_contract.verify_dynamic_library(
                    self.contract, library, "linux", runner=wrong_soname
                )

    def test_dynamic_tool_output_is_redacted_from_every_failure_class(self) -> None:
        secret = "ghp_DYNAMIC_SECRET_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"

        def export_row(
            ordinal: int,
            hint: str,
            rva: str,
            payload: str,
        ) -> str:
            return f"{ordinal:>12}{hint:>5}{rva:>9}{payload}"

        def dumpbin_document(rows: list[str]) -> str:
            count = len(rows)
            return "\n".join(
                [
                    "        1 ordinal base",
                    f"        {count} number of functions",
                    f"        {count} number of names",
                    "",
                    "    ordinal hint RVA      name",
                    *rows,
                    "",
                    "  Summary",
                    "",
                    "        1000 .text",
                    "",
                ]
            )

        malformed_cases = (
            ("macos", f"_{secret} second-token\n", "cannot parse nm"),
            ("linux", f"{secret}\n", "cannot parse nm"),
            (
                "windows",
                dumpbin_document([f"malformed {secret}"]),
                "cannot parse dumpbin",
            ),
        )
        for platform, output, expected in malformed_cases:
            with self.subTest(parser=platform):
                message = self._assert_redacted_error(
                    lambda value=output, target=platform: (
                        c_abi_contract._dynamic_exports(value, target)
                    ),
                    expected,
                    secret,
                )
                self.assertRegex(message, r"row=[0-9]+, chars=[0-9]+")
                self.assertRegex(message, r"sha256=[0-9a-f]{64}")

        numeric_rows = [
            export_row(1, "0", "00001000", f"{secret} = {secret}")
        ]
        oversized_declaration = dumpbin_document(numeric_rows).replace(
            "        1 number of functions",
            f"        {'9' * 5000} number of functions",
            1,
        )
        numeric_cases = (
            (
                "declared-count",
                oversized_declaration,
                "supported integer range",
            ),
            (
                "ordinal",
                dumpbin_document(
                    [
                        export_row(
                            100_000,
                            "0",
                            "00001000",
                            f"{secret} = {secret}",
                        )
                    ]
                ),
                "cannot parse dumpbin",
            ),
            (
                "hint",
                dumpbin_document(
                    [
                        export_row(
                            1,
                            "FFFFF",
                            "00001000",
                            f"{secret} = {secret}",
                        )
                    ]
                ),
                "cannot parse dumpbin",
            ),
        )
        for label, output, expected in numeric_cases:
            with self.subTest(numeric_bound=label):
                self._assert_redacted_error(
                    lambda value=output: c_abi_contract._dynamic_exports(
                        value,
                        "windows",
                    ),
                    expected,
                    secret,
                )

        duplicate_output = f"_{secret}\n_{secret}\n"
        duplicate_message = self._assert_redacted_error(
            lambda: c_abi_contract._dynamic_exports(
                duplicate_output,
                "macos",
            ),
            "defines export more than once",
            secret,
        )
        self.assertIn("row=2", duplicate_message)

        forwarded_output = dumpbin_document(
            [
                export_row(
                    1,
                    "0",
                    "",
                    f"{secret} (forwarded to {secret}.Target)",
                )
            ]
        )
        forwarded_message = self._assert_redacted_error(
            lambda: c_abi_contract._dynamic_exports(
                forwarded_output,
                "windows",
            ),
            "forwarded export",
            secret,
        )
        self.assertRegex(forwarded_message, r"sha256=[0-9a-f]{64}")

        for platform in ("macos", "linux", "windows"):
            with self.subTest(extra_export=platform), tempfile.TemporaryDirectory() as temporary:
                library = self._library(pathlib.Path(temporary), platform)
                identity = self.contract.document["package"]["platforms"][platform]

                def runner(command: list[str]) -> str:
                    if platform == "macos":
                        if command[:2] == ["nm", "-gUj"]:
                            return self._nm_exports(underscore=True) + f"_{secret}\n"
                        if command[:2] == ["otool", "-D"]:
                            return f"{library}:\n{identity['install_name']}\n"
                        if command[:2] == ["otool", "-L"]:
                            return (
                                f"{library}:\n\t{identity['install_name']} "
                                f"(compatibility version {identity['compatibility_version']}, "
                                f"current version {identity['current_version']})\n"
                            )
                    elif platform == "linux":
                        if command[0] == "nm":
                            return (
                                "".join(
                                    f"{name} T 0 0\n"
                                    for name in sorted(self.contract.export_names)
                                )
                                + f"{secret} T 0 0\n"
                            )
                        if command[0] == "readelf":
                            return (
                                " 0x000000000000000e (SONAME) Library soname: "
                                f"[{identity['soname']}]\n"
                            )
                    else:
                        names = sorted(self.contract.export_names) + [secret]
                        return dumpbin_document(
                            [
                                export_row(
                                    index,
                                    f"{index - 1:X}",
                                    "00001000",
                                    f"{name} = {name}",
                                )
                                for index, name in enumerate(names, start=1)
                            ]
                        )
                    self.fail(f"unexpected command: {command}")

                message = self._assert_redacted_error(
                    lambda: c_abi_contract.verify_dynamic_library(
                        self.contract,
                        library,
                        platform,
                        runner=runner,
                    ),
                    "extra_count=1",
                    secret,
                )
                self.assertIn(
                    f"extra_sha256={hashlib.sha256(secret.encode()).hexdigest()}",
                    message,
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            macos_library = self._library(root, "macos")
            macos_identity = self.contract.document["package"]["platforms"]["macos"]

            def wrong_macos_install_name(command: list[str]) -> str:
                if command[0] == "nm":
                    return self._nm_exports(underscore=True)
                if command[:2] == ["otool", "-D"]:
                    return f"{macos_library}:\n@rpath/{secret}.dylib\n"
                self.fail(f"unexpected command: {command}")

            self._assert_redacted_error(
                lambda: c_abi_contract.verify_dynamic_library(
                    self.contract,
                    macos_library,
                    "macos",
                    runner=wrong_macos_install_name,
                ),
                "install name differs",
                secret,
            )

            def wrong_macos_linkage(command: list[str]) -> str:
                if command[0] == "nm":
                    return self._nm_exports(underscore=True)
                if command[:2] == ["otool", "-D"]:
                    return f"{macos_library}:\n{macos_identity['install_name']}\n"
                if command[:2] == ["otool", "-L"]:
                    return (
                        f"{macos_library}:\n\t@rpath/{secret}.dylib "
                        "(compatibility version 2.0.0, current version 2.0.0)\n"
                    )
                self.fail(f"unexpected command: {command}")

            self._assert_redacted_error(
                lambda: c_abi_contract.verify_dynamic_library(
                    self.contract,
                    macos_library,
                    "macos",
                    runner=wrong_macos_linkage,
                ),
                "versions differ",
                secret,
            )

            linux_library = self._library(root, "linux")

            def wrong_linux_soname(command: list[str]) -> str:
                if command[0] == "nm":
                    return "".join(
                        f"{name} T 0 0\n"
                        for name in sorted(self.contract.export_names)
                    )
                if command[0] == "readelf":
                    return (
                        " 0x000000000000000e (SONAME) Library soname: "
                        f"[{secret}]\n"
                    )
                self.fail(f"unexpected command: {command}")

            self._assert_redacted_error(
                lambda: c_abi_contract.verify_dynamic_library(
                    self.contract,
                    linux_library,
                    "linux",
                    runner=wrong_linux_soname,
                ),
                "SONAME differs",
                secret,
            )

    def test_windows_library_passes_and_exact_export_set_is_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            library = self._library(pathlib.Path(temporary), "windows")

            def export_row(
                ordinal: int, hint: str, rva: str, payload: str
            ) -> str:
                return f"{ordinal:>12}{hint:>5}{rva:>9}{payload}"

            def dumpbin(
                extra: str | None = None,
                omit: str | None = None,
                trailing_row: str | None = None,
                *,
                declared_functions: int | None = None,
                declared_names: int | None = None,
                hint_offset: int = 0,
                internal_template: str | None = "{name}",
                include_summary: bool = True,
                ordinal_base: int = 1,
                shared_first_ordinal: bool = False,
                duplicate_hint: bool = False,
                duplicate_summary: bool = False,
            ):
                names = sorted(self.contract.export_names - ({omit} if omit else set()))
                if extra is not None:
                    names.append(extra)

                def runner(command: list[str]) -> str:
                    self.assertEqual(command[0], "dumpbin")
                    row_total = len(names) + (1 if trailing_row is not None else 0)
                    functions = (
                        row_total
                        if declared_functions is None
                        else declared_functions
                    )
                    named = row_total if declared_names is None else declared_names
                    rows = [
                        f"        {ordinal_base} ordinal base",
                        f"        {functions} number of functions",
                        f"        {named} number of names",
                        "",
                        "    ordinal hint RVA      name",
                    ]
                    for index, name in enumerate(names, start=1):
                        ordinal = ordinal_base + index - 1
                        if shared_first_ordinal and index == 2:
                            ordinal = ordinal_base
                        hint = index - 1 + hint_offset
                        if duplicate_hint and index == 2:
                            hint = 0
                        payload = name
                        if internal_template is not None:
                            payload += " = " + internal_template.format(name=name)
                        rows.append(
                            export_row(
                                ordinal,
                                f"{hint:X}",
                                "00001000",
                                payload,
                            )
                        )
                    if trailing_row is not None:
                        rows.append(trailing_row)
                    if include_summary:
                        rows.extend(["", "  Summary", "", "        1000 .text"])
                        if duplicate_summary:
                            rows.extend(["", "  Summary"])
                    return "\n".join(rows) + "\n"

                return runner

            c_abi_contract.verify_dynamic_library(
                self.contract, library, "windows", runner=dumpbin()
            )
            for internal_template in (
                None,
                "_{name}",
                "@ILT+640(_{name})",
                "{name} (undecorated symbol annotation)",
            ):
                with self.subTest(internal_template=internal_template):
                    c_abi_contract.verify_dynamic_library(
                        self.contract,
                        library,
                        "windows",
                        runner=dumpbin(internal_template=internal_template),
                    )
            c_abi_contract.verify_dynamic_library(
                self.contract,
                library,
                "windows",
                runner=dumpbin(declared_functions=12, ordinal_base=5),
            )
            c_abi_contract.verify_dynamic_library(
                self.contract,
                library,
                "windows",
                runner=dumpbin(shared_first_ordinal=True),
            )
            with self.assertRaisesRegex(CAbiContractError, "extra_count=1"):
                c_abi_contract.verify_dynamic_library(
                    self.contract,
                    library,
                    "windows",
                    runner=dumpbin(extra="q_periapt_surprise"),
                )
            with self.assertRaisesRegex(CAbiContractError, "extra_count=1"):
                c_abi_contract.verify_dynamic_library(
                    self.contract,
                    library,
                    "windows",
                    runner=dumpbin(extra="qpn_mlkem_bridge_leak"),
                )
            with self.assertRaisesRegex(CAbiContractError, "extra_count=1"):
                c_abi_contract.verify_dynamic_library(
                    self.contract,
                    library,
                    "windows",
                    runner=dumpbin(extra="unexpected_export"),
                )
            with self.assertRaisesRegex(CAbiContractError, "defines export more than once"):
                c_abi_contract.verify_dynamic_library(
                    self.contract,
                    library,
                    "windows",
                    runner=dumpbin(extra="q_periapt_version"),
                )
            with self.assertRaisesRegex(CAbiContractError, "ordinal-only export"):
                c_abi_contract.verify_dynamic_library(
                    self.contract,
                    library,
                    "windows",
                    runner=dumpbin(
                        trailing_row=export_row(10, "", "00002000", "[NONAME]"),
                        declared_functions=10,
                        declared_names=9,
                    ),
                )
            with self.assertRaisesRegex(CAbiContractError, "cannot parse dumpbin"):
                c_abi_contract.verify_dynamic_library(
                    self.contract,
                    library,
                    "windows",
                    runner=dumpbin(trailing_row="malformed export row"),
                )
            for target in ("KERNEL32.Sleep", "NTDLL.#27"):
                with self.subTest(forwarder=target), self.assertRaisesRegex(
                    CAbiContractError, "forwarded export"
                ):
                    c_abi_contract.verify_dynamic_library(
                        self.contract,
                        library,
                        "windows",
                        runner=dumpbin(
                            trailing_row=export_row(
                                10,
                                "9",
                                "",
                                "q_periapt_abi_version "
                                f"(forwarded to {target})",
                            )
                        ),
                    )
            with self.assertRaisesRegex(CAbiContractError, "cannot parse dumpbin"):
                c_abi_contract.verify_dynamic_library(
                    self.contract,
                    library,
                    "windows",
                    runner=dumpbin(
                        trailing_row=export_row(
                            10,
                            "9",
                            "00002000",
                            "q_periapt_abi_version (forwarded to KERNEL32.Sleep)",
                        )
                    ),
                )
            for rva, payload in (
                ("00000000", "unexpected_export = unexpected_export"),
                ("", "unexpected_export = unexpected_export"),
                ("00002000", "unexpected_export = internal = another"),
            ):
                with self.subTest(rva=rva, payload=payload), self.assertRaisesRegex(
                    CAbiContractError, "cannot parse dumpbin"
                ):
                    c_abi_contract.verify_dynamic_library(
                        self.contract,
                        library,
                        "windows",
                        runner=dumpbin(
                            trailing_row=export_row(10, "9", rva, payload)
                        ),
                    )
            with self.assertRaisesRegex(CAbiContractError, "named-export count"):
                c_abi_contract.verify_dynamic_library(
                    self.contract,
                    library,
                    "windows",
                    runner=dumpbin(declared_functions=9, declared_names=8),
                )
            with self.assertRaisesRegex(CAbiContractError, "hints do not cover"):
                c_abi_contract.verify_dynamic_library(
                    self.contract,
                    library,
                    "windows",
                    runner=dumpbin(hint_offset=1),
                )
            with self.assertRaisesRegex(CAbiContractError, "hint more than once"):
                c_abi_contract.verify_dynamic_library(
                    self.contract,
                    library,
                    "windows",
                    runner=dumpbin(duplicate_hint=True),
                )
            with self.assertRaisesRegex(CAbiContractError, "outside the declared"):
                c_abi_contract.verify_dynamic_library(
                    self.contract,
                    library,
                    "windows",
                    runner=dumpbin(
                        trailing_row=export_row(
                            11,
                            "9",
                            "00002000",
                            "unexpected_export = unexpected_export",
                        )
                    ),
                )
            with self.assertRaisesRegex(CAbiContractError, "one Summary"):
                c_abi_contract.verify_dynamic_library(
                    self.contract,
                    library,
                    "windows",
                    runner=dumpbin(include_summary=False),
                )
            with self.assertRaisesRegex(CAbiContractError, "one Summary"):
                c_abi_contract.verify_dynamic_library(
                    self.contract,
                    library,
                    "windows",
                    runner=dumpbin(duplicate_summary=True),
                )

            def missing_name_count(command: list[str]) -> str:
                return dumpbin()(command).replace(
                    "        9 number of names\n", "", 1
                )

            with self.assertRaisesRegex(CAbiContractError, "number of names exactly once"):
                c_abi_contract.verify_dynamic_library(
                    self.contract,
                    library,
                    "windows",
                    runner=missing_name_count,
                )
            with self.assertRaisesRegex(CAbiContractError, "missing=.*q_periapt_encapsulate"):
                c_abi_contract.verify_dynamic_library(
                    self.contract,
                    library,
                    "windows",
                    runner=dumpbin(omit="q_periapt_encapsulate"),
                )

    def test_default_runner_accepts_only_clean_strict_utf8_stdout(self) -> None:
        self.assertEqual(
            c_abi_contract._default_runner(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-c",
                    "import sys; sys.stdout.buffer.write(b'ok\\n')",
                ]
            ),
            "ok\n",
        )

        invalid_secret = "ghp_INVALID_UTF8_SECRET_ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        invalid_payload = invalid_secret.encode() + b"\xff"
        with self.assertRaises(CAbiContractError) as captured:
            c_abi_contract._default_runner(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-c",
                    (
                        "import sys; "
                        f"sys.stdout.buffer.write({invalid_payload!r})"
                    ),
                ]
            )
        self.assertIn("stdout is not strict UTF-8", str(captured.exception))
        self.assertIn(
            f"offset={len(invalid_secret.encode())}",
            str(captured.exception),
        )
        self.assertIn(
            f"stdout_bytes={len(invalid_payload)}",
            str(captured.exception),
        )
        self.assertIn(
            f"stdout_sha256={hashlib.sha256(invalid_payload).hexdigest()}",
            str(captured.exception),
        )
        rendered = "".join(
            traceback.format_exception(
                type(captured.exception),
                captured.exception,
                captured.exception.__traceback__,
            )
        )
        self.assertNotIn(invalid_secret, rendered)
        self.assertIsNone(captured.exception.__cause__)

    def test_default_runner_rejects_diagnostics_and_failures_without_leaking_output(
        self,
    ) -> None:
        secret = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"
        cases = (
            (
                "diagnostics",
                f"import sys; sys.stderr.write({secret!r})",
                "emitted diagnostics",
            ),
            (
                "nonzero",
                (
                    "import sys; "
                    f"sys.stdout.write({secret!r}); "
                    f"sys.stderr.write({secret!r}); "
                    "raise SystemExit(7)"
                ),
                "exit_code=7",
            ),
        )
        for label, script, expected in cases:
            with self.subTest(label=label):
                with self.assertRaises(CAbiContractError) as captured:
                    c_abi_contract._default_runner(
                        [sys.executable, "-I", "-S", "-c", script]
                    )
                message = str(captured.exception)
                rendered = "".join(
                    traceback.format_exception(
                        type(captured.exception),
                        captured.exception,
                        captured.exception.__traceback__,
                    )
                )
                self.assertIn(expected, message)
                self.assertRegex(message, r"sha256=[0-9a-f]{64}")
                expected_digest = hashlib.sha256(secret.encode()).hexdigest()
                self.assertIn(f"stderr_bytes={len(secret.encode())}", message)
                self.assertIn(f"stderr_sha256={expected_digest}", message)
                if label == "nonzero":
                    self.assertIn(f"stdout_bytes={len(secret.encode())}", message)
                    self.assertIn(f"stdout_sha256={expected_digest}", message)
                self.assertNotIn(secret, rendered)
                self.assertIsNone(captured.exception.__cause__)

    def test_default_runner_enforces_both_output_limits(self) -> None:
        secret = "ghp_OUTPUT_LIMIT_SECRET_ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        for stream in ("stdout", "stderr"):
            with self.subTest(stream=stream), mock.patch.object(
                c_abi_contract,
                f"MAX_INSPECTOR_{stream.upper()}_BYTES",
                32,
            ):
                script = (
                    "import sys; "
                    f"secret={secret!r}.encode(); "
                    f"sys.{stream}.buffer.write(secret * 256); "
                    f"sys.{stream}.flush()"
                )
                with self.assertRaises(CAbiContractError) as captured:
                    c_abi_contract._default_runner(
                        [sys.executable, "-I", "-S", "-c", script]
                    )
                message = str(captured.exception)
                rendered = "".join(
                    traceback.format_exception(
                        type(captured.exception),
                        captured.exception,
                        captured.exception.__traceback__,
                    )
                )
                self.assertIn(f"{stream} exceeded 32-byte limit", message)
                self.assertNotIn(secret, rendered)

    def test_default_runner_enforces_timeout_and_reaps_process(self) -> None:
        started = time.monotonic()
        with (
            mock.patch.object(
                c_abi_contract,
                "INSPECTOR_TIMEOUT_SECONDS",
                0.05,
            ),
            mock.patch.object(
                c_abi_contract,
                "INSPECTOR_TERMINATION_SECONDS",
                1.0,
            ),
            mock.patch.object(
                c_abi_contract,
                "INSPECTOR_READER_JOIN_SECONDS",
                1.0,
            ),
            self.assertRaises(CAbiContractError) as captured,
        ):
            c_abi_contract._default_runner(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-c",
                    (
                        "import time; "
                        "secret='ghp_TIMEOUT_SECRET_ABCDEFGHIJKLMNOPQRSTUVWXYZ'; "
                        "time.sleep(10)"
                    ),
                ]
            )
        self.assertIn("exceeded 0.05-second timeout", str(captured.exception))
        rendered = "".join(
            traceback.format_exception(
                type(captured.exception),
                captured.exception,
                captured.exception.__traceback__,
            )
        )
        self.assertNotIn("ghp_TIMEOUT_SECRET_ABCDEFGHIJKLMNOPQRSTUVWXYZ", rendered)
        self.assertLess(time.monotonic() - started, 3.0)

    def test_static_nm_diagnostics_are_bounded_and_do_not_echo_rows(self) -> None:
        archive = "/private/archive-token.a"
        secret = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"
        accepted_rows = (
            f"{archive}:{'m' * c_abi_contract.MAX_LLVM_NM_MEMBER_CHARS}: ordinary",
            f"{archive}:member.o: {'s' * c_abi_contract.MAX_LLVM_NM_SYMBOL_CHARS}",
        )
        for index, row in enumerate(accepted_rows, start=1):
            with self.subTest(accepted_boundary=index):
                self.assertEqual(
                    c_abi_contract._static_reserved_exports(
                        row + "\n",
                        "linux",
                        archive,
                    ),
                    frozenset(),
                )

        valid_row = f"{archive}:member.o: ordinary"
        malformed_secret_row = (
            f"wrong-prefix:member.o: q_periapt_bad_{secret}"
        )
        row_prefix = f"{archive}:"
        row_suffix = ": ordinary"
        row_filler = "r" * (
            c_abi_contract.MAX_LLVM_NM_ROW_CHARS
            + 1
            - len(row_prefix)
            - len(row_suffix)
        )
        oversized_row = f"{row_prefix}{row_filler}{row_suffix}"
        cases = (
            (
                valid_row + "\n" + malformed_secret_row,
                2,
                malformed_secret_row,
            ),
            (
                f"{archive}:{'m' * (c_abi_contract.MAX_LLVM_NM_MEMBER_CHARS + 1)}: ordinary",
                1,
                f"{archive}:{'m' * (c_abi_contract.MAX_LLVM_NM_MEMBER_CHARS + 1)}: ordinary",
            ),
            (
                f"{archive}:member.o: {'s' * (c_abi_contract.MAX_LLVM_NM_SYMBOL_CHARS + 1)}",
                1,
                f"{archive}:member.o: {'s' * (c_abi_contract.MAX_LLVM_NM_SYMBOL_CHARS + 1)}",
            ),
            (
                oversized_row,
                1,
                oversized_row,
            ),
        )
        for index, (output, line_number, rejected_row) in enumerate(cases, start=1):
            with self.subTest(index=index):
                with self.assertRaises(CAbiContractError) as captured:
                    c_abi_contract._static_reserved_exports(
                        output + "\n",
                        "linux",
                        archive,
                    )
                message = str(captured.exception)
                expected_sha256 = hashlib.sha256(
                    rejected_row.encode("utf-8", errors="surrogatepass")
                ).hexdigest()
                self.assertIn(f"row={line_number}", message)
                self.assertIn(f"chars={len(rejected_row)}", message)
                self.assertIn(f"sha256={expected_sha256}", message)
                self.assertNotIn(secret, message)
                self.assertNotIn("m" * 128, message)
                self.assertNotIn("r" * 128, message)
                self.assertNotIn("s" * 128, message)

    def test_static_nm_reserved_symbol_errors_are_redacted(self) -> None:
        archive = "/private/archive-token.a"
        symbol = "q_periapt_secret_token_do_not_echo_abcdefghijklmnop"
        cases = (
            (
                "linux-decorated",
                "linux",
                f"{archive}:member.o: _{symbol}",
                "decorated reserved symbol",
                1,
            ),
            (
                "macos-undecorated",
                "macos",
                f"{archive}:member.o: {symbol}",
                "undecorated reserved symbol",
                1,
            ),
            (
                "duplicate",
                "linux",
                (
                    f"{archive}:member.o: {symbol}\n"
                    f"{archive}:other.o: {symbol}"
                ),
                "defines reserved symbol more than once",
                2,
            ),
        )
        for label, platform, output, expected, line_number in cases:
            with self.subTest(label=label):
                with self.assertRaises(CAbiContractError) as captured:
                    c_abi_contract._static_reserved_exports(
                        output + "\n",
                        platform,
                        archive,
                    )
                message = str(captured.exception)
                self.assertIn(expected, message)
                self.assertIn(f"row={line_number}", message)
                self.assertRegex(message, r"sha256=[0-9a-f]{64}")
                self.assertNotIn(symbol, message)

    def test_static_library_reserved_namespace_is_exact_and_fail_closed(self) -> None:
        for platform in ("macos", "linux", "windows"):
            with self.subTest(platform=platform), tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary)
                library = self._static_library(root, platform)
                llvm_nm = self._llvm_nm(root)

                def output(
                    command: list[str],
                    *,
                    extra: str | None = None,
                    omit: str | None = None,
                    duplicate: str | None = None,
                    malformed=None,
                ) -> str:
                    self.assertEqual(
                        command[:-1],
                        [
                            str(llvm_nm),
                            "--defined-only",
                            "--extern-only",
                            "--no-demangle",
                            "--print-file-name",
                            "--just-symbol-name",
                        ],
                    )
                    archive = pathlib.Path(command[-1])
                    self.assertTrue(archive.is_absolute())
                    self.assertNotEqual(archive, library)
                    self.assertRegex(
                        archive.name,
                        rf"^archive-[0-9a-f]{{64}}{re.escape(library.suffix)}$",
                    )
                    self.assertEqual(archive.read_bytes(), library.read_bytes())
                    if os.name != "nt":
                        self.assertEqual(archive.stat().st_mode & 0o077, 0)
                        self.assertEqual(archive.parent.stat().st_mode & 0o077, 0)

                    def row(member: str, symbol: str) -> str:
                        return f"{archive}:{member}: {symbol}"

                    names = sorted(
                        self.contract.export_names - ({omit} if omit else set())
                    )
                    if extra is not None:
                        names.append(extra)
                    if duplicate is not None:
                        names.append(duplicate)
                    lines = [
                        row("q_periapt_ffi_abi2.object.o", "__rust_internal_symbol"),
                        row(
                            "q_periapt_ffi_abi2.object.o",
                            "__ZN16q_periapt_policy10nist_level17h0123456789abcdefE",
                        ),
                        row(
                            "q_periapt_ffi_abi2.object.o",
                            "qpn_mlkem_bridge_v1_2_0_768_decapsulate",
                        ),
                    ]
                    if platform == "windows":
                        lines.extend(
                            (
                                row(
                                    "bcryptprimitives.dll",
                                    "__imp_BCryptGenRandom",
                                ),
                                row(
                                    r"C:\a\rust\rust\build\x86_64-pc-windows-msvc"
                                    r"\stage1-std\x86_64-pc-windows-msvc\dist\build"
                                    r"\compiler_builtins-c006b7d82162e693\out"
                                    r"\d067f95df2315da6-ucmpti2.o",
                                    "__ucmpti2",
                                ),
                            )
                        )
                    prefix = "_" if platform == "macos" else ""
                    lines.extend(
                        row("q_periapt_ffi_abi2.object.o", f"{prefix}{name}")
                        for name in names
                    )
                    if malformed is not None:
                        lines.append(
                            malformed(str(archive))
                            if callable(malformed)
                            else malformed
                        )
                    return "\n".join(lines) + "\n"

                def runner(command: list[str]) -> str:
                    return output(command)

                c_abi_contract.verify_static_library(
                    self.contract,
                    library,
                    platform,
                    llvm_nm,
                    runner=runner,
                )
                if platform == "windows":
                    c_abi_contract.verify_static_library(
                        self.contract,
                        library,
                        platform,
                        llvm_nm,
                        runner=lambda command: output(command).replace(
                            "\n", "\r\n"
                        ),
                    )

                forged_version = (
                    "_q_periapt_version"
                    if platform == "macos"
                    else "q_periapt_version"
                )
                cases = (
                    (
                        {"extra": "q_periapt_surprise"},
                        "extra_count=1",
                    ),
                    (
                        {"omit": "q_periapt_encapsulate"},
                        "missing=.*q_periapt_encapsulate",
                    ),
                    (
                        {"duplicate": "q_periapt_version"},
                        "defines reserved symbol more than once",
                    ),
                    (
                        {"malformed": "q_periapt_bad symbol"},
                        "cannot parse llvm-nm static reserved-symbol row",
                    ),
                    (
                        {
                            "malformed": lambda archive: (
                                f"{archive}:member.o: q_periapt_bad symbol"
                            )
                        },
                        "cannot parse llvm-nm static reserved-symbol row",
                    ),
                    (
                        {
                            "malformed": lambda archive: (
                                f"{archive}:evil: member.obj: ordinary"
                            )
                        },
                        "cannot parse llvm-nm static reserved-symbol row",
                    ),
                    (
                        {
                            "malformed": lambda archive: (
                                f"{archive}:weird.obj: q_periapt_extra: benign"
                            )
                        },
                        "cannot parse llvm-nm static reserved-symbol row",
                    ),
                    (
                        {
                            "malformed": (
                                r"D:\a\q-periapt\q-periapt\target\static\out"
                                r"\ea708c7824d36062-mlkem_bridge.o:"
                            )
                        },
                        "cannot parse llvm-nm static reserved-symbol row",
                    ),
                    (
                        {
                            "omit": "q_periapt_version",
                            "malformed": lambda archive, symbol=forged_version: (
                                f"{archive}:evil.obj: __ordinary\n"
                                f"forged-prefix:member.o: {symbol}"
                            ),
                        },
                        "cannot parse llvm-nm static reserved-symbol row",
                    ),
                    (
                        {
                            "omit": "q_periapt_version",
                            "malformed": lambda archive, symbol=forged_version: (
                                f"{archive}:evil.obj: __ordinary\r"
                                f"forged-prefix:member.o: {symbol}"
                            ),
                        },
                        "cannot parse llvm-nm static reserved-symbol row",
                    ),
                    (
                        {
                            "omit": "q_periapt_version",
                            "malformed": lambda archive, symbol=forged_version: (
                                f"{archive}:evil.obj: __ordinary\r\n"
                                f"forged-prefix:member.o: {symbol}"
                            ),
                        },
                        "cannot parse llvm-nm static reserved-symbol row",
                    ),
                    (
                        {
                            "omit": "q_periapt_version",
                            "malformed": lambda archive, symbol=forged_version: (
                                f"{archive}:evil.obj: __ordinary\u2028"
                                f"forged-prefix:member.o: {symbol}"
                            ),
                        },
                        "cannot parse llvm-nm static reserved-symbol row",
                    ),
                )
                for arguments, message in cases:
                    with self.subTest(platform=platform, message=message):
                        with self.assertRaisesRegex(CAbiContractError, message):
                            c_abi_contract.verify_static_library(
                                self.contract,
                                library,
                                platform,
                                llvm_nm,
                                runner=lambda command, values=arguments: output(
                                    command, **values
                                ),
                            )

                private_extra = (
                    "q_periapt_secret_token_do_not_echo_abcdefghijklmnop"
                )
                with self.assertRaises(CAbiContractError) as captured:
                    c_abi_contract.verify_static_library(
                        self.contract,
                        library,
                        platform,
                        llvm_nm,
                        runner=lambda command: output(
                            command,
                            extra=private_extra,
                        ),
                    )
                self.assertIn("extra_count=1", str(captured.exception))
                self.assertIn(
                    "extra_sha256="
                    + hashlib.sha256(private_extra.encode()).hexdigest(),
                    str(captured.exception),
                )
                self.assertIn(
                    "forbidden_sha256=" + hashlib.sha256(b"").hexdigest(),
                    str(captured.exception),
                )
                self.assertNotIn(private_extra, str(captured.exception))

                with self.assertRaises(CAbiContractError) as captured:
                    c_abi_contract.verify_static_library(
                        self.contract,
                        library,
                        platform,
                        llvm_nm,
                        runner=lambda command: output(
                            command,
                            extra="q_periapt_combine",
                        ),
                    )
                self.assertIn("extra_count=1", str(captured.exception))
                self.assertIn("forbidden_count=1", str(captured.exception))
                combine_sha256 = hashlib.sha256(
                    b"q_periapt_combine"
                ).hexdigest()
                self.assertIn(
                    f"extra_sha256={combine_sha256}",
                    str(captured.exception),
                )
                self.assertIn(
                    f"forbidden_sha256={combine_sha256}",
                    str(captured.exception),
                )
                self.assertNotIn("q_periapt_combine", str(captured.exception))

                if platform == "macos":
                    with self.assertRaisesRegex(
                        CAbiContractError,
                        "undecorated reserved symbol on macos",
                    ):
                        c_abi_contract.verify_static_library(
                            self.contract,
                            library,
                            platform,
                            llvm_nm,
                            runner=lambda command: output(
                                command,
                                omit="q_periapt_version",
                                malformed=lambda archive: (
                                    f"{archive}:member.o: q_periapt_version"
                                ),
                            ),
                        )
                else:
                    with self.assertRaisesRegex(
                        CAbiContractError,
                        f"decorated reserved symbol on {platform}",
                    ):
                        c_abi_contract.verify_static_library(
                            self.contract,
                            library,
                            platform,
                            llvm_nm,
                            runner=lambda command: output(
                                command,
                                omit="q_periapt_version",
                                malformed=lambda archive: (
                                    f"{archive}:member.o: _q_periapt_version"
                                ),
                            ),
                        )

    def test_static_library_authenticated_snapshot_rejects_mutation(self) -> None:
        for target in ("source", "authenticated-copy"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary)
                library = self._static_library(root, "linux")
                llvm_nm = self._llvm_nm(root)
                inspected: list[pathlib.Path] = []

                def runner(command: list[str]) -> str:
                    archive = pathlib.Path(command[-1])
                    inspected.append(archive)
                    output = "".join(
                        f"{archive}:member.o: {name}\n"
                        for name in sorted(self.contract.export_names)
                    )
                    if target == "source":
                        library.write_bytes(b"changed")
                    else:
                        archive.write_bytes(b"changed")
                    return output

                with self.assertRaisesRegex(CAbiContractError, "changed during"):
                    c_abi_contract.verify_static_library(
                        self.contract,
                        library,
                        "linux",
                        llvm_nm,
                        runner=runner,
                    )
                self.assertEqual(len(inspected), 1)
                self.assertFalse(inspected[0].exists())
                self.assertFalse(inspected[0].parent.exists())

    def test_static_library_authentication_path_is_fresh_per_call(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            library = self._static_library(root, "linux")
            llvm_nm = self._llvm_nm(root)
            inspected: list[pathlib.Path] = []

            def runner(command: list[str]) -> str:
                archive = pathlib.Path(command[-1])
                inspected.append(archive)
                return "".join(
                    f"{archive}:member.o: {name}\n"
                    for name in sorted(self.contract.export_names)
                )

            with mock.patch.object(
                c_abi_contract.secrets,
                "token_hex",
                side_effect=("1" * 64, "2" * 64),
            ) as token_hex:
                for _ in range(2):
                    c_abi_contract.verify_static_library(
                        self.contract,
                        library,
                        "linux",
                        llvm_nm,
                        runner=runner,
                    )

            self.assertEqual(token_hex.call_count, 2)
            token_hex.assert_has_calls([mock.call(32), mock.call(32)])
            self.assertEqual(
                [path.name for path in inspected],
                [f"archive-{'1' * 64}.a", f"archive-{'2' * 64}.a"],
            )
            self.assertNotEqual(inspected[0], inspected[1])
            self.assertTrue(all(not path.exists() for path in inspected))

    def test_windows_private_snapshot_does_not_require_fchmod(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "snapshot.lib"
            with (
                mock.patch.object(c_abi_contract.os, "name", "nt"),
                mock.patch.object(
                    c_abi_contract.os,
                    "fchmod",
                    side_effect=AssertionError("Windows must not call fchmod"),
                    create=True,
                ),
            ):
                c_abi_contract._write_private_snapshot(path, b"snapshot")
            self.assertEqual(path.read_bytes(), b"snapshot")

    def test_static_library_requires_expected_filename_absolute_nm_and_regular_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            llvm_nm = self._llvm_nm(root)
            wrong = root / "libq_periapt_ffi.a"
            wrong.write_bytes(b"fixture")
            with self.assertRaisesRegex(CAbiContractError, "static-library filename differs"):
                c_abi_contract.verify_static_library(
                    self.contract,
                    wrong,
                    "linux",
                    llvm_nm,
                    runner=lambda _command: "",
                )

            library = self._static_library(root, "linux")
            with self.assertRaisesRegex(CAbiContractError, "llvm-nm path must be absolute"):
                c_abi_contract.verify_static_library(
                    self.contract,
                    library,
                    "linux",
                    pathlib.Path("llvm-nm"),
                    runner=lambda _command: "",
                )

            symlink = root / "static-link.a"
            symlink.symlink_to(library.name)
            with self.assertRaisesRegex(CAbiContractError, "non-symlink regular file"):
                c_abi_contract.verify_static_library(
                    self.contract,
                    symlink,
                    "linux",
                    llvm_nm,
                    runner=lambda _command: "",
                )

    def test_wrong_filename_unknown_platform_and_symlink_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            wrong_name = root / "libq_periapt_ffi.dylib"
            wrong_name.write_bytes(b"fixture")
            with self.assertRaisesRegex(CAbiContractError, "filename differs"):
                c_abi_contract.verify_dynamic_library(
                    self.contract, wrong_name, "macos", runner=lambda _command: ""
                )
            with self.assertRaisesRegex(CAbiContractError, "unknown dynamic-library platform"):
                c_abi_contract.verify_dynamic_library(
                    self.contract, wrong_name, "solaris", runner=lambda _command: ""
                )

            target = self._library(root, "linux")
            symlink = root / "linked-library"
            symlink.symlink_to(target)
            with self.assertRaisesRegex(CAbiContractError, "non-symlink regular file"):
                c_abi_contract.verify_dynamic_library(
                    self.contract, symlink, "linux", runner=lambda _command: ""
                )


if __name__ == "__main__":
    unittest.main()
