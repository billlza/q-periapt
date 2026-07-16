from __future__ import annotations

import copy
import json
import pathlib
import tempfile
import unittest

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

            with self.assertRaisesRegex(CAbiContractError, "extra=.*qpn_mlkem_bridge_leak"):
                c_abi_contract.verify_dynamic_library(
                    self.contract, library, "macos", runner=extra_export
                )

            def generic_extra(command: list[str]) -> str:
                if command[:2] == ["nm", "-gUj"]:
                    return self._nm_exports(underscore=True) + "_unexpected_export\n"
                return runner(command)

            with self.assertRaisesRegex(CAbiContractError, "extra=.*unexpected_export"):
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

            with self.assertRaisesRegex(CAbiContractError, "extra=.*qpn_mlkem_bridge_leak"):
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
            with self.assertRaisesRegex(CAbiContractError, "extra=.*q_periapt_surprise"):
                c_abi_contract.verify_dynamic_library(
                    self.contract,
                    library,
                    "windows",
                    runner=dumpbin(extra="q_periapt_surprise"),
                )
            with self.assertRaisesRegex(CAbiContractError, "extra=.*qpn_mlkem_bridge_leak"):
                c_abi_contract.verify_dynamic_library(
                    self.contract,
                    library,
                    "windows",
                    runner=dumpbin(extra="qpn_mlkem_bridge_leak"),
                )
            with self.assertRaisesRegex(CAbiContractError, "extra=.*unexpected_export"):
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

    def test_static_library_reserved_namespace_is_exact_and_fail_closed(self) -> None:
        for platform in ("macos", "linux", "windows"):
            with self.subTest(platform=platform), tempfile.TemporaryDirectory() as temporary:
                root = pathlib.Path(temporary)
                library = self._static_library(root, platform)
                llvm_nm = self._llvm_nm(root)

                def output(
                    *,
                    extra: str | None = None,
                    omit: str | None = None,
                    duplicate: str | None = None,
                    malformed: str | None = None,
                ) -> str:
                    names = sorted(
                        self.contract.export_names - ({omit} if omit else set())
                    )
                    if extra is not None:
                        names.append(extra)
                    if duplicate is not None:
                        names.append(duplicate)
                    lines = [
                        "q_periapt_ffi_abi2.object.o:",
                        "__rust_internal_symbol",
                        "__ZN16q_periapt_policy10nist_level17h0123456789abcdefE",
                        "qpn_mlkem_bridge_v1_2_0_768_decapsulate",
                    ]
                    if platform == "windows":
                        lines.extend(
                            (
                                "bcryptprimitives.dll:",
                                "__imp_BCryptGenRandom",
                                "BCRYPTPRIMITIVES.DLL:",
                            )
                        )
                    prefix = "_" if platform == "macos" else ""
                    lines.extend(f"{prefix}{name}" for name in names)
                    if malformed is not None:
                        lines.append(malformed)
                    return "\n".join(lines) + "\n"

                def runner(command: list[str]) -> str:
                    self.assertEqual(
                        command,
                        [
                            str(llvm_nm),
                            "--defined-only",
                            "--extern-only",
                            "--just-symbol-name",
                            str(library),
                        ],
                    )
                    return output()

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
                        runner=lambda _command: output().replace("\n", "\r\n"),
                    )

                cases = (
                    (
                        output(extra="q_periapt_surprise"),
                        "extra=.*q_periapt_surprise",
                    ),
                    (
                        output(omit="q_periapt_encapsulate"),
                        "missing=.*q_periapt_encapsulate",
                    ),
                    (
                        output(duplicate="q_periapt_version"),
                        "defines reserved symbol more than once",
                    ),
                    (
                        output(malformed="q_periapt_bad symbol"),
                        "cannot parse llvm-nm static reserved-symbol row",
                    ),
                    (
                        output(malformed="T q_periapt_surprise"),
                        "cannot parse llvm-nm static reserved-symbol row",
                    ),
                    (
                        output(malformed="archive.o: q_periapt_surprise"),
                        "cannot parse llvm-nm static reserved-symbol row",
                    ),
                    (
                        output(malformed="q_periapt_surprise:"),
                        "cannot parse llvm-nm static reserved-symbol row",
                    ),
                )
                for nm_output, message in cases:
                    with self.subTest(platform=platform, message=message):
                        with self.assertRaisesRegex(CAbiContractError, message):
                            c_abi_contract.verify_static_library(
                                self.contract,
                                library,
                                platform,
                                llvm_nm,
                                runner=lambda _command, value=nm_output: value,
                            )

                if platform != "windows":
                    windows_import_heading = output(
                        malformed="bcryptprimitives.dll:"
                    )
                    with self.assertRaisesRegex(
                        CAbiContractError,
                        "cannot parse llvm-nm static reserved-symbol row",
                    ):
                        c_abi_contract.verify_static_library(
                            self.contract,
                            library,
                            platform,
                            llvm_nm,
                            runner=lambda _command, value=windows_import_heading: value,
                        )
                else:
                    malformed_import_headings = (
                        "q_periapt_surprise.dll:",
                        "Q_PERIAPT_SURPRISE.DLL:",
                        "_q_periapt_surprise.dll:",
                        "_Q_PERIAPT_SURPRISE.DLL:",
                        r"outside\bcryptprimitives.dll:",
                        "bcryptprimitives.dll::",
                        " bcryptprimitives.dll:",
                        "bcryptprimitives.dll: ",
                        "bcryptprimitives.dll: __imp_BCryptGenRandom",
                        "ſystem.dll:",
                        "Kernel32.dll:",
                    )
                    for malformed_heading in malformed_import_headings:
                        with self.subTest(malformed_heading=malformed_heading):
                            malformed_import_heading = output(
                                malformed=malformed_heading
                            )
                            with self.assertRaisesRegex(
                                CAbiContractError,
                                "cannot parse llvm-nm static reserved-symbol row",
                            ):
                                c_abi_contract.verify_static_library(
                                    self.contract,
                                    library,
                                    platform,
                                    llvm_nm,
                                    runner=lambda _command, value=(
                                        malformed_import_heading
                                    ): value,
                                )

                    import_heading_with_extra = output(
                        extra="q_periapt_surprise"
                    )
                    with self.assertRaisesRegex(
                        CAbiContractError,
                        "extra=.*q_periapt_surprise",
                    ):
                        c_abi_contract.verify_static_library(
                            self.contract,
                            library,
                            platform,
                            llvm_nm,
                            runner=lambda _command: import_heading_with_extra,
                        )

                if platform == "macos":
                    undecorated = output(
                        omit="q_periapt_version",
                        malformed="q_periapt_version",
                    )
                    with self.assertRaisesRegex(
                        CAbiContractError,
                        "undecorated reserved symbol on macos",
                    ):
                        c_abi_contract.verify_static_library(
                            self.contract,
                            library,
                            platform,
                            llvm_nm,
                            runner=lambda _command, value=undecorated: value,
                        )
                else:
                    decorated = output(
                        omit="q_periapt_version",
                        malformed="_q_periapt_version",
                    )
                    with self.assertRaisesRegex(
                        CAbiContractError,
                        f"decorated reserved symbol on {platform}",
                    ):
                        c_abi_contract.verify_static_library(
                            self.contract,
                            library,
                            platform,
                            llvm_nm,
                            runner=lambda _command, value=decorated: value,
                        )

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
