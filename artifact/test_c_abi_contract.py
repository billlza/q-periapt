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

    def _nm_exports(self, *, underscore: bool = False, omit: str | None = None) -> str:
        names = sorted(self.contract.export_names - ({omit} if omit else set()))
        prefix = "_" if underscore else ""
        return "".join(f"{prefix}{name}\n" for name in names)

    def test_contract_and_normalized_header_pass(self) -> None:
        self.assertEqual(self.contract.document["abi"]["major"], 2)
        self.assertEqual(self.contract.document["package"]["semver"], "0.1.0-alpha.1")
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

            def dumpbin(extra: str | None = None, omit: str | None = None):
                names = sorted(self.contract.export_names - ({omit} if omit else set()))
                if extra is not None:
                    names.append(extra)

                def runner(command: list[str]) -> str:
                    self.assertEqual(command[0], "dumpbin")
                    rows = ["ordinal hint RVA      name"]
                    rows.extend(
                        f"      {index}    0 00001000 {name}"
                        for index, name in enumerate(names, start=1)
                    )
                    return "\n".join(rows) + "\n"

                return runner

            c_abi_contract.verify_dynamic_library(
                self.contract, library, "windows", runner=dumpbin()
            )
            with self.assertRaisesRegex(CAbiContractError, "extra=.*q_periapt_surprise"):
                c_abi_contract.verify_dynamic_library(
                    self.contract,
                    library,
                    "windows",
                    runner=dumpbin(extra="q_periapt_surprise"),
                )
            with self.assertRaisesRegex(CAbiContractError, "missing=.*q_periapt_encapsulate"):
                c_abi_contract.verify_dynamic_library(
                    self.contract,
                    library,
                    "windows",
                    runner=dumpbin(omit="q_periapt_encapsulate"),
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
