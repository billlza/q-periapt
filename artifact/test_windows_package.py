from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import tomllib
import unittest

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


INHERITING_DESCENDANT_SCRIPT = """
import os
import pathlib
import sys
import time

os.write(1, b"descendant-stdout\\n")
os.write(2, b"descendant-stderr\\n")
pathlib.Path(sys.argv[1]).write_text(str(os.getpid()), encoding="ascii")
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

    def _package(self, root: pathlib.Path) -> pathlib.Path:
        package = root / (
            "q-periapt-c-abi2-0.1.0-alpha.2-x86_64-pc-windows-msvc"
        )
        for relative in windows_package.EXPECTED_PAYLOAD_FILES:
            path = package / relative
            path.parent.mkdir(parents=True, exist_ok=True)
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

    def test_tampering_extra_files_and_symlinks_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            package = self._package(root)
            self._create(package)

            (package / "bin/q_periapt_ffi_abi2.dll").write_bytes(b"tampered")
            with self.assertRaisesRegex(WindowsPackageError, "(?:size|hash) mismatch"):
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
            "function Resolve-TrustedToolchainFile",
            "[System.IO.FileAttributes]::ReparsePoint",
            "$MsvcInstallation = Initialize-MsvcEnvironment",
            '-TrustedRoot $MsvcInstallation',
            '-ExpectedName "dumpbin.exe"',
            '"--dumpbin", $Dumpbin',
            '"--sha256", $ExpectedArchiveSha256',
        ):
            self.assertIn(token, script)
        for forbidden in (
            "function Get-DllDependencies",
            '"--dependency"',
            '"--expected-dependency"',
        ):
            self.assertNotIn(forbidden, script)
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
