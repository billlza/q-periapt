#!/usr/bin/env python3
"""Regression tests for the fail-closed Android ELF/AAR verifier."""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import io
import pathlib
import stat
import subprocess
import tempfile
import textwrap
import unittest
import warnings
import zipfile

from claim_ledger import canonical_tree_digest, repository_paths
from git_provenance import run_git_text
from android_elf import (
    ABI_SPECS,
    FFI_EXPORTS,
    FFI_LIBRARY,
    JNI_LIBRARY,
    REQUIRED_AAR_ENTRIES,
    REQUIRED_ABIS,
    THIRD_PARTY_RUST_INVENTORY,
    AndroidVerificationError,
    audit_aar,
    audit_classes_jar,
    canonical_json as canonical_android_manifest_json,
    verify_aar,
    verify_expected_git_commit,
    verify_library,
    verify_manifest_source_provenance,
)
from third_party_licenses import canonical_json as canonical_license_inventory_json


CLASS_BYTES = b"\xca\xfe\xba\xbe\x00\x00\x00\x37"


def elf_header(abi: str) -> bytes:
    spec = ABI_SPECS[abi]
    header = bytearray(64)
    header[:7] = b"\x7fELF" + bytes((spec.elf_class, 1, 1))
    header[16:18] = (3).to_bytes(2, "little")
    header[18:20] = spec.machine.to_bytes(2, "little")
    return bytes(header)


def zip_bytes(entries: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(entries.items()):
            info = zipfile.ZipInfo(name, (2000, 1, 1, 0, 0, 0))
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
    return output.getvalue()


class AndroidElfVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def write_tool(self, name: str, body: str) -> pathlib.Path:
        path = self.root / name
        path.write_text("#!/usr/bin/env python3\n" + textwrap.dedent(body), encoding="utf-8")
        path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        return path

    def fake_tools(
        self,
        *,
        nm_exit: int = 0,
        nm_stderr: str = "",
        load_alignment: str = "0x4000",
    ) -> tuple[pathlib.Path, pathlib.Path]:
        exports_literal = repr(sorted(FFI_EXPORTS))
        nm = self.write_tool(
            "llvm-nm",
            f"""
            import pathlib
            import sys

            library = pathlib.Path(sys.argv[-1]).name
            symbols = {exports_literal} if library == {FFI_LIBRARY!r} else ["JNI_OnLoad"]
            for symbol in symbols:
                print(f"{{symbol}} T 100 8")
            if {nm_stderr!r}:
                print({nm_stderr!r}, file=sys.stderr)
            raise SystemExit({nm_exit})
            """,
        )
        readelf = self.write_tool(
            "llvm-readelf",
            f"""
            import pathlib
            import sys

            library = pathlib.Path(sys.argv[-1]).name
            print("Program Headers:")
            print("  Type Offset VirtAddr PhysAddr FileSiz MemSiz Flg Align")
            print("  LOAD 0x0 0x0 0x0 0x100 0x100 R E {load_alignment}")
            print("  GNU_RELRO 0x0 0x0 0x0 0x100 0x100 R 0x1")
            print("  GNU_STACK 0x0 0x0 0x0 0x0 0x0 RW 0x0")
            print("Section Headers:")
            print("  [ 0] NULL 0 0 0")
            print("  [ 1] .dynsym DYNSYM 0 0 0")
            print("  [ 2] .dynstr STRTAB 0 0 0")
            print("Dynamic section:")
            print(f"  0x000000000000000e (SONAME) Library soname: [{{library}}]")
            if library == {JNI_LIBRARY!r}:
                print("  0x0000000000000001 (NEEDED) Shared library: [libq_periapt_ffi_abi2.so]")
            print("  0x0000000000000001 (NEEDED) Shared library: [libc.so]")
            print("  0x000000000000001e (FLAGS) BIND_NOW")
            print("  0x000000006ffffffb (FLAGS_1) NOW")
            """,
        )
        return nm, readelf

    def write_library(self, abi: str, library: str) -> pathlib.Path:
        path = self.root / abi / library
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(elf_header(abi))
        return path

    def classes_jar(self) -> bytes:
        return zip_bytes({"dev/qperiapt/android/QPeriaptAndroid.class": CLASS_BYTES})

    def third_party_entries(self) -> dict[str, bytes]:
        license_data = b"Dependency license text\n"
        license_path = "THIRD_PARTY/rust/example-dependency-1.0.0/LICENSE"
        inventory = {
            "schema_version": 1,
            "kind": "qperiapt.third_party_rust_licenses",
            "root_package": "q-periapt-ffi",
            "target": "x86_64-linux-android",
            "packages": [
                {
                    "checksum": "a" * 64,
                    "license_expression": "MIT",
                    "name": "example-dependency",
                    "source": "registry+https://github.com/rust-lang/crates.io-index",
                    "version": "1.0.0",
                    "license_files": [
                        {
                            "bytes": len(license_data),
                            "path": license_path,
                            "sha256": hashlib.sha256(license_data).hexdigest(),
                        }
                    ],
                }
            ],
        }
        return {
            THIRD_PARTY_RUST_INVENTORY: canonical_license_inventory_json(inventory),
            "META-INF/" + license_path: license_data,
        }

    def aar_entries(self) -> dict[str, bytes]:
        entries: dict[str, bytes] = {}
        for name in REQUIRED_AAR_ENTRIES:
            if name == "classes.jar":
                entries[name] = self.classes_jar()
            elif name.startswith("jni/"):
                abi = name.split("/")[1]
                entries[name] = elf_header(abi)
            else:
                entries[name] = b"release-metadata\n"
        entries.update(self.third_party_entries())
        return entries

    def write_aar(self) -> pathlib.Path:
        path = self.root / "q-periapt-android-0.1.0-alpha.2.aar"
        path.write_bytes(zip_bytes(self.aar_entries()))
        return path

    def manifest_release_fixture(
        self,
    ) -> tuple[
        pathlib.Path,
        pathlib.Path,
        pathlib.Path,
        pathlib.Path,
        pathlib.Path,
        dict[str, object],
    ]:
        source_root = self.root
        source_files = {
            "artifact/android-aar.sh": b"#!/bin/sh\n",
            "artifact/android_elf.py": b"# verifier\n",
            "artifact/release_binary_scan.py": b"# scanner\n",
            "artifact/third_party_licenses.py": b"# license collector\n",
            "bindings/android/src/main/java/dev/qperiapt/android/QPeriaptAndroid.java": b"final class QPeriaptAndroid {}\n",
            "bindings/android/jni/qperiapt_jni.c": b"int qperiapt_jni_fixture;\n",
            "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json": b"{}\n",
        }
        (source_root / ".gitignore").write_text("target/\n", encoding="utf-8")
        for relative, data in source_files.items():
            path = source_root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        subprocess.run(["git", "init", "-q", str(source_root)], check=True)
        subprocess.run(
            ["git", "-C", str(source_root), "config", "user.name", "QPeriapt Test"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(source_root), "config", "user.email", "test@invalid.local"],
            check=True,
        )
        subprocess.run(["git", "-C", str(source_root), "add", "."], check=True)
        subprocess.run(
            ["git", "-C", str(source_root), "commit", "-qm", "fixture"],
            check=True,
        )

        work = source_root / "target" / "manifest-fixture"
        work.mkdir(parents=True)
        self.root = work
        entries = self.aar_entries()
        aar = work / "q-periapt-android-0.1.0-alpha.2.aar"
        aar.write_bytes(zip_bytes(entries))
        manifest_path = work / "MANIFEST.json"
        llvm_nm, llvm_readelf = self.fake_tools()

        commit = run_git_text(
            source_root, ["rev-parse", "--verify", "HEAD^{commit}"]
        )
        epoch = int(
            run_git_text(source_root, ["show", "-s", "--format=%ct", commit])
        )
        exports_digest = hashlib.sha256(
            ("\n".join(sorted(FFI_EXPORTS)) + "\n").encode("utf-8")
        ).hexdigest()
        contract_relative = "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json"
        native = {
            abi: {
                "ffi_so_sha256": hashlib.sha256(
                    entries[f"jni/{abi}/{FFI_LIBRARY}"]
                ).hexdigest(),
                "jni_so_sha256": hashlib.sha256(
                    entries[f"jni/{abi}/{JNI_LIBRARY}"]
                ).hexdigest(),
            }
            for abi in REQUIRED_ABIS
        }
        payload: dict[str, object] = {
            "schema_version": 3,
            "kind": "qperiapt.android_aar_manifest",
            "package": aar.name,
            "version": "0.1.0-alpha.2",
            "generated_at": dt.datetime.fromtimestamp(
                epoch, tz=dt.timezone.utc
            ).isoformat().replace("+00:00", "Z"),
            "source_date_epoch": epoch,
            "git_commit": commit,
            "git_dirty": False,
            "diagnostic_only": False,
            "source_tree_sha256": canonical_tree_digest(
                source_root, repository_paths(source_root)
            ),
            "package_only": True,
            "device_runtime_proof": False,
            "boundary": "AAR/JNI packaging proof only; Android emulator or physical-device instrumentation is required before claiming Android runtime readiness.",
            "third_party": {
                "rust": {
                    "covered_targets": [
                        "aarch64-linux-android",
                        "x86_64-linux-android",
                        "armv7-linux-androideabi",
                        "i686-linux-android",
                    ],
                    "inventory_path": THIRD_PARTY_RUST_INVENTORY,
                    "inventory_sha256": hashlib.sha256(
                        entries[THIRD_PARTY_RUST_INVENTORY]
                    ).hexdigest(),
                    "package_count": 1,
                    "target": "x86_64-linux-android",
                }
            },
            "abi": {
                "major": 2,
                "contract_path": contract_relative,
                "contract_sha256": hashlib.sha256(
                    source_files[contract_relative]
                ).hexdigest(),
                "exports_sha256": exports_digest,
                "export_count": len(FFI_EXPORTS),
                "platform": "android-aar",
                "runtime_identity": {
                    "abis": list(REQUIRED_ABIS),
                    "jni_library": JNI_LIBRARY,
                    "loader_order": ["q_periapt_ffi_abi2", "qperiapt_jni_abi2"],
                    "runtime_library": FFI_LIBRARY,
                },
                "shared_filename": FFI_LIBRARY,
                "static_filename": "not-shipped-abi2",
            },
            "android": {
                "sdk": "local-android-sdk",
                "ndk": "29.0.14206865",
                "platform": "android-35",
                "build_tools": "36.0.0",
                "min_sdk": 23,
                "native_page_alignment": 16384,
                "native_stripped": True,
                "abis": list(REQUIRED_ABIS),
            },
            "artifacts": {
                "aar_sha256": hashlib.sha256(aar.read_bytes()).hexdigest(),
                "classes_jar_sha256": hashlib.sha256(entries["classes.jar"]).hexdigest(),
                "java_facade_sha256": hashlib.sha256(
                    source_files["bindings/android/src/main/java/dev/qperiapt/android/QPeriaptAndroid.java"]
                ).hexdigest(),
                "jni_adapter_sha256": hashlib.sha256(
                    source_files["bindings/android/jni/qperiapt_jni.c"]
                ).hexdigest(),
                "script_sha256": hashlib.sha256(
                    source_files["artifact/android-aar.sh"]
                ).hexdigest(),
                "elf_verifier_sha256": hashlib.sha256(
                    source_files["artifact/android_elf.py"]
                ).hexdigest(),
                "release_binary_scan_sha256": hashlib.sha256(
                    source_files["artifact/release_binary_scan.py"]
                ).hexdigest(),
                "third_party_license_collector_sha256": hashlib.sha256(
                    source_files["artifact/third_party_licenses.py"]
                ).hexdigest(),
                "native": native,
            },
        }
        manifest_path.write_bytes(canonical_android_manifest_json(payload))
        return source_root, aar, manifest_path, llvm_nm, llvm_readelf, payload

    def test_manifest_is_canonical_exact_and_release_toolchain_bound(self) -> None:
        source_root, aar, manifest, llvm_nm, llvm_readelf, payload = (
            self.manifest_release_fixture()
        )

        def verify_payload(candidate: dict[str, object]) -> None:
            manifest.write_bytes(canonical_android_manifest_json(candidate))
            verify_aar(
                aar,
                llvm_nm=llvm_nm,
                llvm_readelf=llvm_readelf,
                manifest=manifest,
                require_release_manifest=True,
                source_root=source_root,
            )

        verify_payload(payload)

        extra_top_level = copy.deepcopy(payload)
        extra_top_level["signed"] = True
        with self.assertRaisesRegex(AndroidVerificationError, "manifest fields differ"):
            verify_payload(extra_top_level)

        extra_android_field = copy.deepcopy(payload)
        extra_android_field["android"]["provenance"] = "unbound"
        with self.assertRaisesRegex(
            AndroidVerificationError, "Android metadata fields differ"
        ):
            verify_payload(extra_android_field)

        extra_native_field = copy.deepcopy(payload)
        extra_native_field["artifacts"]["native"]["arm64-v8a"]["signed"] = True
        with self.assertRaisesRegex(
            AndroidVerificationError, "native hashes for arm64-v8a fields differ"
        ):
            verify_payload(extra_native_field)

        manifest.write_bytes(b" " + canonical_android_manifest_json(payload))
        with self.assertRaisesRegex(AndroidVerificationError, "not canonical JSON"):
            verify_aar(
                aar,
                llvm_nm=llvm_nm,
                llvm_readelf=llvm_readelf,
                manifest=manifest,
                require_release_manifest=True,
                source_root=source_root,
            )

        wrong_ndk = copy.deepcopy(payload)
        wrong_ndk["android"]["ndk"] = "29.1.0"
        with self.assertRaisesRegex(AndroidVerificationError, "NDK 29.0.14206865"):
            verify_payload(wrong_ndk)

        wrong_build_tools = copy.deepcopy(payload)
        wrong_build_tools["android"]["build_tools"] = "35.0.0"
        with self.assertRaisesRegex(AndroidVerificationError, "build-tools 36.0.0"):
            verify_payload(wrong_build_tools)

        wrong_platform = copy.deepcopy(payload)
        wrong_platform["android"]["platform"] = "android-34"
        with self.assertRaisesRegex(AndroidVerificationError, "target android-35"):
            verify_payload(wrong_platform)

    def test_all_four_abis_and_both_libraries_pass(self) -> None:
        nm, readelf = self.fake_tools()
        for abi in ABI_SPECS:
            for library in (FFI_LIBRARY, JNI_LIBRARY):
                with self.subTest(abi=abi, library=library):
                    verify_library(
                        self.write_library(abi, library),
                        abi=abi,
                        library=library,
                        llvm_nm=nm,
                        llvm_readelf=readelf,
                    )

    def test_valid_tool_output_with_nonzero_exit_is_rejected(self) -> None:
        nm, readelf = self.fake_tools(nm_exit=1)
        path = self.write_library("arm64-v8a", FFI_LIBRARY)
        with self.assertRaisesRegex(AndroidVerificationError, r"exit status 1"):
            verify_library(
                path,
                abi="arm64-v8a",
                library=FFI_LIBRARY,
                llvm_nm=nm,
                llvm_readelf=readelf,
            )

    def test_load_alignment_below_16k_is_rejected(self) -> None:
        nm, readelf = self.fake_tools(load_alignment="0x1000")
        path = self.write_library("x86", JNI_LIBRARY)
        with self.assertRaisesRegex(AndroidVerificationError, r"below 16 KiB"):
            verify_library(
                path,
                abi="x86",
                library=JNI_LIBRARY,
                llvm_nm=nm,
                llvm_readelf=readelf,
            )

    def test_successful_tool_with_diagnostics_is_rejected(self) -> None:
        nm, readelf = self.fake_tools(nm_stderr="unexpected warning")
        path = self.write_library("arm64-v8a", FFI_LIBRARY)
        with self.assertRaisesRegex(AndroidVerificationError, r"emitted diagnostics"):
            verify_library(
                path,
                abi="arm64-v8a",
                library=FFI_LIBRARY,
                llvm_nm=nm,
                llvm_readelf=readelf,
            )

    def test_expected_aar_sha256_mismatch_fails_closed(self) -> None:
        nm, readelf = self.fake_tools()
        with self.assertRaisesRegex(AndroidVerificationError, r"SHA-256 mismatch"):
            verify_aar(
                self.write_aar(),
                llvm_nm=nm,
                llvm_readelf=readelf,
                expected_aar_sha256="0" * 64,
            )

    def test_final_aar_is_audited_and_extracted_elfs_are_reverified(self) -> None:
        nm, readelf = self.fake_tools()
        extracted = self.root / "verified-extract"
        verify_aar(
            self.write_aar(),
            llvm_nm=nm,
            llvm_readelf=readelf,
            extract_to=extracted,
        )
        actual = {
            path.relative_to(extracted).as_posix()
            for path in extracted.rglob("*")
            if path.is_file()
        }
        self.assertEqual(
            actual,
            set(REQUIRED_AAR_ENTRIES) | set(self.third_party_entries()),
        )

    def test_duplicate_aar_entry_is_rejected(self) -> None:
        path = self.write_aar()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(path, "a") as archive:
                info = zipfile.ZipInfo("classes.jar", (2000, 1, 1, 0, 0, 0))
                info.external_attr = 0o100644 << 16
                archive.writestr(info, self.classes_jar())
        with self.assertRaisesRegex(AndroidVerificationError, r"duplicate entry"):
            audit_aar(path)

    def test_nested_archive_in_classes_jar_is_rejected(self) -> None:
        data = zip_bytes(
            {
                "dev/qperiapt/android/QPeriaptAndroid.class": CLASS_BYTES,
                "dev/qperiapt/android/payload.jar": b"not allowed",
            }
        )
        with self.assertRaisesRegex(AndroidVerificationError, r"unexpected entry|nested"):
            audit_classes_jar(data)

    def test_private_build_path_in_extracted_aar_content_is_rejected(self) -> None:
        nm, readelf = self.fake_tools()
        path = self.write_aar()
        entries: dict[str, bytes] = {}
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                entries[info.filename] = archive.read(info)
        entries["R.txt"] = b"/Users/private/build/root"
        path.write_bytes(zip_bytes(entries))
        with self.assertRaisesRegex(AndroidVerificationError, r"macOS user home"):
            verify_aar(path, llvm_nm=nm, llvm_readelf=readelf)

    def test_third_party_license_inventory_binds_exact_bytes(self) -> None:
        path = self.write_aar()
        entries = self.aar_entries()
        license_path = next(
            name
            for name in entries
            if name.startswith("META-INF/THIRD_PARTY/rust/")
            and name != THIRD_PARTY_RUST_INVENTORY
        )
        entries[license_path] = b"tampered license\n"
        path.write_bytes(zip_bytes(entries))
        with self.assertRaisesRegex(AndroidVerificationError, r"bytes differ"):
            audit_aar(path)


class AndroidManifestProvenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp_dir.name)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(
            ["git", "-C", str(self.root), "config", "user.name", "QPeriapt Test"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(self.root), "config", "user.email", "test@invalid.local"],
            check=True,
        )
        (self.root / "source.txt").write_text("source\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.root), "add", "source.txt"], check=True)
        subprocess.run(["git", "-C", str(self.root), "commit", "-qm", "fixture"], check=True)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def manifest(self) -> dict[str, object]:
        commit = run_git_text(self.root, ["rev-parse", "--verify", "HEAD^{commit}"])
        epoch = int(run_git_text(self.root, ["show", "-s", "--format=%ct", commit]))
        source_digest = canonical_tree_digest(self.root, repository_paths(self.root))
        return {
            "git_commit": commit,
            "git_dirty": False,
            "diagnostic_only": False,
            "source_date_epoch": epoch,
            "generated_at": dt.datetime.fromtimestamp(
                epoch, tz=dt.timezone.utc
            ).isoformat().replace("+00:00", "Z"),
            "source_tree_sha256": source_digest,
        }

    def test_exact_clean_source_provenance_passes_release_verification(self) -> None:
        verify_manifest_source_provenance(
            self.manifest(),
            source_root=self.root,
            require_release=True,
        )

    def test_runtime_timestamp_is_rejected(self) -> None:
        manifest = self.manifest()
        manifest["generated_at"] = "2099-01-01T00:00:00Z"
        with self.assertRaisesRegex(AndroidVerificationError, "exactly equal"):
            verify_manifest_source_provenance(
                manifest,
                source_root=self.root,
                require_release=False,
            )

    def test_diagnostic_only_must_exactly_match_dirty_provenance(self) -> None:
        manifest = self.manifest()
        manifest["diagnostic_only"] = True
        with self.assertRaisesRegex(AndroidVerificationError, "exactly match git_dirty"):
            verify_manifest_source_provenance(
                manifest,
                source_root=self.root,
                require_release=False,
            )

    def test_source_change_after_manifest_is_rejected(self) -> None:
        manifest = self.manifest()
        (self.root / "source.txt").write_text("changed\n", encoding="utf-8")
        with self.assertRaisesRegex(AndroidVerificationError, "git_dirty differs"):
            verify_manifest_source_provenance(
                manifest,
                source_root=self.root,
                require_release=False,
            )

    def test_expected_release_commit_must_be_exact_and_equal(self) -> None:
        actual = "a" * 40
        verify_expected_git_commit("", actual)
        verify_expected_git_commit(actual, actual)
        with self.assertRaisesRegex(AndroidVerificationError, "exactly 40"):
            verify_expected_git_commit("A" * 40, actual)
        with self.assertRaisesRegex(AndroidVerificationError, "differs"):
            verify_expected_git_commit("b" * 40, actual)


if __name__ == "__main__":
    unittest.main()
