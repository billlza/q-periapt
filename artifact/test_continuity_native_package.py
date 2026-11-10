"""Native archive boundaries, using an explicit synthetic ELF control library."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import continuity_c_abi as abi
import continuity_c_consumer as c
import continuity_native_package as native
import continuity_release_manifest as manifest
import rust_sdk_profile as sdk

TARGET = "x86_64-unknown-linux-gnu"
DYNAMIC = f'''Dynamic section:
 0x1 (NEEDED) Shared library: [libgcc_s.so.1]
 0x1 (NEEDED) Shared library: [libc.so.6]
 0xe (SONAME) Library soname: [{native.LIBRARY}]
Version needs section:
 0x0: Version: 1 File: libc.so.6 Cnt: 2
 0x0: Name: GLIBC_2.2.5 Flags: none Version: 2
 0x0: Name: GLIBC_2.34 Flags: none Version: 3
 0x0: Version: 1 File: libgcc_s.so.1 Cnt: 1
 0x0: Name: GCC_3.0 Flags: none Version: 4
'''


class NativeMetadataTests(unittest.TestCase):
    def test_existing_linux_job_retains_archive_and_public_package_receipts(self):
        text = (native.package.ROOT / ".github/workflows/ci.yml").read_text()
        block = text.split("  continuity-installed-rust:\n", 1)[1].split("\n  continuity-installed-swift:", 1)[0]
        self.assertIn("--with-c-consumer --with-native-package --witness-openssl-prefix /usr", block)
        upload = block.split("      - name: Retain ", 1)[1]
        self.assertIn("if: always()", upload)
        self.assertIn("if-no-files-found: error", upload)
        lines = re.search(r"          path: \|\n((?:            [^\n]+\n)+)", upload)[1].splitlines()
        # The archive, digest records and public probe logs are all retained;
        # private scenario storage is outside those explicit selections.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            prefix = root / "target/continuity-installed-rust"
            names = [f"{native.NAME}-{native.VERSION}-{TARGET}.zip", native.REPORT, native.ROW, native.IDENTITY,
                     "native-package/probe-run.stdout", "native-package/probe-run.json"]
            wanted = set()
            for name in names:
                path = prefix / name; native.write(path, b"public package evidence"); wanted.add(path)
            private = prefix / "private/journal"; native.write(private, b"private fixture")
            selected = {path for line in lines for path in root.glob(line.strip()) if path.is_file()}
            self.assertEqual(wanted - selected, set())
            self.assertNotIn(private, selected)

    def test_runtime_contract_preserves_all_needed_names_and_versions(self):
        result = native.dynamic_contract(DYNAMIC, TARGET)
        self.assertEqual(result["needed"], ["libc.so.6", "libgcc_s.so.1"])
        self.assertEqual(result["symbol_versions"], ["GCC_3.0", "GLIBC_2.2.5", "GLIBC_2.34"])
        self.assertIsNone(result["loader_search_path"])

    def test_runtime_refuses_wrong_soname_extra_duplicate_or_redirected_dependencies(self):
        bad = [DYNAMIC.replace(native.LIBRARY, "other.so"),
               DYNAMIC.replace("libgcc_s.so.1", "libqpc-other.so"),
               DYNAMIC + " 0x1 (NEEDED) Shared library: [libc.so.6]\n",
               DYNAMIC + " 0x1d (RUNPATH) Library runpath: [/tmp/other]\n",
               DYNAMIC + " 0xf (RPATH) Library rpath: [$ORIGIN]\n",
               DYNAMIC + " 0x7 (FILTER) Filter library: [other.so]\n",
               DYNAMIC.replace("GLIBC_2.34", "GLIBC_PRIVATE"),
               DYNAMIC.replace("GLIBC_2.34", "CUSTOM_1.0")]
        for value in bad:
            with self.subTest(text=value), self.assertRaises(ValueError):
                native.dynamic_contract(value, TARGET)

    def test_target_is_checked_from_bytes_before_tools(self):
        value = bytearray(64)
        value[:7] = b"\x7fELF\x02\x01\x01"
        struct.pack_into("<HHI", value, 16, 3, 62, 1)
        struct.pack_into("<H", value, 52, 64)
        native.elf_target(value, TARGET)
        for index, replacement in ((4, 1), (5, 2), (7, 9), (16, 2), (18, 183), (52, 0)):
            changed = bytearray(value); changed[index] = replacement
            with self.subTest(index=index), self.assertRaises(ValueError):
                native.elf_target(changed, TARGET)
        with self.assertRaises(ValueError):
            native.elf_target(value[:63], TARGET)
        with self.assertRaises(ValueError):
            native.elf_target(value, "x86_64-pc-windows-msvc")

    def test_execution_rejects_unfinished_profile_wrong_path_and_changed_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            outside = Path(temp).resolve()
            path = outside / "c-installed-release" / native.LIBRARY
            native.write(path, b"explicit fixture")
            pin = sdk.snapshot(path)
            row = {"completed": True, "partition_completed": True, "build_profiles": ["debug", "release"],
                   "release_claim_eligible": False, "execution": {"debug": {"fixture": True},
                   "release": {"binaries": {"C_library": {"path": str(path), "bytes": pin.size, "sha256": pin.sha256}}}}}
            self.assertEqual(native.selected_execution(outside, row)["sha256"], pin.sha256)
            for name, value in (("completed", False), ("partition_completed", False),
                                ("build_profiles", ["release"]), ("failure", "incomplete"),
                                ("release_claim_eligible", True)):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    native.selected_execution(outside, dict(row, **{name: value}))
            changed = copy.deepcopy(row)
            changed["execution"]["release"]["binaries"]["C_library"]["path"] = str(path.parent / "other.so")
            with self.assertRaisesRegex(ValueError, "path"):
                native.selected_execution(outside, changed)
            path.write_bytes(b"substituted")
            with self.assertRaisesRegex(ValueError, "bytes"):
                native.selected_execution(outside, row)
            path.unlink(); path.symlink_to("/dev/zero")
            with self.assertRaises(ValueError):
                native.selected_execution(outside, row)


@unittest.skipUnless(os.uname().sysname == "Linux" and os.uname().machine in native.TARGETS
                     and Path("/usr/bin/cc").exists(), "Linux C compiler control")
class NativeArchiveControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.outside, self.output = self.root / "outside", self.root / "evidence"
        self.outside.mkdir(); self.output.mkdir()
        self.consumer = self.outside / "c-consumer"
        for relative in ("qpc_owner.h", abi.CONTRACT):
            sdk.copy(c.FIXTURE / relative, self.consumer / relative)
        (self.consumer / "Cargo.toml").write_text("# explicit synthetic package control\n")
        self.cc = Path("/usr/bin/cc").resolve(strict=True)
        self.library = self.outside / "c-installed-release" / native.LIBRARY
        self.library.parent.mkdir()
        contract = abi.load(c.FIXTURE)
        arg, closed = contract["constants"]["QPC_ARGUMENT"], contract["constants"]["QPC_CLOSED"]
        fixture = "#include <stdint.h>\n#include <stddef.h>\n#include <unistd.h>\n"
        for name in sorted(c.EXPORTS - {"qpc_owner_v1_open", "qpc_owner_v1_close"}):
            fixture += f"int32_t {name}(void) {{ return 0; }}\n"
        fixture += (f"int32_t qpc_owner_v1_open(const uint8_t *p, size_t n, uint8_t q, uint64_t *h, void *e) "
                    f"{{ (void)p; (void)n; (void)q; if(e) *h=0; return {arg}; }}\n"
                    f"int32_t qpc_owner_v1_close(uint64_t h, void *e) "
                    f"{{ (void)h; (void)e; (void)getpid(); return {closed}; }}\n")
        self.fixture = self.root / "synthetic-owner.c"
        self.fixture.write_text(fixture)
        subprocess.run([str(self.cc), "-shared", "-fPIC", "-O2", str(self.fixture),
                        "-Wl,-soname," + native.LIBRARY, "-o", str(self.library)], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        value = sdk.snapshot(self.library)
        self.result = {"completed": True, "partition_completed": True, "build_profiles": ["debug", "release"],
            "release_claim_eligible": False, "compiler": {"path": str(self.cc), "sha256": sdk.snapshot(self.cc).sha256},
            "execution": {"debug": {"explicit_synthetic_control": True}, "release": {"binaries": {
                "C_library": {"path": str(self.library), "bytes": value.size, "sha256": value.sha256}}}}}
        sdk.write_json(self.output / "C_CONSUMER.json", self.result)
        rustc = self.root / "toolchain/bin/rustc"
        native.write(rustc, b"synthetic compiler identity for archive control")
        rust_docs = self.root / "toolchain/share/doc/rust"
        sdk.copy(native.package.ROOT / "LICENSES/Rust-1.98.1-library.html", rust_docs / "COPYRIGHT-library.html")
        native.write(rust_docs / "licenses/fixture.txt", b"synthetic compiler license fixture\n")
        self.env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "RUSTC": str(rustc)}
        self.source = {"commit": "a" * 40, "tree": "b" * 40}

    def qualify(self, *, extract=None):
        original_command = sdk.command
        def command(argv, prefix, cwd, *, environment=None):
            if argv[0] == "synthetic-cargo":
                return b"{}"
            return original_command(argv, prefix, cwd, environment=environment)
        def collect(_, root, target, **kwargs):
            native.write(root / "THIRD_PARTY/rust/fixture/LICENSE", b"synthetic dependency fixture\n")
        with patch.object(sdk, "inspect_package_source", return_value=(self.source["commit"], False)), \
                patch.object(native, "run_git_text", return_value=self.source["tree"]), \
                patch.object(native.licenses, "collect", side_effect=collect), \
                patch.object(native.licenses, "verify", return_value={"explicit_synthetic_control": True}), \
                patch.object(sdk, "command", side_effect=command), \
                patch.object(native, "extract_zip", side_effect=extract or native.extract_zip):
            return native.qualify_native(self.outside, self.output, self.result, ["synthetic-cargo"], self.env,
                source_commit=self.source["commit"], engine_package_id="continuity-engine")

    def test_real_elf_archive_reopens_and_loads_extracted_library(self):
        result = self.qualify()
        self.assertTrue(result["completed"])
        self.assertTrue(result["installed_probe"]["completed"])
        self.assertFalse(result["release_claim_eligible"])
        self.assertFalse(result["publication_performed"])
        self.assertEqual(result["native"]["sha256"], sdk.snapshot(self.library).sha256)
        row = json.loads((self.output / native.ROW).read_text())
        self.assertEqual(row["interfaces"], ["continuity_c"])
        inputs = manifest.Inputs(self.output)
        manifest._package_identity(row, inputs, {}, {}, self.source)
        for reference in row["artifacts"] + row["assessments"]:
            inputs.read(reference, maximum=manifest.MAX_ARTIFACT)
        inputs.unchanged()
        self.assertEqual(row["artifacts"][0]["sha256"], sdk.snapshot(self.output / result["archive"]["path"]).sha256)
        engine_path = self.output / "engine/Cargo.toml"
        native.write(engine_path, b'[package]\nname = "q-periapt-continuity"\nversion = "0.2.0"\n')
        engine_file = sdk.snapshot(engine_path)
        engine = {"id": "continuity-engine", "role": "engine", "name": "q-periapt-continuity", "version": "0.2.0",
                  "format": "cargo", "metadata": {"path": "engine/Cargo.toml", "bytes": engine_file.size,
                  "sha256": engine_file.sha256}, "workspace": None, "dependencies": [], "interfaces": [],
                  "artifacts": [], "assessments": []}
        accepted = manifest._packages([engine, row], manifest.Inputs(self.output), stage="candidate",
            source=self.source, interfaces={"continuity_c": {"package_version": "0.2.0"}})
        self.assertEqual(accepted["packages"], 2)
        self.assertEqual(accepted["artifacts"], 1)
        self.assertEqual(accepted["assessments"][0]["kind"], "qperiapt.continuity_native_package")
        bad = copy.deepcopy(row)
        c_receipt = sdk.snapshot(self.output / "C_CONSUMER.json")
        bad["assessments"].append({"path": "C_CONSUMER.json", "bytes": c_receipt.size, "sha256": c_receipt.sha256})
        with self.assertRaisesRegex(ValueError, "assessment report identity"):
            manifest._packages([engine, bad], manifest.Inputs(self.output), stage="candidate",
                source=self.source, interfaces={"continuity_c": {"package_version": "0.2.0"}})

    def test_reopened_member_injection_blocks_success_and_distribution_row(self):
        original = native.extract_zip
        def changed(*args, **kwargs):
            result = original(*args, **kwargs)
            destination = args[1] / kwargs["root_name"]
            (destination / "extra-library.so").write_bytes(b"injected")
            return result
        with self.assertRaisesRegex(ValueError, "members or bytes"):
            self.qualify(extract=changed)
        report = json.loads((self.output / native.REPORT).read_text())
        self.assertFalse(report["completed"])
        self.assertIn("failure", report)
        self.assertFalse((self.output / native.ROW).exists())

    def test_original_library_mutation_before_final_acceptance_is_detected(self):
        original = native.extract_zip
        def changed(*args, **kwargs):
            result = original(*args, **kwargs)
            self.library.write_bytes(b"replaced after archive creation")
            return result
        with self.assertRaisesRegex(ValueError, "library bytes"):
            self.qualify(extract=changed)
        self.assertFalse(json.loads((self.output / native.REPORT).read_text())["completed"])

    def test_duplicate_export_and_nonowner_symbol_are_refused(self):
        def run(argv, label):
            if label == "exports":
                return ("\n".join(f"{name} T 0 1" for name in sorted(c.EXPORTS))
                        + "\nqpc_owner_v1_open T 0 1\n").encode()
            return DYNAMIC.encode()
        with self.assertRaisesRegex(ValueError, "exported functions"):
            native.verify_native(self.library, native.TARGETS[os.uname().machine][0], run)


if __name__ == "__main__":
    unittest.main()
