"""Synthetic package controls; actual service execution has its own receipt."""
from __future__ import annotations

import copy
import hashlib
import io
import json
from pathlib import Path
import stat
import struct
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import continuity_release_manifest as manifest
import continuity_service_package as service
import continuity_service_licenses as notices
from deterministic_archive import create_tar_gz, extract_tar_gz


TARGET = "x86_64-unknown-linux-gnu"
DYNAMIC = """[Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
 0x1 (NEEDED) Shared library: [libc.so.6]
 0x1 (NEEDED) Shared library: [libcrypto.so.3]
 Name: GLIBC_2.38
 Name: OPENSSL_3.0.0
"""


def elf():
    data = bytearray(64)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", data, 16, 3, 62, 1)
    struct.pack_into("<H", data, 52, 64)
    return bytes(data)


class ServicePackageControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source = {"commit": "a" * 40, "tree": "b" * 40}

    def test_executable_contract_keeps_actual_runtime_requirements(self):
        contract = service.executable_contract(elf(), DYNAMIC, TARGET)
        self.assertEqual(contract["needed"], ["libc.so.6", "libcrypto.so.3"])
        self.assertEqual(contract["symbol_versions"], ["GLIBC_2.38", "OPENSSL_3.0.0"])

    def test_loader_injection_architecture_and_unlisted_dependencies_fail(self):
        for text in (DYNAMIC + " (RUNPATH) Library runpath: [/tmp]\n",
                     DYNAMIC + " (NEEDED) Shared library: [libprivate.so]\n",
                     DYNAMIC + " (NEEDED) Shared library: [libc.so.6]\n",
                     DYNAMIC.replace("/lib64/ld-linux-x86-64.so.2", "/tmp/loader"),
                     DYNAMIC.replace("OPENSSL_3.0.0", "PRIVATE_1.0")):
            with self.subTest(text=text), self.assertRaises(ValueError):
                service.executable_contract(elf(), text, TARGET)
        data = bytearray(elf()); struct.pack_into("<H", data, 18, 183)
        with self.assertRaisesRegex(ValueError, "architecture"):
            service.executable_contract(bytes(data), DYNAMIC, TARGET)

    def test_packaged_document_links_keep_original_source_commit(self):
        data = b"[Local](NATIVE_DEVICE.md) [Other](../../docs/SDK_HOST_STORE.md#state) [Here](#same) [Web](https://example.test/)\n"
        output = service.document(data, service.APP + "/DIRECTORY_LEASES.md", self.source["commit"])
        self.assertIn(b"/blob/" + b"a" * 40 + b"/research/continuity-reference-app/NATIVE_DEVICE.md", output)
        self.assertIn(b"/blob/" + b"a" * 40 + b"/docs/SDK_HOST_STORE.md#state", output)
        self.assertIn(b"[Here](#same) [Web](https://example.test/)", output)

    def test_cargo_manifest_path_does_not_admit_ancestor_wrapper_overrides(self):
        cargo_home = self.root / "cargo-home"
        cargo_home.mkdir()
        cwd = self.root / "private-build"
        cwd.mkdir()
        service.cargo_configuration(cwd, cargo_home)
        service.write(self.root / ".cargo/config.toml", b'[build]\nrustc-wrapper="/tmp/unselected-wrapper"\n')
        with self.assertRaisesRegex(ValueError, "configuration or credential override"):
            service.cargo_configuration(cwd, cargo_home)

    def test_upstream_notice_revision_is_bound_to_exact_registry_archive(self):
        vcs = {"git": {"sha1": "c" * 40}, "path_in_vcs": "member"}
        raw = json.dumps(vcs).encode()
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            entry = tarfile.TarInfo("synthetic-1.0.0/.cargo_vcs_info.json")
            entry.size = len(raw)
            archive.addfile(entry, io.BytesIO(raw))
        data = buffer.getvalue()
        pin = {"name": "synthetic", "version": "1.0.0", "registry_checksum": hashlib.sha256(data).hexdigest(), "vcs": vcs}
        notices.verify_crate(data, pin)
        with self.assertRaisesRegex(ValueError, "checksum"):
            notices.verify_crate(data + b"changed", pin)
        changed = copy.deepcopy(pin); changed["vcs"]["git"]["sha1"] = "d" * 40
        with self.assertRaisesRegex(ValueError, "upstream revision"):
            notices.verify_crate(data, changed)

    def test_license_copy_cannot_change_after_notice_authentication(self):
        file = {"path": "LICENSES/continuity-services/synthetic/LICENSE", "bytes": 7, "sha256": "e" * 64}
        origin = {"packages": [{"name": "synthetic", "version": "1.0.0", "files": [file]}]}
        inventory = {"packages": [{"name": "synthetic", "version": "1.0.0", "license_files": [
            {**file, "path": "THIRD_PARTY/rust/synthetic-1.0.0/LICENSE"}]}]}
        notices.verify_inventory(inventory, origin)
        inventory["packages"][0]["license_files"][0]["sha256"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "authenticated bytes"):
            notices.verify_inventory(inventory, origin)

    def build_rows(self):
        build = self.root / "build"
        metadata = {"packages": [{"name": service.SOURCE_PACKAGE, "id": "reference-id", "source": None,
                                  "version": "0.0.0", "manifest_path": str(self.root / service.APP / "Cargo.toml")}]}
        rows = [{"reason": "compiler-artifact", "package_id": "reference-id", "profile": {"test": False, "opt_level": "3"},
                 "target": {"name": name, "kind": ["bin"], "src_path": str(self.root / service.APP / "src/bin" / (name + ".rs"))},
                 "executable": str(build / TARGET / "release" / name)} for name in service.BINARIES]
        rows.append({"reason": "build-finished", "success": True})
        return build, metadata, rows

    def test_actual_build_selection_requires_all_original_release_paths(self):
        build, metadata, rows = self.build_rows()
        encode = lambda value: b"\n".join(json.dumps(row).encode() for row in value)
        selected = service.select_build(encode(rows), metadata, build, TARGET, self.root)
        self.assertEqual(set(selected), set(service.BINARIES))
        for field, value in (("executable", "/tmp/other"), ("package_id", "other-package"),
                             ("profile", {"test": True, "opt_level": "3"})):
            changed = copy.deepcopy(rows); changed[0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                service.select_build(encode(changed), metadata, build, TARGET, self.root)
        with self.assertRaises(ValueError):
            service.select_build(encode(rows[1:]), metadata, build, TARGET, self.root)

    def staging(self):
        stage = self.root / "staging"
        stage.mkdir()
        for relative in service.EXECUTABLES:
            service.write(stage / relative, b"explicit synthetic executable control\n")
            (stage / relative).chmod(0o755)
        service.write(stage / "README.md", b"Synthetic public document.\n")
        contents = {"kind": "unit.synthetic_service_contents", "target": TARGET, "files": service.inventory(stage)}
        service.write(stage / service.CONTENTS, service.canonical(contents))
        return stage, contents

    def test_archive_readback_preserves_exact_selected_executable_permissions(self):
        stage, contents = self.staging()
        archive, repeated = self.root / "first.tar.gz", self.root / "repeated.tar.gz"
        arguments = dict(root_name="synthetic-services", mtime=service.MTIME, limits=service.LIMITS,
                         executable_paths=service.archive_executables("synthetic-services"))
        first = create_tar_gz(stage, archive, **arguments)
        second = create_tar_gz(stage, repeated, **arguments)
        self.assertEqual(first.archive_sha256, second.archive_sha256)
        extract_tar_gz(archive, self.root / "installed", expected_sha256=first.archive_sha256, **arguments)
        installed = self.root / "installed/synthetic-services"
        with patch.object(service.licenses, "verify", return_value={}):
            service.verify_package(installed, contents)
            self.assertEqual(stat.S_IMODE((installed / next(iter(service.EXECUTABLES))).stat().st_mode), 0o755)
            service.write(installed / "unexpected-state.redb", b"synthetic injection")
            with self.assertRaisesRegex(ValueError, "members or bytes"):
                service.verify_package(installed, contents)

    def test_missing_executable_permission_or_symlink_is_refused(self):
        stage, _ = self.staging()
        binary = stage / next(iter(service.EXECUTABLES))
        binary.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "permission"):
            service.inventory(stage)
        binary.unlink(); binary.symlink_to("/bin/false")
        with self.assertRaisesRegex(ValueError, "symlink"):
            service.inventory(stage)

    def file(self, name, data):
        service.write(self.root / name, data)
        return {"path": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}

    def result(self):
        artifact = self.file("synthetic.tar.gz", b"synthetic manifest artifact, not a service archive")
        result = {"kind": "qperiapt.continuity_service_package", "completed": True,
                  "source": self.source, "archive": artifact, "release_claim_eligible": False}
        self.file(service.INSTALLATION, service.canonical({"kind": "qperiapt.continuity_service_installation",
                  "completed": True, "source": self.source, "archive": artifact}))
        return result

    def test_typed_service_row_passes_actual_candidate_manifest_acceptance(self):
        result = self.result()
        service.records(self.root, result, "continuity-engine")
        self.file(service.REPORT, service.canonical(result))
        engine = {"id": "continuity-engine", "role": "engine", "name": "q-periapt-continuity", "version": "0.2.0",
                  "format": "cargo", "metadata": self.file("engine/Cargo.toml",
                    b'[package]\nname="q-periapt-continuity"\nversion="0.2.0"\n'),
                  "workspace": None, "dependencies": [], "interfaces": [], "artifacts": [], "assessments": []}
        row = json.loads((self.root / service.ROW).read_text())
        inputs = manifest.Inputs(self.root)
        accepted = manifest._packages([engine, row], inputs, stage="candidate", source=self.source, interfaces={})
        inputs.unchanged()
        self.assertEqual(accepted["roles"], ["engine", "service"])
        self.assertEqual(len(accepted["assessments"]), 2)
        self.assertTrue(all(value["completed"] for value in accepted["assessments"]))

    def test_mismatched_installation_source_cannot_create_distribution_row(self):
        result = self.result()
        result["source"] = {"commit": "c" * 40, "tree": "d" * 40}
        with self.assertRaisesRegex(ValueError, "installation identity"):
            service.records(self.root, result, "continuity-engine")
        self.assertFalse((self.root / service.ROW).exists())

    def test_workflow_retains_only_public_output(self):
        workflow = (service.ROOT / ".github/workflows/continuity-services.yml").read_text()
        self.assertIn("--output target/continuity-services", workflow)
        self.assertIn("target/continuity-services/commands/**", workflow)
        self.assertNotIn("private-probe-state", workflow)
        self.assertNotIn("qperiapt-services-", workflow)


if __name__ == "__main__":
    unittest.main()
