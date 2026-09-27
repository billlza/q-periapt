"""SDK profile admission with synthetic PE fixtures; native execution stays a separate gate."""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import struct
import tempfile
import unittest

import test_sdk_cbom_contract as cbom_fixture
import test_windows_package as legacy_fixture
import windows_package as windows


class WindowsStaticFilenameTests(unittest.TestCase):
    @staticmethod
    def member(name, data):
        header = (name.encode().ljust(16) + b"0".ljust(12) + b"0".ljust(6)
                  + b"0".ljust(6) + b"644".ljust(8) + str(len(data)).encode().ljust(10) + b"`\n")
        return header + data + (b"\n" if len(data) % 2 else b"")

    @staticmethod
    def object():
        code = b"D:\\a\\must-remain-in-code\0"
        symbol_offset = 60 + len(code)
        header = struct.pack("<HHIIIHH", 0x8664, 1, 0, symbol_offset, 3, 0, 0)
        section = struct.pack("<8sIIIIIIHHI", b".text", 0, 0, len(code), 60, 0, 0, 0, 0, 0x60000020)
        symbol = struct.pack("<8sIhHBB", b".file", 0, -2, 0, 103, 1)
        filename = b"D:\\a\\private.asm\0".ljust(18, b"\0")
        public = struct.pack("<8sIhHBB", b"answer", 0, 1, 0x20, 2, 0)
        return header + section + code + symbol + filename + public + struct.pack("<I", 4), symbol_offset

    def test_only_file_auxiliary_bytes_change_in_mixed_archive(self):
        obj, symbol_offset = self.object()
        payload = b"answer\0example.dll\0"
        imported = struct.pack("<HHHHIIHH", 0, 0xffff, 0, 0x8664, 0, len(payload), 0, 4) + payload
        prefix = b"!<arch>\n" + self.member("/", b"index-offsets-remain")
        archive = prefix + self.member("source.obj/", obj) + self.member("example.dll/", imported)
        expected = bytearray(archive)
        start = len(prefix) + 60 + symbol_offset + 18
        expected[start:start + 18] = b"<source>".ljust(18, b"\0")
        actual, count = windows.normalize_static_debug_filenames(archive)
        self.assertEqual((actual, count), (bytes(expected), 1))
        self.assertIn(b"D:\\a\\must-remain-in-code\0", actual)
        self.assertTrue(actual.endswith(self.member("example.dll/", imported)))
        self.assertEqual(windows.normalize_static_debug_filenames(actual), (actual, 1))

    def test_malformed_or_overlapping_metadata_is_rejected(self):
        original, symbol_offset = self.object()
        changes = []
        for offset, fmt, value in ((0, "<H", 0xaa64), (8, "<I", 60),
                                   (12, "<I", 0xffffffff), (16, "<H", 2),
                                   (symbol_offset + 12, "<h", 1),
                                   (symbol_offset + 17, "<B", 4)):
            value_bytes = bytearray(original)
            struct.pack_into(fmt, value_bytes, offset, value)
            changes.append(bytes(value_bytes))
        changes.append(original[:-6])
        for obj in changes:
            with self.subTest(data_sha256=hashlib.sha256(obj).hexdigest()), self.assertRaises(windows.WindowsPackageError):
                windows.normalize_static_debug_filenames(b"!<arch>\n" + self.member("bad.obj/", obj))
        valid = b"!<arch>\n" + self.member("source.obj/", original)
        for data in (b"!<thin>\n", valid[:-1], valid + b"unexpected tail"):
            with self.subTest(data=data[:8]), self.assertRaises(windows.WindowsPackageError):
                windows.normalize_static_debug_filenames(data)

    def test_copy_preserves_input_and_refuses_existing_output(self):
        obj, _ = self.object()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, destination = root / "compiler.lib", root / "distribution.lib"
            data = b"!<arch>\n" + self.member("source.obj/", obj)
            source.write_bytes(data)
            result = windows.create_static_distribution_copy(source, destination)
            self.assertEqual(source.read_bytes(), data)
            self.assertEqual(result["source_sha256"], hashlib.sha256(data).hexdigest())
            self.assertEqual(result["bytes"], len(data))
            self.assertEqual(result["normalized_filename_records"], 1)
            destination.write_bytes(b"previous attempt")
            with self.assertRaises(FileExistsError):
                windows.create_static_distribution_copy(source, destination)
            self.assertEqual(destination.read_bytes(), b"previous attempt")


class WindowsSDKStaticLibraryTests(unittest.TestCase):
    def test_sdk_and_legacy_link_dependencies_require_the_selected_profile(self):
        sdk = ("bcrypt.lib", "advapi32.lib", "kernel32.lib", "ntdll.lib", "userenv.lib",
               "ws2_32.lib", "dbghelp.lib", "/defaultlib:msvcrt")
        self.assertEqual(windows.SDK_WINDOWS_NATIVE_STATIC_LIBRARY_TOKENS, sdk)
        output = legacy_fixture._native_static_libraries_output(*sdk)
        self.assertEqual(windows.parse_rustc_native_static_libraries(output, profile="sdk-alpha1"),
                         [*sdk[:-1], "msvcrt.lib"])
        with self.assertRaises(windows.WindowsPackageError):
            windows.parse_rustc_native_static_libraries(output)
        legacy = legacy_fixture._native_static_libraries_output(
            *windows.EXPECTED_WINDOWS_NATIVE_STATIC_LIBRARY_TOKENS)
        with self.assertRaises(windows.WindowsPackageError):
            windows.parse_rustc_native_static_libraries(legacy, profile="sdk-alpha1")
        for changed in (sdk[:-1], (*sdk, "extra.lib"), (sdk[1], sdk[0], *sdk[2:]),
                        (*sdk[:-1], "/defaultlib:libcmt"), (*sdk[:-1], "@extra.rsp")):
            with self.subTest(tokens=changed), self.assertRaises(windows.WindowsPackageError):
                windows.parse_rustc_native_static_libraries(
                    legacy_fixture._native_static_libraries_output(*changed), profile="sdk-alpha1")
        with self.assertRaisesRegex(windows.WindowsPackageError, "unknown.*profile"):
            windows.parse_rustc_native_static_libraries(output, profile="unknown")


class WindowsSDKProfileTests(unittest.TestCase):
    def setUp(self):
        self.repository = Path(__file__).resolve().parent.parent
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)
        fixture = legacy_fixture.WindowsPackageManifestTests()
        fixture.repository_root = self.repository
        old = fixture._package(self.folder)
        self.package = self.folder / f"q-periapt-c-abi2-{windows.SDK_PACKAGE_SEMVER}-{windows.TARGET}"
        old.rename(self.package)
        (self.package / "share/q-periapt/abi/q-periapt-c-abi-v2.json").unlink()
        shutil.copy2(self.repository / windows.SDK_CONTRACT_PATH, self.package / windows.SDK_EMBEDDED_CONTRACT)
        for packaged, source in windows.SDK_PAYLOAD_SOURCES.items():
            path = self.package / packaged
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(self.repository / source, path)
        cbom = cbom_fixture.SDKCBOMContractTests()
        cbom.setUp()
        self.addCleanup(cbom.doCleanups)
        (self.package / "share/q-periapt/bom/cbom.cdx.json").write_bytes(windows._canonical_json(cbom.document))

    def create(self, profile="sdk-alpha1"):
        return windows.create_manifest(
            self.package, self.repository, package_name=self.package.name, version=windows.SDK_PACKAGE_SEMVER,
            git_commit="a" * 40, git_tree="b" * 40, source_date_epoch=1_700_000_000,
            rustc=windows.EXPECTED_RUSTC_VERSION, cargo=windows.EXPECTED_CARGO_VERSION,
            cl="MSVC 19.44.35222.0", dependencies=["KERNEL32.dll", "bcrypt.dll"], profile=profile)

    def verify(self, profile="sdk-alpha1"):
        return windows.verify_package(self.package, repository_root=self.repository, profile=profile)

    def reseal(self, manifest):
        entries = []
        for path in self.package.rglob("*"):
            if not path.is_file() or path.name in {"MANIFEST.json", "SHA256SUMS"}:
                continue
            data = path.read_bytes()
            entries.append({"path": path.relative_to(self.package).as_posix(), "bytes": len(data),
                            "mode": "0o644", "type": "file", "sha256": hashlib.sha256(data).hexdigest()})
        # The wire format orders exact POSIX strings. WindowsPath ordering
        # instead folds case, which can mask the intended rejection below.
        manifest["files"] = sorted(entries, key=lambda entry: entry["path"])
        document = windows._canonical_json(manifest)
        (self.package / "MANIFEST.json").write_bytes(document)
        hashes = {entry["path"]: entry["sha256"] for entry in entries}
        hashes["MANIFEST.json"] = hashlib.sha256(document).hexdigest()
        (self.package / "SHA256SUMS").write_text("".join(f"{digest}  {path}\n" for path, digest in sorted(hashes.items())))

    def test_explicit_profile_preserves_legacy_and_binds_current_payload(self):
        with self.assertRaisesRegex(windows.WindowsPackageError, "version must be 0.1.5"):
            self.create(profile="legacy")
        manifest = self.create()
        self.assertEqual(manifest["schema_version"], 4)
        self.assertEqual(manifest["kind"], windows.SDK_KIND)
        self.assertEqual((manifest["abi"]["major"], manifest["abi"]["export_count"]), (2, 43))
        self.assertIs(manifest["release_claim_eligible"], False)
        self.assertEqual(manifest["authenticode"]["reason"], windows.SDK_UNSIGNED_REASON)
        self.assertNotIn("attestations", manifest["authenticode"]["reason"])
        self.assertEqual(self.verify(), manifest)
        self.reseal(manifest)
        self.assertEqual(self.verify(), manifest)
        with self.assertRaises(windows.WindowsPackageError):
            self.verify(profile="legacy")
        with self.assertRaisesRegex(windows.WindowsPackageError, "unknown.*profile"):
            self.verify(profile="unknown")

    def test_rehashed_source_or_missing_owner_payload_cannot_pass(self):
        manifest = self.create()
        path = self.package / "share/q-periapt/sdk_smoke.c"
        original = path.read_bytes()
        path.write_bytes(original + b"\n/* substituted consumer */\n")
        self.reseal(manifest)
        with self.assertRaisesRegex(windows.WindowsPackageError, "shipped source differs"):
            self.verify()
        path.unlink()
        self.reseal(manifest)
        with self.assertRaisesRegex(windows.WindowsPackageError, "file set differs"):
            self.verify()

    def test_coherent_schema_version_abi_or_release_relabeling_is_rejected(self):
        original = self.create()
        for key, value in (("schema_version", 3), ("schema_version", 4.0), ("kind", windows.KIND),
                           ("profile", "legacy"), ("version", "0.1.5"), ("release_claim_eligible", True),
                           ("git_dirty", True)):
            changed = copy.deepcopy(original)
            changed[key] = value
            self.reseal(changed)
            with self.subTest(field=key, value=value), self.assertRaises(windows.WindowsPackageError):
                self.verify()
        for key, value in (("major", 3), ("major", 2.0), ("export_count", 9), ("export_count", 43.0)):
            changed = copy.deepcopy(original)
            changed["abi"][key] = value
            self.reseal(changed)
            with self.subTest(abi_field=key, value=value), self.assertRaises(windows.WindowsPackageError):
                self.verify()

    def test_legacy_nine_asset_cbom_cannot_admit_sdk(self):
        manifest = self.create()
        path = self.package / "share/q-periapt/bom/cbom.cdx.json"
        document = json.loads(path.read_text())
        document["components"] = [row for row in document["components"] if row["name"] in windows.EXPECTED_CRYPTO_ASSETS]
        path.write_bytes(windows._canonical_json(document))
        self.reseal(manifest)
        with self.assertRaisesRegex(windows.WindowsPackageError, "asset inventory differs"):
            self.verify()

    def test_sdk_producer_and_archive_verifier_select_profile_and_same_library_names(self):
        script = (self.repository / "artifact/windows-package.ps1").read_text()
        for required in ('[ValidateSet("legacy", "sdk-alpha1")]', '$Version = "0.2.0-alpha.1"',
                         '"--profile", $Profile', '"--profile", "native-sdk-alpha1"',
                         '"--features", "sdk-cbom"', '"share/q-periapt/legacy/q_periapt.h"',
                         '"share/q-periapt/sdk_smoke.c"', '"LICENSES/Rust-1.97.0-library.html"',
                         'dynamic-smoke,sdk-dynamic-smoke,sdk-static-smoke,static-smoke',
                         'SDK output already exists', 'installed SDK consumers must be outside the checkout',
                         'Windows archive changed during consumer execution'):
            with self.subTest(required=required):
                self.assertIn(required, script)
        self.assertIn('"bin/q_periapt_ffi_abi2.dll"', script)
        self.assertNotIn("q_periapt_ffi_abi3", script)
        self.assertIn('"AWS_LC_SYS_STATIC_x86_64_pc_windows_msvc"] = "1"', script)
        self.assertIn('"AWS_LC_SYS_USE_SYSTEM_x86_64_pc_windows_msvc"] = "0"', script)
        self.assertIn('"AWS_LC_SYS_CFLAGS_x86_64_pc_windows_msvc"]', script)
        self.assertIn('/Ddllexport=', script)
        self.assertNotIn('/D__declspec', script)
        self.assertNotIn('/Ddllimport', script)
        self.assertNotIn('DISABLE_CPU_JITTER_ENTROPY=1', script)
        self.assertEqual(windows.SCHEMA_VERSION, 3)
        self.assertEqual(windows.PACKAGE_SEMVER, "0.1.5")


if __name__ == "__main__":
    unittest.main()
