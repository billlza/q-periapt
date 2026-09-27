"""Admission and linkage controls; these synthetic tests do not claim a network run."""
from pathlib import Path
import copy
import hashlib
import tempfile
import unittest

import rust_sdk_profile as rust
import sdk_installed_connection as installed
from sdk_connection_interop import StaticClientLinkage, verify_client_load, verify_static_linkage


class InstalledConnectionAdmissionTests(unittest.TestCase):
    def test_equal_versions_do_not_substitute_for_same_current_native_inputs(self):
        swift = {"rust_workspace_build_inputs": "a" * 64}
        cohort = {"version": "0.2.0-alpha.1", "source_inputs": {"rust_workspace_sha256": "a" * 64}}
        installed.same_native_sources(swift, cohort, "a" * 64)
        for source, report, current in (
            ({"rust_workspace_build_inputs": "b" * 64}, cohort, "a" * 64),
            (swift, cohort, "b" * 64), (swift, {"source_inputs": {}}, "a" * 64),
            ({}, cohort, "a" * 64), (swift, cohort, ""),
        ):
            with self.subTest(source=source, current=current), self.assertRaises(ValueError):
                installed.same_native_sources(source, report, current)

    def test_hash_pins_and_actual_link_map_prevent_archive_or_origin_substitution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            library, client, link_map = root / "libq_periapt_ffi_abi2.a", root / "client", root / "link.map"
            library.write_bytes(b"selected package archive")
            digest = hashlib.sha256(library.read_bytes()).hexdigest()
            link_map.write_text(f"# Path: {client}\n# Arch: arm64\n# Object files:\n[  0] linker synthesized\n[  1] {library}(sdk.o)\n# Sections:\n")
            linkage = StaticClientLinkage(library, digest, link_map, "arm64")
            self.assertEqual(verify_static_linkage(client, linkage)["library_sha256"], digest)
            with self.assertRaisesRegex(RuntimeError, "selected package"):
                verify_static_linkage(client, StaticClientLinkage(library, "b" * 64, link_map, "arm64"))
            with self.assertRaisesRegex(ValueError, "wrong executable"):
                verify_static_linkage(root / "other", linkage)
            library.write_bytes(b"different bytes")
            with self.assertRaisesRegex(RuntimeError, "selected package"):
                verify_static_linkage(client, linkage)
            with self.assertRaisesRegex(ValueError, "digest differs"):
                installed.pinned(library, digest)

    def test_static_runtime_requires_positive_executable_identity_and_no_dynamic_sdk(self):
        client, library = Path("/frozen/client"), Path("/frozen/libq_periapt_ffi_abi2.a")
        valid = b"dyld[1]: <00000000-0000-0000-0000-000000000000> /frozen/client\ndyld[1]: <00000000-0000-0000-0000-000000000000> /usr/lib/libSystem.B.dylib\n"
        verify_client_load(valid, client, library, static=True)
        transitions = (b"dyld[1]: move loaded to delayed: CryptoKit\n"
                       b"dyld[1]: move delayed to loaded: CryptoKit\n")
        verify_client_load(valid + transitions, client, library, static=True)
        for invalid in (b"", valid.replace(b"/frozen/client", b"/other/client"),
                        valid.replace(b"/frozen/client", b"/frozen/client-extra"),
                        b"ordinary diagnostic mentions /frozen/client\n", valid + valid,
                        valid + b"dyld[1]: malformed image record\n", transitions,
                        valid + b"dyld[1]: move delayed to loaded: libq_periapt_ffi.2.dylib\n",
                        valid + b"dyld[1]: <00000000-0000-0000-0000-000000000000> /other/libq_periapt_ffi.2.dylib\n",
                        valid + b"dyld[1]: <00000000-0000-0000-0000-000000000000> /other/libQPeriaptSDK.dylib\n"):
            with self.subTest(invalid=invalid), self.assertRaises(RuntimeError):
                verify_client_load(invalid, client, library, static=True)
        dynamic = Path("/frozen/libq_periapt_ffi.2.dylib")
        verify_client_load(valid.replace(b"/frozen/client", str(dynamic).encode()), client, dynamic, static=False)
        for wrong in (str(dynamic).encode(), valid.replace(b"/frozen/client", str(dynamic).encode() + b".other")):
            with self.assertRaises(RuntimeError):
                verify_client_load(wrong, client, dynamic, static=False)
        with self.assertRaises(RuntimeError):
            verify_client_load(valid, client, dynamic, static=False)

    def test_dynamic_runtime_rejects_mixed_sdk_images_and_transitions(self):
        client, library = Path("/frozen/client"), Path("/frozen/libq_periapt_ffi_abi2.dylib")
        def image(path):
            return f"dyld[1]: <00000000-0000-0000-0000-000000000000> {path}\n".encode()
        valid = image(client) + image(library) + image("/usr/lib/libSystem.B.dylib")
        verify_client_load(valid, client, library, static=False)
        verify_client_load(valid + b"dyld[1]: move delayed to loaded: libq_periapt_ffi_abi2.dylib\n",
                           client, library, static=False)
        for extra in (image(library), image("/other/libq_periapt_ffi_abi2.dylib"),
                      image("/other/libQPeriaptSDK.dylib"), image("/other/libqperiapt.so.2"),
                      b"dyld[1]: move delayed to loaded: libQPeriaptSDK.dylib\n",
                      b"dyld[1]: move loaded to delayed: libq_periapt_ffi.2.dylib\n"):
            with self.subTest(extra=extra), self.assertRaises(RuntimeError):
                verify_client_load(valid + extra, client, library, static=False)

    def test_sdk_image_names_do_not_match_only_a_directory_name(self):
        client = Path("/frozen/client")
        ordinary = b"dyld[1]: <00000000-0000-0000-0000-000000000000> /qperiapt-consumer/libunrelated.dylib\n"
        executable = b"dyld[1]: <00000000-0000-0000-0000-000000000000> /frozen/client\n"
        verify_client_load(executable + ordinary, client, Path("/frozen/libq_periapt_ffi_abi2.a"), static=True)
        library = Path("/frozen/libq_periapt_ffi_abi2.dylib")
        selected = f"dyld[1]: <00000000-0000-0000-0000-000000000000> {library}\n".encode()
        verify_client_load(executable + selected + ordinary, client, library, static=False)

    def test_rust_metadata_cannot_resolve_checkout_mixed_or_registry_product_crates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            rows = [{"name": installed.CONSUMER_NAME, "version": "0.0.0", "manifest_path": str(root / "Cargo.toml"), "source": None}]
            rows += [{"name": name, "version": rust.VERSION, "source": None,
                      "manifest_path": str(root / "packages" / f"{name}-{rust.VERSION}" / "Cargo.toml")}
                     for name in rust.CONSUMER_CRATES]
            lock = b'version = 4\n[[package]]\nname="external"\nversion="1.0.0"\nsource="registry+https://github.com/rust-lang/crates.io-index"\nchecksum="' + b'a' * 64 + b'"\n'
            result = installed.verify_rust_resolution({"packages": rows}, root, lock, lock)
            self.assertEqual((result["product_crates"], result["external_packages"]), (9, 1))
            changes = []
            for key, value in (("manifest_path", "/checkout/crates/q-periapt-core/Cargo.toml"),
                               ("version", "0.1.5"), ("source", "registry+https://github.com/rust-lang/crates.io-index")):
                candidate = copy.deepcopy(rows); candidate[1][key] = value; changes.append(candidate)
            changes.extend((rows[:-1], rows + [rows[1]]))
            for candidate in changes:
                with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                    installed.verify_rust_resolution({"packages": candidate}, root, lock, lock)
            with self.assertRaisesRegex(ValueError, "external dependency"):
                installed.verify_rust_resolution({"packages": rows}, root, lock.replace(b'a' * 64, b'b' * 64), lock)


if __name__ == "__main__":
    unittest.main()
