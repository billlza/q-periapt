"""Admission and linkage controls; these synthetic tests do not claim a network run."""
from pathlib import Path
import copy
import hashlib
import os
import tempfile
import unittest
from unittest.mock import patch

import rust_sdk_profile as rust
import sdk_installed_connection as installed
from sdk_connection_interop import StaticClientLinkage, verify_client_load, verify_static_linkage


class InstalledConnectionAdmissionTests(unittest.TestCase):
    def test_explicit_toolchain_replaces_ambient_compiler_and_selector_settings(self):
        original = {"PATH": "/ambient/bin", "RUSTUP_HOME": "/ambient/rustup",
            "RUSTC": "/ambient/rustc", "RUSTC_WRAPPER": "/ambient/wrapper",
            "RUSTFLAGS": "--cfg bypass", "CARGO_ENCODED_RUSTFLAGS": "hostile",
            "CARGO_HOME": "/ambient/cache", "DYLD_LIBRARY_PATH": "/ambient/libraries"}
        selected = installed.rust_environment(original, Path("/selected/toolchain"),
                                               Path("/selected/cache"), Path("/outside/build"))
        self.assertEqual(selected["RUSTC"], "/selected/toolchain/bin/rustc")
        self.assertEqual(selected["RUSTDOC"], "/selected/toolchain/bin/rustdoc")
        self.assertEqual(selected["PATH"].split(os.pathsep)[0], "/selected/toolchain/bin")
        self.assertEqual(selected["CARGO_HOME"], "/selected/cache")
        self.assertEqual(selected["RUSTFLAGS"], "-D warnings")
        for name in ("RUSTUP_HOME", "RUSTC_WRAPPER", "CARGO_ENCODED_RUSTFLAGS", "DYLD_LIBRARY_PATH"):
            self.assertNotIn(name, selected)
        self.assertEqual(original["RUSTC"], "/ambient/rustc")

    def test_tool_identity_requires_compiler_and_clippy_and_detects_replacement(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "bin").mkdir()
            names = ("cargo", "rustc", "rustdoc", "cargo-clippy", "clippy-driver")
            for name in names:
                (root / "bin" / name).write_bytes(name.encode())
            before = installed.rust_tools(root)
            self.assertEqual(set(before), set(names))
            (root / "bin/clippy-driver").write_bytes(b"different driver")
            self.assertNotEqual(before, installed.rust_tools(root))
            (root / "bin/cargo-clippy").unlink()
            with self.assertRaises(ValueError):
                installed.rust_tools(root)

    def test_output_admission_uses_the_actual_destination_without_creating_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            target = root / "target"
            target.mkdir()
            (target / "parent").mkdir()
            expected = target / "fresh"
            with patch.object(installed, "ROOT", root):
                self.assertEqual(installed.fresh_output_path(expected), expected)
                self.assertEqual(installed.fresh_output_path(target / "parent/../fresh"), expected)
            self.assertFalse(expected.exists())

    def test_output_admission_rejects_escapes_links_and_existing_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            target, outside = root / "target", root / "outside"
            target.mkdir()
            outside.mkdir()
            (target / "redirect").symlink_to(outside, target_is_directory=True)
            (target / "dangling").symlink_to(target / "missing", target_is_directory=True)
            prior = target / "prior"
            prior.mkdir()
            marker = prior / "evidence"
            marker.write_bytes(b"retained")
            for requested in (target / "../escaped", target / "redirect/escaped",
                              target / "dangling", prior):
                with self.subTest(requested=requested), patch.object(installed, "ROOT", root):
                    with self.assertRaises(ValueError):
                        installed.fresh_output_path(requested)
            self.assertFalse((root / "escaped").exists())
            self.assertEqual(list(outside.iterdir()), [])
            self.assertTrue((target / "dangling").is_symlink())
            self.assertEqual(marker.read_bytes(), b"retained")

    def test_equal_versions_do_not_substitute_for_same_current_native_inputs(self):
        swift = {"rust_workspace_build_inputs": "a" * 64}
        cohort = {"version": "0.2.0", "source_inputs": {"rust_workspace_sha256": "a" * 64}}
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
