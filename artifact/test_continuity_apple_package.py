"""Reject wrong Apple slices, exports and Cargo provenance before admission."""
from pathlib import Path
import hashlib
import json
import plistlib
import tempfile
import unittest

import continuity_apple_package as apple
import continuity_c_consumer as c
from continuity_apple_consumer import verify_linkage


class ApplePackageTests(unittest.TestCase):
    def test_exact_exports_refuse_missing_extra_and_duplicate(self):
        rows = [("00000000 T _" + name + "\n").encode() for name in sorted(c.EXPORTS)]
        apple.verify_exports(b"".join(rows))
        for altered in (b"".join(rows[1:]), b"".join(rows + rows[:1]),
                        b"".join(rows) + b"00000000 T _qpc_unreviewed_v1\n"):
            with self.assertRaisesRegex(ValueError, "exports"):
                apple.verify_exports(altered)

    def test_cargo_requires_exact_root_target_static_release_output(self):
        consumer = Path("/private/qualified/c-consumer")
        build = Path("/private/qualified/apple/native")
        target = "aarch64-apple-ios"
        expected = build / target / "release" / apple.LIBRARY
        row = dict(reason="compiler-artifact", manifest_path=str(consumer / "Cargo.toml"),
                   target=dict(name=c.LIBRARY, crate_types=["staticlib"]),
                   profile=dict(opt_level="3", test=False), filenames=[str(expected)])
        def encoded(value): return (json.dumps(value) + "\n").encode()
        self.assertEqual(apple.built_static(encoded(row), consumer, build, target), expected)
        for field, value in (("manifest_path", "/checkout/Cargo.toml"),
                             ("target", dict(name=c.LIBRARY, crate_types=["cdylib"])),
                             ("profile", dict(opt_level="0", test=False)),
                             ("profile", dict(opt_level="3", test=True)),
                             ("filenames", [str(build / "aarch64-apple-ios-sim/release" / apple.LIBRARY)])):
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                apple.built_static(encoded(dict(row, **{field: value})), consumer, build, target)
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            apple.built_static(encoded(row) * 2, consumer, build, target)
        with self.assertRaisesRegex(ValueError, "unsupported"):
            apple.built_static(encoded(row), consumer, build, "x86_64-apple-ios")

    def fixture(self, root):
        rows, binaries = [], {}
        for index, (target, (platform, variant)) in enumerate(apple.TARGETS.items()):
            name = "slice-" + str(index); folder = root / name
            data = target.encode(); apple.write(folder / apple.LIBRARY, data)
            apple.write(folder / "Headers/qpc_owner.h", b"public header")
            apple.write(folder / "Headers/module.modulemap", apple.MODULE)
            row = dict(LibraryIdentifier=name, LibraryPath=apple.LIBRARY, HeadersPath="Headers",
                       SupportedArchitectures=["arm64"], SupportedPlatform=platform)
            if variant: row["SupportedPlatformVariant"] = variant
            rows.append(row); binaries[target] = {"sha256": hashlib.sha256(data).hexdigest()}
        (root / "Info.plist").write_bytes(plistlib.dumps({"AvailableLibraries": rows}))
        return rows, binaries

    def test_xcframework_requires_every_exact_platform_and_bound_library(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); rows, binaries = self.fixture(root)
            apple.verify_xcframework(root, binaries, b"public header")
            alterations = [rows[:-1], rows + [rows[0]], [rows[0], rows[0], rows[2]],
                           [dict(rows[0], SupportedArchitectures=["arm64", "x86_64"]), *rows[1:]],
                           [dict(rows[0], LibraryIdentifier="../other"), *rows[1:]],
                           [dict(rows[0], SupportedPlatform="tvos"), *rows[1:]]]
            for altered in alterations:
                with self.subTest(rows=altered), self.assertRaises(ValueError):
                    (root / "Info.plist").write_bytes(plistlib.dumps({"AvailableLibraries": altered}))
                    apple.verify_xcframework(root, binaries, b"public header")
            (root / "Info.plist").write_bytes(plistlib.dumps({"AvailableLibraries": rows}))
            (root / rows[1]["LibraryIdentifier"] / apple.LIBRARY).write_bytes(b"wrong library")
            with self.assertRaisesRegex(ValueError, "wrong native target"):
                apple.verify_xcframework(root, binaries, b"public header")

    def test_xcode_inventory_order_is_canonical_without_deduplication(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); rows, _ = self.fixture(root)
            a = plistlib.dumps({"AvailableLibraries": rows, "XCFrameworkFormatVersion": "1.0"})
            b = plistlib.dumps({"XCFrameworkFormatVersion": "1.0", "AvailableLibraries": list(reversed(rows))}, sort_keys=False)
            self.assertNotEqual(a, b)
            self.assertEqual(apple.canonical_xcframework_info(a), apple.canonical_xcframework_info(b))
            for altered in [rows[:-1], [rows[0], rows[0], rows[2]]]:
                with self.assertRaises(ValueError):
                    apple.canonical_xcframework_info(plistlib.dumps({"AvailableLibraries": altered}))

    def test_headers_and_modules_must_match_the_owned_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); rows, binaries = self.fixture(root)
            for name in ["qpc_owner.h", "module.modulemap"]:
                path = root / rows[0]["LibraryIdentifier"] / "Headers" / name
                original = path.read_bytes(); path.write_bytes(b"changed")
                with self.assertRaisesRegex(ValueError, "C interface differs"):
                    apple.verify_xcframework(root, binaries, b"public header")
                path.write_bytes(original)

    def test_installed_members_cannot_be_added_deleted_or_changed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); apple.write(root / "Package.swift", apple.MANIFEST)
            expected = {"files": apple.file_hashes(root)}
            (root / apple.CONTENTS).write_text(json.dumps(expected))
            for name, data in (("injected", b"extra"), ("Package.swift", b"different")):
                path = root / name; original = path.read_bytes() if path.exists() else None
                path.write_bytes(data)
                with self.assertRaisesRegex(ValueError, "members or bytes"):
                    apple.verify_package(root, expected, {}, b"")
                if original is None: path.unlink()
                else: path.write_bytes(original)
            (root / "Package.swift").unlink()
            with self.assertRaisesRegex(ValueError, "members or bytes"):
                apple.verify_package(root, expected, {}, b"")

    def test_linker_paths_allow_only_aliases_of_the_exact_selected_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); original = root / "original"; original.mkdir()
            alias = root / "alias"; alias.symlink_to(original, target_is_directory=True)
            library = original / apple.LIBRARY; library.write_bytes(b"native")
            executable = original / "consumer"; executable.write_bytes(b"executable")
            link_map = root / "LinkMap.txt"
            def record(lib, exe):
                link_map.write_text(f"# Path: {exe}\n# Arch: arm64\n# Object files:\n[  0] linker synthesized\n[  1] {lib}(owner.o)\n# Sections:\n")
            record(alias / apple.LIBRARY, alias / "consumer")
            self.assertEqual(verify_linkage(link_map, library, executable)["linked_archive_objects"], 1)
            other = root / "other"; other.mkdir()
            (other / apple.LIBRARY).write_bytes(b"native")
            (other / "consumer").write_bytes(b"executable")
            record(other / apple.LIBRARY, executable)
            with self.assertRaisesRegex(ValueError, "another native archive"):
                verify_linkage(link_map, library, executable)
            record(library, other / "consumer")
            with self.assertRaisesRegex(ValueError, "another executable"):
                verify_linkage(link_map, library, executable)

    def test_source_tree_does_not_follow_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / "redirect").symlink_to("/tmp")
            with self.assertRaisesRegex(ValueError, "symlink"):
                apple.file_hashes(root)


if __name__ == "__main__":
    unittest.main()
