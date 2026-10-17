"""Alpha Swift packages cannot reuse legacy receipts or accept altered payloads."""
import copy
import io
import json
from pathlib import Path
import os
import stat
import subprocess
import textwrap
import tempfile
import unittest
import zipfile

import apple_distribution
import apple_sdk_profile as sdk
from test_apple_distribution import archive_bytes, thin_archive, write_zip_entry


class AppleSDKProfileTests(unittest.TestCase):
    def test_unsigned_packages_reject_source_drift_before_reporting_success(self):
        builder = (sdk.ROOT / "artifact/swift-xcframework.sh").read_text()
        function = builder.split("assert_release_source_snapshot() {\n", 1)[1].split(
            "\n}\nassert_release_source_snapshot", 1)[0]
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve(strict=True)
            checkout = parent / "checkout"
            checkout.mkdir()
            environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
            environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_SYSTEM="/dev/null")

            def git(*arguments):
                return subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-C", str(checkout), *arguments],
                                      env=environment, text=True, capture_output=True, check=True).stdout.strip()

            git("init", "-q")
            (checkout / "input.txt").write_text("source input\n")
            git("add", "input.txt")
            git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "input")
            original = git("rev-parse", "HEAD")
            harness = parent / "harness.sh"
            harness.write_text(textwrap.dedent('''\
                #!/bin/sh
                set -eu
                ROOT=$1
                SOURCE_COMMIT=$2
                APPLE_RELEASE_MODE=$3
                QPERIAPT_ALLOW_DIRTY_SWIFT_XCFRAMEWORK=$4
                QPERIAPT_INTERNAL_APPLE_SOURCE_COMMIT=$SOURCE_COMMIT
                QPERIAPT_INTERNAL_APPLE_DURABILITY_ROOT=$ROOT
                release_git() { git -C "$ROOT" "$@"; }
                assert_release_source_snapshot() {
                ''') + function + "\n}\nassert_release_source_snapshot\n")

            def check(mode, dirty, passes, message=""):
                result = subprocess.run(["sh", str(harness), str(checkout), original, mode, dirty],
                                        env=environment, text=True, capture_output=True, check=False)
                self.assertEqual(result.returncode == 0, passes, result.stderr)
                if message:
                    self.assertIn(message, result.stderr)

            for mode in ("0", "1"):
                check(mode, "0", True)
            generated = checkout / "unexpected-cache"
            generated.write_text("generated outside the build directory\n")
            check("0", "0", False, "worktree changed")
            check("1", "0", False, "worktree changed")
            check("0", "1", True)  # Explicit unsigned diagnostics retain their existing allowance.
            check("1", "1", False, "worktree changed")
            generated.unlink()
            git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                "commit", "--allow-empty", "-qm", "different commit")
            for mode in ("0", "1"):
                for dirty in ("0", "1"):
                    check(mode, dirty, False, "commit changed")

    def test_platform_inventory_excludes_intel_macos_but_retains_ios_simulator(self):
        self.assertEqual(sdk.HOST_TARGETS, ("aarch64-apple-darwin",))
        self.assertEqual(sdk.TARGETS, ("aarch64-apple-darwin", "aarch64-apple-ios",
                                      "aarch64-apple-ios-sim", "x86_64-apple-ios"))
        self.assertEqual(sdk.SLICES, ("macos-arm64", "ios-arm64", "ios-arm64_x86_64-simulator"))
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            for host in ("x86_64-apple-darwin", "aarch64-apple-ios", "aarch64-apple-ios-sim", "x86_64-apple-ios"):
                with self.subTest(host=host), self.assertRaisesRegex(ValueError, "explicit Apple host target"):
                    sdk.prepare(parent / "unused.zip", parent, host)
            self.assertEqual(list(parent.iterdir()), [])

    def test_sdk_and_legacy_archives_have_separate_closed_layouts(self):
        legacy_entries = (apple_distribution.EXPECTED_XCFRAMEWORK_DIRECTORIES |
                          apple_distribution.EXPECTED_XCFRAMEWORK_FILES)
        for profile in ("legacy", "sdk-020"):
            payload = io.BytesIO()
            with zipfile.ZipFile(payload, "w") as archive:
                for legacy_name in sorted(legacy_entries):
                    name = (legacy_name.replace("macos-arm64_x86_64", "macos-arm64")
                            if profile == "sdk-020" else legacy_name)
                    if name.endswith("/"):
                        data, mode = b"", stat.S_IFDIR | 0o755
                    else:
                        relative = legacy_name.removeprefix("CQPeriapt.xcframework/")
                        data = (archive_bytes(relative) if relative in apple_distribution.EXPECTED_XCFRAMEWORK_LIBRARIES
                                else b"fixture")
                        if profile == "sdk-020" and name.endswith("macos-arm64/libq_periapt_ffi_abi2.a"):
                            data = thin_archive(b"arm64")
                        mode = stat.S_IFREG | 0o644
                    write_zip_entry(archive, name, data, mode=mode)
            with self.subTest(profile=profile):
                apple_distribution._validate_xcframework_zip_bytes(
                    payload.getvalue(), require_signature=False, profile=profile)
                other = "sdk-020" if profile == "legacy" else "legacy"
                with self.assertRaisesRegex(apple_distribution.AppleDistributionError, "exact static-only layout"):
                    apple_distribution._validate_xcframework_zip_bytes(
                        payload.getvalue(), require_signature=False, profile=other)
                if profile == "legacy":
                    apple_distribution._validate_xcframework_zip_bytes(payload.getvalue(), require_signature=False)
        with self.assertRaisesRegex(apple_distribution.AppleDistributionError, "SDK signing contract"):
            apple_distribution._expected_archive_entries(True, profile="sdk-020")
        with self.assertRaisesRegex(apple_distribution.AppleDistributionError, "unsupported XCFramework profile"):
            apple_distribution._expected_archive_entries(False, profile="unknown")

    def test_sdk_rejects_legacy_dual_macos_runtime_policy_before_tools_or_payload(self):
        environment = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        result = subprocess.run(
            ["sh", str(sdk.ROOT / "artifact/swift-xcframework-consumer-check.sh"),
             "/unused/package", "/unused/evidence", "/unused/framework", "--validate-only"],
            env={**environment, "QPERIAPT_INTERNAL_APPLE_PACKAGE_PROFILE": "sdk-020",
                 "QPERIAPT_INTERNAL_REQUIRE_DUAL_MACOS_RUNTIME": "1"},
            text=True, capture_output=True, timeout=30, check=False)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("dual macOS runtime policy is legacy-only", result.stderr)

    def test_xcode_scheme_requires_known_consumer_identity_and_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "schemes.json"
            def write(name, schemes):
                path.write_text(json.dumps({"workspace": {"name": name, "schemes": schemes}}))
            for schemes, expected in ((["QPeriaptSDKConsumer"], "QPeriaptSDKConsumer"),
                                      (["QPeriaptLinkProbe", "QPeriaptSDKConsumer"], "QPeriaptLinkProbe")):
                write("QPeriaptSDKConsumer", schemes)
                self.assertEqual(sdk.select_consumer_scheme(path), expected)
            for name, schemes in (("other", ["QPeriaptLinkProbe"]), ("QPeriaptSDKConsumer", []),
                                   ("QPeriaptSDKConsumer", ["other"]), ("QPeriaptSDKConsumer", [None]),
                                   ("QPeriaptSDKConsumer", ["QPeriaptLinkProbe", "QPeriaptLinkProbe"])):
                write(name, schemes)
                with self.subTest(name=name, schemes=schemes), self.assertRaises(ValueError):
                    sdk.select_consumer_scheme(path)

    def test_link_map_binds_archive_path_architecture_and_nonempty_object_set(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "link.map"
            library = Path("/installed/libq_periapt_ffi_abi2.a")
            probe = Path("/installed/probe")
            valid = (f"# Path: {probe}\n# Arch: arm64\n# Object files:\n"
                     f"[  0] linker synthesized\n[  1] {library}(sdk.o)\n# Sections:\n").encode()
            path.write_bytes(valid + b"# Symbols:\nraw literal \xc0\n")
            self.assertEqual(sdk.verify_link_map(path, library, probe, "arm64")["linked_archive_objects"], 1)
            for mutated in (valid.replace(b"arm64", b"x86_64"), valid.replace(b"/installed/probe", b"/other/probe"),
                            valid.replace(b"/installed/lib", b"/other/lib"), valid.replace(b"[  1]", b"[  0]"),
                            valid.replace(b"[  1]", b"[ 00]"), valid.replace(b"(sdk.o)", b"()"),
                            valid.replace(f"[  1] {library}(sdk.o)\n".encode(), b""),
                            valid.replace(b"# Sections:", b"# Other:"),
                            valid.replace(b"/installed/lib", b"/installed/\xc0lib")):
                path.write_bytes(mutated)
                with self.subTest(mutated=mutated), self.assertRaises(ValueError):
                    sdk.verify_link_map(path, library, probe, "arm64")

    def test_host_tools_and_each_sdk_target_have_separate_deployment_floors(self):
        with tempfile.TemporaryDirectory() as temporary:
            compiler = Path(temporary) / "compiler"
            compiler.write_text('#!/bin/sh\nprintf "%s %s\\n" "${MACOSX_DEPLOYMENT_TARGET-unset}" "${IPHONEOS_DEPLOYMENT_TARGET-unset}"\n')
            compiler.chmod(0o700)
            wrapper = str(sdk.ROOT / "artifact/apple-sdk-rustc.sh")
            env = {**os.environ, "MACOSX_DEPLOYMENT_TARGET": "27.0", "IPHONEOS_DEPLOYMENT_TARGET": "27.0"}
            cases = [([], "unset unset\n"), (["-vV"], "unset unset\n")]
            for target in sdk.TARGETS:
                expected = "13.0 unset\n" if target.endswith("darwin") else "unset 16.0\n"
                cases += [(["--target", target], expected), ([f"--target={target}"], expected)]
            for args, expected in cases:
                with self.subTest(args=args):
                    r = subprocess.run(["sh", wrapper, str(compiler), *args], env=env,
                                       text=True, capture_output=True, timeout=10, check=False)
                    self.assertEqual((r.returncode, r.stdout, r.stderr), (0, expected, ""))
            for args in (["--target"], ["--target="], ["--target", "unknown"],
                         ["--target", "x86_64-apple-darwin"], ["--target=x86_64-apple-darwin"],
                         ["--target=aarch64-apple-ios", "--target", "aarch64-apple-darwin"]):
                with self.subTest(args=args):
                    r = subprocess.run(["sh", wrapper, str(compiler), *args], env=env,
                                       text=True, capture_output=True, timeout=10, check=False)
                    self.assertEqual(r.returncode, 2)
                    self.assertEqual(r.stdout, "")

    def test_legacy_signing_mode_and_unknown_profiles_fail_before_build(self):
        environment = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        for arguments, mode, expected in ((["--profile", "sdk-020"], "1", "legacy receipts cannot admit it"),
                                          (["--profile", "abi3"], "0", "accepts only --profile sdk-020")):
            with self.subTest(arguments=arguments):
                result = subprocess.run(["sh", str(sdk.ROOT / "artifact/swift-xcframework.sh"), *arguments],
                    env={**environment, "QPERIAPT_INTERNAL_APPLE_RELEASE_MODE": mode},
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30, check=False)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn(expected, result.stderr)
                self.assertNotIn("Build Apple static libraries", result.stdout)

    def test_payload_changes_and_manifest_type_or_version_changes_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary)
            (package / "Package.swift").write_text(sdk.PACKAGE)
            identity = {"rust_workspace_build_inputs": "a" * 64, "files": {}}
            valid = {"schema_version": 1, "kind": "qperiapt.swift_sdk_contents", "profile": sdk.PROFILE,
                     "version": sdk.VERSION, "abi_major": 2, "source_inputs": identity,
                     "files": sdk.inventory(package)}
            for key, value in (("version", "0.1.5"), ("abi_major", 3), ("schema_version", True),
                               ("files", {}), ("source_inputs", {})):
                changed = copy.deepcopy(valid)
                changed[key] = value
                (package / sdk.CONTENTS).write_bytes(sdk.canonical_json(changed))
                with self.subTest(key=key), self.assertRaisesRegex(ValueError, "contents/source manifest differs"):
                    sdk.verify_package(package, identity, cargo_lock=None, expected_native_files={})
            (package / sdk.CONTENTS).write_bytes(sdk.canonical_json(valid))
            (package / "Package.swift").write_text(sdk.PACKAGE + "\n// changed after packaging\n")
            with self.assertRaisesRegex(ValueError, "contents/source manifest differs"):
                sdk.verify_package(package, identity, cargo_lock=None, expected_native_files={})

    def test_rehashing_contents_cannot_replace_the_checked_native_payload(self):
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary)
            (package / "Binaries").mkdir()
            native = package / "Binaries/library.a"
            native.write_bytes(b"native origin")
            original = sdk.inventory(package)
            native.write_bytes(b"changed after native consumer checks")
            manifest = {"schema_version": 1, "kind": "qperiapt.swift_sdk_contents", "profile": sdk.PROFILE,
                        "version": sdk.VERSION, "abi_major": 2, "source_inputs": {}, "files": sdk.inventory(package)}
            (package / sdk.CONTENTS).write_bytes(sdk.canonical_json(manifest))
            with self.assertRaisesRegex(ValueError, "native payload differs from the verified XCFramework"):
                sdk.verify_package(package, {}, cargo_lock=None, expected_native_files=original)
            with self.assertRaisesRegex(ValueError, "native payload differs from the verified XCFramework"):
                sdk.verify_package(package, {}, cargo_lock=None, expected_native_files={})

    def test_xcframework_digest_must_match_before_zip_parsing(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "changed.zip"
            path.write_bytes(b"replacement artifact")
            with self.assertRaisesRegex(ValueError, "changed after native verification"):
                sdk.verified_xcframework_files(path, "0" * 64)
            for digest in ("", "0" * 63, "A" * 64):
                with self.subTest(digest=digest), self.assertRaisesRegex(ValueError, "canonical SHA-256"):
                    sdk.verified_xcframework_files(path, digest)

    def test_symlinked_package_entries_and_root_are_not_followed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / "package"
            package.mkdir()
            (root / "outside").mkdir()
            (root / "outside/key.txt").write_text("not a package file")
            (package / "escape").symlink_to(root / "outside", target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "non-regular"):
                sdk.inventory(package)
            (root / "alias").symlink_to(package, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "regular directory"):
                sdk.inventory(root / "alias")


if __name__ == "__main__":
    unittest.main()
