"""Producer failure/source controls; compiler and LLVM execution is simulated."""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import json
from pathlib import Path
import shlex
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import continuity_android_build as build
import continuity_android_distribution as distribution
from bounded_process import BoundedProcessError
from test_continuity_android_distribution import class_bytes, license_bytes, native_bytes, readelf_output


class BuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source_paths = sorted(p.relative_to(distribution.ROOT).as_posix()
            for p in (distribution.ROOT / distribution.ADAPTER / "src/main/java").rglob("*.java"))
        cls.contract = distribution.source_contract(cls.source_paths)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.source = {"commit": "a" * 40, "tree": "b" * 40, "tree_sha256": "c" * 64}

    def class_members(self):
        from continuity_android_classes import jni_contract
        native, callbacks = jni_contract(self.contract["bridge"])
        members = {name.removesuffix(".java") + ".class": class_bytes(name.removesuffix(".java"))
                   for name in self.contract["java"]}
        name = "dev/qperiapt/continuity/android/Native"
        members[name + ".class"] = class_bytes(name,
            [(n, d, 0x010a) for n, d in native.items()] + [(n, d, 0x000a) for n, d in callbacks.items()])
        return members

    def test_environment_remaps_both_roots_and_rejects_inherited_overrides(self):
        inherited = {key: "attacker" for key in ("RUSTC", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CC",
            "CC_aarch64-linux-android", "CFLAGS", "TARGET_CFLAGS", "HOST_CC", "CRATE_CC_NO_DEFAULTS",
            "SDKROOT", "DYLD_INSERT_LIBRARIES", "LD_PRELOAD", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH")}
        inherited.update({name: "attacker" for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE",
            "GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0", "GIT_CONFIG_GLOBAL")})
        inherited["PATH"] = "/usr/bin:/bin"
        outside, account = self.root / "build space", self.root / "user space"
        env, flags = build.build_environment(inherited, outside=outside, toolchain=self.root / "rust",
            ndk_tools=self.root / "ndk", account_root=account)
        self.assertNotIn("attacker", env.values())
        self.assertNotIn("RUSTFLAGS", env)
        self.assertNotIn("GIT_DIR", env)
        self.assertEqual(env["GIT_CONFIG_GLOBAL"], "/dev/null")
        self.assertEqual(env["CC_SHELL_ESCAPED_FLAGS"], "1")
        self.assertEqual(shlex.split(env["CFLAGS"]), flags)
        self.assertEqual(env["CARGO_ENCODED_RUSTFLAGS"].split("\x1f"), ["-Dwarnings",
            f"--remap-path-prefix={outside}=/qperiapt/installed", f"--remap-path-prefix={account}=/qperiapt-build/user"])
        self.assertEqual(env["CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER"], str(self.root / "ndk/bin/aarch64-linux-android23-clang"))
        with self.assertRaisesRegex(ValueError, "remap root"):
            build.build_environment({}, outside=outside, toolchain=self.root, ndk_tools=self.root, account_root=Path("/"))

    def test_native_recipe_keeps_api23_arm64_hardening_hidden_jni_and_explicit_clippy(self):
        adapter = self.root / "android"
        for name in ("continuity_jni.c", "owner.c"):
            build.write_file(adapter / "jni" / name, b"/* fixture */")
        commands = build.native_commands(self.root / "rust", self.root / "ndk", self.root / "c",
            adapter, self.root / "native", ["-ffile-prefix-map=/user=/remapped"])
        cargo = commands["native-build"]
        self.assertEqual(cargo[cargo.index("--target") + 1], "aarch64-linux-android")
        for flag in ("--release", "--locked", "--offline", "--lib"):
            self.assertIn(flag, cargo)
        for flag in build.HARDENING:
            self.assertIn("link-arg=-Wl," + flag, cargo)
            self.assertIn("-Wl," + flag, commands["jni-build"])
        self.assertTrue(commands["jni-build"][0].endswith("aarch64-linux-android23-clang"))
        for flag in ("-Werror", "-Wpedantic", "-fvisibility=hidden", "-fPIC", "-shared"):
            self.assertIn(flag, commands["jni-build"])
        self.assertTrue(commands["clippy"][0].endswith("/cargo-clippy"))
        self.assertEqual(commands["clippy"][-3:], ["--", "-D", "warnings"])
        (adapter / "jni/continuity_jni.c").unlink()
        with self.assertRaisesRegex(ValueError, "JNI source"):
            build.native_commands(self.root, self.root, self.root, adapter, self.root, [])

    def test_repackaged_engine_must_match_captured_source_even_after_source_restore(self):
        sources = {build.ENGINE + "/Cargo.toml": b"current manifest", build.ENGINE + "/src/lib.rs": b"current engine"}
        files = {"Cargo.toml.orig": b"current manifest", "Cargo.toml": b"normalized", "src/lib.rs": b"current engine"}
        build.verify_candidate_snapshot(files, sources)
        for key in ("Cargo.toml.orig", "src/lib.rs"):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "consumed source snapshot"):
                build.verify_candidate_snapshot({**files, key: b"temporarily replaced"}, sources)

    def test_missing_tracked_build_input_fails_instead_of_shortening_source_inventory(self):
        missing = build.ENGINE + "/src/new.rs"
        with mock.patch.object(build, "ROOT", self.root), self.assertRaises(ValueError):
            build.capture_sources([missing], {"pinned": {}})

    def test_directory_snapshot_rejects_symlink_and_size_overflow(self):
        directory = self.root / "sources"; directory.mkdir()
        (directory / "a").write_bytes(b"abc")
        with self.assertRaisesRegex(ValueError, "exceeds"):
            build.directory_files(directory, maximum=2)
        (directory / "link").symlink_to(directory / "a")
        with self.assertRaisesRegex(ValueError, "symlink"):
            build.directory_files(directory)

    def test_java_compiler_output_is_verified_against_current_jni_descriptors(self):
        for mutate in (False, True):
            outside = self.root / str(mutate); outside.mkdir()
            def run(argv, label):
                self.assertEqual(label, "javac")
                self.assertEqual(argv[1:6], ["--release", "11", "-Xlint:all", "-Werror", "-d"])
                classes = Path(argv[6])
                members = self.class_members()
                if mutate:
                    name = "dev/qperiapt/continuity/android/Native.class"
                    members[name] = class_bytes(name[:-6])
                for name, data in members.items(): build.write_file(classes / name, data)
            if mutate:
                with self.assertRaises(ValueError): build.compile_classes(run, self.root, outside, self.contract)
            else:
                jar, verification = build.compile_classes(run, self.root, outside, self.contract)
                self.assertEqual(verification["native_methods"], 23)
                self.assertEqual(len(distribution.zip_entries(jar)), 68)

    def test_javac_cannot_modify_copied_sources(self):
        def run(argv, label):
            for name, data in self.class_members().items(): build.write_file(Path(argv[6]) / name, data)
            next((self.root / "java-source").rglob("*.java")).write_bytes(b"modified")
        with self.assertRaisesRegex(ValueError, "changed copied source"):
            build.compile_classes(run, self.root, self.root, self.contract)

    def test_wrong_compiler_or_java_version_is_rejected(self):
        outputs = {"rustc": (build.RUSTC + "\nhost: aarch64-apple-darwin\n").encode(),
            "cargo-clippy-version": build.CLIPPY.encode(), "clippy-driver-version": build.CLIPPY.encode(),
            "java-version": b"openjdk 25.0.5", "javac-version": b"javac 25.0.5", "clang": b"Android clang"}
        run = lambda argv, label: outputs[label]
        build.verify_tool_versions(run, self.root, self.root, self.root)
        for label, replacement in (("rustc", b"rustc 1.90.0"), ("clippy-driver-version", b"clippy 0.1.90"),
                                    ("java-version", b"openjdk 21.0.5"), ("javac-version", b"javac 26")):
            before = outputs[label]; outputs[label] = replacement
            with self.subTest(label=label), self.assertRaises(ValueError):
                build.verify_tool_versions(run, self.root, self.root, self.root)
            outputs[label] = before

    def test_tool_identity_requires_and_pins_selected_android_standard_library(self):
        rust, ndk, java = (self.root / name for name in ("rust", "ndk", "java"))
        for home, names in ((rust, ("cargo", "rustc", "rustdoc", "cargo-clippy", "clippy-driver")),
                            (ndk, ("aarch64-linux-android23-clang", "clang", "ld.lld", "llvm-ar", "llvm-nm", "llvm-readelf", "llvm-strip")),
                            (java, ("java", "javac"))):
            for name in names:
                path = home / "bin" / name
                build.write_file(path, b"synthetic executable"); path.chmod(0o700)
        for path in (ndk / "source.properties", ndk / "sysroot/usr/include/jni.h", java / "release", java / "lib/modules"):
            build.write_file(path, b"synthetic tool data")
        with mock.patch.object(distribution.elf, "verify_ndk_r29", return_value=distribution.NDK), \
             mock.patch.object(distribution.elf, "find_ndk_toolchain", return_value=ndk):
            with self.assertRaisesRegex(ValueError, "standard library is missing"):
                build.tool_identity(rust, ndk, java)
            standard = rust / "lib/rustlib" / distribution.TARGET / "lib"
            build.write_file(standard / "libstd-fixture.rlib", b"synthetic target std")
            (standard / "self-contained").mkdir()
            first, _ = build.tool_identity(rust, ndk, java)
            self.assertIn("rust-android-std/libstd-fixture.rlib", first)
            build.write_file(standard / "self-contained/target-object.o", b"synthetic object")
            second, _ = build.tool_identity(rust, ndk, java)
            self.assertNotEqual(first, second)
            self.assertIn("rust-android-std/self-contained/target-object.o", second)

    def test_real_timeout_keeps_partial_streams_and_typed_failure_receipt(self):
        prefix = self.root / "timeout-control"
        argv = [sys.executable, "-I", "-S", "-c",
                "import sys,time; print('before timeout',flush=True); "
                "print('stderr before timeout',file=sys.stderr,flush=True); time.sleep(10)"]
        with mock.patch.dict(build.COMMAND_TIMEOUTS, {"timeout-control": 1}), \
             self.assertRaises(BoundedProcessError) as failure:
            build.run_command(argv, prefix, self.root, environment={"PATH": "/usr/bin:/bin"})
        self.assertEqual(failure.exception.kind, "timeout")
        record = json.loads(prefix.with_suffix(".json").read_bytes())
        self.assertFalse(record["completed"])
        self.assertEqual(record["failure_kind"], "timeout")
        self.assertEqual(record["timeout_seconds"], 1)
        self.assertIn(b"before timeout", prefix.with_suffix(".stdout").read_bytes())
        self.assertIn(b"stderr before timeout", prefix.with_suffix(".stderr").read_bytes())

    def simulate(self, *, fail=None, mutate_installed=False):
        """Execute the real producer/assembler with explicit synthetic tool outputs."""
        checkout = self.root / "checkout"; checkout.mkdir()
        outside = self.root / "outside"; outside.mkdir()
        toolchain, ndk, java_home = (self.root / name for name in ("rust", "ndk", "java"))
        for path in (toolchain, ndk, java_home): path.mkdir()
        selected_report = self.root / "SDK.json"; selected_report.write_bytes(b"selected SDK report")
        output = checkout / "target/android-build"
        args = argparse.Namespace(report=selected_report, report_sha256=distribution.sha(selected_report.read_bytes()),
            sdk_run_id="1234", toolchain_root=toolchain, ndk=ndk, java_home=java_home, output=output,
            source_commit=self.source["commit"], source_tree=self.source["tree"],
            source_tree_sha256=self.source["tree_sha256"], native_package_id="continuity-native")
        sources = dict(self.contract["pinned"])
        sources.update({build.ENGINE + "/src/lib.rs": b"current engine", build.ENGINE + "/Cargo.lock": b"lock",
                        distribution.CONSUMER + "/Cargo.toml": b"[workspace]\n",
                        distribution.CONSUMER + "/src/lib.rs": b"current C interface"})
        tools = {"fixture": {"path": "/synthetic/tool", "sha256": "d" * 64}}
        def package_candidate(cargo, producer, producer_build, sdk_output, cohort, packages, logs, run, env):
            run(["git", "ls-files", build.ENGINE], "candidate-sources")
            data = b"synthetic source archive"
            name = package_name = "q-periapt-continuity-0.2.0.crate"
            build.write_file(logs / name, data)
            return {"file": package_name, "sha256": distribution.sha(data), "bytes": len(data)}, {
                "Cargo.toml.orig": sources[build.ENGINE + "/Cargo.toml"], "src/lib.rs": b"current engine"}
        def extract(consumer, report_root, records):
            with (consumer / "Cargo.toml").open("a") as stream: stream.write("[patch.crates-io]\n")
        def command(argv, prefix, cwd, *, environment):
            label = prefix.name
            stdout = {"rustc": (build.RUSTC + "\nhost: aarch64-apple-darwin\n").encode(),
                "cargo-clippy-version": build.CLIPPY.encode(), "clippy-driver-version": build.CLIPPY.encode(),
                "java-version": b"openjdk 25.0.5", "javac-version": b"javac 25.0.5", "clang": b"Android clang",
                "workspace-metadata": b"{}", "consumer-metadata": b"{}"}.get(label, b"")
            if label == "candidate-sources":
                self.assertEqual(argv[0], "/usr/bin/git")
                self.assertIn("--git-dir=" + str(checkout / ".git"), argv)
                self.assertNotIn("GIT_DIR", environment)
                stdout = ("\n".join(name for name in sorted(sources) if name.startswith(build.ENGINE + "/")) + "\n").encode()
            prefix.with_suffix(".stdout").write_bytes(stdout)
            prefix.with_suffix(".stderr").write_bytes(b"simulated failure" if label == fail else b"")
            prefix.with_suffix(".json").write_bytes(distribution.canonical({"argv": argv, "returncode": int(label == fail)}))
            if label == fail: raise ValueError("simulated compiler failure: " + label)
            if label == "native-build":
                build.write_file(Path(environment["CARGO_TARGET_DIR"]) / distribution.TARGET / "release" / distribution.C_LIBRARY, native_bytes())
            elif label == "jni-build":
                build.write_file(Path(argv[-1]), native_bytes())
            elif label == "javac":
                for name, data in self.class_members().items(): build.write_file(Path(argv[6]) / name, data)
                if mutate_installed: (outside / "c-consumer/src/lib.rs").write_bytes(b"changed by tool")
            return stdout
        def collect(consumer, notices, target, **kwargs):
            entries = distribution.zip_entries(license_bytes())
            for name, data in entries.items(): build.write_file(notices / name, data)
            return json.loads(entries["THIRD_PARTY/rust/INVENTORY.json"])
        def inspect(argv, **kwargs):
            name = Path(argv[-1]).name
            exports = self.contract["exports"] if name == distribution.C_LIBRARY else {"JNI_OnLoad"}
            stdout = ("".join(n + " T 0 1\n" for n in sorted(exports)).encode()
                      if "llvm-nm" in argv[0] else readelf_output(name))
            return SimpleNamespace(returncode=0, stdout=stdout, stderr=b"")
        real_mkdtemp = tempfile.mkdtemp
        def mkdtemp(*args, **kwargs):
            if kwargs.get("prefix") == "qperiapt-android-build-": return str(outside)
            return real_mkdtemp(*args, **kwargs)
        with ExitStack() as stack:
            replacements = [
                (build, "ROOT", checkout), (distribution, "ROOT", checkout),
                (build.os, "uname", lambda: SimpleNamespace(sysname="Darwin", machine="arm64")),
                (distribution, "repository_paths", lambda root: sorted(sources)),
                (distribution, "source_identity", lambda **kwargs: self.source),
                (distribution, "source_contract", lambda paths: self.contract),
                (build, "capture_sources", lambda paths, contract: sources),
                (build, "tool_identity", lambda *args: (tools, ndk)),
                (build.tempfile, "mkdtemp", mkdtemp),
                (build.sdk, "source_identity", lambda: {"rust_workspace_sha256": "f" * 64}),
                (build.package, "admit_sdk_report", lambda *args, **kwargs: (build.sdk.snapshot(selected_report), {"crates": {}})),
                (build.sdk, "classify", lambda metadata: {}),
                (build.package, "package_candidate", package_candidate), (build.sdk, "extract_recorded_crates", extract),
                (build.package, "verify_resolution", lambda *args, **kwargs: {"product_crates": 9}),
                (build.sdk, "verify_consumed_sources", lambda *args, **kwargs: None),
                (build, "run_command", command), (build.third_party_licenses, "collect", collect),
                (distribution, "native_tools", lambda ndk: {key: ndk / key for key in ("llvm-nm", "llvm-readelf")}),
                (distribution, "capture_output", inspect),
            ]
            for obj, name, value in replacements: stack.enter_context(mock.patch.object(obj, name, value))
            # The assembler pins its inspection binaries independently.
            for name in ("llvm-nm", "llvm-readelf"): (ndk / name).write_bytes(b"synthetic inspection tool")
            try:
                report = build.build(args)
            except ValueError:
                if fail is None and not mutate_installed: raise
                report = json.loads((output / "BUILD.json").read_bytes())
            return output, report

    def test_full_synthetic_producer_publishes_receipts_then_reopens_actual_capsule(self):
        output, report = self.simulate()
        self.assertTrue(report["completed"])
        self.assertTrue(report["native_compilation_executed"])
        self.assertTrue(report["java_compilation_executed"])
        self.assertTrue(report["distribution_reopened"])
        self.assertEqual(report["native_verification"]["c"]["exports"], 158)
        self.assertEqual(report["classes_verification"]["native_methods"], 23)
        selection = (output / "INPUT_SELECTION.json").read_bytes()
        distribution.validate_selection(selection, output, expected_sha256=distribution.sha(selection), source=self.source)
        self.assertTrue((output / "capsule" / report["aar"]["path"]).is_file())
        self.assertFalse(report["art_executed"])
        self.assertFalse(report["release_claim_eligible"])

    def test_failed_native_compiler_retains_failure_without_success_receipt(self):
        output, report = self.simulate(fail="native-build")
        self.assertFalse(report["completed"])
        self.assertTrue(report["native_compilation_executed"])
        self.assertFalse(report["java_compilation_executed"])
        self.assertIn("native-build", report["failure"])
        for name in ("native-build.json", "classes-build.json", "INPUT_SELECTION.json", "capsule"):
            self.assertFalse((output / name).exists())
        self.assertTrue((output / "commands/native-build.stderr").is_file())

    def test_failed_java_compiler_cannot_issue_receipts_for_successful_native_build(self):
        output, report = self.simulate(fail="javac")
        self.assertFalse(report["completed"])
        self.assertTrue(report["native_compilation_executed"])
        self.assertTrue(report["java_compilation_executed"])
        self.assertFalse((output / "native-build.json").exists())
        self.assertFalse((output / "INPUT_SELECTION.json").exists())

    def test_postbuild_installed_source_mutation_prevents_receipts(self):
        output, report = self.simulate(mutate_installed=True)
        self.assertFalse(report["completed"])
        self.assertIn("changed installed source", report["failure"])
        self.assertFalse((output / "INPUT_SELECTION.json").exists())


if __name__ == "__main__":
    unittest.main()
