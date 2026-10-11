"""Rebuild the same installed C engine on Rust 1.90 and exercise Swift root recovery."""
from pathlib import Path
import hashlib
import os
import re

import continuity_c_consumer as c
import continuity_c_root as c_root
import continuity_swift_root as swift_root
from continuity_package_archive import archive, unpack, MAX_PACKAGE
import rust_sdk_profile as sdk
from rust_sdk_msrv import RUSTC, tool_identity
import third_party_licenses as licenses

SCOPE = ("Installed same-source Rust 1.90 Debug C engine and Swift facade on macOS arm64; "
         "four original/alternative root recovery routes, default worker stacks, cleanup and bidirectional "
         "message recovery after rekey. This is the minimum-compiler root regression, not the whole foreign matrix.")


ROOT_TESTS = frozenset((
    'configuration::tests::account_authority::root_replacement::alternatives::root_foreign_adoption_resumes_actual_winner_without_a_local_winner_plan',
    'configuration::tests::account_authority::root_replacement::alternatives::root_foreign_transition_resumes_the_exact_independently_approved_next_plan',
    'configuration::tests::account_authority::root_replacement::cancellation::root_foreign_either_handle_cancels_the_actual_successor_witness_call',
    'configuration::tests::account_authority::root_replacement::cancellation::root_foreign_precancel_does_not_transfer_an_active_device',
    'configuration::tests::account_authority::root_replacement::root_foreign_cleanup_failure_consumes_controller_and_revokes_successor',
    'configuration::tests::account_authority::root_replacement::root_foreign_preflight_preserves_owners_then_transfer_fences_cached_device',
    'configuration::tests::account_authority::root_replacement::root_foreign_resume_cleanup_keeps_successor_live_until_controller_close',
))


def verify_native_tests(stdout: bytes) -> None:
    text = stdout.decode()
    passed = re.findall(r"^test ([a-z_:]+) \.\.\. ok$", text, re.MULTILINE)
    sdk.require(len(passed) == len(ROOT_TESTS) and set(passed) == ROOT_TESTS
                and re.search(r"^test result: ok\. 7 passed; 0 failed; 0 ignored; 0 measured; ", text, re.MULTILINE),
                "minimum native root tests did not execute completely")


def validate_versions(rustc: str, cargo: str) -> None:
    sdk.require(rustc.splitlines() and rustc.splitlines()[0] == RUSTC
                and cargo.strip().startswith("cargo 1.90.0 "),
                "Swift root minimum lane requires the actual Rust/Cargo 1.90.0 toolchain")


def qualify(outside: Path, output: Path, source: Path, swift_files: dict[str, bytes],
            toolchain: Path, environment: dict, swift: Path, swift_identity: dict) -> dict:
    from continuity_swift_consumer import LIBRARY, compiler_command, verify_tests, verify_linkage
    sdk.require(os.uname().sysname == "Darwin" and os.uname().machine == "arm64",
                "minimum Swift root lane requires macOS arm64")
    toolchain = toolchain.resolve(strict=True)
    tools = tool_identity(toolchain)
    # Run independently of the canonical compiler's build tree and retain its
    # exact package/lock inputs. No resolver update or source regeneration occurs.
    inputs = {str(p.relative_to(source)): sdk.snapshot(p, maximum=MAX_PACKAGE).sha256
              for p in source.rglob("*") if p.is_file()}
    build = outside / "minimum-root-build"
    native_dir = outside / "minimum-root-native"
    native_dir.mkdir(mode=0o700)
    env = {k: v for k, v in environment.items()
           if not k.startswith(("RUST", "DYLD_", "LD_", "QPERIAPT_", "QPC_", "SWIFT_"))
           and k not in ("CC", "CXX", "AR", "LD", "CPP", "CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS",
                         "CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "OBJC_INCLUDE_PATH", "LIBRARY_PATH",
                         "SDKROOT", "MACOSX_DEPLOYMENT_TARGET")}
    env.update(CARGO_TARGET_DIR=str(build), CARGO_NET_OFFLINE="true", CARGO_INCREMENTAL="0",
               RUSTC=str(toolchain / "bin/rustc"), RUSTDOC=str(toolchain / "bin/rustdoc"),
               RUSTFLAGS="-D warnings", RUSTDOCFLAGS="-D warnings",
               DYLD_FALLBACK_LIBRARY_PATH=str(toolchain / "lib"),
               PATH=str(toolchain / "bin") + os.pathsep + environment.get("PATH", os.defpath))
    result = {"completed": False, "scope": SCOPE, "release_claim_eligible": False,
              "tool_binaries": tools, "source_files": inputs}
    def run(argv, label, *, runtime=None, cwd=source):
        return sdk.command(argv, output / ("swift-minimum-" + label), cwd,
                           environment=env if runtime is None else runtime)
    try:
        result["rustc"] = run([str(toolchain / "bin/rustc"), "--version", "--verbose"], "rustc").decode()
        result["cargo"] = run([str(toolchain / "bin/cargo"), "--version"], "cargo").decode()
        validate_versions(result["rustc"], result["cargo"])
        cargo = [str(toolchain / "bin/cargo")]
        run([*cargo, "rustc", "--locked", "--offline", "--lib", "-j", "2", "--", "-C",
             "link-arg=-Wl,-install_name,@rpath/" + LIBRARY], "native-build")
        sdk.copy(build / "debug" / LIBRARY, native_dir / LIBRARY, maximum=c.MAX_BINARY)
        compiler = Path(run(["/usr/bin/xcrun", "--find", "clang"], "clang-path").decode().strip()).resolve(strict=True)
        sysroot = Path(run(["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-path"], "sdk-path").decode().strip()).resolve(strict=True)
        compiler_before = sdk.snapshot(compiler, maximum=1024**3).sha256
        sdk_before = sdk.snapshot(sysroot / "SDKSettings.json").sha256
        flags = ["-isysroot", str(sysroot)]
        run([str(compiler), *flags, "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wpedantic", "-pthread", "-O0",
             *[str(source / name) for name in ("client.c", "recovery_client.c", "opening_client.c")],
             "-I", str(source), "-L", str(native_dir), "-lq_periapt_continuity_c_consumer",
             "-Wl,-rpath,@loader_path", "-o", str(native_dir / "qpc-c-client")], "peer-build")
        runtime = {k: v for k, v in env.items() if not k.startswith(("DYLD_", "LD_"))}
        casework = outside / "minimum-root-cases"
        casework.mkdir(mode=0o700)
        capture = output / "swift-minimum-root"
        capture.mkdir(mode=0o700)
        native = c_root.qualify(casework, capture, source, native_dir, build / "debug", compiler, flags,
                                "debug", cargo, run, darwin=True, runtime=runtime, filename=LIBRARY)
        result["C"] = native
        # All public library-owner tests run on the same minimum engine below;
        # native root tests additionally exercise malformed and cancellation paths.
        tested = run([*cargo, "test", "--locked", "--offline", "--lib", "root_foreign", "-j", "2", "--", "--nocapture"], "native-root-tests")
        verify_native_tests(tested)
        result["native_root_tests"] = sorted(ROOT_TESTS)
        files = dict(swift_files)
        files["native/lib/" + LIBRARY] = sdk.snapshot(native_dir / LIBRARY, maximum=c.MAX_BINARY).data
        notice = toolchain / "share/doc/rust/COPYRIGHT-library.html"
        files["LICENSES/Rust-1.90.0-library.html"] = sdk.snapshot(notice).data
        hashes = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
        payload = archive(files)
        package = output / "q-periapt-continuity-swift-0.0.0-minimum-root.zip"
        with package.open("xb") as stream:
            stream.write(payload)
        installed = outside / "swift-minimum-root-installed"
        unpack(payload, hashes, installed)
        licenses.verify(installed, expected_target="aarch64-apple-darwin", root_package=c.NAME)
        library = installed / "native/lib" / LIBRARY
        tested = run([str(swift), "test", "--package-path", str(installed), "--configuration", "debug", "-j", "2",
                      "-Xswiftc", "-warnings-as-errors", "-Xcc", "-I" + str(installed / "native/include"),
                      "-Xlinker", "-L" + str(library.parent), "-Xlinker", "-rpath", "-Xlinker", str(library.parent)],
                     "swift-tests", runtime=runtime)
        verify_tests(tested, sdk.snapshot(output / "swift-minimum-swift-tests.stderr").data)
        binary_dir = Path(run([str(swift), "build", "--package-path", str(installed), "--configuration", "debug",
                               "--show-bin-path"], "swift-binary-path", runtime=runtime).decode().strip()).resolve(strict=True)
        sdk.require(binary_dir.is_relative_to(installed / ".build"), "minimum Swift binary escaped its installed package")
        binary = binary_dir / "ContinuityClient"
        dependencies = run(["/usr/bin/otool", "-L", str(binary)], "swift-dependencies", runtime=runtime).decode()
        loader = run(["/usr/bin/otool", "-l", str(binary)], "swift-loader", runtime=runtime).decode()
        verify_linkage(dependencies, loader, library.parent)
        def run_swift(argv, label, *, runtime=None):
            return run(argv, "swift-" + label, runtime=runtime)
        result["Swift"] = swift_root.qualify(casework, capture, "debug", runtime, binary, native, library, run_swift)
        sdk.require(all(sdk.snapshot(installed / name, maximum=MAX_PACKAGE).sha256 == digest for name, digest in hashes.items())
                    and sdk.snapshot(package).sha256 == hashlib.sha256(payload).hexdigest(), "minimum Swift package changed")
        sdk.require(inputs == {str(p.relative_to(source)): sdk.snapshot(p, maximum=MAX_PACKAGE).sha256
                               for p in source.rglob("*") if p.is_file()}, "minimum C consumer source/lock changed")
        sdk.require(tools == tool_identity(toolchain) and compiler_command(str(swift))[1] == swift_identity
                    and sdk.snapshot(compiler, maximum=1024**3).sha256 == compiler_before
                    and sdk.snapshot(sysroot / "SDKSettings.json").sha256 == sdk_before,
                    "minimum root compiler or SDK identity changed")
        result.update(completed=True, package=package.name, package_sha256=hashlib.sha256(payload).hexdigest(),
                      package_files=hashes, native_library_sha256=hashes["native/lib/" + LIBRARY], sources_unchanged=True)
    except Exception as error:
        result["failure"] = str(error)
        raise
    finally:
        sdk.write_json(output / "SWIFT_ROOT_MINIMUM.json", result)
    return result
