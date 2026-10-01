"""Package and execute the Swift owner against the already qualified C engine."""
from pathlib import Path, PurePosixPath
import hashlib
import io
import os
import re
import stat
import zipfile

import continuity_c_consumer as c
import continuity_package as package
import rust_sdk_profile as sdk
from evidence_io import parse_strict_json_bytes
import third_party_licenses as licenses

FIXTURE = package.ROOT / "bindings/swift/ContinuityPackageConsumer"
LIBRARY = "libq_periapt_continuity_c_consumer.dylib"
MAX_PACKAGE = 64 * 1024**2
SCOPE = "unpublished installed Swift client/server and shared C/Rust engine; same-host macOS; local original-installation profile"


def compiler_command(value: str) -> tuple[Path, dict]:
    command = Path(value.strip())
    sdk.require(command.is_absolute() and command.name == "swift" and os.access(command, os.X_OK),
                "Swift package-manager command differs")
    resolved = command.resolve(strict=True)
    binary = sdk.snapshot(resolved, maximum=c.MAX_BINARY)
    # Xcode's swift is a link to swift-frontend. Its invoked name selects driver
    # and package-manager dispatch; hashing the target must not change argv[0].
    return command, {"command_path": str(command), "path": str(resolved), "sha256": binary.sha256}


def archive(files: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as zipped:
        for name, data in sorted(files.items()):
            entry = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = (stat.S_IFREG | 0o644) << 16
            zipped.writestr(entry, data)
    result = output.getvalue()
    sdk.require(len(result) <= MAX_PACKAGE, "Swift package exceeds bound")
    return result


def unpack(data: bytes, expected: dict[str, str], destination: Path) -> None:
    sdk.require(len(data) <= MAX_PACKAGE and not destination.exists(), "Swift package input or destination differs")
    with zipfile.ZipFile(io.BytesIO(data)) as zipped:
        entries = zipped.infolist()
        names = [entry.filename for entry in entries]
        sdk.require(len(entries) <= 1024 and len(names) == len(set(names)) and set(names) == set(expected),
                    "Swift package file set differs")
        sdk.require(sum(entry.file_size for entry in entries) <= MAX_PACKAGE, "Swift expanded package exceeds bound")
        selected = {}
        for entry in entries:
            path = PurePosixPath(entry.filename)
            sdk.require(not path.is_absolute() and path.parts and ".." not in path.parts
                        and "\\" not in entry.filename and str(path) == entry.filename
                        and stat.S_ISREG(entry.external_attr >> 16) and not entry.flag_bits & 1,
                        "Swift package entry is not a canonical regular file")
            content = zipped.read(entry)
            sdk.require(hashlib.sha256(content).hexdigest() == expected[entry.filename], "Swift package file hash differs")
            selected[path] = content
    destination.mkdir(mode=0o700)
    for name, content in selected.items():
        path = destination.joinpath(*name.parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(content)
        path.chmod(0o644)


def verify_tests(stdout: bytes, stderr: bytes) -> None:
    text = (stdout + stderr).decode()
    tests = {"OwnerTests.testARCRetiresPendingSlotsAndClosedAliases", "OwnerTests.testDiagnosticRejectsInconsistentAndInvalidUTF8",
             "OwnerTests.testIDsAndTextsRejectAmbiguousInput", "ServerTests.testCallbackCopiesBorrowedRegions",
             "ServerTests.testCallbackFailureAndForeignBoundsCannotBecomeConsumption",
             "ServerTests.testServedRecordRejectsUnknownKindsAndInconsistentBootstrap"}
    passed = [owner + "." + name for owner, name in re.findall(
        r"Test Case '-\[QPeriaptContinuityTests\.(\w+) (\w+)\]' passed", text)]
    sdk.require(len(passed) == len(tests) and set(passed) == tests
                and "Executed 6 tests, with 0 failures" in text,
                "Swift owner tests did not all execute")


def verify_execution(stdout: bytes, directory: Path) -> dict:
    checked = c.verify_execution(stdout, directory, language="Swift")
    checked["public_readbacks"] = checked.pop("application_readbacks") | {
        "c-public-result.json": sdk.snapshot(directory / "c-public-result.json").sha256}
    return checked


def verify_server_execution(stdout: bytes, directory: Path) -> dict:
    checked = c.verify_server_execution(stdout, directory, language="Swift")
    checked["public_readbacks"] = checked.pop("application_readbacks") | {
        "c-server-public-result.json": sdk.snapshot(directory / "c-server-public-result.json").sha256}
    return checked


def verify_linkage(dependencies: str, loader: str, native_dir: Path) -> list[str]:
    names = [line.strip().split(" (", 1)[0] for line in dependencies.splitlines()[1:] if line.strip()]
    sdk.require(names.count("@rpath/" + LIBRARY) == 1 and all(
        name == "@rpath/" + LIBRARY or name.startswith(("/usr/lib/", "/System/Library/Frameworks/"))
        for name in names), "Swift executable depends on an unqualified library")
    paths = re.findall(r"cmd LC_RPATH\s+cmdsize \d+\s+path (.+?) \(offset", loader)
    sdk.require(paths.count(str(native_dir)) == 1, "Swift installed library search path differs")
    # SwiftBuild contributes toolchain/framework rpaths. Each actual client
    # process additionally checks dyld's loaded native image against native_dir.
    return paths


def qualify_swift(outside: Path, output: Path, native: dict, environment: dict) -> dict:
    sdk.require(os.uname().sysname == "Darwin" and native["completed"], "Swift qualification requires a completed native macOS C package")
    result = {"completed": False, "scope": SCOPE, "release_claim_eligible": False, "profiles": {}}
    env = {key: value for key, value in environment.items()
           if not key.startswith(("DYLD_", "LD_", "QPERIAPT_", "QPC_TEST_", "SWIFT_"))}
    try:
        def run(argv, label, cwd=outside, *, runtime=None):
            return sdk.command(argv, output / ("swift-" + label), cwd, environment=env if runtime is None else runtime)
        swift, identity = compiler_command(run(["/usr/bin/xcrun", "--find", "swift"], "tool-path").decode())
        result["compiler"] = dict(identity, version=run([str(swift), "--version"], "tool-version").decode())
        source = {}
        for path in FIXTURE.rglob("*"):
            sdk.require(not path.is_symlink(), "Swift source contains a symlink")
            if path.is_file():
                source[path.relative_to(FIXTURE).as_posix()] = sdk.snapshot(path).data
        for name in ("LICENSE", "LICENSE-APACHE", "LICENSE-MIT"):
            source[name] = sdk.snapshot(package.CANDIDATE / name).data
        source["native/include/qpc_owner.h"] = sdk.snapshot(c.FIXTURE / "qpc_owner.h").data
        source["LICENSES/Rust-1.98.1-library.html"] = sdk.snapshot(package.ROOT / "LICENSES/Rust-1.98.1-library.html").data
        for name in ("INVENTORY.sha256", "LICENSE-INVENTORY.md", "LICENSE.mlkem-native", "PROVENANCE.md"):
            source["LICENSES/mlkem-native/" + name] = sdk.snapshot(
                package.ROOT / "crates/q-periapt-mlkem-native-sys/vendor" / name).data
        sdk.require(os.uname().machine in {"arm64", "x86_64"}, "unqualified Swift host architecture")
        target = "aarch64-apple-darwin" if os.uname().machine == "arm64" else "x86_64-apple-darwin"
        cargo = str(Path(environment["RUSTC"]).parent / "cargo")
        metadata = parse_strict_json_bytes(run([cargo, "metadata", "--locked", "--offline", "--format-version", "1",
            "--filter-platform", target], "license-metadata", outside / "c-consumer", runtime=environment), label="Swift native license graph")
        notices = outside / "swift-native-notices"
        notices.mkdir(mode=0o700)
        licenses.collect(outside / "c-consumer", notices, target, root_package=c.NAME, resolved_metadata=metadata)
        for path in notices.rglob("*"):
            if path.is_file():
                source[path.relative_to(notices).as_posix()] = sdk.snapshot(path).data
        for profile in ("debug", "release"):
            row = native["execution"][profile]
            library = sdk.snapshot(Path(row["binaries"]["C_library"]["path"]), maximum=c.MAX_BINARY)
            sdk.require(library.sha256 == row["binaries"]["C_library"]["sha256"], "native library changed before Swift installation")
            files = dict(source, **{"native/lib/" + LIBRARY: library.data})
            hashes = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
            data = archive(files)
            filename = f"q-periapt-continuity-swift-0.0.0-{profile}.zip"
            with (output / filename).open("xb") as stream:
                stream.write(data)
            consumer = outside / ("swift-installed-" + profile)
            unpack(sdk.snapshot(output / filename, maximum=MAX_PACKAGE).data, hashes, consumer)
            licenses.verify(consumer, expected_target=target, root_package=c.NAME)
            native_dir = consumer / "native/lib"
            arguments = [str(swift), "test", "--package-path", str(consumer), "--configuration", profile,
                         "-j", "2", "-Xswiftc", "-warnings-as-errors", "-Xcc", "-I" + str(consumer / "native/include"),
                         "-Xlinker", "-L" + str(native_dir), "-Xlinker", "-rpath", "-Xlinker", str(native_dir)]
            tested = run(arguments, "tests-" + profile)
            verify_tests(tested, sdk.snapshot(output / f"swift-tests-{profile}.stderr").data)
            path = run([str(swift), "build", "--package-path", str(consumer), "--configuration", profile,
                        "--show-bin-path"], "binary-path-" + profile).decode().strip()
            binary = Path(path).resolve(strict=True) / "ContinuityClient"
            sdk.require(binary.is_relative_to(consumer / ".build"), "Swift executable escaped the installed package")
            executable = sdk.snapshot(binary, maximum=c.MAX_BINARY)
            dependencies = run(["/usr/bin/otool", "-L", str(binary)], "dependencies-" + profile).decode()
            loader = run(["/usr/bin/otool", "-l", str(binary)], "loader-" + profile).decode()
            loader_paths = verify_linkage(dependencies, loader, native_dir)
            trace = Path(row["binaries"]["Rust_trace"]["path"])
            sdk.require(sdk.snapshot(trace, maximum=c.MAX_BINARY).sha256 == row["binaries"]["Rust_trace"]["sha256"],
                        "native protocol harness changed")
            evidence = outside / ("swift-" + profile + "-runtime")
            runtime = dict(env, QPERIAPT_C_OWNER_CLIENT=str(binary), QPERIAPT_INSTALLED_CLIENT_LANGUAGE="Swift",
                           QPERIAPT_EXPECTED_CONTINUITY_LIBRARY=str(native_dir / LIBRARY),
                           QPERIAPT_PUBLIC_SERVICE_EVIDENCE=str(evidence))
            stdout = run([str(trace), "--exact", c.TEST, "--nocapture"], "trace-" + profile, runtime=runtime)
            checked = verify_execution(stdout, evidence)
            exported = output / "swift-public" / profile
            from continuity_c_witness import export_selected
            public_files = export_selected(checked, evidence, exported, SCOPE,
                                           replay=lambda path: verify_execution(stdout, path))
            server_evidence = outside / ("swift-" + profile + "-server-runtime")
            runtime["QPERIAPT_PUBLIC_SERVICE_EVIDENCE"] = str(server_evidence)
            server_stdout = run([str(trace), "--exact", c.SERVER_TEST, "--nocapture"], "server-trace-" + profile, runtime=runtime)
            server_checked = verify_server_execution(server_stdout, server_evidence)
            server_files = export_selected(server_checked, server_evidence, output / "swift-public/server" / profile, SCOPE,
                                            replay=lambda path: verify_server_execution(server_stdout, path))
            for name, expected in hashes.items():
                sdk.require(sdk.snapshot(consumer / name, maximum=MAX_PACKAGE).sha256 == expected,
                            "installed Swift package changed")
            sdk.require(sdk.snapshot(binary, maximum=c.MAX_BINARY).sha256 == executable.sha256,
                        "Swift executable changed during execution")
            result["profiles"][profile] = {"archive": filename, "archive_sha256": hashlib.sha256(data).hexdigest(),
                "files": hashes, "binary": {"path": str(binary), "sha256": executable.sha256, "bytes": executable.size},
                "native_library_sha256": library.sha256, "loader_paths": loader_paths,
                "execution": checked, "public_files": public_files,
                "server_execution": server_checked, "server_public_files": server_files}
        sdk.require(compiler_command(str(swift))[1] == identity, "Swift compiler or command resolution changed")
        result["completed"] = True
    except Exception as error:
        result["failure"] = str(error)
        raise
    finally:
        sdk.write_json(output / "SWIFT_CONSUMER.json", result)
    return result
