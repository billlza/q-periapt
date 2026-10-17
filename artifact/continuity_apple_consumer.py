"""Consume only the extracted Continuity Swift binary package on Apple platforms."""
from pathlib import Path
import re

import continuity_package as package
import rust_sdk_profile as sdk
from apple_sdk_profile import verify_link_map
from continuity_apple_package import LIBRARY, copy

FIXTURE = package.ROOT / "bindings/swift/ContinuityBinaryConsumer"
MARKER = b"CONTINUITY_BINARY_CONSUMER_PASS cancelled=302 closed=2 created_state=false\n"


def verify_linkage(link_map: Path, library: Path, executable: Path) -> dict:
    # Xcode prints /var paths for the same /private/var objects. Admit only a
    # filesystem alias of the exact selected files, never a different input.
    data = sdk.snapshot(link_map, maximum=16 * 1024**2).data
    objects, separator, _ = data.partition(b"\n# Sections:\n")
    sdk.require(bool(separator), "Apple link map object inventory is absent")
    lines = objects.decode("utf-8").splitlines()
    sdk.require(bool(lines) and lines[0].startswith("# Path: "), "Apple link map executable is absent")
    actual_executable = Path(lines[0].removeprefix("# Path: "))
    sdk.require(actual_executable.resolve(strict=True) == executable.resolve(strict=True),
                "Apple link map selects another executable")
    archives = {match[1] for line in lines
                if (match := re.fullmatch(r"\[\s*[0-9]+\] (.+/" + re.escape(LIBRARY) + r")\(.+\)", line))}
    sdk.require(len(archives) == 1, "Apple link map archive is missing or ambiguous")
    actual_library = Path(next(iter(archives)))
    sdk.require(actual_library.resolve(strict=True) == library.resolve(strict=True),
                "Apple link map selects another native archive")
    return verify_link_map(link_map, actual_library, actual_executable, "arm64", archive_basename=LIBRARY)


def qualify_consumer(installed: Path, evidence: Path, environment: dict, binaries: dict) -> dict:
    consumer = installed / "consumer"
    for source in FIXTURE.rglob("*"):
        sdk.require(not source.is_symlink(), "Apple binary consumer contains a symlink")
        if source.is_file(): copy(source, consumer / source.relative_to(FIXTURE))
    env = {key: value for key, value in environment.items()
           if not key.startswith(("DYLD_", "LD_", "RUST", "CARGO_", "SWIFT_", "QPERIAPT_", "QPC_"))}

    def run(argv: list[str], label: str) -> bytes:
        result = sdk.command(argv, evidence / label, consumer, environment=env)
        for suffix in ("stdout", "stderr"):
            data = sdk.snapshot(evidence / (label + "." + suffix)).data
            sdk.require(re.search(rb"(?im)(?:^|[^a-z])(warning|error):", data) is None,
                        "Apple binary consumer emitted diagnostics")
        return result

    def selected(build: Path, library: Path, executable: Path, link_map: Path, target: str) -> dict:
        sdk.require(library.resolve(strict=True).is_relative_to(build.resolve(strict=True)),
                    "Apple consumer selected an archive outside its build")
        native = sdk.snapshot(library, maximum=128 * 1024**2)
        sdk.require(native.sha256 == binaries[target]["sha256"], "Apple consumer selected another target archive")
        linkage = verify_linkage(link_map, library, executable)
        sdk.require(run(["/usr/bin/xcrun", "lipo", "-archs", str(executable)], "consumer-arch-" + target).strip() == b"arm64",
                    "Apple consumer executable architecture differs")
        return {"target": target, "executable_sha256": sdk.snapshot(executable, maximum=128 * 1024**2).sha256,
                "selected_archive_sha256": native.sha256, "linkage": linkage}

    work = installed.parent
    mac_build = work / "build-macos"
    mac_map = work / "macos-LinkMap.txt"
    args = ["/usr/bin/xcrun", "swift", "build", "--package-path", str(consumer), "--scratch-path", str(mac_build), "-c", "release"]
    run([*args, "-Xswiftc", "-strict-concurrency=complete", "-Xswiftc", "-warnings-as-errors",
         "-Xlinker", "-map", "-Xlinker", str(mac_map)], "consumer-macos-build")
    binary_dir = Path(run([*args, "--show-bin-path"], "consumer-macos-bin").decode().strip())
    executable = binary_dir / "ContinuityBinaryConsumer"
    result = {"macos": selected(mac_build, binary_dir / LIBRARY, executable, mac_map, "aarch64-apple-darwin")}
    sdk.require(run([str(executable)], "consumer-macos-run") == MARKER
                and sdk.snapshot(evidence / "consumer-macos-run.stderr").data == b"",
                "installed macOS owner probe did not complete exactly")
    result["macos"]["native_owner_probe"] = True
    for name, target, sdk_name, destination in (
        ("ios", "aarch64-apple-ios", "iphoneos", "generic/platform=iOS"),
        ("simulator", "aarch64-apple-ios-sim", "iphonesimulator", "generic/platform=iOS Simulator"),
    ):
        build = work / ("build-" + name)
        link_map = work / (name + "-ContinuityBinaryConsumer-LinkMap.txt")
        map_template = work / (name + "-$(TARGET_NAME)-LinkMap.txt")
        output = run(["/usr/bin/xcodebuild", "-project", str(consumer / "ContinuityBinaryConsumer.xcodeproj"),
            "-scheme", "ContinuityBinaryConsumer", "-configuration", "Release", "-sdk", sdk_name,
            "-destination", destination, "-derivedDataPath", str(build), "ARCHS=arm64",
            "CODE_SIGNING_ALLOWED=NO", "LD_GENERATE_MAP_FILE=YES", "LD_MAP_FILE_PATH=" + str(map_template), "build"],
            "consumer-" + name + "-build")
        sdk.require(b"** BUILD SUCCEEDED **" in output, "iOS consumer build did not finish")
        products = build / "Build/Products" / ("Release-" + sdk_name)
        executable = products / "ContinuityBinaryConsumer.app/ContinuityBinaryConsumer"
        result[name] = selected(build, products / LIBRARY, executable, link_map, target)
    return result
