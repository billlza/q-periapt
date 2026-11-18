"""Build clean native Xcode applications against the two extracted Swift packages."""
import argparse
import os
from pathlib import Path
import plistlib
import shutil
import tempfile

import apple_sdk_profile as swift_sdk
import continuity_apple_package as continuity
import rust_sdk_profile as sdk
from deterministic_archive import extract_zip

FIXTURE = sdk.ROOT / "bindings/swift/ApplePackageConsumer"
PROJECT = "ApplePackageConsumer"
PRODUCTS = {"QPeriapt": ("QPeriaptSDK", "PROBE_SDK", "SDK_KEM_KDF_PASS"),
            "QPeriaptContinuity": ("QPeriaptContinuity", "PROBE_CONTINUITY", "CONTINUITY_NATIVE_OWNER_PASS")}


def select_products(project: dict, names: tuple[str, ...]) -> None:
    objects = project["objects"]
    excluded = {key for key, obj in objects.items() if obj["isa"] == "XCLocalSwiftPackageReference"
                and Path(obj["relativePath"]).name not in names}
    excluded.update(key for key, obj in objects.items() if obj.get("package") in excluded)
    excluded.update(key for key, obj in objects.items() if obj.get("productRef") in excluded)
    for key in excluded:
        del objects[key]
    for obj in objects.values():
        for field in ("packageReferences", "packageProductDependencies", "files"):
            if field in obj:
                obj[field] = [ref for ref in obj[field] if ref not in excluded]
        if obj.get("isa") == "XCBuildConfiguration" and "baseConfigurationReference" in obj:
            obj["buildSettings"]["SWIFT_ACTIVE_COMPILATION_CONDITIONS"] = " ".join(PRODUCTS[n][1] for n in names)


def qualify(sdk_zip: Path, continuity_zip: Path, output: Path) -> None:
    output = output.resolve()
    output.mkdir(mode=0o700)
    environment = {k: os.environ[k] for k in ("HOME", "TMPDIR", "DEVELOPER_DIR") if k in os.environ}
    environment.update(PATH="/usr/bin:/bin:/usr/sbin:/sbin", LC_ALL="C")
    with tempfile.TemporaryDirectory(prefix="qperiapt-swiftpm-") as tmp:
        work = Path(tmp).resolve()
        (work / "unpacked").mkdir()
        def run(args, label, cwd=work):
            return sdk.command(args, output / label, cwd, environment=environment)

        receipt = {"xcode": run(["/usr/bin/xcodebuild", "-version"], "xcode").decode().strip(),
                   "swift": run(["/usr/bin/xcrun", "swift", "--version"], "swift").decode().strip(),
                   "archives": {}, "macos": [], "ios_builds": []}
        for package, archive, profile in (("QPeriapt", sdk_zip, swift_sdk),
                                          ("QPeriaptContinuity", continuity_zip, continuity)):
            audit = extract_zip(archive, work / "unpacked" / package, root_name=package,
                                mtime=profile.MTIME, limits=profile.LIMITS)
            receipt["archives"][package] = {"name": archive.name, "sha256": audit.archive_sha256}

        base = FIXTURE / (PROJECT + ".xcodeproj/project.pbxproj")
        project_xml = run(["/usr/bin/plutil", "-convert", "xml1", "-o", "-", str(base)], "read-project")
        for mode, names in (("sdk", ("QPeriapt",)), ("continuity", ("QPeriaptContinuity",)),
                            ("both", tuple(PRODUCTS))):
            directory = work / mode
            app = directory / PROJECT
            shutil.copytree(FIXTURE, app)
            shutil.copyfile(sdk.ROOT / "bindings/signed-policy-vectors.json", app / "signed-policy-vectors.json")
            for name in names:
                shutil.copytree(work / "unpacked" / name / name, directory / name)
            product_names = [PRODUCTS[name][0] for name in names]
            project = plistlib.loads(project_xml)
            select_products(project, names)
            bundle = app / (PROJECT + ".xcodeproj")
            (bundle / "project.pbxproj").write_bytes(plistlib.dumps(project))

            def build(configuration, label, destination, settings=()):
                derived = directory / label
                run(["/usr/bin/xcodebuild", "-project", str(bundle), "-scheme", PROJECT,
                     "-configuration", configuration, "-destination", destination,
                     "-derivedDataPath", str(derived), *settings, "build"], label + "-build", app)
                return derived / "Build/Products"

            for configuration in ("Debug", "Release"):
                label = mode + "-" + configuration.lower()
                products = build(configuration, label, "platform=macOS,arch=arm64")
                binary = products / configuration / (PROJECT + ".app/Contents/MacOS") / PROJECT
                observed = run([str(binary)], label + "-run", app).decode().splitlines()
                sdk.require(observed == [PRODUCTS[name][2] for name in names], "Apple consumer runtime result differs")
                receipt["macos"].append({"products": product_names,
                                         "configuration": configuration, "runtime": observed})
            if mode == "both":
                for platform, destination, arch in (("iphoneos", "iOS", "arm64"),
                                                    ("iphonesimulator", "iOS Simulator", "arm64"),
                                                    ("iphonesimulator", "iOS Simulator", "x86_64")):
                    label = platform + "-" + arch
                    products = build("Release", label, "generic/platform=" + destination,
                                     ("ARCHS=" + arch, "CODE_SIGNING_ALLOWED=NO"))
                    binary = products / ("Release-" + platform) / (PROJECT + ".app") / PROJECT
                    continuity.verify_architectures(run(["/usr/bin/xcrun", "lipo", "-archs", str(binary)],
                                                        label + "-arch"), (arch,))
                    receipt["ios_builds"].append({"platform": platform, "architecture": arch,
                                                  "configuration": "Release", "products": product_names})
        sdk.write_json(output / "SWIFTPM_VERIFICATION.json", receipt)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk", required=True, type=Path)
    parser.add_argument("--continuity", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    qualify(args.sdk.resolve(), args.continuity.resolve(), args.output)
