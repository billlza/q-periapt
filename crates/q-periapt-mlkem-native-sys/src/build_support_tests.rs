// SPDX-License-Identifier: Apache-2.0 OR MIT

use super::build_support::{
    apple_deployment_target_key, compiler_family_is_supported, inherited_c_codegen_option,
    parse_apple_deployment_target, select_mlkem_implementation, validate_native_compiler_arguments,
    AppleDeploymentTargetError, CCompilerFamily, MlKemImplementation, NativeCompilerArgumentsError,
    NativeTargetMetadataError, AARCH64_NATIVE_IMPLEMENTATION_ID,
    AARCH64_NATIVE_SHA3_IMPLEMENTATION_ID, PORTABLE_IMPLEMENTATION_ID,
};

fn implementation(
    target: &str,
    target_arch: &str,
    target_endian: &str,
    target_env: &str,
    target_os: &str,
    target_vendor: &str,
) -> Result<MlKemImplementation, NativeTargetMetadataError> {
    select_mlkem_implementation(
        target,
        target_arch,
        target_endian,
        target_env,
        target_os,
        target_vendor,
    )
}

#[test]
fn implementation_ids_are_stable_and_unambiguous() {
    assert_eq!(
        MlKemImplementation::Portable.id(),
        PORTABLE_IMPLEMENTATION_ID
    );
    assert_eq!(
        MlKemImplementation::Aarch64Native.id(),
        AARCH64_NATIVE_IMPLEMENTATION_ID
    );
    assert_eq!(
        MlKemImplementation::Aarch64NativeSha3.id(),
        AARCH64_NATIVE_SHA3_IMPLEMENTATION_ID
    );
    assert!(!MlKemImplementation::Portable.uses_aarch64_native());
    assert!(MlKemImplementation::Aarch64Native.uses_aarch64_native());
    assert!(MlKemImplementation::Aarch64NativeSha3.uses_aarch64_native());
    assert_ne!(PORTABLE_IMPLEMENTATION_ID, AARCH64_NATIVE_IMPLEMENTATION_ID);
    assert_ne!(
        PORTABLE_IMPLEMENTATION_ID,
        AARCH64_NATIVE_SHA3_IMPLEMENTATION_ID
    );
    assert_ne!(
        AARCH64_NATIVE_IMPLEMENTATION_ID,
        AARCH64_NATIVE_SHA3_IMPLEMENTATION_ID
    );
    assert_eq!(MlKemImplementation::Portable.aarch64_march_flag(), None);
    assert_eq!(
        MlKemImplementation::Aarch64Native.aarch64_march_flag(),
        Some("-march=armv8-a+nosha3")
    );
    assert_eq!(
        MlKemImplementation::Aarch64NativeSha3.aarch64_march_flag(),
        Some("-march=armv8.4-a+sha3")
    );
}

#[test]
fn exact_native_target_allowlist_is_selected() {
    for (target, target_env, target_os, target_vendor, expected) in [
        (
            "aarch64-apple-darwin",
            "",
            "macos",
            "apple",
            MlKemImplementation::Aarch64NativeSha3,
        ),
        (
            "aarch64-apple-ios",
            "",
            "ios",
            "apple",
            MlKemImplementation::Aarch64Native,
        ),
        (
            "aarch64-apple-ios-sim",
            "sim",
            "ios",
            "apple",
            MlKemImplementation::Aarch64NativeSha3,
        ),
        (
            "aarch64-unknown-linux-gnu",
            "gnu",
            "linux",
            "unknown",
            MlKemImplementation::Aarch64Native,
        ),
        (
            "aarch64-linux-android",
            "",
            "android",
            "unknown",
            MlKemImplementation::Aarch64Native,
        ),
    ] {
        assert_eq!(
            implementation(
                target,
                "aarch64",
                "little",
                target_env,
                target_os,
                target_vendor,
            ),
            Ok(expected),
            "target {target}"
        );
    }
}

#[test]
fn every_non_allowlisted_target_remains_portable() {
    for (target, arch, endian, env, os, vendor) in [
        (
            "x86_64-apple-darwin",
            "x86_64",
            "little",
            "",
            "macos",
            "apple",
        ),
        (
            "aarch64-pc-windows-msvc",
            "aarch64",
            "little",
            "msvc",
            "windows",
            "pc",
        ),
        (
            "aarch64-unknown-linux-musl",
            "aarch64",
            "little",
            "musl",
            "linux",
            "unknown",
        ),
        (
            "aarch64-apple-tvos",
            "aarch64",
            "little",
            "",
            "tvos",
            "apple",
        ),
        (
            "aarch64-apple-ios-macabi",
            "aarch64",
            "little",
            "macabi",
            "ios",
            "apple",
        ),
        (
            "aarch64_be-unknown-linux-gnu",
            "aarch64",
            "big",
            "gnu",
            "linux",
            "unknown",
        ),
        (
            "aarch64-unknown-none",
            "aarch64",
            "little",
            "",
            "none",
            "unknown",
        ),
        (
            "wasm32-unknown-unknown",
            "wasm32",
            "little",
            "",
            "unknown",
            "unknown",
        ),
        (
            "thumbv7em-none-eabihf",
            "arm",
            "little",
            "eabihf",
            "none",
            "unknown",
        ),
    ] {
        assert_eq!(
            implementation(target, arch, endian, env, os, vendor),
            Ok(MlKemImplementation::Portable),
            "target {target}"
        );
    }
}

#[test]
fn compiler_family_contract_is_exact_for_each_implementation() {
    for family in [
        CCompilerFamily::Msvc,
        CCompilerFamily::Clang,
        CCompilerFamily::Gnu,
    ] {
        assert!(compiler_family_is_supported(
            MlKemImplementation::Portable,
            family
        ));
    }
    assert!(!compiler_family_is_supported(
        MlKemImplementation::Portable,
        CCompilerFamily::Unsupported
    ));
    for implementation in [
        MlKemImplementation::Aarch64Native,
        MlKemImplementation::Aarch64NativeSha3,
    ] {
        for family in [CCompilerFamily::Clang, CCompilerFamily::Gnu] {
            assert!(compiler_family_is_supported(implementation, family));
        }
        for family in [CCompilerFamily::Msvc, CCompilerFamily::Unsupported] {
            assert!(!compiler_family_is_supported(implementation, family));
        }
    }
}

#[test]
fn allowlisted_target_metadata_mismatch_fails_closed() {
    let target = "aarch64-apple-ios-sim";
    for (label, result, expected) in [
        (
            "architecture",
            implementation(target, "x86_64", "little", "sim", "ios", "apple"),
            NativeTargetMetadataError::Architecture,
        ),
        (
            "endianness",
            implementation(target, "aarch64", "big", "sim", "ios", "apple"),
            NativeTargetMetadataError::Endianness,
        ),
        (
            "environment",
            implementation(target, "aarch64", "little", "", "ios", "apple"),
            NativeTargetMetadataError::Environment,
        ),
        (
            "operating system",
            implementation(target, "aarch64", "little", "sim", "macos", "apple"),
            NativeTargetMetadataError::OperatingSystem,
        ),
        (
            "vendor",
            implementation(target, "aarch64", "little", "sim", "ios", "unknown"),
            NativeTargetMetadataError::Vendor,
        ),
    ] {
        assert_eq!(result, Err(expected), "metadata field {label}");
    }
}

#[test]
fn native_compiler_contract_allows_owned_baselines_and_reproducible_path_maps() {
    for march in ["-march=armv8-a+nosha3", "-march=armv8.4-a+sha3"] {
        assert_eq!(
            validate_native_compiler_arguments(
                [
                    "-O2",
                    "-I",
                    "src",
                    march,
                    "-ffile-prefix-map=/private/source=/qperiapt/source",
                    "-fdebug-prefix-map=/private/source=/qperiapt/source",
                    "-fmacro-prefix-map=/private/source=/qperiapt/source",
                ],
                if march == "-march=armv8-a+nosha3" {
                    "-march=armv8-a+nosha3"
                } else {
                    "-march=armv8.4-a+sha3"
                },
                None,
            ),
            Ok(()),
            "baseline {march}"
        );
    }
    assert_eq!(
        validate_native_compiler_arguments(
            ["-O2", "-DANDROID", "-march=armv8-a+nosha3"],
            "-march=armv8-a+nosha3",
            Some("-DANDROID"),
        ),
        Ok(())
    );
}

#[test]
fn native_compiler_contract_rejects_missing_duplicate_and_override_arguments() {
    assert_eq!(
        validate_native_compiler_arguments(["-O2"], "-march=armv8-a+nosha3", None),
        Err(NativeCompilerArgumentsError::MissingArmv8Baseline(
            "-march=armv8-a+nosha3"
        ))
    );
    assert_eq!(
        validate_native_compiler_arguments(
            ["-march=armv8-a+nosha3", "-march=armv8-a+nosha3"],
            "-march=armv8-a+nosha3",
            None,
        ),
        Err(NativeCompilerArgumentsError::DuplicateArmv8Baseline(
            "-march=armv8-a+nosha3"
        ))
    );
    assert_eq!(
        validate_native_compiler_arguments(
            ["-march=armv8.4-a+sha3", "-march=armv8.4-a+sha3"],
            "-march=armv8.4-a+sha3",
            None,
        ),
        Err(NativeCompilerArgumentsError::DuplicateArmv8Baseline(
            "-march=armv8.4-a+sha3"
        ))
    );
    // Each owned profile rejects the other profile's baseline outright.
    assert_eq!(
        validate_native_compiler_arguments(
            ["-march=armv8.4-a+sha3"],
            "-march=armv8-a+nosha3",
            None,
        ),
        Err(NativeCompilerArgumentsError::Forbidden(
            "-march=armv8.4-a+sha3"
        ))
    );
    assert_eq!(
        validate_native_compiler_arguments(
            ["-march=armv8-a+nosha3"],
            "-march=armv8.4-a+sha3",
            None,
        ),
        Err(NativeCompilerArgumentsError::Forbidden(
            "-march=armv8-a+nosha3"
        ))
    );
    for forbidden in [
        "-march=armv8.4-a+sha3",
        "-mcpu=native",
        "-mtune=native",
        "-mbranch-protection=bti",
        "-fno-integrated-as",
        "-no-integrated-as",
        "-DDEBUG",
        "-DMLK_FIPS202_NATIVE_AARCH64_X1_SCALAR_H",
        "-DMLK_NATIVE_AARCH64_META_H",
        "-UQPN_MLKEM_BUILD_NATIVE_AARCH64",
        "-DMLK_CONFIG_FILE=hostile.h",
        "-include",
        "-includehostile.h",
        "-include-pch",
        "-imacros=hostile.h",
        "-imacroshostile.h",
        "-iquote=hostile",
        "-iquotehostile",
        "-Xclang",
        "-Xclang=-fno-integrated-as",
        "-Xpreprocessor",
        "-Xpreprocessor=-include",
        "-Xassembler",
        "-Xassembler=-march=armv8.4-a",
        "-mllvm",
        "-mllvm=-aarch64-enable-sha3",
        "-Wa,-march=armv8.4-a",
        "-Wp,-include,hostile.h",
        "--config=hostile.cfg",
        "@hostile.rsp",
    ] {
        assert_eq!(
            validate_native_compiler_arguments(
                ["-march=armv8-a+nosha3", forbidden],
                "-march=armv8-a+nosha3",
                None,
            ),
            Err(NativeCompilerArgumentsError::Forbidden(forbidden)),
            "argument {forbidden}"
        );
    }
    for forbidden in [
        "-march=armv8-a+nosha3",
        "-mcpu=apple-m1",
        "-Xassembler=-march=armv8-a",
    ] {
        assert_eq!(
            validate_native_compiler_arguments(
                ["-march=armv8.4-a+sha3", forbidden],
                "-march=armv8.4-a+sha3",
                None,
            ),
            Err(NativeCompilerArgumentsError::Forbidden(forbidden)),
            "argument {forbidden}"
        );
    }
    assert_eq!(
        validate_native_compiler_arguments(
            ["-march=armv8-a+nosha3"],
            "-march=armv8-a+nosha3",
            Some("-DANDROID"),
        ),
        Err(NativeCompilerArgumentsError::MissingPlatformDefine(
            "-DANDROID"
        ))
    );
    assert_eq!(
        validate_native_compiler_arguments(
            ["-march=armv8-a+nosha3", "-DANDROID", "-DANDROID"],
            "-march=armv8-a+nosha3",
            Some("-DANDROID"),
        ),
        Err(NativeCompilerArgumentsError::DuplicatePlatformDefine(
            "-DANDROID"
        ))
    );
}

#[test]
fn inherited_c_codegen_options_are_rejected_without_blocking_lints_or_remaps() {
    for encoded in [
        "-Zbranch-protection=bti",
        "-Z\u{1f}branch-protection=bti",
        "-Cbranch-protection=pac-ret",
        "-C\u{1f}force-frame-pointers=yes",
        "--codegen=linker-plugin-lto",
    ] {
        assert!(
            inherited_c_codegen_option(encoded).is_some(),
            "encoded flags {encoded:?}"
        );
    }
    for encoded in [
        "-Dwarnings",
        "-Cstrip=debuginfo",
        "--remap-path-prefix=/private/source=/qperiapt/source",
        "-Ctarget-cpu=apple-m1",
    ] {
        assert_eq!(
            inherited_c_codegen_option(encoded),
            None,
            "encoded flags {encoded:?}"
        );
    }
}

#[test]
fn target_os_keys_cover_every_supported_apple_family() {
    assert_eq!(
        apple_deployment_target_key("macos"),
        Some("MACOSX_DEPLOYMENT_TARGET")
    );
    assert_eq!(
        apple_deployment_target_key("ios"),
        Some("IPHONEOS_DEPLOYMENT_TARGET")
    );
    assert_eq!(
        apple_deployment_target_key("tvos"),
        Some("TVOS_DEPLOYMENT_TARGET")
    );
    assert_eq!(
        apple_deployment_target_key("watchos"),
        Some("WATCHOS_DEPLOYMENT_TARGET")
    );
    assert_eq!(
        apple_deployment_target_key("visionos"),
        Some("XROS_DEPLOYMENT_TARGET")
    );
    assert_eq!(apple_deployment_target_key("unknown"), None);
}

#[test]
fn parser_accepts_exact_rustc_forms() {
    for (output, version) in [
        (b"IPHONEOS_DEPLOYMENT_TARGET=10.0".as_slice(), "10.0"),
        (b"IPHONEOS_DEPLOYMENT_TARGET=14.0\n".as_slice(), "14.0"),
        (b"IPHONEOS_DEPLOYMENT_TARGET=16.1\r\n".as_slice(), "16.1"),
    ] {
        assert_eq!(
            parse_apple_deployment_target("ios", output),
            Ok(("IPHONEOS_DEPLOYMENT_TARGET", version))
        );
    }
}

#[test]
fn parser_rejects_non_utf8() {
    assert_eq!(
        parse_apple_deployment_target("ios", b"IPHONEOS_DEPLOYMENT_TARGET=10.\xff"),
        Err(AppleDeploymentTargetError::NonUtf8)
    );
}

#[test]
fn parser_rejects_empty_or_multiline_output() {
    for output in [
        b"".as_slice(),
        b"\n".as_slice(),
        b"IPHONEOS_DEPLOYMENT_TARGET=10.0\nextra".as_slice(),
        b"IPHONEOS_DEPLOYMENT_TARGET=10.0\r".as_slice(),
    ] {
        assert_eq!(
            parse_apple_deployment_target("ios", output),
            Err(AppleDeploymentTargetError::InvalidLine)
        );
    }
}

#[test]
fn parser_rejects_missing_assignment() {
    assert_eq!(
        parse_apple_deployment_target("ios", b"IPHONEOS_DEPLOYMENT_TARGET"),
        Err(AppleDeploymentTargetError::MissingAssignment)
    );
}

#[test]
fn parser_rejects_key_for_the_wrong_target_os() {
    assert_eq!(
        parse_apple_deployment_target("ios", b"MACOSX_DEPLOYMENT_TARGET=10.0\n"),
        Err(AppleDeploymentTargetError::UnexpectedKey)
    );
}

#[test]
fn parser_rejects_invalid_versions() {
    for output in [
        b"IPHONEOS_DEPLOYMENT_TARGET=\n".as_slice(),
        b"IPHONEOS_DEPLOYMENT_TARGET=.1\n".as_slice(),
        b"IPHONEOS_DEPLOYMENT_TARGET=1.\n".as_slice(),
        b"IPHONEOS_DEPLOYMENT_TARGET=1..0\n".as_slice(),
        b"IPHONEOS_DEPLOYMENT_TARGET=1a.0\n".as_slice(),
        b"IPHONEOS_DEPLOYMENT_TARGET=1 0\n".as_slice(),
        b"IPHONEOS_DEPLOYMENT_TARGET=1=0\n".as_slice(),
    ] {
        assert_eq!(
            parse_apple_deployment_target("ios", output),
            Err(AppleDeploymentTargetError::InvalidVersion)
        );
    }
}

#[test]
fn parser_rejects_unsupported_target_os() {
    assert_eq!(
        parse_apple_deployment_target("unknown", b"UNKNOWN_DEPLOYMENT_TARGET=1.0\n"),
        Err(AppleDeploymentTargetError::UnsupportedTargetOs)
    );
}
