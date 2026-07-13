// SPDX-License-Identifier: Apache-2.0 OR MIT

use super::build_support::{
    apple_deployment_target_key, parse_apple_deployment_target, AppleDeploymentTargetError,
};

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
