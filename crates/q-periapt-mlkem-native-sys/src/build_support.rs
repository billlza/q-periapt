// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Strict parsing shared by the Apple C build boundary and its unit tests.

use core::{fmt, str};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AppleDeploymentTargetError {
    NonUtf8,
    InvalidLine,
    MissingAssignment,
    UnexpectedKey,
    InvalidVersion,
    UnsupportedTargetOs,
}

impl fmt::Display for AppleDeploymentTargetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NonUtf8 => "output is not UTF-8",
            Self::InvalidLine => "output must be exactly one non-empty line",
            Self::MissingAssignment => "output is not KEY=VERSION",
            Self::UnexpectedKey => "output key does not match the Apple target OS",
            Self::InvalidVersion => "version is not dot-separated ASCII decimal components",
            Self::UnsupportedTargetOs => "target OS has no supported Apple deployment key",
        })
    }
}

pub(crate) fn apple_deployment_target_key(target_os: &str) -> Option<&'static str> {
    match target_os {
        "ios" => Some("IPHONEOS_DEPLOYMENT_TARGET"),
        "macos" => Some("MACOSX_DEPLOYMENT_TARGET"),
        "tvos" => Some("TVOS_DEPLOYMENT_TARGET"),
        "visionos" => Some("XROS_DEPLOYMENT_TARGET"),
        "watchos" => Some("WATCHOS_DEPLOYMENT_TARGET"),
        _ => None,
    }
}

pub(crate) fn parse_apple_deployment_target<'a>(
    target_os: &str,
    output: &'a [u8],
) -> Result<(&'static str, &'a str), AppleDeploymentTargetError> {
    let expected_key = apple_deployment_target_key(target_os)
        .ok_or(AppleDeploymentTargetError::UnsupportedTargetOs)?;
    let stdout = str::from_utf8(output).map_err(|_| AppleDeploymentTargetError::NonUtf8)?;
    let deployment = stdout
        .strip_suffix("\r\n")
        .or_else(|| stdout.strip_suffix('\n'))
        .unwrap_or(stdout);
    if deployment.is_empty() || deployment.contains('\r') || deployment.contains('\n') {
        return Err(AppleDeploymentTargetError::InvalidLine);
    }

    let (key, version) = deployment
        .split_once('=')
        .ok_or(AppleDeploymentTargetError::MissingAssignment)?;
    if key != expected_key {
        return Err(AppleDeploymentTargetError::UnexpectedKey);
    }
    if version.is_empty()
        || !version.split('.').all(|component| {
            !component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return Err(AppleDeploymentTargetError::InvalidVersion);
    }

    Ok((expected_key, version))
}
