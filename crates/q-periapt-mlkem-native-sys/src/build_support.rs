// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Target selection and strict parsing shared by the C build and its tests.

use core::{fmt, str};

pub(crate) const PORTABLE_IMPLEMENTATION_ID: &str = "mlkem-native-1.2.0/portable-c";
pub(crate) const AARCH64_NATIVE_IMPLEMENTATION_ID: &str =
    "mlkem-native-1.2.0/aarch64-native-arith+fips202-v8a-scalar";
pub(crate) const AARCH64_NATIVE_SHA3_IMPLEMENTATION_ID: &str =
    "mlkem-native-1.2.0/aarch64-native-arith+fips202-v84a";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MlKemImplementation {
    Portable,
    Aarch64Native,
    Aarch64NativeSha3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CCompilerFamily {
    Msvc,
    Clang,
    Gnu,
    Unsupported,
}

pub(crate) const fn compiler_family_is_supported(
    implementation: MlKemImplementation,
    family: CCompilerFamily,
) -> bool {
    match implementation {
        MlKemImplementation::Portable => matches!(
            family,
            CCompilerFamily::Msvc | CCompilerFamily::Clang | CCompilerFamily::Gnu
        ),
        MlKemImplementation::Aarch64Native | MlKemImplementation::Aarch64NativeSha3 => {
            matches!(family, CCompilerFamily::Clang | CCompilerFamily::Gnu)
        }
    }
}

impl MlKemImplementation {
    pub(crate) const fn id(self) -> &'static str {
        match self {
            Self::Portable => PORTABLE_IMPLEMENTATION_ID,
            Self::Aarch64Native => AARCH64_NATIVE_IMPLEMENTATION_ID,
            Self::Aarch64NativeSha3 => AARCH64_NATIVE_SHA3_IMPLEMENTATION_ID,
        }
    }

    pub(crate) const fn uses_aarch64_native(self) -> bool {
        matches!(self, Self::Aarch64Native | Self::Aarch64NativeSha3)
    }

    pub(crate) const fn aarch64_march_flag(self) -> Option<&'static str> {
        match self {
            Self::Portable => None,
            Self::Aarch64Native => Some("-march=armv8-a+nosha3"),
            Self::Aarch64NativeSha3 => Some("-march=armv8.4-a+sha3"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeCompilerArgumentsError<'argument> {
    MissingArmv8Baseline(&'static str),
    DuplicateArmv8Baseline(&'static str),
    MissingPlatformDefine(&'static str),
    DuplicatePlatformDefine(&'argument str),
    Forbidden(&'argument str),
}

impl fmt::Display for NativeCompilerArgumentsError<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingArmv8Baseline(flag) => {
                write!(formatter, "the owned {flag} flag is missing")
            }
            Self::DuplicateArmv8Baseline(flag) => {
                write!(formatter, "the owned {flag} flag is not unique")
            }
            Self::MissingPlatformDefine(argument) => {
                write!(
                    formatter,
                    "the required platform argument {argument:?} is missing"
                )
            }
            Self::DuplicatePlatformDefine(argument) => {
                write!(
                    formatter,
                    "the platform argument {argument:?} is not unique"
                )
            }
            Self::Forbidden(argument) => {
                write!(formatter, "forbidden compiler argument {argument:?}")
            }
        }
    }
}

fn is_forbidden_native_compiler_argument(argument: &str) -> bool {
    argument.starts_with("-D")
        || argument.starts_with("-U")
        || argument.contains("QPN_MLKEM")
        || argument.contains("MLK_CONFIG")
        || argument.starts_with("-march")
        || argument.starts_with("-mcpu")
        || argument.starts_with("-mtune")
        || argument.starts_with("-mattr")
        || argument.starts_with("-mbranch-protection")
        || argument == "-fno-integrated-as"
        || argument == "-no-integrated-as"
        || argument.starts_with("-include")
        || argument.starts_with("-imacros")
        || argument.starts_with("-iquote")
        || argument.starts_with("-Xclang")
        || argument.starts_with("-Xpreprocessor")
        || argument.starts_with("-Xassembler")
        || argument.starts_with("-mllvm")
        || argument.starts_with("-Wa,")
        || argument.starts_with("-Wp,")
        || argument == "-specs"
        || argument.starts_with("-specs=")
        || argument == "--config"
        || argument.starts_with("--config=")
        || argument.starts_with('@')
}

pub(crate) fn validate_native_compiler_arguments<'argument>(
    arguments: impl IntoIterator<Item = &'argument str>,
    expected_march: &'static str,
    required_platform_define: Option<&'static str>,
) -> Result<(), NativeCompilerArgumentsError<'argument>> {
    let mut baseline_count = 0_u8;
    let mut platform_define_count = 0_u8;
    for argument in arguments {
        if argument == expected_march {
            baseline_count = baseline_count.saturating_add(1);
            continue;
        }
        if required_platform_define == Some(argument) {
            platform_define_count = platform_define_count.saturating_add(1);
            continue;
        }
        if is_forbidden_native_compiler_argument(argument) {
            return Err(NativeCompilerArgumentsError::Forbidden(argument));
        }
    }
    if baseline_count == 0 {
        return Err(NativeCompilerArgumentsError::MissingArmv8Baseline(
            expected_march,
        ));
    }
    if baseline_count != 1 {
        return Err(NativeCompilerArgumentsError::DuplicateArmv8Baseline(
            expected_march,
        ));
    }
    if let Some(argument) = required_platform_define {
        return match platform_define_count {
            0 => Err(NativeCompilerArgumentsError::MissingPlatformDefine(
                argument,
            )),
            1 => Ok(()),
            _ => Err(NativeCompilerArgumentsError::DuplicatePlatformDefine(
                argument,
            )),
        };
    }
    Ok(())
}

const INHERITED_C_CODEGEN_OPTIONS: [&str; 16] = [
    "branch-protection",
    "code-model",
    "control-flow-guard",
    "dwarf-version",
    "embed-bitcode",
    "force-frame-pointers",
    "linker-plugin-lto",
    "no-redzone",
    "no-vectorize-loops",
    "no-vectorize-slp",
    "profile-generate",
    "profile-use",
    "relocation-model",
    "soft-float",
    "stack-protector",
    "symbol-mangling-version",
];

fn inherited_c_codegen_name(argument: &str) -> Option<&str> {
    let option = argument
        .strip_prefix("-C")
        .or_else(|| argument.strip_prefix("--codegen="))
        .or_else(|| argument.strip_prefix("-Z"))?;
    Some(option.split('=').next().unwrap_or(option))
}

pub(crate) fn inherited_c_codegen_option(encoded_rustflags: &str) -> Option<&str> {
    let mut expect_codegen_option = false;
    for argument in encoded_rustflags.split('\u{1f}') {
        let option = if expect_codegen_option {
            expect_codegen_option = false;
            Some(argument.split('=').next().unwrap_or(argument))
        } else if argument == "-C" || argument == "--codegen" || argument == "-Z" {
            expect_codegen_option = true;
            None
        } else {
            inherited_c_codegen_name(argument)
        };
        if option.is_some_and(|name| INHERITED_C_CODEGEN_OPTIONS.contains(&name)) {
            return Some(argument);
        }
    }
    None
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeTargetMetadataError {
    Architecture,
    Endianness,
    Environment,
    OperatingSystem,
    Vendor,
}

impl fmt::Display for NativeTargetMetadataError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Architecture => "target architecture differs from the native allowlist",
            Self::Endianness => "target endianness differs from the native allowlist",
            Self::Environment => "target environment differs from the native allowlist",
            Self::OperatingSystem => "target operating system differs from the native allowlist",
            Self::Vendor => "target vendor differs from the native allowlist",
        })
    }
}

#[derive(Clone, Copy)]
struct ExpectedNativeTarget {
    environment: &'static str,
    implementation: MlKemImplementation,
    operating_system: &'static str,
    vendor: &'static str,
}

fn expected_native_target(target: &str) -> Option<ExpectedNativeTarget> {
    // The SHA3 profile is limited to targets whose entire install base
    // guarantees FEAT_SHA3: arm64 macOS (Apple M-series only) and the arm64
    // iOS simulator (executes only on Apple Silicon hosts). The iOS device
    // slice, Android, and generic Linux keep the fixed Armv8-A scalar
    // profile because their supported hardware includes CPUs without the
    // SHA3 extension.
    match target {
        "aarch64-apple-darwin" => Some(ExpectedNativeTarget {
            environment: "",
            implementation: MlKemImplementation::Aarch64NativeSha3,
            operating_system: "macos",
            vendor: "apple",
        }),
        "aarch64-apple-ios" => Some(ExpectedNativeTarget {
            environment: "",
            implementation: MlKemImplementation::Aarch64Native,
            operating_system: "ios",
            vendor: "apple",
        }),
        "aarch64-apple-ios-sim" => Some(ExpectedNativeTarget {
            environment: "sim",
            implementation: MlKemImplementation::Aarch64NativeSha3,
            operating_system: "ios",
            vendor: "apple",
        }),
        "aarch64-unknown-linux-gnu" => Some(ExpectedNativeTarget {
            environment: "gnu",
            implementation: MlKemImplementation::Aarch64Native,
            operating_system: "linux",
            vendor: "unknown",
        }),
        "aarch64-linux-android" => Some(ExpectedNativeTarget {
            environment: "",
            implementation: MlKemImplementation::Aarch64Native,
            operating_system: "android",
            vendor: "unknown",
        }),
        _ => None,
    }
}

pub(crate) fn select_mlkem_implementation(
    target: &str,
    target_arch: &str,
    target_endian: &str,
    target_env: &str,
    target_os: &str,
    target_vendor: &str,
) -> Result<MlKemImplementation, NativeTargetMetadataError> {
    let Some(expected) = expected_native_target(target) else {
        return Ok(MlKemImplementation::Portable);
    };
    if target_arch != "aarch64" {
        return Err(NativeTargetMetadataError::Architecture);
    }
    if target_endian != "little" {
        return Err(NativeTargetMetadataError::Endianness);
    }
    if target_env != expected.environment {
        return Err(NativeTargetMetadataError::Environment);
    }
    if target_os != expected.operating_system {
        return Err(NativeTargetMetadataError::OperatingSystem);
    }
    if target_vendor != expected.vendor {
        return Err(NativeTargetMetadataError::Vendor);
    }
    Ok(expected.implementation)
}

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
