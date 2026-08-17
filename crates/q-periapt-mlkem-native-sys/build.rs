// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Compiles the pinned target-selected mlkem-native implementation with strict
//! diagnostics and hidden bridge visibility.

#[path = "src/build_support.rs"]
mod build_support;

use std::env;
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

const WASM32_UNKNOWN_UNKNOWN: &str = "wasm32-unknown-unknown";
const WASM_CC_ENV: &str = "CC_wasm32_unknown_unknown";
const VENDORED_ROOT: &str = "vendor/mlkem-native";
const NATIVE_ASSEMBLY_WRAPPER: &str = "src/mlkem_bridge_asm.S";
const NATIVE_C_WRAPPER: &str = "src/mlkem_bridge_native.c";
const PORTABLE_C_WRAPPER: &str = "src/mlkem_bridge_portable.c";

fn apple_deployment_target(
    target: &str,
    target_os: &str,
    target_vendor: &str,
) -> Result<Option<(&'static str, String)>, Box<dyn Error>> {
    if target_vendor != "apple" {
        return Ok(None);
    }

    let expected_key = build_support::apple_deployment_target_key(target_os).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            format!("unsupported Apple target OS {target_os:?} for target {target}"),
        )
    })?;

    println!("cargo:rerun-if-env-changed=RUSTC");
    println!("cargo:rerun-if-env-changed={expected_key}");

    let rustc = env::var_os("RUSTC")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Cargo did not provide RUSTC"))?;
    let output = Command::new(rustc)
        .args(["--print", "deployment-target", "--target", target])
        .output()
        .map_err(|source| {
            io::Error::new(
                source.kind(),
                format!("failed to query rustc deployment target for {target}: {source}"),
            )
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "rustc could not report the deployment target for {target} ({}): {}",
                output.status,
                stderr.trim()
            ),
        )
        .into());
    }

    let (key, version) = build_support::parse_apple_deployment_target(target_os, &output.stdout)
        .map_err(|source| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("rustc emitted an invalid deployment target for {target}: {source}"),
            )
        })?;
    debug_assert_eq!(key, expected_key);

    Ok(Some((expected_key, version.to_owned())))
}

fn validate_wasm_compiler(compiler: &cc::Tool) -> Result<(), Box<dyn Error>> {
    if !compiler.is_like_clang() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("{WASM_CC_ENV} must select an upstream LLVM clang with the wasm32 backend"),
        )
        .into());
    }

    let mut command: Command = compiler.to_command();
    let output = command.arg("--print-targets").output().map_err(|source| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            format!("failed to inspect the compiler selected by {WASM_CC_ENV}: {source}"),
        )
    })?;
    if !output.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("the compiler selected by {WASM_CC_ENV} could not list its registered targets"),
        )
        .into());
    }
    let registered_targets = String::from_utf8(output.stdout).map_err(|source| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "the compiler selected by {WASM_CC_ENV} emitted non-UTF-8 target data: {source}"
            ),
        )
    })?;
    if !registered_targets
        .lines()
        .any(|line| line.trim_start().starts_with("wasm32"))
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "the compiler selected by {WASM_CC_ENV} has no wasm32 backend; Apple clang is unsupported, install upstream LLVM clang and set {WASM_CC_ENV} to its absolute path"
            ),
        )
        .into());
    }
    Ok(())
}

fn wasm_compiler(target: &str) -> Result<Option<PathBuf>, Box<dyn Error>> {
    if target != WASM32_UNKNOWN_UNKNOWN {
        return Ok(None);
    }
    let compiler = env::var_os(WASM_CC_ENV)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "{WASM_CC_ENV} is required for {WASM32_UNKNOWN_UNKNOWN}; set it to an absolute upstream LLVM clang path with the wasm32 backend"
                ),
            )
        })?;
    let compiler = PathBuf::from(compiler);
    if !compiler.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{WASM_CC_ENV} must be an absolute path, got {compiler:?}"),
        )
        .into());
    }
    if !compiler.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{WASM_CC_ENV} must identify a regular compiler executable"),
        )
        .into());
    }
    Ok(Some(compiler))
}

fn configured_build(
    apple_deployment_target: Option<&(&'static str, String)>,
    compiler: Option<&Path>,
    freestanding: bool,
    implementation: build_support::MlKemImplementation,
) -> cc::Build {
    let mut build = cc::Build::new();
    build.include("src").include(VENDORED_ROOT);
    if let Some((key, version)) = apple_deployment_target {
        build.env(key, version);
    }
    if let Some(compiler) = compiler {
        build.compiler(compiler);
    }
    if freestanding {
        build.define("QPN_MLKEM_FREESTANDING", None);
    }
    if implementation.uses_aarch64_native() {
        // The explicit +nosha3 pin is load-bearing: newer Apple simulator
        // drivers keep the default CPU's sha3 feature despite a bare
        // -march=armv8-a, and the owned AArch64 FIPS 202 path must never
        // see the Armv8.4-A SHA3 extension.
        build.inherit_rustflags(false).flag("-march=armv8-a+nosha3");
    }
    build
}

fn same_compiler_metadata(left: &cc::Tool, right: &cc::Tool) -> bool {
    let left_command = left.to_command();
    let right_command = right.to_command();
    left_command.get_program() == right_command.get_program()
        && left_command.get_args().eq(right_command.get_args())
        && left_command.get_envs().eq(right_command.get_envs())
        && left.is_like_clang() == right.is_like_clang()
        && left.is_like_gnu() == right.is_like_gnu()
        && left.is_like_msvc() == right.is_like_msvc()
}

fn validate_compiler(
    compiler: &cc::Tool,
    implementation: build_support::MlKemImplementation,
    target_os: &str,
) -> Result<(), Box<dyn Error>> {
    let family = if compiler.is_like_msvc() {
        build_support::CCompilerFamily::Msvc
    } else if compiler.is_like_clang() {
        build_support::CCompilerFamily::Clang
    } else if compiler.is_like_gnu() {
        build_support::CCompilerFamily::Gnu
    } else {
        build_support::CCompilerFamily::Unsupported
    };
    if implementation.uses_aarch64_native()
        && !build_support::compiler_family_is_supported(implementation, family)
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the allowlisted AArch64 backend requires Clang or GCC",
        )
        .into());
    }
    if !build_support::compiler_family_is_supported(implementation, family) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "q-periapt-mlkem-native-sys supports only MSVC, Clang, and GCC",
        )
        .into());
    }
    if implementation.uses_aarch64_native() {
        let command = compiler.to_command();
        let arguments = command
            .get_args()
            .map(|argument| {
                argument.to_str().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "the AArch64 native compiler arguments must be UTF-8",
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let required_platform_define = (target_os == "android").then_some("-DANDROID");
        build_support::validate_native_compiler_arguments(
            arguments.iter().copied(),
            required_platform_define,
        )
        .map_err(|source| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid fixed AArch64 compiler arguments: {source}"),
            )
        })?;
    }
    Ok(())
}

fn compile_native_assembly(
    apple_deployment_target: Option<&(&'static str, String)>,
    c_compiler: &cc::Tool,
    implementation: build_support::MlKemImplementation,
    target_os: &str,
) -> Result<PathBuf, Box<dyn Error>> {
    let mut assembly = configured_build(apple_deployment_target, None, false, implementation);
    let assembly_compiler = assembly.get_compiler();
    validate_compiler(&assembly_compiler, implementation, target_os)?;
    if !same_compiler_metadata(c_compiler, &assembly_compiler) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the C and assembly compiler metadata differ for the native backend",
        )
        .into());
    }
    assembly
        .file(NATIVE_ASSEMBLY_WRAPPER)
        .warnings(true)
        .warnings_into_errors(true)
        .flag("-Wall")
        .flag("-Wextra")
        .flag("-Werror");
    validate_compiler(&assembly.get_compiler(), implementation, target_os)?;
    let objects = assembly.try_compile_intermediates().map_err(|source| {
        io::Error::other(format!(
            "failed to compile the AArch64 mlkem-native assembly SCU: {source}"
        ))
    })?;
    let [object] = objects.as_slice() else {
        return Err(io::Error::other(format!(
            "the AArch64 mlkem-native assembly SCU produced {} objects instead of one",
            objects.len()
        ))
        .into());
    };
    Ok(object.clone())
}

fn validate_native_build_environment() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-env-changed=CRATE_CC_NO_DEFAULTS");
    if env::var_os("CRATE_CC_NO_DEFAULTS")
        .is_some_and(|value| !value.is_empty() && value != "0" && value != "no" && value != "false")
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "CRATE_CC_NO_DEFAULTS is unsupported for the fixed AArch64 native backend",
        )
        .into());
    }

    println!("cargo:rerun-if-env-changed=CARGO_ENCODED_RUSTFLAGS");
    if let Some(encoded) = env::var_os("CARGO_ENCODED_RUSTFLAGS") {
        let encoded = encoded.into_string().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "CARGO_ENCODED_RUSTFLAGS must be UTF-8 for the AArch64 native backend",
            )
        })?;
        if let Some(option) = build_support::inherited_c_codegen_option(&encoded) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Rust codegen option {option} cannot be inherited by the fixed AArch64 native backend"
                ),
            )
            .into());
        }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=src/mlkem_bridge.c");
    println!("cargo:rerun-if-changed={NATIVE_C_WRAPPER}");
    println!("cargo:rerun-if-changed={PORTABLE_C_WRAPPER}");
    println!("cargo:rerun-if-changed={NATIVE_ASSEMBLY_WRAPPER}");
    println!("cargo:rerun-if-changed=src/mlkem_bridge.h");
    println!("cargo:rerun-if-changed=src/mlkem_config.h");
    println!("cargo:rerun-if-changed=src/mlkem_fips202_aarch64.h");
    println!("cargo:rerun-if-changed={VENDORED_ROOT}");
    println!("cargo:rerun-if-env-changed={WASM_CC_ENV}");

    let target = env::var("TARGET")?;
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH")?;
    let target_endian = env::var("CARGO_CFG_TARGET_ENDIAN")?;
    let target_env = env::var("CARGO_CFG_TARGET_ENV")?;
    let target_os = env::var("CARGO_CFG_TARGET_OS")?;
    let target_vendor = env::var("CARGO_CFG_TARGET_VENDOR")?;
    let implementation = build_support::select_mlkem_implementation(
        &target,
        &target_arch,
        &target_endian,
        &target_env,
        &target_os,
        &target_vendor,
    )
    .map_err(|source| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "native target metadata is inconsistent for {target}: {source}; arch={target_arch:?} endian={target_endian:?} env={target_env:?} os={target_os:?} vendor={target_vendor:?}"
            ),
        )
    })?;
    println!(
        "cargo:rustc-env=QPN_MLKEM_IMPLEMENTATION_ID={}",
        implementation.id()
    );
    if implementation.uses_aarch64_native() {
        validate_native_build_environment()?;
    }
    let apple_deployment_target = apple_deployment_target(&target, &target_os, &target_vendor)?;
    let wasm_compiler = wasm_compiler(&target)?;
    let freestanding = target_arch == "wasm32" || target_os == "none";

    let mut build = configured_build(
        apple_deployment_target.as_ref(),
        wasm_compiler.as_deref(),
        freestanding,
        implementation,
    );
    let compiler = build.get_compiler();
    validate_compiler(&compiler, implementation, &target_os)?;
    if target == WASM32_UNKNOWN_UNKNOWN {
        validate_wasm_compiler(&compiler)?;
    }
    build
        .file(if implementation.uses_aarch64_native() {
            NATIVE_C_WRAPPER
        } else {
            PORTABLE_C_WRAPPER
        })
        .warnings(true)
        .warnings_into_errors(true);
    if compiler.is_like_msvc() {
        build.flag("/std:c11").flag("/W4").flag("/WX");
    } else if compiler.is_like_clang() || compiler.is_like_gnu() {
        build
            .flag("-std=c99")
            .flag("-pedantic-errors")
            .flag("-Wall")
            .flag("-Wextra")
            .flag("-Werror")
            .flag("-Wconversion")
            .flag("-Wsign-conversion")
            .flag("-Wshadow")
            .flag("-Wpointer-arith")
            .flag("-Wmissing-prototypes")
            .flag("-Wstrict-prototypes")
            .flag("-Wundef")
            .flag("-fvisibility=hidden");
        if freestanding {
            build.flag("-ffreestanding");
        }
    }

    if implementation.uses_aarch64_native() {
        let assembly_object = compile_native_assembly(
            apple_deployment_target.as_ref(),
            &compiler,
            implementation,
            &target_os,
        )?;
        build.object(assembly_object);
    }

    validate_compiler(&build.get_compiler(), implementation, &target_os)?;
    build
        .try_compile("q_periapt_mlkem_native")
        .map_err(|source| {
            io::Error::other(format!(
                "failed to compile mlkem-native implementation {} for {target}: {source}",
                implementation.id()
            ))
        })?;
    Ok(())
}
