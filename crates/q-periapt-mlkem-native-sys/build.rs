// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Compiles the pinned portable mlkem-native translation unit with strict C
//! warnings and hidden bridge visibility.

#[path = "src/build_support.rs"]
mod build_support;

use std::env;
use std::error::Error;
use std::io;
use std::path::PathBuf;
use std::process::Command;

const WASM32_UNKNOWN_UNKNOWN: &str = "wasm32-unknown-unknown";
const WASM_CC_ENV: &str = "CC_wasm32_unknown_unknown";

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

fn main() -> Result<(), Box<dyn Error>> {
    const VENDORED_ROOT: &str = "vendor/mlkem-native";

    println!("cargo:rerun-if-changed=src/mlkem_bridge.c");
    println!("cargo:rerun-if-changed=src/mlkem_bridge.h");
    println!("cargo:rerun-if-changed=src/mlkem_config.h");
    println!("cargo:rerun-if-changed={VENDORED_ROOT}");
    println!("cargo:rerun-if-env-changed={WASM_CC_ENV}");

    let target = env::var("TARGET")?;
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH")?;
    let target_os = env::var("CARGO_CFG_TARGET_OS")?;
    let target_vendor = env::var("CARGO_CFG_TARGET_VENDOR")?;
    let apple_deployment_target = apple_deployment_target(&target, &target_os, &target_vendor)?;

    let mut build = cc::Build::new();
    build
        .file("src/mlkem_bridge.c")
        .include("src")
        .include(VENDORED_ROOT)
        .define("MLK_CONFIG_FILE", Some("\"mlkem_config.h\""))
        .warnings(true)
        .warnings_into_errors(true);

    if let Some((key, version)) = &apple_deployment_target {
        build.env(key, version);
    }

    if target == WASM32_UNKNOWN_UNKNOWN {
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
        build.compiler(compiler);
    }

    let freestanding = target_arch == "wasm32" || target_os == "none";
    if freestanding {
        build.define("QPN_MLKEM_FREESTANDING", None);
    }

    let compiler = build.get_compiler();
    if target == WASM32_UNKNOWN_UNKNOWN {
        validate_wasm_compiler(&compiler)?;
    }
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
    } else {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "q-periapt-mlkem-native-sys supports only MSVC, Clang, and GCC",
        )
        .into());
    }

    build
        .try_compile("q_periapt_mlkem_native")
        .map_err(|source| {
            io::Error::other(format!(
                "failed to compile the portable mlkem-native translation unit for {target}: {source}"
            ))
        })?;
    Ok(())
}
