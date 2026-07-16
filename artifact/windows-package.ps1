#!/usr/bin/env pwsh
# Build, package, and re-verify the Windows x64 MSVC ABI2 C SDK.

[CmdletBinding()]
param(
    [ValidateSet("Build", "VerifyArchive")]
    [string] $Mode = "Build",

    [string] $Archive = "",

    [string] $ExpectedSha256 = "",

    [string] $ExpectedManifestSha256 = "",

    [string] $ExpectedContractSha256 = "",

    [string] $ExpectedGitCommit = "",

    [string] $ExpectedGitTree = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false

$Root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
Set-Location -LiteralPath $Root

$Version = "0.1.0-alpha.2"
$Target = "x86_64-pc-windows-msvc"
$PackageName = "q-periapt-c-abi2-$Version-$Target"
$OutRoot = Join-Path $Root "target/qperiapt-windows-package"
$PackageRoot = Join-Path $OutRoot $PackageName
$DefaultArchive = Join-Path $OutRoot "$PackageName.zip"
$VerifyRoot = Join-Path $OutRoot "verify-$PackageName"
$DynamicTarget = Join-Path $Root "target/qperiapt-windows-dynamic"
$StaticTarget = Join-Path $Root "target/qperiapt-windows-static"
$Header = Join-Path $Root "crates/q-periapt-ffi/include/q_periapt.h"
$Contract = Join-Path $Root "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2.json"
$Fixture = Join-Path $Root "bindings/c/signed_policy_fixture.h"
$Smoke = Join-Path $Root "bindings/c/smoke.c"
$MsvcVersionProbe = Join-Path $Root "artifact/msvc-version-probe.c"
$Python = (Get-Command python -ErrorAction Stop).Source

function Invoke-Captured {
    param(
        [Parameter(Mandatory)] [string] $FilePath,
        [Parameter(Mandatory)] [string[]] $Arguments,
        [switch] $Echo
    )

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.WorkingDirectory = $Root
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in $Arguments) {
        [void] $startInfo.ArgumentList.Add($argument)
    }
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) {
            throw "failed to start native command: $FilePath"
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ($Echo) {
            if ($stdout.Length -gt 0) { [Console]::Out.Write($stdout) }
            if ($stderr.Length -gt 0) { [Console]::Error.Write($stderr) }
        }
        if ($process.ExitCode -ne 0) {
            $detail = ($stderr + "`n" + $stdout).Trim()
            throw "native command failed ($($process.ExitCode)): $FilePath $($Arguments -join ' ')`n$detail"
        }
        return [pscustomobject]@{
            Stdout = $stdout
            Stderr = $stderr
        }
    }
    finally {
        $process.Dispose()
    }
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory)] [string] $FilePath,
        [Parameter(Mandatory)] [string[]] $Arguments
    )
    [void] (Invoke-Captured -FilePath $FilePath -Arguments $Arguments -Echo)
}

function Invoke-PythonChecked {
    param([Parameter(Mandatory)] [string[]] $Arguments)

    $invocationArguments = @(
        "-I", "-S", "-B", "-W", "error", "artifact/python_bootstrap.py"
    ) + $Arguments
    Invoke-Checked -FilePath $Python -Arguments $invocationArguments
}

function Get-TrimmedOutput {
    param(
        [Parameter(Mandatory)] [string] $FilePath,
        [Parameter(Mandatory)] [string[]] $Arguments
    )
    $result = Invoke-Captured -FilePath $FilePath -Arguments $Arguments
    return $result.Stdout.Trim()
}

function Assert-SourceSnapshot {
    param(
        [Parameter(Mandatory)] [string] $ExpectedCommit,
        [Parameter(Mandatory)] [string] $ExpectedTree
    )

    $status = Get-TrimmedOutput -FilePath "git.exe" -Arguments @(
        "status", "--porcelain=v1", "--untracked-files=all"
    )
    if ($status) {
        throw "Windows package source changed during release build"
    }
    $actualCommit = Get-TrimmedOutput -FilePath "git.exe" -Arguments @(
        "rev-parse", "--verify", "HEAD^{commit}"
    )
    $actualTree = Get-TrimmedOutput -FilePath "git.exe" -Arguments @(
        "rev-parse", "--verify", "HEAD^{tree}"
    )
    if ($actualCommit -cne $ExpectedCommit -or $actualTree -cne $ExpectedTree) {
        throw "Windows package source commit or tree changed during release build"
    }
}

function Write-Utf8File {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $Content
    )
    [System.IO.File]::WriteAllText(
        $Path,
        $Content.Replace("`r`n", "`n"),
        [System.Text.UTF8Encoding]::new($false)
    )
}

function Assert-TrustedBuildEnvironment {
    $exactOverrides = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    foreach ($name in @(
        "AR", "ARFLAGS", "CC", "CC_SHELL_ESCAPED_FLAGS", "CFLAGS",
        "CPPFLAGS", "CXX", "CXXFLAGS", "CL", "_CL_", "LINK", "_LINK_",
        "CARGO_BUILD_BUILD_DIR", "CARGO_BUILD_RUSTC",
        "CARGO_BUILD_INCREMENTAL",
        "CARGO_BUILD_RUSTC_WRAPPER", "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
        "CARGO_BUILD_RUSTDOC", "CARGO_BUILD_RUSTDOCFLAGS",
        "CARGO_BUILD_RUSTFLAGS", "CARGO_BUILD_TARGET",
        "CARGO_BUILD_TARGET_DIR", "CARGO_ENCODED_RUSTDOCFLAGS",
        "CARGO_ENCODED_RUSTFLAGS", "CARGO_TARGET_DIR", "CC_FORCE_DISABLE",
        "COMPILER_PATH", "CPATH", "CPLUS_INCLUDE_PATH", "CROSS_COMPILE",
        "CRATE_CC_NO_DEFAULTS", "C_INCLUDE_PATH", "GCC_EXEC_PREFIX",
        "HOST_AR", "HOST_ARFLAGS", "HOST_CC", "HOST_CFLAGS",
        "HOST_CPPFLAGS", "HOST_CXX", "HOST_CXXFLAGS", "HOST_RANLIB",
        "HOST_RANLIBFLAGS", "LD", "LDFLAGS", "LIBRARY_PATH",
        "OBJC_INCLUDE_PATH", "RANLIB", "RANLIBFLAGS", "RUSTC",
        "RUSTC_BOOTSTRAP", "RUSTC_LINKER", "RUSTC_WORKSPACE_WRAPPER",
        "RUSTC_WRAPPER", "RUSTDOC", "RUSTDOCFLAGS", "RUSTUP_TOOLCHAIN",
        "SOURCE_DATE_EPOCH", "TARGET_AR", "TARGET_ARFLAGS", "TARGET_CC",
        "TARGET_CFLAGS", "TARGET_CPPFLAGS", "TARGET_CXX", "TARGET_CXXFLAGS",
        "TARGET_RANLIB", "TARGET_RANLIBFLAGS", "ZERO_AR_DATE",
        "CMAKE_C_COMPILER_LAUNCHER", "CMAKE_C_LINKER_LAUNCHER",
        "CMAKE_CROSSCOMPILING_EMULATOR", "CMAKE_GENERATOR",
        "CMAKE_GENERATOR_INSTANCE",
        "CMAKE_GENERATOR_PLATFORM", "CMAKE_GENERATOR_TOOLSET",
        "CMAKE_MODULE_PATH", "CMAKE_PREFIX_PATH", "CMAKE_PROGRAM_PATH",
        "CMAKE_PROJECT_INCLUDE", "CMAKE_PROJECT_INCLUDE_BEFORE",
        "CMAKE_PROJECT_TOP_LEVEL_INCLUDES", "CMAKE_TEST_LAUNCHER",
        "CMAKE_TOOLCHAIN_FILE",
        "CMAKE_USER_MAKE_RULES_OVERRIDE", "CMAKE_USER_MAKE_RULES_OVERRIDE_C",
        "QPeriaptABI2_ROOT",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_CEILING_DIRECTORIES",
        "GIT_COMMON_DIR", "GIT_CONFIG_COUNT", "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_SYSTEM",
        "GIT_DIR", "GIT_DISCOVERY_ACROSS_FILESYSTEM", "GIT_INDEX_FILE",
        "GIT_NAMESPACE", "GIT_OBJECT_DIRECTORY", "GIT_REPLACE_REF_BASE",
        "GIT_SHALLOW_FILE", "GIT_WORK_TREE"
    )) {
        [void] $exactOverrides.Add($name)
    }
    $pattern = [regex]::new(
        '^(?:AR|ARFLAGS|CC|CFLAGS|CPPFLAGS|CXX|CXXFLAGS|RANLIB|RANLIBFLAGS)_.+$|' +
        '^.+_(?:AR|ARFLAGS|CC|CFLAGS|CPPFLAGS|CXX|CXXFLAGS|RANLIB|RANLIBFLAGS)$|' +
        '^CARGO_PROFILE_.+$|' +
        '^CARGO_TARGET_.+_(?:AR|LINKER|RUNNER|RUSTDOCFLAGS|RUSTFLAGS)$|' +
        '^GIT_CONFIG_(?:KEY|VALUE)_[0-9]+$',
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
            [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    $rejected = [System.Collections.Generic.List[string]]::new()
    foreach ($entry in [System.Environment]::GetEnvironmentVariables(
        "Process"
    ).GetEnumerator()) {
        $name = [string] $entry.Key
        $value = [string] $entry.Value
        if ([string]::Equals(
            $name,
            "RUSTFLAGS",
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
            if ($value -cne "-D warnings") { [void] $rejected.Add($name) }
            continue
        }
        if ([string]::Equals(
            $name,
            "CARGO_INCREMENTAL",
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
            if ($value -cne "0") { [void] $rejected.Add($name) }
            continue
        }
        if ($exactOverrides.Contains($name) -or $pattern.IsMatch($name)) {
            [void] $rejected.Add($name)
        }
    }
    if ($rejected.Count -ne 0) {
        $names = @($rejected | Sort-Object -Unique) -join ", "
        throw "Windows package tooling rejects caller build/provenance overrides: $names"
    }
}

function Assert-NoAmbientCargoConfiguration {
    param([Parameter(Mandatory)] [string] $SourceRoot)

    if (-not [System.IO.Path]::IsPathFullyQualified($SourceRoot)) {
        throw "Windows package source root must be absolute"
    }
    $cargoHomeText = $env:CARGO_HOME
    if (-not $cargoHomeText) {
        $home = if ($env:USERPROFILE) { $env:USERPROFILE } else { $env:HOME }
        if (-not $home) {
            throw "Windows package tooling requires CARGO_HOME or a user home"
        }
        $cargoHomeText = Join-Path $home ".cargo"
    }
    if (-not [System.IO.Path]::IsPathFullyQualified($cargoHomeText)) {
        throw "Cargo home must be absolute for Windows package tooling"
    }

    $candidates = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    $cargoHome = [System.IO.Path]::GetFullPath($cargoHomeText)
    foreach ($name in @("config", "config.toml")) {
        [void] $candidates.Add((Join-Path $cargoHome $name))
    }
    $directory = [System.IO.DirectoryInfo]::new(
        [System.IO.Path]::GetFullPath($SourceRoot)
    )
    while ($null -ne $directory) {
        foreach ($name in @("config", "config.toml")) {
            [void] $candidates.Add((Join-Path $directory.FullName ".cargo/$name"))
        }
        $directory = $directory.Parent
    }
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) {
            throw "Windows package tooling rejects ambient Cargo configuration files"
        }
    }
}

function Resolve-TrustedToolchainFile {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $TrustedRoot,
        [Parameter(Mandatory)] [string] $ExpectedName
    )

    if (
        -not [System.IO.Path]::IsPathFullyQualified($Path) -or
        -not [System.IO.Path]::IsPathFullyQualified($TrustedRoot)
    ) {
        throw "trusted toolchain paths must be absolute"
    }
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $fullTrustedRoot = [System.IO.Path]::GetFullPath($TrustedRoot)
    $separators = [char[]] @(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    )
    $trustedPrefix = $fullTrustedRoot.TrimEnd($separators) +
        [System.IO.Path]::DirectorySeparatorChar
    if (-not $fullPath.StartsWith(
        $trustedPrefix,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw "toolchain file is outside the trusted installation: $fullPath"
    }
    if (-not [System.IO.Path]::GetFileName($fullPath).Equals(
        $ExpectedName,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw "toolchain filename differs from the expected identity: $fullPath"
    }
    if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
        throw "toolchain path is not a regular file: $fullPath"
    }

    $volumeRoot = [System.IO.Path]::GetPathRoot($fullPath)
    if (-not $volumeRoot) {
        throw "cannot determine the toolchain volume root: $fullPath"
    }
    $cursor = $volumeRoot
    $relative = $fullPath.Substring($volumeRoot.Length)
    $components = $relative.Split(
        $separators,
        [System.StringSplitOptions]::RemoveEmptyEntries
    )
    foreach ($component in $components) {
        $cursor = Join-Path $cursor $component
        $attributes = [System.IO.File]::GetAttributes($cursor)
        if (
            ($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
        ) {
            throw "toolchain path contains a reparse point: $cursor"
        }
    }
    $leafAttributes = [System.IO.File]::GetAttributes($fullPath)
    if (($leafAttributes -band [System.IO.FileAttributes]::Directory) -ne 0) {
        throw "toolchain path is not a regular file: $fullPath"
    }
    return $fullPath
}

function Resolve-TrustedCommandProcessor {
    param([Parameter(Mandatory)] [string] $SystemDirectory)

    if (-not [System.IO.Path]::IsPathFullyQualified($SystemDirectory)) {
        throw "Windows system directory must be absolute"
    }
    $fullSystemDirectory = [System.IO.Path]::GetFullPath($SystemDirectory)
    $commandProcessor = Resolve-TrustedToolchainFile `
        -Path (Join-Path $fullSystemDirectory "cmd.exe") `
        -TrustedRoot $fullSystemDirectory `
        -ExpectedName "cmd.exe"
    if ($env:ComSpec) {
        if (
            -not [System.IO.Path]::IsPathFullyQualified($env:ComSpec) -or
            -not [System.IO.Path]::GetFullPath($env:ComSpec).Equals(
                $commandProcessor,
                [System.StringComparison]::OrdinalIgnoreCase
            )
        ) {
            throw "ComSpec does not identify the trusted Windows command processor"
        }
    }
    return $commandProcessor
}

function Resolve-TrustedMsvcX64Tools {
    param([Parameter(Mandatory)] [string] $MsvcInstallation)

    if (
        $env:VSCMD_ARG_HOST_ARCH -cne "x64" -or
        $env:VSCMD_ARG_TGT_ARCH -cne "x64"
    ) {
        throw "vcvars64 must select the x64 host and x64 target toolchain"
    }
    if (
        -not $env:VSINSTALLDIR -or
        -not $env:VCINSTALLDIR -or
        -not $env:VCToolsInstallDir -or
        -not [System.IO.Path]::IsPathFullyQualified($MsvcInstallation) -or
        -not [System.IO.Path]::IsPathFullyQualified($env:VSINSTALLDIR) -or
        -not [System.IO.Path]::IsPathFullyQualified($env:VCINSTALLDIR) -or
        -not [System.IO.Path]::IsPathFullyQualified($env:VCToolsInstallDir)
    ) {
        throw "MSVC installation directories must all be absolute"
    }
    $separators = [char[]] @(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    )
    $fullInstallation = [System.IO.Path]::GetFullPath($MsvcInstallation).TrimEnd(
        $separators
    )
    $vsInstallation = [System.IO.Path]::GetFullPath(
        $env:VSINSTALLDIR
    ).TrimEnd($separators)
    $vcInstallation = [System.IO.Path]::GetFullPath(
        $env:VCINSTALLDIR
    ).TrimEnd($separators)
    $expectedVcInstallation = [System.IO.Path]::GetFullPath(
        (Join-Path $fullInstallation "VC")
    ).TrimEnd($separators)
    if (
        -not $vsInstallation.Equals(
            $fullInstallation,
            [System.StringComparison]::OrdinalIgnoreCase
        ) -or
        -not $vcInstallation.Equals(
            $expectedVcInstallation,
            [System.StringComparison]::OrdinalIgnoreCase
        )
    ) {
        throw "vcvars64 selected a different Visual Studio installation"
    }
    $versionsRoot = [System.IO.Path]::GetFullPath(
        (Join-Path $fullInstallation "VC/Tools/MSVC")
    ).TrimEnd($separators)
    $vcTools = [System.IO.Path]::GetFullPath(
        $env:VCToolsInstallDir
    ).TrimEnd($separators)
    $vcToolsParent = [System.IO.Directory]::GetParent($vcTools)
    $vcToolsVersion = [System.IO.Path]::GetFileName($vcTools)
    if (
        $null -eq $vcToolsParent -or
        -not $vcToolsParent.FullName.Equals(
            $versionsRoot,
            [System.StringComparison]::OrdinalIgnoreCase
        ) -or
        $vcToolsVersion -cnotmatch '^[0-9]+\.[0-9]+\.[0-9]+$'
    ) {
        throw "VCToolsInstallDir is not one version directly below the trusted MSVC tools root"
    }
    $bin = [System.IO.Path]::GetFullPath(
        (Join-Path $vcTools "bin/Hostx64/x64")
    )
    $cl = Resolve-TrustedToolchainFile `
        -Path (Join-Path $bin "cl.exe") `
        -TrustedRoot $bin `
        -ExpectedName "cl.exe"
    $linker = Resolve-TrustedToolchainFile `
        -Path (Join-Path $bin "link.exe") `
        -TrustedRoot $bin `
        -ExpectedName "link.exe"
    $dumpbin = Resolve-TrustedToolchainFile `
        -Path (Join-Path $bin "dumpbin.exe") `
        -TrustedRoot $bin `
        -ExpectedName "dumpbin.exe"
    return [pscustomobject] @{
        Bin = $bin
        Cl = $cl
        Dumpbin = $dumpbin
        Linker = $linker
    }
}

function Resolve-TrustedRustLlvmTools {
    param(
        [Parameter(Mandatory)] [string] $RustSysroot,
        [Parameter(Mandatory)] [string] $RustHost
    )

    if ($RustHost -cne "x86_64-pc-windows-msvc") {
        throw "Rust host must be exactly x86_64-pc-windows-msvc"
    }
    if (-not [System.IO.Path]::IsPathFullyQualified($RustSysroot)) {
        throw "Rust sysroot must be absolute"
    }
    $llvmToolsRoot = [System.IO.Path]::GetFullPath(
        (Join-Path $RustSysroot "lib/rustlib/$RustHost/bin")
    )
    $llvmAr = Resolve-TrustedToolchainFile `
        -Path (Join-Path $llvmToolsRoot "llvm-ar.exe") `
        -TrustedRoot $llvmToolsRoot `
        -ExpectedName "llvm-ar.exe"
    $llvmNm = Resolve-TrustedToolchainFile `
        -Path (Join-Path $llvmToolsRoot "llvm-nm.exe") `
        -TrustedRoot $llvmToolsRoot `
        -ExpectedName "llvm-nm.exe"
    return [pscustomobject] @{
        Bin = $llvmToolsRoot
        Ar = $llvmAr
        Nm = $llvmNm
    }
}

function Set-TrustedMsvcPath {
    param(
        [Parameter(Mandatory)] [string] $TrustedBin,
        [Parameter(Mandatory)] [string] $Linker
    )

    if (
        -not [System.IO.Path]::IsPathFullyQualified($TrustedBin) -or
        -not [System.IO.Path]::IsPathFullyQualified($Linker) -or
        -not [System.IO.Path]::GetFileName($Linker).Equals(
            "link.exe",
            [System.StringComparison]::OrdinalIgnoreCase
        )
    ) {
        throw "trusted MSVC PATH inputs must be absolute and name link.exe"
    }
    $fullTrustedBin = [System.IO.Path]::GetFullPath($TrustedBin)
    $fullLinker = [System.IO.Path]::GetFullPath($Linker)
    if (
        -not [System.IO.Path]::GetDirectoryName($fullLinker).Equals(
            $fullTrustedBin,
            [System.StringComparison]::OrdinalIgnoreCase
        ) -or
        -not (Test-Path -LiteralPath $fullLinker -PathType Leaf)
    ) {
        throw "trusted link.exe must be a file directly inside the MSVC bin directory"
    }
    if (-not $env:PATH) {
        throw "PATH is unavailable for deterministic MSVC linker selection"
    }

    $seen = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    [void] $seen.Add($fullTrustedBin)
    $retained = [System.Collections.Generic.List[string]]::new()
    foreach ($entry in $env:PATH.Split([System.IO.Path]::PathSeparator)) {
        if (-not $entry -or -not [System.IO.Path]::IsPathFullyQualified($entry)) {
            throw "PATH contains an empty or relative MSVC linker search directory"
        }
        $fullEntry = [System.IO.Path]::GetFullPath($entry)
        $candidate = Join-Path $fullEntry "link.exe"
        if (Test-Path -LiteralPath $candidate) {
            if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
                throw "MSVC linker search resolved link.exe to a non-file path"
            }
            # The trusted directory is prepended exactly once below. Every
            # other link.exe provider is removed instead of becoming a hidden
            # fallback candidate.
            continue
        }
        if ($seen.Add($fullEntry)) { [void] $retained.Add($fullEntry) }
    }
    $env:PATH = (@($fullTrustedBin) + @($retained)) -join (
        [System.IO.Path]::PathSeparator
    )
    $linkerCandidates = @(
        foreach ($entry in $env:PATH.Split([System.IO.Path]::PathSeparator)) {
            $candidate = Join-Path $entry "link.exe"
            if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                [System.IO.Path]::GetFullPath($candidate)
            }
        }
    )
    if (
        $linkerCandidates.Count -ne 1 -or
        -not $linkerCandidates[0].Equals(
            $fullLinker,
            [System.StringComparison]::OrdinalIgnoreCase
        )
    ) {
        throw "controlled PATH does not resolve only the trusted MSVC linker"
    }
}

function Initialize-MsvcEnvironment {
    $commandProcessor = Resolve-TrustedCommandProcessor `
        -SystemDirectory ([System.Environment]::SystemDirectory)
    $vswhereCandidates = @(
        @(
            "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe",
            "$env:ProgramFiles\Microsoft Visual Studio\Installer\vswhere.exe"
        ) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) }
    )
    if ($vswhereCandidates.Count -ne 1) {
        throw "Visual Studio vswhere.exe must be available exactly once"
    }
    $candidate = $vswhereCandidates[0]
    $pathSeparators = [char[]] @(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    )
    $programFilesRoots = @(
        @(
            $env:ProgramFiles,
            ${env:ProgramFiles(x86)}
        ) | Where-Object {
            $_ -and $candidate.StartsWith(
                [System.IO.Path]::GetFullPath($_).TrimEnd($pathSeparators) +
                [System.IO.Path]::DirectorySeparatorChar,
                [System.StringComparison]::OrdinalIgnoreCase
            )
        }
    )
    if ($programFilesRoots.Count -ne 1) {
        throw "vswhere.exe must belong to exactly one Program Files root"
    }
    $vswhere = Resolve-TrustedToolchainFile `
        -Path $candidate `
        -TrustedRoot $programFilesRoots[0] `
        -ExpectedName "vswhere.exe"
    $installation = Get-TrimmedOutput -FilePath $vswhere -Arguments @(
        "-latest", "-products", "*", "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath"
    )
    if (-not $installation -or -not [System.IO.Path]::IsPathFullyQualified($installation)) {
        throw "Visual Studio with the x64 MSVC toolchain is unavailable"
    }
    $installation = [System.IO.Path]::GetFullPath($installation)
    $vcvars = Resolve-TrustedToolchainFile `
        -Path (Join-Path $installation "VC/Auxiliary/Build/vcvars64.bat") `
        -TrustedRoot $installation `
        -ExpectedName "vcvars64.bat"
    $environmentLines = & $commandProcessor /d /s /c "`"$vcvars`" >nul && set"
    if ($LASTEXITCODE -ne 0) {
        throw "vcvars64.bat failed with exit code $LASTEXITCODE"
    }
    foreach ($line in $environmentLines) {
        $separator = $line.IndexOf("=")
        if ($separator -gt 0) {
            $name = $line.Substring(0, $separator)
            $value = $line.Substring($separator + 1)
            [System.Environment]::SetEnvironmentVariable($name, $value, "Process")
        }
    }
    foreach ($tool in @("cmake.exe", "ctest.exe")) {
        [void] (Get-Command $tool -ErrorAction Stop)
    }
    return $installation
}

function Assert-ImportLibrary {
    param(
        [Parameter(Mandatory)] [string] $ImportLibrary,
        [Parameter(Mandatory)] [string] $Dumpbin
    )

    $output = (Invoke-Captured -FilePath $Dumpbin -Arguments @("/nologo", "/linkermember:1", $ImportLibrary)).Stdout
    if ($output -notmatch '__IMPORT_DESCRIPTOR_q_periapt_ffi_abi2') {
        throw "import library is not bound to q_periapt_ffi_abi2.dll"
    }
    $expected = @(
        "q_periapt_abi_version",
        "q_periapt_decapsulate",
        "q_periapt_decision_from_signed_policy",
        "q_periapt_encapsulate",
        "q_periapt_fixed_suite_id",
        "q_periapt_fixed_suite_id_len",
        "q_periapt_generate_keypair",
        "q_periapt_status_name",
        "q_periapt_version"
    )
    foreach ($symbol in $expected) {
        if ($output -notmatch "(?m)\b$([regex]::Escape($symbol))\b") {
            throw "import library is missing ABI2 symbol: $symbol"
        }
    }
    if ($output -match '(?m)\bq_periapt_(?:combine|hybrid_|mlkem|x25519)') {
        throw "import library exposes a forbidden legacy/raw symbol"
    }
}

function Assert-NativePackage {
    param(
        [Parameter(Mandatory)] [string] $Extracted,
        [Parameter(Mandatory)] [string] $Cl,
        [Parameter(Mandatory)] [string] $LlvmNm,
        [Parameter(Mandatory)] [string] $Dumpbin,
        [Parameter(Mandatory)] [string[]] $NativeStaticLibraries,
        [Parameter(Mandatory)] [string] $TrustedGitCommit,
        [Parameter(Mandatory)] [string] $TrustedGitTree
    )

    $dll = Join-Path $Extracted "bin/q_periapt_ffi_abi2.dll"
    $importLibrary = Join-Path $Extracted "lib/q_periapt_ffi_abi2.lib"
    $staticLibrary = Join-Path $Extracted "lib/q_periapt_ffi_abi2_static.lib"
    foreach ($path in @($dll, $importLibrary, $staticLibrary)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "required extracted Windows library is missing: $path"
        }
    }
    Assert-ImportLibrary -ImportLibrary $importLibrary -Dumpbin $Dumpbin
    Invoke-PythonChecked -Arguments @(
        "artifact/c_abi_contract.py",
        "--contract", (Join-Path $Extracted "share/q-periapt/abi/q-periapt-c-abi-v2.json"),
        "--header", (Join-Path $Extracted "include/qperiapt/abi2/q_periapt.h"),
        "--library", $dll,
        "--static-library", $staticLibrary,
        "--llvm-nm", $LlvmNm,
        "--platform", "windows"
    )
    $manifestVerificationArguments = @(
        "artifact/windows_package.py", "verify",
        "--package-root", $Extracted,
        "--repository-root", $Root,
        "--dumpbin", $Dumpbin,
        "--expected-git-commit", $TrustedGitCommit,
        "--expected-git-tree", $TrustedGitTree
    )
    Invoke-PythonChecked -Arguments $manifestVerificationArguments

    $ConsumerRoot = Join-Path $VerifyRoot "native-consumers"
    New-Item -ItemType Directory -Path $ConsumerRoot -Force | Out-Null
    $dynamicExe = Join-Path $ConsumerRoot "dynamic-smoke.exe"
    $staticExe = Join-Path $ConsumerRoot "static-smoke.exe"
    Invoke-Checked -FilePath $Cl -Arguments @(
        "/nologo", "/std:c11", "/W4", "/WX", "/utf-8",
        (Join-Path $Extracted "share/q-periapt/smoke.c"),
        "/I$Extracted\include\qperiapt\abi2",
        "/Fe:$dynamicExe", "/Fo:$ConsumerRoot\dynamic-smoke.obj",
        "/link", "/WX", $importLibrary
    )
    $savedPath = $env:PATH
    try {
        $env:PATH = (Join-Path $Extracted "bin") + ";" + $savedPath
        Invoke-Checked -FilePath $dynamicExe -Arguments @()
    }
    finally {
        $env:PATH = $savedPath
    }

    $staticArguments = @(
        "/nologo", "/std:c11", "/W4", "/WX", "/utf-8",
        (Join-Path $Extracted "share/q-periapt/smoke.c"),
        "/I$Extracted\include\qperiapt\abi2",
        "/Fe:$staticExe", "/Fo:$ConsumerRoot\static-smoke.obj",
        "/link", "/WX", $staticLibrary
    ) + $NativeStaticLibraries
    Invoke-Checked -FilePath $Cl -Arguments $staticArguments
    $savedPath = $env:PATH
    try {
        $env:PATH = "$env:SystemRoot\System32"
        Invoke-Checked -FilePath $staticExe -Arguments @()
    }
    finally {
        $env:PATH = $savedPath
    }
    $staticDependencies = (Invoke-Captured -FilePath $Dumpbin -Arguments @("/nologo", "/dependents", $staticExe)).Stdout
    if ($staticDependencies -match '(?i)q_periapt_ffi_abi2\.dll') {
        throw "static consumer unexpectedly depends on q_periapt_ffi_abi2.dll"
    }

    $cmakeSource = Join-Path $VerifyRoot "cmake-consumer-source"
    $cmakeBuild = Join-Path $VerifyRoot "cmake-consumer-build"
    New-Item -ItemType Directory -Path $cmakeSource -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $Extracted "share/q-periapt/smoke.c") -Destination (Join-Path $cmakeSource "smoke.c")
    $cmakeLists = @'
cmake_minimum_required(VERSION 3.20)
project(QPeriaptWindowsConsumer C)
find_package(QPeriaptABI2 2.0.0 EXACT CONFIG REQUIRED)
if(NOT QPeriaptABI2_RELEASE_VERSION STREQUAL "@VERSION@")
  message(FATAL_ERROR "QPeriapt release version mismatch")
endif()
add_executable(dynamic-smoke smoke.c)
target_compile_features(dynamic-smoke PRIVATE c_std_11)
target_compile_options(dynamic-smoke PRIVATE /W4 /WX)
target_link_options(dynamic-smoke PRIVATE /WX)
target_link_libraries(dynamic-smoke PRIVATE QPeriaptABI2::qperiapt)
add_custom_command(TARGET dynamic-smoke POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
    "$<TARGET_FILE:QPeriaptABI2::qperiapt>" "$<TARGET_FILE_DIR:dynamic-smoke>")
add_executable(static-smoke smoke.c)
target_compile_features(static-smoke PRIVATE c_std_11)
target_compile_options(static-smoke PRIVATE /W4 /WX)
target_link_options(static-smoke PRIVATE /WX)
target_link_libraries(static-smoke PRIVATE QPeriaptABI2::qperiapt_static)
enable_testing()
add_test(NAME dynamic-smoke COMMAND dynamic-smoke)
add_test(NAME static-smoke COMMAND static-smoke)
'@.Replace("@VERSION@", $Version)
    Write-Utf8File -Path (Join-Path $cmakeSource "CMakeLists.txt") -Content $cmakeLists
    Invoke-Checked -FilePath "cmake.exe" -Arguments @(
        "-S", $cmakeSource, "-B", $cmakeBuild, "-A", "x64",
        "-DCMAKE_PREFIX_PATH=$Extracted",
        "-DQPeriaptABI2_DIR=$Extracted/lib/cmake/QPeriaptABI2",
        "-DCMAKE_FIND_PACKAGE_PREFER_CONFIG=ON",
        "-DCMAKE_FIND_USE_PACKAGE_REGISTRY=OFF",
        "-DCMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY=OFF"
    )
    Invoke-Checked -FilePath "cmake.exe" -Arguments @("--build", $cmakeBuild, "--config", "Release")
    Invoke-Checked -FilePath "ctest.exe" -Arguments @("--test-dir", $cmakeBuild, "-C", "Release", "--output-on-failure")

    $negativeSource = Join-Path $VerifyRoot "cmake-negative-source"
    $negativeBuild = Join-Path $VerifyRoot "cmake-negative-build"
    New-Item -ItemType Directory -Path $negativeSource -Force | Out-Null
    Write-Utf8File -Path (Join-Path $negativeSource "CMakeLists.txt") -Content @'
cmake_minimum_required(VERSION 3.20)
project(QPeriaptWindowsNegative NONE)
find_package(QPeriaptABI2 2.0.1 EXACT CONFIG QUIET PATHS "${QPERIAPT_PREFIX}" NO_DEFAULT_PATH)
if(QPeriaptABI2_FOUND)
  message(FATAL_ERROR "wrong ABI compatibility version unexpectedly resolved")
endif()
'@
    Invoke-Checked -FilePath "cmake.exe" -Arguments @(
        "-S", $negativeSource, "-B", $negativeBuild,
        "-DQPERIAPT_PREFIX=$Extracted",
        "-DCMAKE_FIND_USE_PACKAGE_REGISTRY=OFF",
        "-DCMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY=OFF"
    )
}

function Verify-WindowsArchive {
    param(
        [Parameter(Mandatory)] [string] $ArchivePath,
        [Parameter(Mandatory)] [string] $ExpectedArchiveSha256,
        [Parameter(Mandatory)] [string] $Cl,
        [Parameter(Mandatory)] [string] $LlvmNm,
        [Parameter(Mandatory)] [string] $Dumpbin,
        [Parameter(Mandatory)] [string[]] $NativeStaticLibraries,
        [Parameter(Mandatory)] [string] $TrustedGitCommit,
        [Parameter(Mandatory)] [string] $TrustedGitTree
    )

    if (-not (Test-Path -LiteralPath $ArchivePath -PathType Leaf)) {
        throw "Windows package archive is missing: $ArchivePath"
    }
    if (Test-Path -LiteralPath $VerifyRoot) {
        Remove-Item -LiteralPath $VerifyRoot -Recurse -Force
    }
    $extracted = Join-Path $VerifyRoot $PackageName
    Invoke-PythonChecked -Arguments @(
        "artifact/deterministic_archive.py", "extract-zip",
        "--archive", $ArchivePath,
        "--destination", $VerifyRoot,
        "--root", $PackageName,
        "--sha256", $ExpectedArchiveSha256
    )
    [void] (Assert-NativePackage `
        -Extracted $extracted `
        -Cl $Cl `
        -LlvmNm $LlvmNm `
        -Dumpbin $Dumpbin `
        -NativeStaticLibraries $NativeStaticLibraries `
        -TrustedGitCommit $TrustedGitCommit `
        -TrustedGitTree $TrustedGitTree)
    Write-Host "WINDOWS_C_ABI_PACKAGE_VERIFY_PASS"
}

Assert-TrustedBuildEnvironment
Assert-NoAmbientCargoConfiguration -SourceRoot $Root
$MsvcInstallation = Initialize-MsvcEnvironment
Assert-TrustedBuildEnvironment
$MsvcTools = Resolve-TrustedMsvcX64Tools -MsvcInstallation $MsvcInstallation
$Cl = $MsvcTools.Cl
$Dumpbin = $MsvcTools.Dumpbin
$Linker = $MsvcTools.Linker
[void] (Set-TrustedMsvcPath -TrustedBin $MsvcTools.Bin -Linker $Linker)
$RustSysroot = Get-TrimmedOutput -FilePath "rustc.exe" -Arguments @("--print", "sysroot")
$RustHostOutput = Get-TrimmedOutput -FilePath "rustc.exe" -Arguments @("-vV")
$RustHostMatch = [regex]::Match($RustHostOutput, '(?m)^host:\s*(?<host>\S+)\s*$')
if (-not $RustHostMatch.Success) {
    throw "cannot determine the Rust host triple"
}
$RustcVersion = Get-TrimmedOutput -FilePath "rustc.exe" -Arguments @("--version")
if ($RustcVersion -cne "rustc 1.96.1 (31fca3adb 2026-06-26)") {
    throw "Windows release package requires rustc 1.96.1: $RustcVersion"
}
$CargoVersion = Get-TrimmedOutput -FilePath "cargo.exe" -Arguments @("--version")
if ($CargoVersion -cne "cargo 1.96.1 (356927216 2026-06-26)") {
    throw "Windows release package requires cargo 1.96.1: $CargoVersion"
}
$RustLlvmTools = Resolve-TrustedRustLlvmTools `
    -RustSysroot $RustSysroot `
    -RustHost $RustHostMatch.Groups['host'].Value
$LlvmAr = $RustLlvmTools.Ar
$LlvmNm = $RustLlvmTools.Nm

if ($Mode -eq "VerifyArchive") {
    if (-not $Archive) {
        throw "-Archive is required in VerifyArchive mode"
    }
    foreach ($expected in @(
        $ExpectedSha256,
        $ExpectedManifestSha256,
        $ExpectedContractSha256
    )) {
        if ($expected -cnotmatch '^[0-9a-f]{64}$') {
            throw "VerifyArchive requires each expected SHA-256 as 64 lowercase hexadecimal characters"
        }
    }
    foreach ($expected in @($ExpectedGitCommit, $ExpectedGitTree)) {
        if ($expected -cnotmatch '^[0-9a-f]{40,64}$') {
            throw "VerifyArchive requires trusted lowercase hexadecimal Git commit and tree identities"
        }
    }
    $manifestScratch = Join-Path $OutRoot "verify-input"
    if (Test-Path -LiteralPath $manifestScratch) {
        Remove-Item -LiteralPath $manifestScratch -Recurse -Force
    }
    New-Item -ItemType Directory -Path $OutRoot -Force | Out-Null
    $scratchExtract = Join-Path $manifestScratch $PackageName
    Invoke-PythonChecked -Arguments @(
        "artifact/deterministic_archive.py", "extract-zip",
        "--archive", ([System.IO.Path]::GetFullPath($Archive)),
        "--destination", $manifestScratch,
        "--root", $PackageName,
        "--sha256", $ExpectedSha256
    )
    $actualManifestSha256 = (Get-FileHash -LiteralPath (Join-Path $scratchExtract "MANIFEST.json") -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualManifestSha256 -cne $ExpectedManifestSha256) {
        throw "extracted Windows MANIFEST.json SHA-256 differs from the trusted distribution manifest"
    }
    $actualContractSha256 = (Get-FileHash -LiteralPath (Join-Path $scratchExtract "share/q-periapt/abi/q-periapt-c-abi-v2.json") -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualContractSha256 -cne $ExpectedContractSha256) {
        throw "extracted Windows ABI contract SHA-256 differs from the trusted distribution manifest"
    }
    $config = Get-Content -LiteralPath (Join-Path $scratchExtract "lib/cmake/QPeriaptABI2/QPeriaptABI2Config.cmake") -Raw
    $nativeMatch = [regex]::Match($config, '(?m)^set\(_QPERIAPT_ABI2_STATIC_NATIVE_LIBS(?<values>[^\r\n]*)\)\s*$')
    if (-not $nativeMatch.Success) {
        throw "cannot recover static native libraries from the extracted CMake config"
    }
    $nativeLibraries = @([regex]::Matches($nativeMatch.Groups["values"].Value, '"(?<name>[A-Za-z0-9_.-]+\.lib)"') | ForEach-Object { $_.Groups["name"].Value })
    if ($nativeLibraries.Count -eq 0) {
        throw "extracted CMake config contains no native static libraries"
    }
    Remove-Item -LiteralPath $manifestScratch -Recurse -Force
    Verify-WindowsArchive `
        -ArchivePath ([System.IO.Path]::GetFullPath($Archive)) `
        -ExpectedArchiveSha256 $ExpectedSha256 `
        -Cl $Cl `
        -LlvmNm $LlvmNm `
        -Dumpbin $Dumpbin `
        -NativeStaticLibraries $nativeLibraries `
        -TrustedGitCommit $ExpectedGitCommit `
        -TrustedGitTree $ExpectedGitTree
    exit 0
}

if ($Archive) {
    throw "-Archive is only valid in VerifyArchive mode"
}
if (
    $ExpectedSha256 -or
    $ExpectedManifestSha256 -or
    $ExpectedContractSha256 -or
    $ExpectedGitCommit -or
    $ExpectedGitTree
) {
    throw "expected digest parameters are only valid in VerifyArchive mode"
}

$gitStatus = Get-TrimmedOutput -FilePath "git.exe" -Arguments @(
    "status", "--porcelain=v1", "--untracked-files=all"
)
if ($gitStatus) {
    throw "Windows release packaging requires a clean worktree"
}
$GitCommit = Get-TrimmedOutput -FilePath "git.exe" -Arguments @("rev-parse", "--verify", "HEAD^{commit}")
if ($GitCommit -notmatch '^[0-9a-f]{40}$') {
    throw "Windows package source commit is malformed: $GitCommit"
}
if ($env:QPERIAPT_EXPECTED_GIT_COMMIT -and $GitCommit -ne $env:QPERIAPT_EXPECTED_GIT_COMMIT) {
    throw "Windows package source commit differs from QPERIAPT_EXPECTED_GIT_COMMIT"
}
$GitTree = Get-TrimmedOutput -FilePath "git.exe" -Arguments @("rev-parse", "--verify", "HEAD^{tree}")
if ($GitTree -notmatch '^[0-9a-f]{40,64}$') {
    throw "Windows package source tree is malformed: $GitTree"
}
Assert-SourceSnapshot -ExpectedCommit $GitCommit -ExpectedTree $GitTree
$SourceDateEpochText = Get-TrimmedOutput -FilePath "git.exe" -Arguments @("show", "-s", "--format=%ct", "HEAD")
if ($SourceDateEpochText -notmatch '^(0|[1-9][0-9]*)$') {
    throw "source commit timestamp is malformed: $SourceDateEpochText"
}
$SourceDateEpoch = [int64] $SourceDateEpochText
$metadata = (Get-TrimmedOutput -FilePath "cargo.exe" -Arguments @("metadata", "--locked", "--format-version", "1", "--no-deps")) | ConvertFrom-Json
$ffiPackage = @($metadata.packages | Where-Object { $_.name -eq "q-periapt-ffi" })
if ($ffiPackage.Count -ne 1 -or $ffiPackage[0].version -ne $Version) {
    throw "q-periapt-ffi package version must be $Version"
}

$targetRoot = [System.IO.Path]::GetFullPath((Join-Path $Root "target")) + [System.IO.Path]::DirectorySeparatorChar
foreach ($path in @($OutRoot, $DynamicTarget, $StaticTarget)) {
    $full = [System.IO.Path]::GetFullPath($path)
    if (-not $full.StartsWith($targetRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "refusing to mutate a path outside target: $full"
    }
    if (Test-Path -LiteralPath $full) {
        Remove-Item -LiteralPath $full -Recurse -Force
    }
}
New-Item -ItemType Directory -Path $PackageRoot -Force | Out-Null

$generatedHeader = Join-Path $OutRoot "q_periapt.generated.h"
Invoke-Checked -FilePath "cbindgen.exe" -Arguments @(
    "--config", "crates/q-periapt-ffi/cbindgen.toml",
    "--crate", "q-periapt-ffi",
    "--output", $generatedHeader
)
if (
    (Get-FileHash -LiteralPath $generatedHeader -Algorithm SHA256).Hash -ne
    (Get-FileHash -LiteralPath $Header -Algorithm SHA256).Hash
) {
    throw "generated C header differs from the checked-in ABI2 header"
}
Assert-SourceSnapshot -ExpectedCommit $GitCommit -ExpectedTree $GitTree

$savedCargoTarget = $env:CARGO_TARGET_DIR
$savedRustFlags = $env:RUSTFLAGS
$savedCargoIncremental = $env:CARGO_INCREMENTAL
$savedCc = $env:CC
$savedCFlags = $env:CFLAGS
$savedAr = $env:AR
$savedCargoTermColor = $env:CARGO_TERM_COLOR
$targetCompilerEnvironment = @{
    "AR_x86_64-pc-windows-msvc" = $LlvmAr
    "AR_x86_64_pc_windows_msvc" = $LlvmAr
    "CC_x86_64-pc-windows-msvc" = $Cl
    "CC_x86_64_pc_windows_msvc" = $Cl
}
$savedTargetCompilerEnvironment = @{}
foreach ($name in $targetCompilerEnvironment.Keys) {
    $savedTargetCompilerEnvironment[$name] =
        [System.Environment]::GetEnvironmentVariable($name, "Process")
}
try {
    $env:RUSTFLAGS = "-D warnings"
    $env:CARGO_INCREMENTAL = "0"
    $env:CARGO_TERM_COLOR = "never"
    $env:CC = $Cl
    $env:CFLAGS = "/experimental:deterministic /pathmap:$Root=qperiapt-source"
    $env:AR = $LlvmAr
    foreach ($name in $targetCompilerEnvironment.Keys) {
        [System.Environment]::SetEnvironmentVariable(
            $name,
            $targetCompilerEnvironment[$name],
            "Process"
        )
    }
    $env:CARGO_TARGET_DIR = $DynamicTarget
    $linkArgumentsLog = Join-Path $OutRoot "dynamic-link-arguments.txt"
    Invoke-Checked -FilePath "cargo.exe" -Arguments @(
        "rustc", "-p", "q-periapt-ffi", "--release", "--locked", "--crate-type", "cdylib", "--",
        "--print", "link-args=$linkArgumentsLog", "-Cstrip=debuginfo",
        "-Clink-arg=/Brepro", "-Clink-arg=/WX",
        "-Clink-arg=/DEBUG:NONE", "-Clink-arg=/OPT:REF,NOICF",
        "-Dlinker-messages",
        "--remap-path-prefix=$Root=qperiapt-source"
    )
    Invoke-PythonChecked -Arguments @(
        "artifact/windows_package.py", "verify-linker-invocation",
        "--link-arguments", $linkArgumentsLog,
        "--expected-linker", $Linker
    )
    $env:CARGO_TARGET_DIR = $StaticTarget
    $staticBuild = Invoke-Captured -FilePath "cargo.exe" -Arguments @(
        "rustc", "-p", "q-periapt-ffi", "--release", "--locked", "--crate-type", "staticlib", "--",
        "--print", "native-static-libs", "-Cstrip=debuginfo", "--remap-path-prefix=$Root=qperiapt-source"
    ) -Echo
    $nativeStaticLibrariesLog = Join-Path $OutRoot "native-static-libraries.txt"
    Write-Utf8File `
        -Path $nativeStaticLibrariesLog `
        -Content ($staticBuild.Stdout + "`n" + $staticBuild.Stderr)
    $nativeLibrariesJson = Get-TrimmedOutput -FilePath $Python -Arguments @(
        "-I", "-S", "-B", "-W", "error", "artifact/python_bootstrap.py",
        "artifact/windows_package.py", "parse-native-static-libraries",
        "--compiler-output", $nativeStaticLibrariesLog
    )
    $decodedNativeStaticLibraries = ConvertFrom-Json `
        -InputObject $nativeLibrariesJson `
        -NoEnumerate
    if ($decodedNativeStaticLibraries -isnot [System.Array]) {
        throw "Python verifier must emit a JSON array of native static libraries"
    }
    $expectedNativeStaticLibraries = [string[]] @(
        "kernel32.lib",
        "ntdll.lib",
        "userenv.lib",
        "ws2_32.lib",
        "dbghelp.lib",
        "msvcrt.lib"
    )
    if ($decodedNativeStaticLibraries.Count -ne $expectedNativeStaticLibraries.Count) {
        throw "Python verifier emitted an unexpected native static library count"
    }
    for ($index = 0; $index -lt $expectedNativeStaticLibraries.Count; $index++) {
        $library = $decodedNativeStaticLibraries[$index]
        if ($library -isnot [string]) {
            throw "Python verifier emitted a non-string native static library"
        }
        if (-not [string]::Equals(
            $library,
            $expectedNativeStaticLibraries[$index],
            [System.StringComparison]::Ordinal
        )) {
            throw "Python verifier emitted an unexpected native static library"
        }
    }
    $NativeStaticLibraries = [string[]] $decodedNativeStaticLibraries
}
finally {
    $env:CARGO_TARGET_DIR = $savedCargoTarget
    $env:RUSTFLAGS = $savedRustFlags
    $env:CARGO_INCREMENTAL = $savedCargoIncremental
    $env:CC = $savedCc
    $env:CFLAGS = $savedCFlags
    $env:AR = $savedAr
    $env:CARGO_TERM_COLOR = $savedCargoTermColor
    foreach ($name in $savedTargetCompilerEnvironment.Keys) {
        [System.Environment]::SetEnvironmentVariable(
            $name,
            $savedTargetCompilerEnvironment[$name],
            "Process"
        )
    }
}
Assert-SourceSnapshot -ExpectedCommit $GitCommit -ExpectedTree $GitTree

$dynamicDll = Join-Path $DynamicTarget "release/q_periapt_ffi_abi2.dll"
$dynamicImport = Join-Path $DynamicTarget "release/q_periapt_ffi_abi2.dll.lib"
$staticLibrary = Join-Path $StaticTarget "release/q_periapt_ffi_abi2.lib"
foreach ($path in @($dynamicDll, $dynamicImport, $staticLibrary)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "expected Rust Windows build output is missing: $path"
    }
}
$unexpectedPdbs = @(
    Get-ChildItem `
        -LiteralPath (Join-Path $DynamicTarget "release") `
        -Filter "q_periapt_ffi_abi2*.pdb" `
        -File `
        -Recurse `
        -Force `
        -ErrorAction Stop
)
if ($unexpectedPdbs.Count -ne 0) {
    throw "Windows release DLL build unexpectedly generated a q_periapt_ffi_abi2 PDB"
}

$directories = @(
    "bin", "include/qperiapt/abi2", "lib", "lib/cmake/QPeriaptABI2",
    "share/q-periapt/abi", "share/q-periapt/bom", "LICENSES",
    "THIRD_PARTY/mlkem-native"
)
foreach ($relative in $directories) {
    New-Item -ItemType Directory -Path (Join-Path $PackageRoot $relative) -Force | Out-Null
}
Copy-Item -LiteralPath $dynamicDll -Destination (Join-Path $PackageRoot "bin/q_periapt_ffi_abi2.dll")
Copy-Item -LiteralPath $dynamicImport -Destination (Join-Path $PackageRoot "lib/q_periapt_ffi_abi2.lib")
Copy-Item -LiteralPath $staticLibrary -Destination (Join-Path $PackageRoot "lib/q_periapt_ffi_abi2_static.lib")
Copy-Item -LiteralPath $Header -Destination (Join-Path $PackageRoot "include/qperiapt/abi2/q_periapt.h")
Copy-Item -LiteralPath $Fixture -Destination (Join-Path $PackageRoot "include/qperiapt/abi2/signed_policy_fixture.h")
Copy-Item -LiteralPath $Contract -Destination (Join-Path $PackageRoot "share/q-periapt/abi/q-periapt-c-abi-v2.json")
Copy-Item -LiteralPath $Smoke -Destination (Join-Path $PackageRoot "share/q-periapt/smoke.c")
Copy-Item -LiteralPath (Join-Path $Root "LICENSE") -Destination (Join-Path $PackageRoot "LICENSE")
Copy-Item -LiteralPath (Join-Path $Root "LICENSES/Apache-2.0.txt") -Destination (Join-Path $PackageRoot "LICENSES/Apache-2.0.txt")
Copy-Item -LiteralPath (Join-Path $Root "LICENSES/MIT.txt") -Destination (Join-Path $PackageRoot "LICENSES/MIT.txt")
foreach ($name in @("INVENTORY.sha256", "LICENSE-INVENTORY.md", "LICENSE.mlkem-native", "PROVENANCE.md")) {
    Copy-Item -LiteralPath (Join-Path $Root "crates/q-periapt-mlkem-native-sys/vendor/$name") -Destination (Join-Path $PackageRoot "THIRD_PARTY/mlkem-native/$name")
}
$savedBomRustFlags = $env:RUSTFLAGS
$savedBomCargoIncremental = $env:CARGO_INCREMENTAL
try {
    $env:RUSTFLAGS = "-D warnings"
    $env:CARGO_INCREMENTAL = "0"
    Invoke-Checked -FilePath "cargo.exe" -Arguments @(
        "run", "--locked", "--quiet", "-p", "q-periapt-cli", "--bin", "qperiapt", "--",
        "cbom", "--out", (Join-Path $PackageRoot "share/q-periapt/bom/cbom.cdx.json")
    )
    Invoke-Checked -FilePath "cargo.exe" -Arguments @(
        "run", "--locked", "--quiet", "-p", "q-periapt-cli", "--bin", "qperiapt", "--",
        "sbom", "--lock", "Cargo.lock", "--out", (Join-Path $PackageRoot "share/q-periapt/bom/sbom.cdx.json")
    )
}
finally {
    $env:RUSTFLAGS = $savedBomRustFlags
    $env:CARGO_INCREMENTAL = $savedBomCargoIncremental
}
Invoke-PythonChecked -Arguments @(
    "artifact/third_party_licenses.py", "create",
    "--root", $Root,
    "--package-root", $PackageRoot,
    "--target", $Target
)

$nativeCmake = ($NativeStaticLibraries | ForEach-Object { '"' + $_ + '"' }) -join " "
$configTemplate = @'
include_guard(GLOBAL)
if(NOT DEFINED QPeriaptABI2_FIND_VERSION OR
   NOT QPeriaptABI2_FIND_VERSION VERSION_EQUAL "2.0.0" OR
   NOT QPeriaptABI2_FIND_VERSION_EXACT)
  message(FATAL_ERROR "QPeriaptABI2 must be requested as find_package(QPeriaptABI2 2.0.0 EXACT CONFIG REQUIRED)")
endif()
get_filename_component(_QPERIAPT_ABI2_PREFIX "${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)
set(QPeriaptABI2_VERSION "2.0.0")
set(QPeriaptABI2_ABI_MAJOR "2")
set(QPeriaptABI2_RELEASE_VERSION "@VERSION@")
set(QPeriaptABI2_INCLUDE_DIR "${_QPERIAPT_ABI2_PREFIX}/include/qperiapt/abi2")
set(QPeriaptABI2_LIBRARY "${_QPERIAPT_ABI2_PREFIX}/bin/q_periapt_ffi_abi2.dll")
set(QPeriaptABI2_IMPORT_LIBRARY "${_QPERIAPT_ABI2_PREFIX}/lib/q_periapt_ffi_abi2.lib")
set(QPeriaptABI2_STATIC_LIBRARY "${_QPERIAPT_ABI2_PREFIX}/lib/q_periapt_ffi_abi2_static.lib")
set(_QPERIAPT_ABI2_STATIC_NATIVE_LIBS @NATIVE_LIBS@)
foreach(_required IN ITEMS
    "${QPeriaptABI2_INCLUDE_DIR}/q_periapt.h"
    "${QPeriaptABI2_LIBRARY}"
    "${QPeriaptABI2_IMPORT_LIBRARY}"
    "${QPeriaptABI2_STATIC_LIBRARY}")
  if(NOT EXISTS "${_required}")
    message(FATAL_ERROR "QPeriapt ABI2 package file is missing: ${_required}")
  endif()
endforeach()
if(NOT TARGET QPeriaptABI2::qperiapt)
  add_library(QPeriaptABI2::qperiapt SHARED IMPORTED)
  set_target_properties(QPeriaptABI2::qperiapt PROPERTIES
    IMPORTED_LOCATION "${QPeriaptABI2_LIBRARY}"
    IMPORTED_IMPLIB "${QPeriaptABI2_IMPORT_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${QPeriaptABI2_INCLUDE_DIR}")
endif()
if(NOT TARGET QPeriaptABI2::qperiapt_static)
  add_library(QPeriaptABI2::qperiapt_static STATIC IMPORTED)
  set_target_properties(QPeriaptABI2::qperiapt_static PROPERTIES
    IMPORTED_LOCATION "${QPeriaptABI2_STATIC_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${QPeriaptABI2_INCLUDE_DIR}")
  set_property(TARGET QPeriaptABI2::qperiapt_static APPEND PROPERTY
    INTERFACE_LINK_LIBRARIES ${_QPERIAPT_ABI2_STATIC_NATIVE_LIBS})
endif()
'@
$config = $configTemplate.Replace("@VERSION@", $Version).Replace("@NATIVE_LIBS@", $nativeCmake)
Write-Utf8File -Path (Join-Path $PackageRoot "lib/cmake/QPeriaptABI2/QPeriaptABI2Config.cmake") -Content $config
Write-Utf8File -Path (Join-Path $PackageRoot "lib/cmake/QPeriaptABI2/QPeriaptABI2ConfigVersion.cmake") -Content @'
set(PACKAGE_VERSION "2.0.0")
if(PACKAGE_FIND_VERSION VERSION_EQUAL PACKAGE_VERSION)
  set(PACKAGE_VERSION_EXACT TRUE)
  set(PACKAGE_VERSION_COMPATIBLE TRUE)
else()
  set(PACKAGE_VERSION_COMPATIBLE FALSE)
  set(PACKAGE_VERSION_UNSUITABLE TRUE)
endif()
'@
$readmeTemplate = @'
# Q-Periapt C ABI 2 — @VERSION@ (x86_64-pc-windows-msvc)

This research-alpha SDK supports Windows x64 with the MSVC ABI. It includes the
ABI2 DLL, its import library, a separate static library, headers, CMake config,
the frozen ABI contract, SBOM/CBOM, third-party notices, and checksums.

The DLL is intentionally marked **unsigned experimental prerelease** because no
trusted Windows Authenticode credential was available. Do not confuse the
GitHub immutable-release/artifact attestations with Authenticode trust.

Use `find_package(QPeriaptABI2 2.0.0 EXACT CONFIG REQUIRED)` and link either
`QPeriaptABI2::qperiapt` or `QPeriaptABI2::qperiapt_static`.
'@
Write-Utf8File -Path (Join-Path $PackageRoot "README.md") -Content $readmeTemplate.Replace("@VERSION@", $Version)

$packagedDll = Join-Path $PackageRoot "bin/q_periapt_ffi_abi2.dll"
Assert-ImportLibrary `
    -ImportLibrary (Join-Path $PackageRoot "lib/q_periapt_ffi_abi2.lib") `
    -Dumpbin $Dumpbin
Invoke-PythonChecked -Arguments @(
    "artifact/c_abi_contract.py",
    "--contract", (Join-Path $PackageRoot "share/q-periapt/abi/q-periapt-c-abi-v2.json"),
    "--header", (Join-Path $PackageRoot "include/qperiapt/abi2/q_periapt.h"),
    "--library", $packagedDll,
    "--static-library", (Join-Path $PackageRoot "lib/q_periapt_ffi_abi2_static.lib"),
    "--llvm-nm", $LlvmNm,
    "--platform", "windows"
)
$clVersionResult = Invoke-Captured -FilePath $Python -Arguments @(
    "-I", "-S", "-B", "-W", "error", "artifact/python_bootstrap.py",
    "artifact/windows_package.py", "inspect-msvc-version",
    "--cl", $Cl,
    "--probe", $MsvcVersionProbe
)
if ($clVersionResult.Stderr.Length -ne 0) {
    throw "MSVC compiler version inspector emitted diagnostics"
}
$clVersion = $clVersionResult.Stdout.Trim()
if ($clVersion -cnotmatch '^MSVC [1-9][0-9]\.[0-9]{2}\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,9})$') {
    throw "MSVC compiler version inspector returned a malformed contract"
}
Assert-SourceSnapshot -ExpectedCommit $GitCommit -ExpectedTree $GitTree
$ManifestRustcVersion = Get-TrimmedOutput -FilePath "rustc.exe" -Arguments @("--version")
$ManifestCargoVersion = Get-TrimmedOutput -FilePath "cargo.exe" -Arguments @("--version")
if ($ManifestRustcVersion -cne $RustcVersion -or $ManifestCargoVersion -cne $CargoVersion) {
    throw "Windows Rust toolchain changed during release package construction"
}
$manifestArguments = @(
    "artifact/windows_package.py", "create",
    "--package-root", $PackageRoot,
    "--repository-root", $Root,
    "--package-name", $PackageName,
    "--version", $Version,
    "--git-commit", $GitCommit,
    "--git-tree", $GitTree,
    "--source-date-epoch", $SourceDateEpochText,
    "--rustc", $ManifestRustcVersion,
    "--cargo", $ManifestCargoVersion,
    "--cl", $clVersion,
    "--dumpbin", $Dumpbin
)
Invoke-PythonChecked -Arguments $manifestArguments
Assert-SourceSnapshot -ExpectedCommit $GitCommit -ExpectedTree $GitTree

Invoke-PythonChecked -Arguments @(
    "artifact/deterministic_archive.py", "create-zip",
    "--source", $PackageRoot,
    "--output", $DefaultArchive,
    "--root", $PackageName,
    "--mtime", $SourceDateEpochText
)
$builtArchiveSha256 = (Get-FileHash -LiteralPath $DefaultArchive -Algorithm SHA256).Hash.ToLowerInvariant()
Verify-WindowsArchive `
    -ArchivePath $DefaultArchive `
    -ExpectedArchiveSha256 $builtArchiveSha256 `
    -Cl $Cl `
    -LlvmNm $LlvmNm `
    -Dumpbin $Dumpbin `
    -NativeStaticLibraries $NativeStaticLibraries `
    -TrustedGitCommit $GitCommit `
    -TrustedGitTree $GitTree
Assert-SourceSnapshot -ExpectedCommit $GitCommit -ExpectedTree $GitTree
Write-Host "WINDOWS_C_ABI_PACKAGE_ARCHIVE=$DefaultArchive"
Write-Host "WINDOWS_C_ABI_PACKAGE_PASS"
