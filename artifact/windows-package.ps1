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

function Initialize-MsvcEnvironment {
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
    $environmentLines = & $env:ComSpec /d /s /c "`"$vcvars`" >nul && set"
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
    foreach ($tool in @("cl.exe", "dumpbin.exe", "cmake.exe", "ctest.exe")) {
        [void] (Get-Command $tool -ErrorAction Stop)
    }
    return $installation
}

function Get-NativeStaticLibraries {
    param([Parameter(Mandatory)] [string] $CompilerOutput)

    $matches = [regex]::Matches(
        $CompilerOutput,
        '(?m)^\s*(?:note:\s*)?native-static-libs:\s*(?<libraries>[^\r\n]+)\s*$'
    )
    if ($matches.Count -ne 1) {
        throw "rustc must emit exactly one native-static-libs line; got $($matches.Count)"
    }
    $libraries = [System.Collections.Generic.List[string]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    foreach ($token in ($matches[0].Groups["libraries"].Value -split '\s+')) {
        if (-not $token) { continue }
        $match = [regex]::Match($token, '^-l(?:dylib=)?(?<name>[A-Za-z0-9_.-]+)$')
        if (-not $match.Success) {
            throw "unsupported native-static-libs token: $token"
        }
        $library = $match.Groups["name"].Value
        if (-not $library.EndsWith(".lib", [System.StringComparison]::OrdinalIgnoreCase)) {
            $library += ".lib"
        }
        if (-not $seen.Add($library)) {
            throw "duplicate native static library emitted by rustc: $library"
        }
        $libraries.Add($library)
    }
    if ($libraries.Count -eq 0) {
        throw "rustc emitted an empty native-static-libs set"
    }
    return [string[]] $libraries
}

function Assert-PeHardening {
    param(
        [Parameter(Mandatory)] [string] $Library,
        [Parameter(Mandatory)] [string] $Dumpbin
    )

    $headers = (Invoke-Captured -FilePath $Dumpbin -Arguments @("/nologo", "/headers", $Library)).Stdout
    $requirements = @{
        "x64 PE machine" = '(?im)^\s*8664\s+machine\s+\(x64\)\s*$'
        "dynamic base" = '(?im)^\s*Dynamic base\s*$'
        "NX compatible" = '(?im)^\s*NX compatible\s*$'
        "high entropy VA" = '(?im)^\s*High Entropy Virtual Addresses\s*$'
    }
    foreach ($entry in $requirements.GetEnumerator()) {
        if (-not [regex]::IsMatch($headers, $entry.Value)) {
            throw "PE hardening check failed ($($entry.Key)): $Library"
        }
    }
    $debugDirectory = [regex]::Matches(
        $headers,
        '(?im)^\s*(?<rva>[0-9A-F]+)\s+\[\s*(?<size>[0-9A-F]+)\]\s+RVA\s+\[size\]\s+of Debug Directory\s*$'
    )
    if ($debugDirectory.Count -ne 1) {
        throw "dumpbin must report exactly one debug-directory data entry"
    }
    if (
        [Convert]::ToUInt64($debugDirectory[0].Groups["rva"].Value, 16) -ne 0 -or
        [Convert]::ToUInt64($debugDirectory[0].Groups["size"].Value, 16) -ne 0
    ) {
        throw "release DLL contains a PE debug directory: $Library"
    }
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
    Assert-PeHardening -Library $dll -Dumpbin $Dumpbin
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
    Invoke-Checked -FilePath "cl.exe" -Arguments @(
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
    Invoke-Checked -FilePath "cl.exe" -Arguments $staticArguments
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
        -LlvmNm $LlvmNm `
        -Dumpbin $Dumpbin `
        -NativeStaticLibraries $NativeStaticLibraries `
        -TrustedGitCommit $TrustedGitCommit `
        -TrustedGitTree $TrustedGitTree)
    Write-Host "WINDOWS_C_ABI_PACKAGE_VERIFY_PASS"
}

$MsvcInstallation = Initialize-MsvcEnvironment
$Dumpbin = Resolve-TrustedToolchainFile `
    -Path (Get-Command "dumpbin.exe" -CommandType Application -ErrorAction Stop).Source `
    -TrustedRoot $MsvcInstallation `
    -ExpectedName "dumpbin.exe"
$RustSysroot = Get-TrimmedOutput -FilePath "rustc.exe" -Arguments @("--print", "sysroot")
$RustHostOutput = Get-TrimmedOutput -FilePath "rustc.exe" -Arguments @("-vV")
$RustHostMatch = [regex]::Match($RustHostOutput, '(?m)^host:\s*(?<host>\S+)\s*$')
if (-not $RustHostMatch.Success) {
    throw "cannot determine the Rust host triple"
}
$LlvmNm = Join-Path $RustSysroot "lib/rustlib/$($RustHostMatch.Groups['host'].Value)/bin/llvm-nm.exe"
if (-not (Test-Path -LiteralPath $LlvmNm -PathType Leaf)) {
    throw "matching Rust llvm-nm.exe is unavailable: $LlvmNm"
}

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
$savedCFlags = $env:CFLAGS
try {
    $env:CFLAGS = "/pathmap:$Root=qperiapt-source"
    $env:CARGO_TARGET_DIR = $DynamicTarget
    Invoke-Checked -FilePath "cargo.exe" -Arguments @(
        "rustc", "-p", "q-periapt-ffi", "--release", "--locked", "--crate-type", "cdylib", "--",
        "-Cstrip=debuginfo", "-Clink-arg=/Brepro", "--remap-path-prefix=$Root=qperiapt-source"
    )
    $env:CARGO_TARGET_DIR = $StaticTarget
    $staticBuild = Invoke-Captured -FilePath "cargo.exe" -Arguments @(
        "rustc", "-p", "q-periapt-ffi", "--release", "--locked", "--crate-type", "staticlib", "--",
        "--print", "native-static-libs", "-Cstrip=debuginfo", "--remap-path-prefix=$Root=qperiapt-source"
    ) -Echo
    $NativeStaticLibraries = @(
        Get-NativeStaticLibraries -CompilerOutput ($staticBuild.Stdout + "`n" + $staticBuild.Stderr)
    )
}
finally {
    $env:CARGO_TARGET_DIR = $savedCargoTarget
    $env:CFLAGS = $savedCFlags
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
Invoke-Checked -FilePath "cargo.exe" -Arguments @(
    "run", "--locked", "--quiet", "-p", "q-periapt-cli", "--bin", "qperiapt", "--",
    "cbom", "--out", (Join-Path $PackageRoot "share/q-periapt/bom/cbom.cdx.json")
)
Invoke-Checked -FilePath "cargo.exe" -Arguments @(
    "run", "--locked", "--quiet", "-p", "q-periapt-cli", "--bin", "qperiapt", "--",
    "sbom", "--lock", "Cargo.lock", "--out", (Join-Path $PackageRoot "share/q-periapt/bom/sbom.cdx.json")
)
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
Assert-PeHardening -Library $packagedDll -Dumpbin $Dumpbin
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
$clHelp = (Invoke-Captured -FilePath "cl.exe" -Arguments @("/?")).Stdout
$clVersionLines = @(
    $clHelp -split "`r?`n" | Where-Object { $_ -match 'Microsoft.*Compiler' }
)
if ($clVersionLines.Count -ne 1) {
    throw "cl.exe must emit exactly one compiler-version line"
}
$clVersion = $clVersionLines[0].Trim()
if (-not $clVersion) { throw "MSVC compiler version is empty" }
Assert-SourceSnapshot -ExpectedCommit $GitCommit -ExpectedTree $GitTree
$manifestArguments = @(
    "artifact/windows_package.py", "create",
    "--package-root", $PackageRoot,
    "--repository-root", $Root,
    "--package-name", $PackageName,
    "--version", $Version,
    "--git-commit", $GitCommit,
    "--git-tree", $GitTree,
    "--source-date-epoch", $SourceDateEpochText,
    "--rustc", (Get-TrimmedOutput -FilePath "rustc.exe" -Arguments @("--version")),
    "--cargo", (Get-TrimmedOutput -FilePath "cargo.exe" -Arguments @("--version")),
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
    -LlvmNm $LlvmNm `
    -Dumpbin $Dumpbin `
    -NativeStaticLibraries $NativeStaticLibraries `
    -TrustedGitCommit $GitCommit `
    -TrustedGitTree $GitTree
Assert-SourceSnapshot -ExpectedCommit $GitCommit -ExpectedTree $GitTree
Write-Host "WINDOWS_C_ABI_PACKAGE_ARCHIVE=$DefaultArchive"
Write-Host "WINDOWS_C_ABI_PACKAGE_PASS"
