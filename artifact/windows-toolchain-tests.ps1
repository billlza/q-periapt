#!/usr/bin/env pwsh
# Exercise the production MSVC x64 tool resolver against controlled paths.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not $IsWindows) {
    throw "Windows MSVC toolchain resolver tests require Windows"
}

$Root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$Python = (Get-Command python -ErrorAction Stop).Source
$ProductionScript = Join-Path $PSScriptRoot "windows-package.ps1"
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $ProductionScript,
    [ref] $tokens,
    [ref] $parseErrors
)
if ($parseErrors.Count -ne 0) {
    throw "cannot parse the production Windows package script"
}

foreach ($functionName in @(
    "Invoke-Captured",
    "Invoke-Checked",
    "Invoke-PythonChecked",
    "Assert-TrustedBuildEnvironment",
    "Resolve-CargoHome",
    "Assert-NoAmbientCargoConfiguration",
    "New-EncodedReleaseRustFlags",
    "Resolve-TrustedToolchainFile",
    "Resolve-TrustedCommandProcessor",
    "Resolve-TrustedMsvcX64Tools",
    "Resolve-TrustedRustLlvmTools",
    "Assert-TrustedMsvcPath",
    "Set-TrustedMsvcPath",
    "Assert-BareMsvcLinkerSearchBoundary",
    "Get-TrustedMsvcLinkerFingerprint",
    "Assert-MsvcLinkerFingerprintUnchanged"
)) {
    $definitions = @($ast.FindAll(
        {
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -ceq $functionName
        },
        $true
    ))
    if ($definitions.Count -ne 1) {
        throw "production resolver function count differs: $functionName"
    }
    Invoke-Expression $definitions[0].Extent.Text
}

function Write-FixtureTool {
    param([Parameter(Mandatory)] [string] $Path)

    $parent = [System.IO.Path]::GetDirectoryName($Path)
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    [System.IO.File]::WriteAllBytes($Path, [byte[]] @(0))
}

function Assert-Fails {
    param(
        [Parameter(Mandatory)] [scriptblock] $Action,
        [Parameter(Mandatory)] [string] $Label,
        [Parameter(Mandatory)] [string] $ExpectedMessage
    )

    $failed = $false
    try {
        [void] (& $Action)
    }
    catch {
        $failed = $true
        if (-not $_.Exception.Message.Contains(
            $ExpectedMessage,
            [System.StringComparison]::Ordinal
        )) {
            throw "negative resolver case failed for the wrong reason: $Label"
        }
    }
    if (-not $failed) {
        throw "negative resolver case unexpectedly passed: $Label"
    }
}

function Assert-RejectsEnvironmentOverride {
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [string] $Value
    )

    $saved = [System.Environment]::GetEnvironmentVariable($Name, "Process")
    try {
        [System.Environment]::SetEnvironmentVariable($Name, $Value, "Process")
        Assert-Fails `
            -Label "environment override $Name" `
            -ExpectedMessage $Name `
            -Action {
            Assert-TrustedBuildEnvironment
        }
    }
    finally {
        [System.Environment]::SetEnvironmentVariable($Name, $saved, "Process")
    }
}

function Assert-ResolvedTools {
    param(
        [Parameter(Mandatory)] [pscustomobject] $Tools,
        [Parameter(Mandatory)] [string] $Bin
    )

    $expected = @{
        Cl = "cl.exe"
        Dumpbin = "dumpbin.exe"
        Linker = "link.exe"
    }
    if (-not $Tools.Bin.Equals(
        [System.IO.Path]::GetFullPath($Bin),
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw "resolved MSVC bin directory differs"
    }
    foreach ($entry in $expected.GetEnumerator()) {
        $actual = $Tools.($entry.Key)
        $expectedPath = [System.IO.Path]::GetFullPath(
            (Join-Path $Bin $entry.Value)
        )
        if (-not $actual.Equals(
            $expectedPath,
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
            throw "resolved MSVC tool differs: $($entry.Key)"
        }
    }
}

$TargetRoot = [System.IO.Path]::GetFullPath((Join-Path $Root "target"))
New-Item -ItemType Directory -Path $TargetRoot -Force | Out-Null
$TestRoot = Join-Path $TargetRoot (
    "windows-toolchain-tests-" + [System.Guid]::NewGuid().ToString("N")
)
$savedHostArch = $env:VSCMD_ARG_HOST_ARCH
$savedTargetArch = $env:VSCMD_ARG_TGT_ARCH
$savedVsInstall = $env:VSINSTALLDIR
$savedVcInstall = $env:VCINSTALLDIR
$savedToolsInstall = $env:VCToolsInstallDir
$savedPath = $env:PATH
$savedComSpec = $env:ComSpec
$savedRustFlags = $env:RUSTFLAGS
$savedCargoEncodedRustFlags = $env:CARGO_ENCODED_RUSTFLAGS
$savedCargoIncremental = $env:CARGO_INCREMENTAL
$savedCargoHome = $env:CARGO_HOME
$savedUserProfile = $env:USERPROFILE
$savedHome = $env:HOME

try {
    $env:RUSTFLAGS = "-D warnings"
    $env:CARGO_INCREMENTAL = "0"
    Assert-TrustedBuildEnvironment
    foreach ($name in @(
        "CL",
        "_CL_",
        "LINK",
        "_LINK_",
        "RUSTC",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "CARGO_BUILD_RUSTC",
        "CARGO_BUILD_RUSTC_WRAPPER",
        "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
        "CARGO_BUILD_INCREMENTAL",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_AR",
        "CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER",
        "CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS",
        "AR_x86_64-pc-windows-msvc",
        "AR_x86_64_pc_windows_msvc",
        "ARFLAGS_x86_64-pc-windows-msvc",
        "RANLIB_x86_64-pc-windows-msvc",
        "CC_x86_64-pc-windows-msvc",
        "CARGO_PROFILE_RELEASE_LTO",
        "CMAKE_C_COMPILER_LAUNCHER",
        "CMAKE_C_LINKER_LAUNCHER",
        "CMAKE_CROSSCOMPILING_EMULATOR",
        "CMAKE_PROJECT_INCLUDE",
        "CMAKE_TEST_LAUNCHER",
        "QPeriaptABI2_ROOT",
        "GIT_DIR"
    )) {
        Assert-RejectsEnvironmentOverride -Name $name -Value "untrusted"
    }
    Assert-RejectsEnvironmentOverride -Name "RUSTFLAGS" -Value "-A warnings"
    Assert-RejectsEnvironmentOverride -Name "CARGO_INCREMENTAL" -Value "1"

    New-Item -ItemType Directory -Path $TestRoot | Out-Null
    $redactedRoot = Join-Path $TestRoot "private-producer-root-sentinel"
    New-Item -ItemType Directory -Path $redactedRoot | Out-Null
    $redactedSentinel = [System.IO.Path]::GetFullPath($redactedRoot)
    $redactedSuccessFixture = Join-Path $redactedRoot "success.bin"
    [System.IO.File]::WriteAllBytes(
        $redactedSuccessFixture,
        [System.Text.Encoding]::UTF8.GetBytes("safe payload")
    )
    $originalConsoleOut = [Console]::Out
    $originalConsoleError = [Console]::Error
    $successConsoleOut = [System.IO.StringWriter]::new()
    $successConsoleError = [System.IO.StringWriter]::new()
    try {
        [Console]::SetOut($successConsoleOut)
        [Console]::SetError($successConsoleError)
        Invoke-PythonChecked `
            -Arguments @(
                "artifact/release_binary_scan.py",
                $redactedSuccessFixture,
                "--forbid-text",
                $redactedSentinel
            ) `
            -RedactArguments
    }
    finally {
        [Console]::SetOut($originalConsoleOut)
        [Console]::SetError($originalConsoleError)
    }
    $successConsoleText = $successConsoleOut.ToString() +
        $successConsoleError.ToString()
    $successConsoleOut.Dispose()
    $successConsoleError.Dispose()
    if ($successConsoleText.Length -ne 0) {
        throw "redacted successful scanner invocation emitted output"
    }

    $redactedScanFixture = Join-Path $redactedRoot "failure.bin"
    [System.IO.File]::WriteAllText(
        $redactedScanFixture,
        "prefix$redactedSentinel`nsuffix",
        [System.Text.UTF8Encoding]::new($false)
    )
    $redactedFailureObserved = $false
    $failureConsoleOut = [System.IO.StringWriter]::new()
    $failureConsoleError = [System.IO.StringWriter]::new()
    try {
        [Console]::SetOut($failureConsoleOut)
        [Console]::SetError($failureConsoleError)
        try {
            Invoke-PythonChecked `
                -Arguments @(
                    "artifact/release_binary_scan.py",
                    $redactedScanFixture,
                    "--forbid-text",
                    $redactedSentinel
                ) `
                -RedactArguments
        }
        catch {
            $redactedFailureObserved = $true
            if (-not $_.Exception.Message.Contains(
                "<redacted invocation and output>",
                [System.StringComparison]::Ordinal
            )) {
                throw "redacted scanner failure omitted its redaction marker"
            }
            if ($_.Exception.Message.Contains(
                $redactedSentinel,
                [System.StringComparison]::Ordinal
            )) {
                throw "redacted scanner failure disclosed a forbidden root"
            }
        }
    }
    finally {
        [Console]::SetOut($originalConsoleOut)
        [Console]::SetError($originalConsoleError)
    }
    $failureConsoleText = $failureConsoleOut.ToString() +
        $failureConsoleError.ToString()
    $failureConsoleOut.Dispose()
    $failureConsoleError.Dispose()
    if (-not $redactedFailureObserved) {
        throw "redacted scanner failure fixture unexpectedly passed"
    }
    if ($failureConsoleText.Length -ne 0) {
        throw "redacted failing scanner invocation emitted output"
    }

    $missingExecutable = Join-Path $redactedRoot "missing-executable.exe"
    $startFailureConsoleOut = [System.IO.StringWriter]::new()
    $startFailureConsoleError = [System.IO.StringWriter]::new()
    $redactedStartFailureObserved = $false
    try {
        [Console]::SetOut($startFailureConsoleOut)
        [Console]::SetError($startFailureConsoleError)
        try {
            [void] (Invoke-Captured `
                -FilePath $missingExecutable `
                -Arguments @($redactedSentinel) `
                -Echo `
                -RedactArguments)
        }
        catch {
            $redactedStartFailureObserved = $true
            if (-not $_.Exception.Message.Contains(
                "<redacted invocation and output>",
                [System.StringComparison]::Ordinal
            )) {
                throw "redacted start failure omitted its redaction marker"
            }
            if ($_.Exception.Message.Contains(
                $redactedSentinel,
                [System.StringComparison]::Ordinal
            )) {
                throw "redacted start failure disclosed a forbidden root"
            }
        }
    }
    finally {
        [Console]::SetOut($originalConsoleOut)
        [Console]::SetError($originalConsoleError)
    }
    $startFailureConsoleText = $startFailureConsoleOut.ToString() +
        $startFailureConsoleError.ToString()
    $startFailureConsoleOut.Dispose()
    $startFailureConsoleError.Dispose()
    if (-not $redactedStartFailureObserved) {
        throw "redacted missing-executable fixture unexpectedly passed"
    }
    if ($startFailureConsoleText.Length -ne 0) {
        throw "redacted start failure emitted output"
    }
    $rustSysroot = Join-Path $TestRoot "rust-sysroot"
    $rustHost = "x86_64-pc-windows-msvc"
    $rustBin = Join-Path $rustSysroot "lib/rustlib/$rustHost/bin"
    $llvmAr = Join-Path $rustBin "llvm-ar.exe"
    $llvmNm = Join-Path $rustBin "llvm-nm.exe"
    Write-FixtureTool -Path $llvmAr
    Write-FixtureTool -Path $llvmNm
    $rustTools = Resolve-TrustedRustLlvmTools `
        -RustSysroot $rustSysroot `
        -RustHost $rustHost
    foreach ($entry in @{
        Ar = $llvmAr
        Bin = $rustBin
        Nm = $llvmNm
    }.GetEnumerator()) {
        if (-not $rustTools.($entry.Key).Equals(
            [System.IO.Path]::GetFullPath($entry.Value),
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
            throw "resolved Rust LLVM tool differs: $($entry.Key)"
        }
    }
    Assert-Fails `
        -Label "wrong Rust host" `
        -ExpectedMessage "Rust host must be exactly" `
        -Action {
        Resolve-TrustedRustLlvmTools `
            -RustSysroot $rustSysroot `
            -RustHost "aarch64-pc-windows-msvc"
    }
    Assert-Fails `
        -Label "relative Rust sysroot" `
        -ExpectedMessage "Rust sysroot must be absolute" `
        -Action {
        Resolve-TrustedRustLlvmTools `
            -RustSysroot "relative-rust-sysroot" `
            -RustHost $rustHost
    }
    Remove-Item -LiteralPath $llvmAr
    Assert-Fails `
        -Label "missing Rust llvm-ar" `
        -ExpectedMessage "toolchain path is not a regular file" `
        -Action {
        Resolve-TrustedRustLlvmTools `
            -RustSysroot $rustSysroot `
            -RustHost $rustHost
    }
    Write-FixtureTool -Path $llvmAr

    $systemDirectory = Join-Path $TestRoot "Windows/System32"
    $commandProcessor = Join-Path $systemDirectory "cmd.exe"
    Write-FixtureTool -Path $commandProcessor
    $env:ComSpec = $commandProcessor
    $resolvedCommandProcessor = Resolve-TrustedCommandProcessor `
        -SystemDirectory $systemDirectory
    if (-not $resolvedCommandProcessor.Equals(
        [System.IO.Path]::GetFullPath($commandProcessor),
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw "resolved command processor differs"
    }
    $env:ComSpec = Join-Path $TestRoot "Outside/cmd.exe"
    Assert-Fails `
        -Label "untrusted ComSpec" `
        -ExpectedMessage "ComSpec does not identify" `
        -Action {
        Resolve-TrustedCommandProcessor -SystemDirectory $systemDirectory
    }
    $env:ComSpec = "relative-cmd.exe"
    Assert-Fails `
        -Label "relative ComSpec" `
        -ExpectedMessage "ComSpec does not identify" `
        -Action {
        Resolve-TrustedCommandProcessor -SystemDirectory $systemDirectory
    }
    $env:ComSpec = $commandProcessor

    $cargoSource = Join-Path $TestRoot "cargo-source"
    $cargoHome = Join-Path $TestRoot "cargo-home"
    New-Item -ItemType Directory -Path $cargoSource, $cargoHome | Out-Null
    $env:CARGO_HOME = $cargoHome
    $resolvedCargoHome = Resolve-CargoHome
    if (-not $resolvedCargoHome.Equals(
        [System.IO.Path]::GetFullPath($cargoHome),
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw "resolved Cargo home differs"
    }
    Assert-NoAmbientCargoConfiguration `
        -SourceRoot $cargoSource `
        -CargoHome $resolvedCargoHome

    $cargoHomeConfig = Join-Path $cargoHome "config.toml"
    Write-FixtureTool -Path $cargoHomeConfig
    Assert-Fails `
        -Label "Cargo home configuration" `
        -ExpectedMessage "rejects ambient Cargo configuration files" `
        -Action {
        Assert-NoAmbientCargoConfiguration `
            -SourceRoot $cargoSource `
            -CargoHome $resolvedCargoHome
    }
    Remove-Item -LiteralPath $cargoHomeConfig

    $sourceConfig = Join-Path $cargoSource ".cargo/config"
    Write-FixtureTool -Path $sourceConfig
    Assert-Fails `
        -Label "source ancestor Cargo configuration" `
        -ExpectedMessage "rejects ambient Cargo configuration files" `
        -Action {
        Assert-NoAmbientCargoConfiguration `
            -SourceRoot $cargoSource `
            -CargoHome $resolvedCargoHome
    }
    Remove-Item -LiteralPath (Join-Path $cargoSource ".cargo") -Recurse

    $env:CARGO_HOME = "relative-cargo-home"
    Assert-Fails `
        -Label "relative Cargo home" `
        -ExpectedMessage "Cargo home must be absolute" `
        -Action {
        Resolve-CargoHome
    }
    $env:CARGO_HOME = $cargoHome

    $fallbackHome = Join-Path $TestRoot "fallback user home"
    $fallbackCargoHome = Join-Path $fallbackHome ".cargo"
    New-Item -ItemType Directory -Path $fallbackCargoHome -Force | Out-Null
    $env:CARGO_HOME = $null
    $env:USERPROFILE = $fallbackHome
    $env:HOME = $null
    $resolvedFallbackCargoHome = Resolve-CargoHome
    if (-not $resolvedFallbackCargoHome.Equals(
        [System.IO.Path]::GetFullPath($fallbackCargoHome),
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw "USERPROFILE Cargo home fallback differs"
    }
    $env:USERPROFILE = $null
    $env:HOME = $fallbackHome
    $resolvedHomeFallbackCargoHome = Resolve-CargoHome
    if (-not $resolvedHomeFallbackCargoHome.Equals(
        [System.IO.Path]::GetFullPath($fallbackCargoHome),
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw "HOME Cargo home fallback differs"
    }
    $env:USERPROFILE = $null
    $env:HOME = $null
    Assert-Fails `
        -Label "missing Cargo and user home" `
        -ExpectedMessage "requires CARGO_HOME or a user home" `
        -Action {
        Resolve-CargoHome
    }
    $env:CARGO_HOME = $cargoHome
    $env:USERPROFILE = $savedUserProfile
    $env:HOME = $savedHome

    $remapSource = Join-Path $TestRoot "remap=source"
    $remapCargoHome = Join-Path $TestRoot "remap cargo home"
    $remapRustSysroot = Join-Path $TestRoot "remap rust sysroot"
    New-Item `
        -ItemType Directory `
        -Path $remapSource, $remapCargoHome, $remapRustSysroot `
        -Force | Out-Null
    $encodedRustFlags = New-EncodedReleaseRustFlags `
        -SourceRoot $remapSource `
        -CargoHome $remapCargoHome `
        -RustSysroot $remapRustSysroot
    $actualRustFlags = [string[]] $encodedRustFlags.Split([char] 0x1f)
    $expectedRustFlags = [System.Collections.Generic.List[string]]::new()
    [void] $expectedRustFlags.Add("-D")
    [void] $expectedRustFlags.Add("warnings")
    foreach ($mapping in @(
        @($remapSource, "qperiapt-source"),
        @($remapCargoHome, "qperiapt-cargo-home"),
        @($remapRustSysroot, "qperiapt-rust-sysroot")
    )) {
        $nativePath = [System.IO.Path]::GetFullPath($mapping[0])
        [void] $expectedRustFlags.Add(
            "--remap-path-prefix=$nativePath=$($mapping[1])"
        )
        $portablePath = $nativePath.Replace('\', '/')
        if ($portablePath -cne $nativePath) {
            [void] $expectedRustFlags.Add(
                "--remap-path-prefix=$portablePath=$($mapping[1])"
            )
        }
    }
    if ($actualRustFlags.Count -ne $expectedRustFlags.Count) {
        throw "encoded release Rust flag count differs"
    }
    for ($index = 0; $index -lt $expectedRustFlags.Count; $index++) {
        if ($actualRustFlags[$index] -cne $expectedRustFlags[$index]) {
            throw "encoded release Rust flag differs at index $index"
        }
    }
    Assert-Fails `
        -Label "relative Rust remap source" `
        -ExpectedMessage "source root must be absolute" `
        -Action {
        New-EncodedReleaseRustFlags `
            -SourceRoot "relative-source" `
            -CargoHome $remapCargoHome `
            -RustSysroot $remapRustSysroot
    }
    Assert-Fails `
        -Label "missing Rust remap Cargo home" `
        -ExpectedMessage "Cargo home must be an existing directory" `
        -Action {
        New-EncodedReleaseRustFlags `
            -SourceRoot $remapSource `
            -CargoHome (Join-Path $TestRoot "missing-cargo-home") `
            -RustSysroot $remapRustSysroot
    }
    $nestedRemapRoot = Join-Path $remapSource "nested"
    New-Item -ItemType Directory -Path $nestedRemapRoot | Out-Null
    Assert-Fails `
        -Label "overlapping Rust remap roots" `
        -ExpectedMessage "must be distinct and non-overlapping" `
        -Action {
        New-EncodedReleaseRustFlags `
            -SourceRoot $remapSource `
            -CargoHome $nestedRemapRoot `
            -RustSysroot $remapRustSysroot
    }
    Assert-Fails `
        -Label "volume Rust remap root" `
        -ExpectedMessage "cannot be a volume root" `
        -Action {
        New-EncodedReleaseRustFlags `
            -SourceRoot ([System.IO.Path]::GetPathRoot($remapSource)) `
            -CargoHome $remapCargoHome `
            -RustSysroot $remapRustSysroot
    }

    $installation = Join-Path $TestRoot "VisualStudio"
    $versionsRoot = Join-Path $installation "VC/Tools/MSVC"
    $versionRoot = Join-Path $versionsRoot "14.50.12345"
    $bin = Join-Path $versionRoot "bin/Hostx64/x64"
    foreach ($name in @("cl.exe", "link.exe", "dumpbin.exe")) {
        Write-FixtureTool -Path (Join-Path $bin $name)
    }

    $env:VSCMD_ARG_HOST_ARCH = "x64"
    $env:VSCMD_ARG_TGT_ARCH = "x64"
    $env:VSINSTALLDIR = $installation + [System.IO.Path]::DirectorySeparatorChar
    $env:VCINSTALLDIR = (Join-Path $installation "VC") + `
        [System.IO.Path]::DirectorySeparatorChar
    $env:VCToolsInstallDir = $versionRoot + [System.IO.Path]::DirectorySeparatorChar
    $env:PATH = $bin
    $resolved = Resolve-TrustedMsvcX64Tools -MsvcInstallation $installation
    Assert-ResolvedTools -Tools $resolved -Bin $bin

    $harmless = Join-Path $TestRoot "harmless-bin"
    $decoy = Join-Path $TestRoot "decoy-bin"
    New-Item -ItemType Directory -Path $harmless, $decoy | Out-Null
    Write-FixtureTool -Path (Join-Path $decoy "link.exe")
    $env:PATH = @($decoy, $harmless, $bin, $harmless) -join (
        [System.IO.Path]::PathSeparator
    )
    Set-TrustedMsvcPath -TrustedBin $bin -Linker $resolved.Linker
    $controlledPath = @($env:PATH.Split([System.IO.Path]::PathSeparator))
    if (
        $controlledPath.Count -ne 2 -or
        -not $controlledPath[0].Equals(
            [System.IO.Path]::GetFullPath($bin),
            [System.StringComparison]::OrdinalIgnoreCase
        ) -or
        -not $controlledPath[1].Equals(
            [System.IO.Path]::GetFullPath($harmless),
            [System.StringComparison]::OrdinalIgnoreCase
        )
    ) {
        throw "controlled MSVC PATH differs"
    }

    foreach ($invalidPath in @(
        "relative-bin",
        ($harmless + [System.IO.Path]::PathSeparator)
    )) {
        $env:PATH = $invalidPath
        Assert-Fails `
            -Label "invalid MSVC PATH entry" `
            -ExpectedMessage "empty or relative MSVC linker search directory" `
            -Action {
            Set-TrustedMsvcPath -TrustedBin $bin -Linker $resolved.Linker
        }
    }
    $nonFileProvider = Join-Path $TestRoot "non-file-provider"
    New-Item -ItemType Directory -Path (
        Join-Path $nonFileProvider "link.exe"
    ) -Force | Out-Null
    $env:PATH = $nonFileProvider
    Assert-Fails `
        -Label "non-file PATH linker" `
        -ExpectedMessage "link.exe to a non-file path" `
        -Action {
        Set-TrustedMsvcPath -TrustedBin $bin -Linker $resolved.Linker
    }
    $env:PATH = $bin

    $rustApplicationDirectory = Join-Path $rustSysroot "bin"
    $windowsDirectory = Join-Path $TestRoot "Windows"
    New-Item -ItemType Directory -Path $rustApplicationDirectory -Force | Out-Null
    $linkerFingerprint = Get-TrustedMsvcLinkerFingerprint `
        -MsvcInstallation $installation `
        -ExpectedBin $resolved.Bin `
        -ExpectedLinker $resolved.Linker `
        -RustToolsSearchDirectory $rustBin `
        -RustApplicationDirectory $rustApplicationDirectory `
        -SystemDirectory $systemDirectory `
        -WindowsDirectory $windowsDirectory `
        -NormalizePath
    if (
        $linkerFingerprint.Path -cne $resolved.Linker -or
        $linkerFingerprint.Length -ne 1 -or
        $linkerFingerprint.Sha256 -cnotmatch '^[0-9A-F]{64}$' -or
        $linkerFingerprint.LastWriteTimeUtcTicks -le 0
    ) {
        throw "trusted MSVC linker fingerprint differs"
    }
    foreach ($invalidSearch in @(
        @("relative-tools", $rustApplicationDirectory, $systemDirectory, $windowsDirectory),
        @((Join-Path $TestRoot "missing-tools"), $rustApplicationDirectory, $systemDirectory, $windowsDirectory),
        @($rustBin, $rustBin, $systemDirectory, $windowsDirectory)
    )) {
        Assert-Fails `
            -Label "invalid bare linker search directory" `
            -ExpectedMessage "bare MSVC linker search directory" `
            -Action {
            Assert-BareMsvcLinkerSearchBoundary `
                -TrustedBin $resolved.Bin `
                -Linker $resolved.Linker `
                -RustToolsSearchDirectory $invalidSearch[0] `
                -RustApplicationDirectory $invalidSearch[1] `
                -SystemDirectory $invalidSearch[2] `
                -WindowsDirectory $invalidSearch[3]
        }
    }
    foreach ($shadowDirectory in @(
        $rustBin,
        $rustApplicationDirectory,
        $systemDirectory,
        $windowsDirectory
    )) {
        $shadowLinker = Join-Path $shadowDirectory "link.exe"
        Write-FixtureTool -Path $shadowLinker
        Assert-Fails `
            -Label "higher-priority bare linker provider" `
            -ExpectedMessage "untrusted higher-priority provider" `
            -Action {
            Assert-BareMsvcLinkerSearchBoundary `
                -TrustedBin $resolved.Bin `
                -Linker $resolved.Linker `
                -RustToolsSearchDirectory $rustBin `
                -RustApplicationDirectory $rustApplicationDirectory `
                -SystemDirectory $systemDirectory `
                -WindowsDirectory $windowsDirectory
        }
        Remove-Item -LiteralPath $shadowLinker -Force
    }
    $directoryShadow = Join-Path $rustBin "link.exe"
    New-Item -ItemType Directory -Path $directoryShadow | Out-Null
    Assert-Fails `
        -Label "directory bare linker provider" `
        -ExpectedMessage "untrusted higher-priority provider" `
        -Action {
        Assert-BareMsvcLinkerSearchBoundary `
            -TrustedBin $resolved.Bin `
            -Linker $resolved.Linker `
            -RustToolsSearchDirectory $rustBin `
            -RustApplicationDirectory $rustApplicationDirectory `
            -SystemDirectory $systemDirectory `
            -WindowsDirectory $windowsDirectory
    }
    Remove-Item -LiteralPath $directoryShadow -Recurse -Force

    $reparseTarget = Join-Path $TestRoot "linker-reparse-target"
    New-Item -ItemType Directory -Path $reparseTarget | Out-Null
    $reparseShadow = Join-Path $rustBin "link.exe"
    New-Item -ItemType Junction -Path $reparseShadow -Target $reparseTarget | Out-Null
    Assert-Fails `
        -Label "reparse-point bare linker provider" `
        -ExpectedMessage "untrusted higher-priority provider" `
        -Action {
        Assert-BareMsvcLinkerSearchBoundary `
            -TrustedBin $resolved.Bin `
            -Linker $resolved.Linker `
            -RustToolsSearchDirectory $rustBin `
            -RustApplicationDirectory $rustApplicationDirectory `
            -SystemDirectory $systemDirectory `
            -WindowsDirectory $windowsDirectory
    }
    Remove-Item -LiteralPath $reparseShadow -Force

    $normalizedPath = $env:PATH
    $env:PATH = @($decoy, $bin) -join [System.IO.Path]::PathSeparator
    Assert-Fails `
        -Label "post-build PATH mutation" `
        -ExpectedMessage "controlled PATH does not resolve only" `
        -Action {
        Get-TrustedMsvcLinkerFingerprint `
            -MsvcInstallation $installation `
            -ExpectedBin $resolved.Bin `
            -ExpectedLinker $resolved.Linker `
            -RustToolsSearchDirectory $rustBin `
            -RustApplicationDirectory $rustApplicationDirectory `
            -SystemDirectory $systemDirectory `
            -WindowsDirectory $windowsDirectory
    }
    if ($env:PATH -cne (@($decoy, $bin) -join [System.IO.Path]::PathSeparator)) {
        throw "post-build PATH assertion mutated PATH"
    }
    $env:PATH = $normalizedPath

    $modifiedFingerprint = [pscustomobject] @{
        Path = $linkerFingerprint.Path
        Sha256 = $linkerFingerprint.Sha256
        Length = $linkerFingerprint.Length
        LastWriteTimeUtcTicks = $linkerFingerprint.LastWriteTimeUtcTicks + 1
        PathEnvironment = $linkerFingerprint.PathEnvironment
    }
    Assert-Fails `
        -Label "linker fingerprint mutation" `
        -ExpectedMessage "file or search path changed" `
        -Action {
        Assert-MsvcLinkerFingerprintUnchanged `
            -Before $linkerFingerprint `
            -After $modifiedFingerprint
    }

    Remove-Item -LiteralPath $resolved.Linker -Force
    Assert-Fails `
        -Label "deleted trusted linker before post-check" `
        -ExpectedMessage "toolchain path is not a regular file" `
        -Action {
        Get-TrustedMsvcLinkerFingerprint `
            -MsvcInstallation $installation `
            -ExpectedBin $resolved.Bin `
            -ExpectedLinker $resolved.Linker `
            -RustToolsSearchDirectory $rustBin `
            -RustApplicationDirectory $rustApplicationDirectory `
            -SystemDirectory $systemDirectory `
            -WindowsDirectory $windowsDirectory
    }
    Write-FixtureTool -Path $resolved.Linker

    $env:VSCMD_ARG_HOST_ARCH = "x86"
    Assert-Fails `
        -Label "wrong host architecture" `
        -ExpectedMessage "vcvars64 must select" `
        -Action {
        Resolve-TrustedMsvcX64Tools -MsvcInstallation $installation
    }
    $env:VSCMD_ARG_HOST_ARCH = "x64"

    $env:VSCMD_ARG_TGT_ARCH = "arm64"
    Assert-Fails `
        -Label "wrong target architecture" `
        -ExpectedMessage "vcvars64 must select" `
        -Action {
        Resolve-TrustedMsvcX64Tools -MsvcInstallation $installation
    }
    $env:VSCMD_ARG_TGT_ARCH = "x64"

    $env:VSINSTALLDIR = Join-Path $TestRoot "OtherVisualStudio"
    Assert-Fails `
        -Label "different Visual Studio installation" `
        -ExpectedMessage "selected a different Visual Studio installation" `
        -Action {
        Resolve-TrustedMsvcX64Tools -MsvcInstallation $installation
    }
    $env:VSINSTALLDIR = $installation

    $env:VCINSTALLDIR = Join-Path $installation "OtherVC"
    Assert-Fails `
        -Label "different VC installation" `
        -ExpectedMessage "selected a different Visual Studio installation" `
        -Action {
        Resolve-TrustedMsvcX64Tools -MsvcInstallation $installation
    }
    $env:VCINSTALLDIR = Join-Path $installation "VC"

    $outsideVersion = Join-Path $TestRoot "Outside/VC/Tools/MSVC/14.50.12345"
    $env:VCToolsInstallDir = $outsideVersion
    Assert-Fails `
        -Label "tools outside the Visual Studio installation" `
        -ExpectedMessage "VCToolsInstallDir is not one version" `
        -Action {
        Resolve-TrustedMsvcX64Tools -MsvcInstallation $installation
    }

    $nestedVersion = Join-Path $versionRoot "nested"
    $env:VCToolsInstallDir = $nestedVersion
    Assert-Fails `
        -Label "nested tools version" `
        -ExpectedMessage "VCToolsInstallDir is not one version" `
        -Action {
        Resolve-TrustedMsvcX64Tools -MsvcInstallation $installation
    }

    $invalidVersion = Join-Path $versionsRoot "preview"
    $env:VCToolsInstallDir = $invalidVersion
    Assert-Fails `
        -Label "noncanonical tools version" `
        -ExpectedMessage "VCToolsInstallDir is not one version" `
        -Action {
        Resolve-TrustedMsvcX64Tools -MsvcInstallation $installation
    }

    $env:VCToolsInstallDir = $versionRoot
    $linker = Join-Path $bin "link.exe"
    Remove-Item -LiteralPath $linker
    Assert-Fails `
        -Label "missing linker" `
        -ExpectedMessage "toolchain path is not a regular file" `
        -Action {
        Resolve-TrustedMsvcX64Tools -MsvcInstallation $installation
    }
    Write-FixtureTool -Path $linker

    $dumpbin = Join-Path $bin "dumpbin.exe"
    Remove-Item -LiteralPath $dumpbin
    New-Item -ItemType Directory -Path $dumpbin | Out-Null
    Assert-Fails `
        -Label "tool path is a directory" `
        -ExpectedMessage "toolchain path is not a regular file" `
        -Action {
        Resolve-TrustedMsvcX64Tools -MsvcInstallation $installation
    }
    Remove-Item -LiteralPath $dumpbin -Recurse
    Write-FixtureTool -Path $dumpbin

    $junctionVersion = Join-Path $versionsRoot "14.50.54321"
    New-Item -ItemType Junction -Path $junctionVersion -Target $versionRoot | Out-Null
    $env:VCToolsInstallDir = $junctionVersion
    Assert-Fails `
        -Label "tools version is a reparse point" `
        -ExpectedMessage "toolchain path contains a reparse point" `
        -Action {
        Resolve-TrustedMsvcX64Tools -MsvcInstallation $installation
    }

    Write-Host "WINDOWS_MSVC_TOOLCHAIN_RESOLVER_PASS"
}
finally {
    [System.Environment]::SetEnvironmentVariable(
        "VSCMD_ARG_HOST_ARCH", $savedHostArch, "Process"
    )
    [System.Environment]::SetEnvironmentVariable(
        "VSCMD_ARG_TGT_ARCH", $savedTargetArch, "Process"
    )
    [System.Environment]::SetEnvironmentVariable(
        "VSINSTALLDIR", $savedVsInstall, "Process"
    )
    [System.Environment]::SetEnvironmentVariable(
        "VCINSTALLDIR", $savedVcInstall, "Process"
    )
    [System.Environment]::SetEnvironmentVariable(
        "VCToolsInstallDir", $savedToolsInstall, "Process"
    )
    [System.Environment]::SetEnvironmentVariable("PATH", $savedPath, "Process")
    [System.Environment]::SetEnvironmentVariable(
        "ComSpec", $savedComSpec, "Process"
    )
    [System.Environment]::SetEnvironmentVariable(
        "RUSTFLAGS", $savedRustFlags, "Process"
    )
    [System.Environment]::SetEnvironmentVariable(
        "CARGO_ENCODED_RUSTFLAGS", $savedCargoEncodedRustFlags, "Process"
    )
    [System.Environment]::SetEnvironmentVariable(
        "CARGO_INCREMENTAL", $savedCargoIncremental, "Process"
    )
    [System.Environment]::SetEnvironmentVariable(
        "CARGO_HOME", $savedCargoHome, "Process"
    )
    [System.Environment]::SetEnvironmentVariable(
        "USERPROFILE", $savedUserProfile, "Process"
    )
    [System.Environment]::SetEnvironmentVariable(
        "HOME", $savedHome, "Process"
    )
    if (Test-Path -LiteralPath $TestRoot) {
        Remove-Item -LiteralPath $TestRoot -Recurse -Force
    }
}
