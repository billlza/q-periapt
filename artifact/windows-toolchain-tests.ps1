#!/usr/bin/env pwsh
# Exercise the production MSVC x64 tool resolver against controlled paths.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not $IsWindows) {
    throw "Windows MSVC toolchain resolver tests require Windows"
}

$Root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
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
    "Assert-TrustedBuildEnvironment",
    "Assert-NoAmbientCargoConfiguration",
    "Resolve-TrustedToolchainFile",
    "Resolve-TrustedCommandProcessor",
    "Resolve-TrustedMsvcX64Tools",
    "Set-TrustedMsvcPath"
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
        Librarian = "lib.exe"
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
$savedCargoIncremental = $env:CARGO_INCREMENTAL
$savedCargoHome = $env:CARGO_HOME

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
    Assert-NoAmbientCargoConfiguration -SourceRoot $cargoSource

    $cargoHomeConfig = Join-Path $cargoHome "config.toml"
    Write-FixtureTool -Path $cargoHomeConfig
    Assert-Fails `
        -Label "Cargo home configuration" `
        -ExpectedMessage "rejects ambient Cargo configuration files" `
        -Action {
        Assert-NoAmbientCargoConfiguration -SourceRoot $cargoSource
    }
    Remove-Item -LiteralPath $cargoHomeConfig

    $sourceConfig = Join-Path $cargoSource ".cargo/config"
    Write-FixtureTool -Path $sourceConfig
    Assert-Fails `
        -Label "source ancestor Cargo configuration" `
        -ExpectedMessage "rejects ambient Cargo configuration files" `
        -Action {
        Assert-NoAmbientCargoConfiguration -SourceRoot $cargoSource
    }
    Remove-Item -LiteralPath (Join-Path $cargoSource ".cargo") -Recurse

    $env:CARGO_HOME = "relative-cargo-home"
    Assert-Fails `
        -Label "relative Cargo home" `
        -ExpectedMessage "Cargo home must be absolute" `
        -Action {
        Assert-NoAmbientCargoConfiguration -SourceRoot $cargoSource
    }
    $env:CARGO_HOME = $cargoHome

    $installation = Join-Path $TestRoot "VisualStudio"
    $versionsRoot = Join-Path $installation "VC/Tools/MSVC"
    $versionRoot = Join-Path $versionsRoot "14.50.12345"
    $bin = Join-Path $versionRoot "bin/Hostx64/x64"
    foreach ($name in @("cl.exe", "link.exe", "dumpbin.exe", "lib.exe")) {
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
        "CARGO_INCREMENTAL", $savedCargoIncremental, "Process"
    )
    [System.Environment]::SetEnvironmentVariable(
        "CARGO_HOME", $savedCargoHome, "Process"
    )
    if (Test-Path -LiteralPath $TestRoot) {
        Remove-Item -LiteralPath $TestRoot -Recurse -Force
    }
}
