#!/usr/bin/env pwsh
# Exercise the production command boundary. This does not run MSVC or a PE binary.
[CmdletBinding()]
param([Parameter(Mandatory)] [string] $Python)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$Root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$Profile = "sdk-alpha1"
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $PSScriptRoot "windows-package.ps1"), [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw "production package script does not parse" }
$function = @($ast.FindAll({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq "Invoke-Captured"
}, $true))
if ($function.Count -ne 1) { throw "production command boundary is ambiguous" }
Invoke-Expression $function[0].Extent.Text
$valid = Invoke-Captured -FilePath $Python -Arguments @("-I", "-S", "-c", "print('completed')")
if ($valid.Stdout.Trim() -cne "completed" -or $valid.Stderr.Length -ne 0) { throw "valid command output differs" }
foreach ($source in @(
    "print('warning: must fail')",
    "print('error C9999: must fail')",
    "import sys; print('warning C9999: must fail', file=sys.stderr)",
    "print('CMake Warning at example.cmake:1:')",
    "print('CMake Warning (dev) at example.cmake:1:')",
    "print('CMake Deprecation Warning at example.cmake:1:')"
)) {
    $rejected = $false
    try { [void](Invoke-Captured -FilePath $Python -Arguments @("-I", "-S", "-c", $source)) }
    catch {
        if (-not $_.Exception.Message.Contains("emitted a warning or error")) { throw }
        $rejected = $true
    }
    if (-not $rejected) { throw "zero-status diagnostics were accepted" }
}
$rejected = $false
try { [void](Invoke-Captured -FilePath $Python -Arguments @("-I", "-S", "-c", "print('private-fixture'); raise SystemExit(7)") -RedactArguments) }
catch {
    if ($_.Exception.Message.Contains("private-fixture") -or -not $_.Exception.Message.Contains("redacted")) { throw }
    $rejected = $true
}
if (-not $rejected) { throw "failed command was accepted" }
Write-Host "WINDOWS_SDK_COMMAND_BOUNDARY_PASS"

# These are symbol-list fixtures, not a dumpbin/MSVC or Windows runtime result.
$symbolFunction = @($ast.FindAll({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq "Assert-ImportLibrarySymbols"
}, $true))
if ($symbolFunction.Count -ne 1) { throw "production import-library boundary is ambiguous" }
Invoke-Expression $symbolFunction[0].Extent.Text
$Contract = Join-Path $Root "crates/q-periapt-ffi/abi/q-periapt-c-abi-v2-sdk-alpha1.json"
$names = @((Get-Content -LiteralPath $Contract -Raw | ConvertFrom-Json).abi.exports | ForEach-Object { $_.name })
$fixture = @("  100 __IMPORT_DESCRIPTOR_q_periapt_ffi_abi2")
foreach ($name in $names) { $fixture += @("  200 $name", "  200 __imp_$name") }
Assert-ImportLibrarySymbols -Output ($fixture -join "`r`n")
$sdkName = @($names | Where-Object { $_.StartsWith("q_periapt_sdk_") })[0]
$mutations = @(
    @{ Lines = @($fixture | Where-Object { $_ -cne "  200 $sdkName" }); Count = $fixture.Count - 1 },
    @{ Lines = @($fixture | Where-Object { $_ -cne "  200 __imp_$sdkName" }); Count = $fixture.Count - 1 },
    @{ Lines = @($fixture + "  200 q_periapt_sdk_unreviewed"); Count = $fixture.Count + 1 },
    @{ Lines = @($fixture + '  200 q_periapt_sdk_unreviewed$alias'); Count = $fixture.Count + 1 },
    @{ Lines = @($fixture | Where-Object { $_ -cne "  200 q_periapt_status_name" -and $_ -cne "  200 q_periapt_version" }) + "  200 q_periapt_status_name,q_periapt_version"; Count = $fixture.Count - 1 },
    @{ Lines = @($fixture + "  200 $sdkName"); Count = $fixture.Count + 1 }
)
foreach ($mutated in $mutations) {
    if ($mutated.Lines.Count -ne $mutated.Count -or @($mutated.Lines | Where-Object { $_ -isnot [string] }).Count -ne 0) {
        throw "symbol mutation fixture differs from its intended shape"
    }
    $rejected = $false
    try { Assert-ImportLibrarySymbols -Output ($mutated.Lines -join "`r`n") }
    catch {
        if (-not $_.Exception.Message.Contains("public symbols differ")) { throw }
        $rejected = $true
    }
    if (-not $rejected) { throw "incomplete, extra or duplicate SDK import symbols were accepted" }
}
Write-Host "WINDOWS_SDK_IMPORT_SYMBOL_FIXTURES_PASS"
