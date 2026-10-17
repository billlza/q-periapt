[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repository = Split-Path $PSScriptRoot -Parent
$output = Join-Path $PSScriptRoot 'out'
if (Test-Path -LiteralPath $output) { throw 'Refusing to reuse an observation directory' }
New-Item -ItemType Directory -Path $output | Out-Null
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) { throw 'vswhere is unavailable' }
$installation = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if ($LASTEXITCODE -ne 0 -or @($installation).Count -ne 1) { throw 'Visual Studio selection failed' }
$vcvars = Join-Path $installation 'VC/Auxiliary/Build/vcvars64.bat'
if ($vcvars -match '["%\r\n]' -or -not (Test-Path -LiteralPath $vcvars -PathType Leaf)) { throw 'Invalid vcvars path' }
$environmentLines = & $env:ComSpec /d /s /c "`"$vcvars`" >nul && set"
if ($LASTEXITCODE -ne 0) { throw 'vcvars failed' }
foreach ($line in $environmentLines) {
    if ($line -match '^([^=]+)=(.*)$') {
        [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process')
    } else { throw 'Malformed toolchain environment line' }
}
if ($env:VSCMD_ARG_HOST_ARCH -ne 'x64' -or $env:VSCMD_ARG_TGT_ARCH -ne 'x64') { throw 'Expected x64 native toolchain' }
$compiler = (Get-Command cl.exe -CommandType Application).Source
$metadata = [ordered]@{
    schema = 1
    commit = $env:GITHUB_SHA
    runner = $env:ImageOS
    image_version = $env:ImageVersion
    os = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription
    architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    experiment = 'anonymous-scratch'
    compiler = $compiler
    compiler_sha256 = (Get-FileHash -LiteralPath $compiler -Algorithm SHA256).Hash.ToLowerInvariant()
    sources = @{}
    product_qualification = $false
}
foreach ($name in @('anonymous-scratch/probe.c', 'anonymous-scratch/run.ps1', '.github/workflows/windows-scratch-probe.yml')) {
    $metadata.sources[$name] = (Get-FileHash -LiteralPath (Join-Path $repository $name) -Algorithm SHA256).Hash.ToLowerInvariant()
}
$metadata | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $output 'environment.json') -Encoding utf8NoBOM
Push-Location $output
try {
    & $compiler /nologo /W4 /WX /std:c17 /TC /Fe:probe.exe /Fo:probe.obj (Join-Path $PSScriptRoot 'probe.c') 1>build.stdout 2>build.stderr
    if ($LASTEXITCODE -ne 0) { throw 'Native compilation failed; see build stdout/stderr' }
    $start = [System.Diagnostics.ProcessStartInfo]::new((Join-Path $output 'probe.exe'))
    $start.ArgumentList.Add((Join-Path $output 'fixture'))
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [System.Diagnostics.Process]::Start($start)
    try {
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $timedOut = $false
        if (-not $process.WaitForExit(30000)) {
            $timedOut = $true
            $process.Kill($true)
            if (-not $process.WaitForExit(5000)) { throw 'Owned observation process did not stop after kill' }
        }
        $observations = $stdout.GetAwaiter().GetResult()
        $diagnostic = $stderr.GetAwaiter().GetResult()
        [IO.File]::WriteAllText((Join-Path $output 'observations.jsonl'), $observations)
        [IO.File]::WriteAllText((Join-Path $output 'probe.stderr'), $diagnostic)
        [IO.File]::WriteAllText((Join-Path $output 'exit-code.txt'), [string]$process.ExitCode)
        if ($timedOut) { throw 'Native observation exceeded 30 seconds; terminal output retained' }
        if ($process.ExitCode -ne 0) { throw 'Native control failed; see retained observations' }
        if ($diagnostic.Length -ne 0) { throw 'Unexpected native diagnostic' }
        $records = @($observations -split '\r?\n' | Where-Object { $_.Length -gt 0 } | ForEach-Object { $_ | ConvertFrom-Json -AsHashtable })
        $terminal = $records[-1]
        if ($terminal.observations_completed -ne $true -or $terminal.control_failures -ne 0 -or
            $terminal.power_loss_tested -ne $false -or $terminal.product_qualification -ne $false) {
            throw 'Missing exact terminal observation boundary'
        }
    } finally { $process.Dispose() }
} finally { Pop-Location }
