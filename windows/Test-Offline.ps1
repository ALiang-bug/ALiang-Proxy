# Windows PowerShell 5.1. Runs local checks without credentials or elevation.
[CmdletBinding()]
param([string]$SetupPath)
$ErrorActionPreference = 'Stop'
foreach ($name in @('ALiang-Proxy.ps1', 'SystemProxy.ps1', 'NodeTests.ps1',
                    'Test-Core.ps1', 'Test-SystemProxy.ps1', 'Test-Tunnel.ps1', 'Test-Offline.ps1')) {
    $file = Join-Path $PSScriptRoot $name
    $tokens = $null
    $parseErrors = $null
    [void][Management.Automation.Language.Parser]::ParseFile($file, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count) {
        $parseErrors | ForEach-Object { Write-Host ('{0}:{1}: {2}' -f $name, $_.Extent.StartLineNumber, $_.Message) }
        throw "PowerShell syntax validation failed for $name."
    }
}
'PowerShell syntax checks passed.'
$launcher = Start-Process -FilePath (Join-Path $PSScriptRoot 'ALiang-Proxy.exe') -ArgumentList '--verify-ui' -PassThru
try {
    if (!$launcher.WaitForExit(25000)) {
        $launcher.Kill()
        throw 'Launcher UI check timed out.'
    }
    if ($launcher.ExitCode -ne 0) { throw 'Launcher or WinForms initialization failed.' }
} finally { $launcher.Dispose() }
'Launcher and WinForms initialization passed.'
& (Join-Path $PSScriptRoot 'Test-Core.ps1')
& (Join-Path $PSScriptRoot 'Test-SystemProxy.ps1')
if ($SetupPath) {
    $setup = Get-Item -LiteralPath $SetupPath
    if ($setup.PSIsContainer -or $setup.Name -ne 'ALiang-Proxy-Setup-x64.exe') {
        throw 'Supply the matching ALiang-Proxy-Setup-x64.exe.'
    }
    $process = Start-Process -FilePath $setup.FullName -ArgumentList '--verify-payload' -PassThru
    try {
        if (!$process.WaitForExit(30000)) {
            $process.Kill()
            throw 'Setup payload check timed out.'
        }
        if ($process.ExitCode -ne 0) { throw 'Setup extraction, shortcut creation, or cleanup failed.' }
    } finally { $process.Dispose() }
    'Windows setup extraction and shortcut check passed.'
}
'Offline checks passed.'
