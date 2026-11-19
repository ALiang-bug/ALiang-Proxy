# Windows PowerShell 5.1. Shared by the elevated app worker and the manual route test.
[CmdletBinding()]
param(
    [string]$Profile,
    [switch]$SavedProfile,
    [Parameter(Mandatory)][string]$ExitNode,
    [Parameter(Mandatory)][switch]$ApplyTunnel,
    [switch]$SimulateCrash,
    [int]$OwnerPid,
    [long]$OwnerStartTicks,
    [string]$EventId
)
$ErrorActionPreference = 'Stop'
if (!$ApplyTunnel) { throw 'Pass -ApplyTunnel to confirm temporary routing changes.' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'An elevated Windows PowerShell session is required.'
}
$corePath = Join-Path $PSScriptRoot 'proxy-core.exe'
if (!(Test-Path -LiteralPath $corePath -PathType Leaf)) { throw 'Missing proxy-core.exe.' }
$utf8 = New-Object System.Text.UTF8Encoding($false, $true)
$store = Join-Path $env:LOCALAPPDATA 'ALiangProxy'
$groupMember = ''
$resolver = ''
if ($SavedProfile) {
    if ($Profile) { throw 'Choose either a local file or the saved profile.' }
    Add-Type -AssemblyName System.Security
    $savedFile = Get-Item -LiteralPath (Join-Path $store 'profile.dpapi')
    if ($savedFile.Length -gt 8MB) { throw 'Saved profile is too large.' }
    $sealed = [IO.File]::ReadAllBytes($savedFile.FullName)
    $plain = [Security.Cryptography.ProtectedData]::Unprotect($sealed, $null, 'CurrentUser')
    $yaml = $utf8.GetString($plain)
    if ($yaml.TrimStart().StartsWith('{')) {
        try { $record = ConvertFrom-Json $yaml } catch { $record = $null }
        if ($null -ne $record -and $record.PSObject.Properties['yaml']) {
            $yaml = [string]$record.yaml
            $resolver = [string]$record.resolver
            if ([string]$record.exit -ceq $ExitNode) { $groupMember = [string]$record.member }
        }
    }
} else {
    if (!$Profile) { throw 'Supply a local profile file.' }
    $profileFile = Get-Item -LiteralPath $Profile
    if ($profileFile.PSIsContainer -or $profileFile.Length -gt 1MB) { throw 'Invalid profile file.' }
    $yaml = $utf8.GetString([IO.File]::ReadAllBytes($profileFile.FullName)).TrimStart([char]0xFEFF)
}
if (!$yaml -or $utf8.GetByteCount($yaml) -gt 1MB) { throw 'Invalid profile contents.' }
$watched = @('0.0.0.0/0', '::/0', '0.0.0.0/1', '128.0.0.0/1', '::/1', '8000::/1')
function Get-WatchedRoutes {
    Get-NetRoute -PolicyStore ActiveStore |
        Where-Object { $_.DestinationPrefix -in $watched } |
        ForEach-Object { '{0}|{1}|{2}|{3}' -f $_.DestinationPrefix, $_.InterfaceIndex, $_.NextHop, $_.RouteMetric } |
        Sort-Object
}

$managed = $OwnerPid -ne 0
$lock = $null
$ownerProcess = $null
$stopEvent = $null
$readyEvent = $null
$child = $null
$baselineTaken = $false
$readyVerified = $false
$crashVerified = $false
try {
    if ($managed) {
        if (!$SavedProfile -or $SimulateCrash -or $EventId -cnotmatch '^[a-f0-9]{32}$') {
            throw 'Invalid managed tunnel session.'
        }
        $ownerProcess = [Diagnostics.Process]::GetProcessById($OwnerPid)
        if ($ownerProcess.StartTime.ToUniversalTime().Ticks -ne $OwnerStartTicks) {
            throw 'The tunnel owner is no longer available.'
        }
        $stopEvent = [Threading.EventWaitHandle]::OpenExisting("Local\ALiangTunStop-$EventId")
        $readyEvent = [Threading.EventWaitHandle]::OpenExisting("Local\ALiangTunReady-$EventId")
        if ($ownerProcess.HasExited -or $stopEvent.WaitOne(0)) { return }
    } else {
        [void][IO.Directory]::CreateDirectory($store)
        $lock = [IO.File]::Open((Join-Path $store 'instance.lock'), 'OpenOrCreate', 'ReadWrite', 'None')
    }
    $settings = Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    if ($settings.ProxyEnable -eq 1 -or $settings.AutoConfigURL -or
        [IO.File]::Exists((Join-Path $store 'proxy-restore.json'))) {
        throw 'Restore the Windows proxy before testing TUN.'
    }
    if (Get-NetIPInterface -InterfaceAlias 'ALiangProxy' -ErrorAction SilentlyContinue) {
        throw 'An ALiangProxy interface already exists.'
    }
    if (Get-NetRoute -PolicyStore ActiveStore | Where-Object {
        $_.DestinationPrefix -in $watched -and $_.DestinationPrefix.EndsWith('/1')
    }) { throw 'Existing split default routes detected. Use a clean test VM.' }
    $baseline = @(Get-WatchedRoutes)
    if (!$baseline.Count) { throw 'No default routes to verify.' }
    $baselineTaken = $true

    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $corePath
    $info.Arguments = 'tun'
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $managed
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    $info.StandardOutputEncoding = $utf8
    $child = [Diagnostics.Process]::Start($info)
    $request = @{ YAML = $yaml; Exit = $ExitNode; Port = 17890; Resolver = $resolver }
    if ($groupMember) { $request.Group = $ExitNode; $request.Member = $groupMember }
    $frame = $request | ConvertTo-Json -Compress
    $bytes = $utf8.GetBytes($frame + "`n")
    $child.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length)
    $child.StandardInput.BaseStream.Flush()
    $ready = $child.StandardOutput.ReadLineAsync()
    $clock = [Diagnostics.Stopwatch]::StartNew()
    while (!$ready.Wait(250)) {
        if ($managed -and ($ownerProcess.HasExited -or $stopEvent.WaitOne(0))) { return }
        if ($clock.ElapsedMilliseconds -ge 20000) { throw 'Tunnel startup timed out.' }
    }
    if (!$ready.Result -or !(ConvertFrom-Json $ready.Result).ready) {
        throw 'The core did not report tunnel readiness.'
    }
    $clock = [Diagnostics.Stopwatch]::StartNew()
    do {
        if ($managed -and ($ownerProcess.HasExited -or $stopEvent.WaitOne(0))) { return }
        if ($child.HasExited) { throw 'The core exited before Windows applied the tunnel routes.' }
        $interfaces = @(Get-NetIPInterface -InterfaceAlias 'ALiangProxy' -ErrorAction SilentlyContinue)
        $indices = @($interfaces | Select-Object -ExpandProperty InterfaceIndex -Unique)
        $prefixes = @()
        if ($indices.Count) {
            $prefixes = @(Get-NetRoute -PolicyStore ActiveStore | Where-Object {
                $_.InterfaceIndex -in $indices
            } | Select-Object -ExpandProperty DestinationPrefix)
        }
        $ipv4 = '0.0.0.0/0' -in $prefixes -or ('0.0.0.0/1' -in $prefixes -and '128.0.0.0/1' -in $prefixes)
        $ipv6 = '::/0' -in $prefixes -or ('::/1' -in $prefixes -and '8000::/1' -in $prefixes)
        if ($ipv4 -and $ipv6) { break }
        Start-Sleep -Milliseconds 250
    } while ($clock.ElapsedMilliseconds -lt 5000)
    if (!$ipv4 -or !$ipv6) { throw 'Windows did not report both tunnel default routes in time.' }
    foreach ($destination in @('192.0.2.10', '2001:db8::10')) {
        # Find-NetRoute performs a local lookup and sends no test traffic.
        $effective = @(Find-NetRoute -RemoteIPAddress $destination | Where-Object {
            $_.PSObject.Properties['DestinationPrefix']
        })
        if ($effective.Count -ne 1 -or $effective[0].InterfaceIndex -notin $indices) {
            throw "Windows did not select the tunnel for $destination."
        }
    }
    $readyVerified = $true
    'Windows selected the tunnel for the IPv4 and IPv6 route lookups.'
    if ($managed) {
        [void]$readyEvent.Set()
        while (!$ownerProcess.HasExited -and !$stopEvent.WaitOne(250)) {
            if ($child.HasExited) { throw 'Tunnel core exited unexpectedly.' }
        }
    } elseif ($SimulateCrash) {
        # Kill only the child created by this invocation, with stdin still open.
        $child.Kill()
        if (!$child.WaitForExit(5000)) { throw 'The simulated crash did not terminate the core.' }
        if ($child.ExitCode -eq 0) { throw 'The core exited normally before the simulated crash.' }
        $crashVerified = $true
    } else {
        [void](Read-Host 'Perform any authorized checks now, then press Enter to stop')
    }
} finally {
    try {
        $cleanStop = $false
        if ($child) {
            try {
                if (!$child.HasExited) {
                    $child.StandardInput.Close()
                    if ($child.WaitForExit(10000)) {
                        $cleanStop = $child.ExitCode -eq 0
                    } else {
                        $child.Kill()
                        if (!$child.WaitForExit(5000)) { throw 'The core did not exit after forced termination.' }
                        Write-Warning 'Tunnel core required forced termination.'
                    }
                }
            } finally { $child.Dispose() }
        }
        if ($baselineTaken) {
            $expected = $baseline -join "`n"
            $clock = [Diagnostics.Stopwatch]::StartNew()
            do {
                $restored = (@(Get-WatchedRoutes) -join "`n") -ceq $expected
                if ($restored) { break }
                Start-Sleep -Milliseconds 250
            } while ($clock.ElapsedMilliseconds -lt 5000)
            if (!$restored) { throw 'Default routes did not return to baseline.' }
            'Default and split-default routes match baseline.'
        }
        if ($readyVerified -and !$cleanStop -and !$crashVerified) {
            throw 'Route baseline matched, but graceful core shutdown was not observed.'
        }
        if ($crashVerified) { 'Default route recovery verified after forced process termination.' }
    } catch {
        $_.Exception.Data['ALiangTunnelCleanup'] = $true
        throw
    } finally {
        foreach ($resource in @($lock, $ownerProcess, $stopEvent, $readyEvent)) {
            if ($null -ne $resource) { $resource.Dispose() }
        }
    }
}
