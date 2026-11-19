# Windows PowerShell 5.1. Uses only a synthetic profile and loopback traffic.
$ErrorActionPreference = 'Stop'
$core = Join-Path $PSScriptRoot 'proxy-core.exe'
$utf8 = New-Object Text.UTF8Encoding($false, $true)
$yaml = @'
proxies:
  - name: offline-node
    type: trojan
    server: 127.0.0.1
    port: 9
    password: offline-fixture
    sni: offline.invalid
rules:
  - MATCH,offline-node
'@

function Open-Core([string]$mode, [int]$port) {
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $core
    $start.Arguments = $mode
    $start.UseShellExecute = $false
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.StandardOutputEncoding = $utf8
    $child = [Diagnostics.Process]::Start($start)
    try {
        $json = @{ YAML = $yaml; Exit = 'offline-node'; Port = $port } | ConvertTo-Json -Compress
        $frame = $utf8.GetBytes($json + "`n")
        $child.StandardInput.BaseStream.Write($frame, 0, $frame.Length)
        $child.StandardInput.BaseStream.Flush()
        return $child
    } catch {
        try { if (!$child.HasExited) { $child.Kill() } } finally { $child.Dispose() }
        throw
    }
}

function Read-Core($child) {
    $read = $child.StandardOutput.ReadLineAsync()
    if (!$read.Wait(10000) -or !$read.Result) { throw 'Core did not emit a response.' }
    ConvertFrom-Json $read.Result
}

$listener = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0)
$listener.Start()
try { $port = ([Net.IPEndPoint]$listener.LocalEndpoint).Port } finally { $listener.Stop() }

$child = Open-Core 'inspect' $port
try {
    $rows = @(Read-Core $child)
    if ($rows.Count -ne 1 -or $rows[0].tag -ne 'offline-node' -or $rows[0].type -ne 'trojan' -or
        !$child.WaitForExit(5000) -or $child.ExitCode -ne 0) {
        throw 'Subscription inspection failed.'
    }
} finally {
    try { if (!$child.HasExited) { $child.Kill() } } finally { $child.Dispose() }
}

$child = Open-Core 'run' $port
try {
    if (!(Read-Core $child).ready) { throw 'Proxy readiness was not reported.' }
    $connection = New-Object Net.Sockets.TcpClient
    try {
        $connect = $connection.ConnectAsync([Net.IPAddress]::Loopback, $port)
        if (!$connect.Wait(3000)) { throw 'Loopback connection timed out.' }
        $stream = $connection.GetStream()
        $stream.ReadTimeout = 3000
        # SOCKS greeting only. The test never asks the proxy to dial a target.
        $greeting = [byte[]]@(5, 1, 0)
        $stream.Write($greeting, 0, $greeting.Length)
        if ($stream.ReadByte() -ne 5 -or $stream.ReadByte() -ne 0) {
            throw 'The proxy did not complete the SOCKS5 greeting.'
        }
    } finally { $connection.Dispose() }
    $child.StandardInput.Close()
    if (!$child.WaitForExit(5000) -or $child.ExitCode -ne 0) {
        throw 'The proxy did not exit cleanly after stdin closed.'
    }
} finally {
    try { if (!$child.HasExited) { $child.Kill() } } finally { $child.Dispose() }
}
$rebound = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, $port)
try { $rebound.Start() } finally { $rebound.Stop() }
'Windows core smoke test passed.'
