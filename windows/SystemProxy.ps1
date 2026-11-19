Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class ALiangWinInet {
    [DllImport("wininet.dll", EntryPoint = "InternetSetOptionW", ExactSpelling = true, SetLastError = true)]
    public static extern bool InternetSetOption(IntPtr handle, int option, IntPtr buffer, int length);
}
'@

$proxyKeyPath = 'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$proxyJournal = Join-Path $store 'proxy-restore.json'
$proxyEndpoint = '127.0.0.1:17890'

function Refresh-SystemProxy {
    [void][ALiangWinInet]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0)
    [void][ALiangWinInet]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0)
}

function Assert-ProxyValueTypes($key) {
    $names = $key.GetValueNames()
    if (($names -contains 'ProxyEnable' -and
        ($key.GetValueKind('ProxyEnable') -ne 'DWord' -or $key.GetValue('ProxyEnable') -notin @(0, 1))) -or
        ($names -contains 'ProxyServer' -and $key.GetValueKind('ProxyServer') -ne 'String')) {
        throw 'Unsupported existing Windows proxy settings.'
    }
}

function Restore-SystemProxy {
    if (![IO.File]::Exists($proxyJournal)) { return }
    if ((Get-Item -LiteralPath $proxyJournal).Length -gt 16KB) { throw 'Invalid proxy recovery record.' }
    $old = ConvertFrom-Json ([IO.File]::ReadAllText($proxyJournal))
    if ($old.version -ne 1 -or $old.enabled -notin @(-1, 0) -or
        $old.serverPresent -isnot [bool] -or $old.server -isnot [string]) {
        throw 'Invalid proxy recovery record.'
    }
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($proxyKeyPath, $true)
    if (!$key) { throw 'Windows Internet Settings unavailable.' }
    try {
        Assert-ProxyValueTypes $key
        $enabled = $key.GetValue('ProxyEnable', -1)
        $server = $key.GetValue('ProxyServer', $null)
        $originalServer = if ($old.serverPresent) { $old.server } else { $null }
        if (($enabled -ne 1 -and $enabled -ne $old.enabled) -or
            ($server -cne $proxyEndpoint -and $server -cne $originalServer)) {
            throw 'Windows proxy changed externally. Check Windows proxy settings before resolving the recovery record.'
        }
        # The only valid interrupted states have either the original or our value.
        if ($enabled -eq 1) {
            if ($server -cne $proxyEndpoint) { throw 'Windows proxy changed externally.' }
            if ($old.enabled -eq -1) { $key.DeleteValue('ProxyEnable', $false) }
            else { $key.SetValue('ProxyEnable', 0, 'DWord') }
        }
        if ($server -ceq $proxyEndpoint) {
            if ($old.serverPresent) { $key.SetValue('ProxyServer', $old.server, 'String') }
            else { $key.DeleteValue('ProxyServer', $false) }
        }
        $key.Flush()
        Refresh-SystemProxy
        [IO.File]::Delete($proxyJournal)
    } finally { $key.Dispose() }
}

function Enable-SystemProxy {
    if ([IO.File]::Exists($proxyJournal)) { throw 'Restore the previous Windows proxy settings first.' }
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($proxyKeyPath, $true)
    if (!$key) { throw 'Windows Internet Settings unavailable.' }
    try {
        Assert-ProxyValueTypes $key
        $enabled = $key.GetValue('ProxyEnable', -1)
        if ($enabled -notin @(-1, 0) -or $key.GetValue('AutoConfigURL', '')) {
            throw 'An existing manual or script proxy is configured.'
        }
        $server = $key.GetValue('ProxyServer', $null)
        $record = @{ version = 1; enabled = $enabled; serverPresent = ($null -ne $server); server = [string]$server }
        $json = $record | ConvertTo-Json -Compress
        $bytes = $utf8.GetBytes($json)
        if ($bytes.Length -gt 16KB) { throw 'Existing proxy address is too long.' }
        [void][IO.Directory]::CreateDirectory($store)
        $temporary = $proxyJournal + '.' + [Guid]::NewGuid().ToString('N')
        try {
            $file = [IO.File]::Open($temporary, 'CreateNew', 'Write', 'None')
            try { $file.Write($bytes, 0, $bytes.Length); $file.Flush($true) }
            finally { $file.Dispose() }
            [IO.File]::Move($temporary, $proxyJournal)
        } finally {
            if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
        }
        $key.SetValue('ProxyServer', $proxyEndpoint, 'String')
        $key.SetValue('ProxyEnable', 1, 'DWord')
        $key.Flush()
        Refresh-SystemProxy
    } finally { $key.Dispose() }
}
