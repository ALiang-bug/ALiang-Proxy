# Run with Windows PowerShell 5.1. Uses a temporary registry key.
$ErrorActionPreference = 'Stop'
$store = Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString('N'))
$utf8 = New-Object Text.UTF8Encoding($false)
. (Join-Path $PSScriptRoot 'SystemProxy.ps1')
function Refresh-SystemProxy {}
$proxyKeyPath = 'Software\ALiangProxyTest-' + [Guid]::NewGuid().ToString('N')
$key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($proxyKeyPath)
try {
    $key.SetValue('ProxyServer', 'original.invalid:80', 'String')
    Enable-SystemProxy
    if ($key.GetValue('ProxyEnable') -ne 1 -or $key.GetValue('ProxyServer') -ne $proxyEndpoint) {
        throw 'Enable did not apply the expected settings.'
    }
    Restore-SystemProxy
    if (($key.GetValueNames() -contains 'ProxyEnable') -or $key.GetValue('ProxyServer') -ne 'original.invalid:80') {
        throw 'Restore did not preserve the original registry values.'
    }
    foreach ($stage in @('journal-only', 'address-written')) {
        Enable-SystemProxy
        $key.DeleteValue('ProxyEnable', $false)
        if ($stage -eq 'journal-only') {
            $key.SetValue('ProxyServer', 'original.invalid:80', 'String')
        }
        Restore-SystemProxy
        if (($key.GetValueNames() -contains 'ProxyEnable') -or
            $key.GetValue('ProxyServer') -ne 'original.invalid:80' -or [IO.File]::Exists($proxyJournal)) {
            throw "Interrupted state did not recover: $stage"
        }
    }
    $key.SetValue('ProxyEnable', 0, 'DWord')
    Enable-SystemProxy
    Restore-SystemProxy
    if ($key.GetValue('ProxyEnable', -1) -ne 0 -or $key.GetValue('ProxyServer') -ne 'original.invalid:80') {
        throw 'Restore did not preserve an explicit disabled setting.'
    }
    $key.SetValue('ProxyEnable', -1, 'DWord')
    $invalidFlag = $false
    try { Enable-SystemProxy } catch { $invalidFlag = $true }
    if (!$invalidFlag -or $key.GetValue('ProxyEnable') -ne -1 -or [IO.File]::Exists($proxyJournal)) {
        throw 'An unsupported registry flag was treated as a missing value.'
    }
    $key.DeleteValue('ProxyEnable')
    Enable-SystemProxy
    $key.SetValue('ProxyEnable', '1', 'String')
    $typeConflict = $false
    try { Restore-SystemProxy } catch { $typeConflict = $true }
    if (!$typeConflict -or $key.GetValueKind('ProxyEnable') -ne 'String' -or
        ![IO.File]::Exists($proxyJournal)) {
        throw 'An externally changed registry type was overwritten.'
    }
    $key.SetValue('ProxyEnable', 1, 'DWord')
    Restore-SystemProxy
    Enable-SystemProxy
    $key.SetValue('ProxyServer', 'other.invalid:80', 'String')
    $conflict = $false
    try { Restore-SystemProxy } catch { $conflict = $true }
    if (!$conflict -or $key.GetValue('ProxyServer') -ne 'other.invalid:80' -or ![IO.File]::Exists($proxyJournal)) {
        throw 'Conflicting settings were overwritten or recovery was lost.'
    }
    'System proxy recovery tests passed.'
} finally {
    $key.Dispose()
    [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree($proxyKeyPath)
    if ([IO.Directory]::Exists($store)) { [IO.Directory]::Delete($store, $true) }
}
