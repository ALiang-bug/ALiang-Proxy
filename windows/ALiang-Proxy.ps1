[CmdletBinding()]
param([switch]$VerifyUI)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Security

$core = Join-Path $PSScriptRoot 'proxy-core.exe'
$store = Join-Path $env:LOCALAPPDATA 'ALiangProxy'
$profile = Join-Path $store 'profile.dpapi'
$script:yaml = $null
$script:subscription = ''
$script:process = $null
$utf8 = New-Object System.Text.UTF8Encoding($false, $true)
. (Join-Path $PSScriptRoot 'SystemProxy.ps1')
if (!$VerifyUI) {
    [void][IO.Directory]::CreateDirectory($store)
    try {
        $instanceLock = [IO.File]::Open((Join-Path $store 'instance.lock'), 'OpenOrCreate', 'ReadWrite', 'None')
    } catch {
        [void][Windows.Forms.MessageBox]::Show('Another instance is running or the profile folder is unavailable.')
        return
    }
}

function Start-CoreRequest([string]$command, [string]$source, [string]$exit, [string]$address = '', [bool]$speed = $false) {
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $core
    $info.Arguments = $command
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    $info.StandardOutputEncoding = $utf8
    $process = [Diagnostics.Process]::Start($info)
    if ($command -eq 'check-tun') { return $process }
    try {
        $request = @{ YAML = $source; Exit = $exit; Port = 17890; URL = $address; Speed = $speed }
        if ($command -in @('run', 'probe')) {
            $request.Resolver = $resolverIDs[$resolverPicker.SelectedIndex]
        }
        if ($command -eq 'run' -and $memberPicker.SelectedIndex -gt 0) {
            $request.Group = $exit
            $request.Member = [string]$memberPicker.SelectedItem
        }
        $json = $request | ConvertTo-Json -Compress
        $bytes = $utf8.GetBytes($json + "`n")
        $process.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length)
        $process.StandardInput.BaseStream.Flush()
        return $process
    } catch {
        try { if (!$process.HasExited) { $process.Kill() } } finally { $process.Dispose() }
        throw
    }
}

function Send-Core([string]$command, [string]$source, [string]$exit, [string]$address = '') {
    $process = Start-CoreRequest $command $source $exit $address
    try {
        $read = $process.StandardOutput.ReadLineAsync()
        if (!$read.Wait(10000) -or !$read.Result) { throw 'Core did not respond.' }
        $result = ConvertFrom-Json $read.Result
        if ($command -eq 'run') {
            if (!$result.ready) { throw 'Proxy failed to start.' }
            $script:process = $process
            return
        }
        return $result
    } finally {
        if ($script:process -ne $process) {
            if (!$process.HasExited) { $process.Kill() }
            $process.Dispose()
        }
    }
}

function Stop-Core {
    $restoreFailed = $false
    try { Restore-SystemProxy } catch { $restoreFailed = $true }
    if (!$script:process) {
        if ($restoreFailed) { $status.Text = 'Recovery pending. Check Windows proxy settings.' }
        return
    }
    $stopMessage = 'Local proxy stopped.'
    try {
        if ($script:process.HasExited) {
            $stopMessage = 'The proxy core exited unexpectedly.'
        } else {
            $script:process.StandardInput.Close()
            if (!$script:process.WaitForExit(4000)) {
                $script:process.Kill()
                if (!$script:process.WaitForExit(2000)) { throw 'Core is still running.' }
                $stopMessage = 'The proxy core required forced termination.'
            } elseif ($script:process.ExitCode -ne 0) {
                $stopMessage = 'The proxy core reported a shutdown error.'
            }
        }
    } catch {
        $stopMessage = 'Could not confirm the proxy core stopped.'
    }
    if ($script:process.HasExited) {
        $script:process.Dispose()
        $script:process = $null
    }
    $status.Text = if ($restoreFailed) { 'Recovery pending. Check Windows proxy settings.' } else { $stopMessage }
}

function Save-Profile([string]$source, [string]$address, [string]$exitTag, [string]$memberTag = '') {
    [IO.Directory]::CreateDirectory($store) | Out-Null
    $payload = @{
        yaml = $source; url = $address; exit = $exitTag; member = $memberTag
        resolver = $resolverIDs[$resolverPicker.SelectedIndex]
    } | ConvertTo-Json -Compress
    $encrypted = [Security.Cryptography.ProtectedData]::Protect($utf8.GetBytes($payload), $null, 'CurrentUser')
    $pending = Join-Path $store ([Guid]::NewGuid().ToString() + '.tmp')
    try {
        [IO.File]::WriteAllBytes($pending, $encrypted)
        if ([IO.File]::Exists($profile)) { [IO.File]::Replace($pending, $profile, $null) }
        else { [IO.File]::Move($pending, $profile) }
    } finally {
        if ([IO.File]::Exists($pending)) { [IO.File]::Delete($pending) }
    }
}

function Set-Profile([string]$source, [bool]$save, [string]$address = '', [string]$preferredExit = '', [string]$preferredMember = '') {
    $entries = @(Send-Core 'inspect' $source '')
    if (!$entries.Count) { throw 'No supported node found.' }
    $tags = [string[]]@($entries | ForEach-Object { [string]$_.tag })
    if (!$preferredExit) {
        $preferredExit = [string]$nodes.SelectedItem
        if ($memberPicker.SelectedIndex -gt 0) { $preferredMember = [string]$memberPicker.SelectedItem }
    }
    $index = [Array]::IndexOf($tags, $preferredExit)
    if ($index -lt 0) {
        $default = $entries | Where-Object { $_.defaultExit } | Select-Object -First 1
        $index = [Math]::Max(0, [Array]::IndexOf($tags, [string]$default.tag))
    }
    if ($tags[$index] -cne $preferredExit -or $preferredMember -cnotin @($entries[$index].outbounds)) {
        $preferredMember = ''
    }
    if ($save) { Save-Profile $source $address $tags[$index] $preferredMember }
    $script:yaml = $source
    $script:subscription = $address
    $script:loadingNodes = $true
    try {
        $script:exitEntries = $entries
        $nodes.Items.Clear()
        $nodes.Items.AddRange($tags)
        $nodes.SelectedIndex = $index
        Update-MemberPicker $preferredMember
    } finally { $script:loadingNodes = $false }
    $status.Text = "Loaded $($entries.Count) nodes and groups"
}

function Restore-SavedProfile {
    if ((Get-Item -LiteralPath $profile).Length -gt 8MB) { throw 'Saved profile is too large.' }
    $plain = [Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($profile), $null, 'CurrentUser')
    $decoded = $utf8.GetString($plain)
    if ($decoded.TrimStart().StartsWith('{')) {
        try { $saved = ConvertFrom-Json $decoded } catch { $saved = $null }
        if ($null -ne $saved -and $saved.PSObject.Properties['yaml']) {
            $resolverPicker.SelectedIndex = [Math]::Max(0, [Array]::IndexOf($resolverIDs, [string]$saved.resolver))
            Set-Profile ([string]$saved.yaml) $false ([string]$saved.url) ([string]$saved.exit) ([string]$saved.member)
            return
        }
    }
    Set-Profile $decoded $false
}

$window = New-Object Windows.Forms.Form
$window.Text = 'ALiang Proxy'
$window.ClientSize = New-Object Drawing.Size(760, 680)
$window.StartPosition = 'CenterScreen'
$window.FormBorderStyle = 'FixedDialog'
$window.MaximizeBox = $false
$window.AutoScaleMode = 'Dpi'
$window.AutoScroll = $true
$window.MaximumSize = [Windows.Forms.Screen]::PrimaryScreen.WorkingArea.Size
$window.Font = New-Object Drawing.Font('Segoe UI', 10)

function Get-UIColor([string]$hex) {
    [Drawing.ColorTranslator]::FromHtml($hex)
}

function Set-ButtonStyle($button, [bool]$primary = $false) {
    $button.UseVisualStyleBackColor = $false
    $button.FlatStyle = 'Flat'
    $button.FlatAppearance.BorderColor = Get-UIColor '#38556E'
    $button.FlatAppearance.MouseOverBackColor = Get-UIColor '#325C78'
    $button.FlatAppearance.MouseDownBackColor = Get-UIColor '#164C68'
    $button.BackColor = if ($primary) { Get-UIColor '#006B86' } else { Get-UIColor '#20384E' }
    $button.ForeColor = Get-UIColor '#F2F7FC'
    $button.Cursor = [Windows.Forms.Cursors]::Hand
}

function New-Control($type, $label, $x, $y, $w, $h) {
    $control = New-Object "Windows.Forms.$type"
    $control.Text = $label
    $control.SetBounds($x, $y, $w, $h)
    $window.Controls.Add($control)
    if ($type -eq 'Button') { Set-ButtonStyle $control }
    if ($type -in @('ComboBox', 'TextBox')) {
        $control.BackColor = Get-UIColor '#20384E'
        $control.ForeColor = Get-UIColor '#F2F7FC'
    }
    if ($type -eq 'Label') { $control.BackColor = $window.BackColor }
    return $control
}

function Add-Section([string]$title, [int]$top) {
    $heading = New-Control Label $title 42 ($top + 12) 370 26
    $heading.Font = New-Object Drawing.Font('Segoe UI Semibold', 12)
    $heading.ForeColor = Get-UIColor '#8AD8EE'
}

$window.BackColor = Get-UIColor '#101C2B'
$window.ForeColor = Get-UIColor '#F2F7FC'
$title = New-Control Label 'ALiang Proxy' 24 15 455 38
$title.BackColor = $window.BackColor
$title.Font = New-Object Drawing.Font('Segoe UI Semibold', 23)
$endpoint = New-Control Label 'Local endpoint   127.0.0.1:17890   |   HTTP / SOCKS5' 26 58 700 24
$endpoint.BackColor = $window.BackColor
$endpoint.ForeColor = Get-UIColor '#AFC8DC'

Add-Section 'Subscription' 98
$import = New-Control Button 'Import Clash YAML' 42 169 166 31
$update = New-Control Button 'Update subscription' 218 169 168 31
$null = New-Control Label 'HTTPS address' 42 139 121 24
$urlBox = New-Control TextBox '' 166 137 402 28
$urlBox.UseSystemPasswordChar = $true
$urlBox.AccessibleName = 'HTTPS subscription address'
$urlBox.MaxLength = 8192
$download = New-Control Button 'Import HTTPS' 580 134 137 32
Set-ButtonStyle $download $true

Add-Section 'Proxy connection' 224
$null = New-Control Label 'Default exit' 42 269 126 26
$nodes = New-Control ComboBox '' 178 265 539 30
$nodes.AccessibleName = 'Default exit'
$nodes.DropDownStyle = 'DropDownList'
$null = New-Control Label 'Group member' 42 306 126 26
$memberPicker = New-Control ComboBox '' 178 302 539 30
$memberPicker.AccessibleName = 'Group member'
$memberPicker.DropDownStyle = 'DropDownList'
$memberPicker.Enabled = $false
$null = New-Control Label 'Node DNS' 42 343 126 26
$resolverPicker = New-Control ComboBox '' 178 339 539 30
$resolverPicker.AccessibleName = 'Node DNS'
$resolverPicker.DropDownStyle = 'DropDownList'
$resolverPicker.Items.AddRange([object[]]@('System DNS', 'AliDNS (DoH)', 'Cloudflare (DoH)'))
$resolverIDs = @('system', 'ali', 'cloudflare')
$resolverPicker.SelectedIndex = 0
$start = New-Control Button 'Start local proxy' 42 391 155 41
Set-ButtonStyle $start $true
$stop = New-Control Button 'Stop local proxy' 207 391 153 41
$systemOn = New-Control Button 'Enable Windows proxy' 370 391 170 41
$systemOff = New-Control Button 'Restore Windows proxy' 550 391 167 41

Add-Section 'TUN tunnel' 468
$null = New-Control Label 'Routes traffic through a virtual adapter.' 42 507 308 25
$tunnel = New-Control Button 'Start TUN' 425 491 88 39
$tunnelOff = New-Control Button 'Stop TUN' 519 491 88 39
$tunnelCheck = New-Control Button 'Check internet' 613 491 104 39
$tunnelOff.Enabled = $false
$tunnelCheck.Enabled = $false
$tunnel.AccessibleDescription = 'Starts the bundled tunnel after Windows administrator approval.'

Add-Section 'Node performance' 563
$probeButton = New-Control Button 'Batch node tests' 514 573 203 39
$status = New-Control Label 'Import a local file or HTTPS subscription' 26 635 710 40
$status.BackColor = $window.BackColor
$status.ForeColor = Get-UIColor '#B8DAEA'
$script:loadingNodes = $false
$script:exitEntries = @()
function Update-MemberPicker([string]$preferred = '') {
    $memberPicker.Items.Clear()
    $memberPicker.Enabled = $false
    if ($nodes.SelectedIndex -lt 0) { return }
    $entry = $script:exitEntries[$nodes.SelectedIndex]
    if ($entry.type -ne 'selector') { return }
    [void]$memberPicker.Items.Add('Use subscription default')
    foreach ($member in $entry.outbounds) { [void]$memberPicker.Items.Add([string]$member) }
    $memberPicker.SelectedIndex = 0
    for ($i = 1; $i -lt $memberPicker.Items.Count; $i++) {
        if ($memberPicker.Items[$i] -ceq $preferred) { $memberPicker.SelectedIndex = $i; break }
    }
    $memberPicker.Enabled = $true
}
function Save-ExitSelection {
    if ($script:loadingNodes -or !$script:yaml -or $nodes.SelectedIndex -lt 0) { return }
    $member = if ($memberPicker.SelectedIndex -gt 0) { [string]$memberPicker.SelectedItem } else { '' }
    try {
        Save-Profile $script:yaml $script:subscription ([string]$nodes.SelectedItem) $member
        $status.Text = 'Default exit saved for the next connection.'
    } catch { $status.Text = 'The selected exit could not be saved.' }
}
$nodes.Add_SelectedIndexChanged({
    if ($script:loadingNodes -or !$script:yaml -or $nodes.SelectedIndex -lt 0) { return }
    $script:loadingNodes = $true
    try { Update-MemberPicker } finally { $script:loadingNodes = $false }
    Save-ExitSelection
})
$memberPicker.Add_SelectedIndexChanged({ Save-ExitSelection })
$resolverPicker.Add_SelectedIndexChanged({ Save-ExitSelection })
$script:tunnelProcess = $null
$script:tunnelStop = $null
$script:tunnelReady = $null
$script:tunnelStopping = $false
$script:tunnelClosePending = $false
$script:tunnelCheckProcess = $null
$script:tunnelCheckRead = $null
$tunnelBlockedControls = @($urlBox, $import, $update, $download, $nodes, $memberPicker,
    $resolverPicker, $start, $stop, $systemOn, $systemOff, $probeButton, $tunnel)

function Clear-TunnelCheck {
    if (!$script:tunnelCheckProcess) { return }
    try {
        if (!$script:tunnelCheckProcess.HasExited) { $script:tunnelCheckProcess.Kill() }
    } catch {
        # The check can finish between HasExited and Kill.
    } finally {
        $script:tunnelCheckProcess.Dispose()
        $script:tunnelCheckProcess = $null
        $script:tunnelCheckRead = $null
    }
}

function Request-TunnelStop {
    if (!$script:tunnelProcess -or $script:tunnelStopping) { return }
    $script:tunnelStopping = $true
    $tunnelOff.Enabled = $false
    $tunnelCheck.Enabled = $false
    Clear-TunnelCheck
    $status.Text = 'Stopping TUN and checking route recovery...'
    [void]$script:tunnelStop.Set()
}

function Update-TunnelStatus {
    if (!$script:tunnelProcess) { return }
    if ($script:tunnelProcess.HasExited) {
        Clear-TunnelCheck
        $code = $script:tunnelProcess.ExitCode
        $wasReady = $script:tunnelReady.WaitOne(0)
        $script:tunnelProcess.Dispose()
        $script:tunnelStop.Dispose()
        $script:tunnelReady.Dispose()
        $script:tunnelProcess = $null
        $script:tunnelStop = $null
        $script:tunnelReady = $null
        $script:tunnelStopping = $false
        $tunnelOff.Enabled = $false
        $tunnelCheck.Enabled = $false
        foreach ($control in $script:tunnelControlStates.Keys) {
            $control.Enabled = $script:tunnelControlStates[$control]
        }
        $status.Text = switch ($code) {
            0 { if ($wasReady) { 'TUN stopped. Default routes match their pre-TUN state.' } else { 'TUN startup cancelled.' } }
            2 { 'TUN could not start or the core exited. Check Windows networking and other VPNs.' }
            default { 'Route recovery could not be confirmed. Check Windows networking before reconnecting.' }
        }
        if ($script:tunnelClosePending) {
            $script:tunnelClosePending = $false
            if ($code -eq 0) { $window.Close() }
        }
    } elseif (!$script:tunnelStopping -and $tunnel.Text -ne 'TUN running' -and $script:tunnelReady.WaitOne(0)) {
        $tunnel.Text = 'TUN running'
        $tunnelCheck.Enabled = $true
        $status.Text = 'TUN routes active. Use Check internet to test DNS and HTTPS.'
    }
    if (!$script:tunnelProcess) { $tunnel.Text = 'Start TUN' }
    if ($script:tunnelCheckRead -and $script:tunnelCheckRead.IsCompleted) {
        try {
            $result = ConvertFrom-Json $script:tunnelCheckRead.Result
            if (!$result -or $result.dns -isnot [bool] -or $result.https -isnot [bool] -or
                $result.tunnelDns -isnot [bool]) {
                throw 'Missing check result.'
            }
            $status.Text = if (!$result.dns -and $result.tunnelDns) {
                'TUN check: Tunnel DNS answered, but Windows system DNS failed.'
            } elseif (!$result.dns) {
                'TUN check: Windows and the IPv4 tunnel DNS returned no usable address.'
            } elseif (!$result.https) {
                'TUN check: DNS lookup succeeded, but HTTPS did not complete.'
            } else {
                'TUN check: DNS lookup and HTTPS succeeded.'
            }
        } catch { $status.Text = 'Could not complete the TUN internet check.' }
        finally {
            Clear-TunnelCheck
            $tunnelCheck.Enabled = $true
        }
    }
}

$tunnel.Add_Click({
    if ($script:tunnelProcess -or !$script:yaml -or $null -eq $nodes.SelectedItem -or
        ![IO.File]::Exists($profile) -or $script:process -or [IO.File]::Exists($proxyJournal)) {
        $status.Text = 'Save a profile, stop the local proxy and restore Windows proxy settings first.'
        return
    }
    $tunnelDNS = switch ($resolverPicker.SelectedIndex) {
        1 { 'AliDNS DoH for node and application DNS' }
        2 { 'Cloudflare DoH for node and application DNS' }
        default { 'System DNS for nodes and Cloudflare DoH through the selected exit for application DNS' }
    }
    $prompt = "TUN temporarily changes Windows routes and uses $tunnelDNS. Close other VPNs first. Windows will ask for administrator approval. Continue?"
    if ([Windows.Forms.MessageBox]::Show($window, $prompt, 'Start TUN', 'OKCancel') -ne 'OK') { return }
    try {
        $id = [Guid]::NewGuid().ToString('N')
        $script:tunnelStop = New-Object Threading.EventWaitHandle($false, 'ManualReset', "Local\ALiangTunStop-$id")
        $script:tunnelReady = New-Object Threading.EventWaitHandle($false, 'ManualReset', "Local\ALiangTunReady-$id")
        $owner = [Diagnostics.Process]::GetCurrentProcess()
        try { $ownerTicks = $owner.StartTime.ToUniversalTime().Ticks } finally { $owner.Dispose() }
        $pathData = [Convert]::ToBase64String($utf8.GetBytes((Join-Path $PSScriptRoot 'Test-Tunnel.ps1')))
        $exitData = [Convert]::ToBase64String($utf8.GetBytes([string]$nodes.SelectedItem))
        $command = @'
$ErrorActionPreference = 'Stop'
try {{
    $scriptPath = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{0}'))
    $exitNode = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{1}'))
    & $scriptPath -SavedProfile -ExitNode $exitNode -ApplyTunnel -OwnerPid {2} -OwnerStartTicks {3} -EventId '{4}'
    exit 0
}} catch {{
    if ($_.Exception.Data.Contains('ALiangTunnelCleanup')) {{ exit 3 }}
    exit 2
}}
'@ -f $pathData, $exitData, $PID, $ownerTicks, $id
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
        $script:tunnelControlStates = @{}
        foreach ($control in $tunnelBlockedControls) { $script:tunnelControlStates[$control] = $control.Enabled }
        $script:tunnelProcess = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -Verb RunAs -WindowStyle Hidden -PassThru -ArgumentList @(
            '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-EncodedCommand', $encoded
        )
    } catch {
        if ($script:tunnelStop) { $script:tunnelStop.Dispose(); $script:tunnelStop = $null }
        if ($script:tunnelReady) { $script:tunnelReady.Dispose(); $script:tunnelReady = $null }
        $status.Text = 'TUN could not request administrator access.'
        return
    }
    foreach ($control in $tunnelBlockedControls) { $control.Enabled = $false }
    $tunnel.Text = 'Starting...'
    $tunnelOff.Enabled = $true
    $status.Text = 'Starting TUN and checking Windows routes...'
})
$tunnelOff.Add_Click({ Request-TunnelStop })
$tunnelCheck.Add_Click({
    if (!$script:tunnelProcess -or $script:tunnelProcess.HasExited -or $script:tunnelStopping -or
        !$script:tunnelReady.WaitOne(0) -or $script:tunnelCheckProcess) { return }
    $prompt = 'Resolve www.apple.com through Windows DNS and, if needed, through the virtual tunnel DNS server? If Windows DNS succeeds, one HTTPS request will also be made.'
    if ([Windows.Forms.MessageBox]::Show($window, $prompt, 'Check TUN internet', 'OKCancel') -ne 'OK') { return }
    if (!$script:tunnelProcess -or $script:tunnelProcess.HasExited -or $script:tunnelStopping) { return }
    try {
        $script:tunnelCheckProcess = Start-CoreRequest 'check-tun' '' ''
        $script:tunnelCheckRead = $script:tunnelCheckProcess.StandardOutput.ReadLineAsync()
        $tunnelCheck.Enabled = $false
        $status.Text = 'Checking Windows DNS and HTTPS...'
    } catch {
        Clear-TunnelCheck
        $status.Text = 'Could not start the TUN internet check.'
    }
})
. (Join-Path $PSScriptRoot 'NodeTests.ps1')
$probeButton.Add_Click({ Show-NodeTests })

function Import-Subscription([string]$address) {
    if ($script:process -or !$address) { return }
    $window.UseWaitCursor = $true
    try {
        $result = Send-Core 'download' '' '' $address
        Set-Profile ([string]$result.yaml) $true $address
    } catch {
        $status.Text = 'Subscription import failed. Existing profile kept.'
    } finally {
        $window.UseWaitCursor = $false
    }
}

$download.Add_Click({
    $address = $urlBox.Text.Trim()
    $urlBox.Clear()
    Import-Subscription $address
})
$update.Add_Click({
    if (!$script:subscription) { $status.Text = 'Import an HTTPS subscription first.'; return }
    Import-Subscription $script:subscription
})

$import.Add_Click({
    if ($script:process) { return }
    $dialog = New-Object Windows.Forms.OpenFileDialog
    $dialog.Filter = 'Clash YAML (*.yaml;*.yml)|*.yaml;*.yml'
    try {
        if ($dialog.ShowDialog() -ne 'OK') { return }
        if ((Get-Item -LiteralPath $dialog.FileName).Length -gt 1MB) { throw 'Profile too large.' }
        Set-Profile ($utf8.GetString([IO.File]::ReadAllBytes($dialog.FileName)).TrimStart([char]0xFEFF)) $true
    } catch { $status.Text = 'Import failed. Check the YAML and supported protocols.' }
    finally { $dialog.Dispose() }
})
$start.Add_Click({
    if ($script:process -or !$script:yaml -or $nodes.SelectedIndex -lt 0) { return }
    try {
        Send-Core 'run' $script:yaml $nodes.SelectedItem
        $status.Text = 'Local proxy listening. Configure your browser to use it.'
    } catch { $status.Text = 'Could not start the proxy. Check port 17890.' }
})
$stop.Add_Click({ Stop-Core })
$systemOn.Add_Click({
    if (!$script:process -or $script:process.HasExited) {
        $status.Text = 'Start the local proxy first.'
        return
    }
    if ([IO.File]::Exists($proxyJournal)) {
        $status.Text = 'A Windows proxy recovery record already exists.'
        return
    }
    try {
        Enable-SystemProxy
        $status.Text = 'Windows proxy enabled for the current user.'
    } catch {
        try { Restore-SystemProxy } catch { }
        $status.Text = 'Could not enable Windows proxy. Check existing settings.'
    }
})
$systemOff.Add_Click({
    try { Restore-SystemProxy; $status.Text = 'Windows proxy recovery complete.' }
    catch { $status.Text = 'Recovery pending. Check Windows proxy settings.' }
})
$window.Add_FormClosing({
    param($sender, $eventArgs)
    if ($script:tunnelProcess) {
        $eventArgs.Cancel = $true
        $script:tunnelClosePending = $true
        Request-TunnelStop
        return
    }
    Stop-Core
    if ($script:process) { $eventArgs.Cancel = $true }
})
$timer = New-Object Windows.Forms.Timer
$timer.Interval = 500
$timer.Add_Tick({
    Update-TunnelStatus
    if ($script:process -and $script:process.HasExited) {
        Stop-Core
    }
})
if ($VerifyUI) {
    $store = Join-Path ([IO.Path]::GetTempPath()) ('aliang-ui-' + [Guid]::NewGuid().ToString('N'))
    $profile = Join-Path $store 'profile.dpapi'
    try {
        if ($window.Handle -eq [IntPtr]::Zero) { throw 'WinForms window handle was not created.' }
        if ($resolverPicker.Items.Count -ne 3) { throw 'Expected DNS options were not created.' }
        foreach ($action in @($download, $start, $systemOn, $tunnel, $tunnelOff, $tunnelCheck, $probeButton)) {
            if (!$window.Controls.Contains($action)) { throw "Missing control: $($action.Text)" }
            $position = $window.Controls.GetChildIndex($action)
            for ($i = 0; $i -lt $position; $i++) {
                if ($action.Bounds.IntersectsWith($window.Controls[$i].Bounds)) {
                    throw "A control covers the $($action.Text) button."
                }
            }
        }
        $fixture = @'
proxies:
  - name: test-node
    type: trojan
    server: 127.0.0.1
    port: 9
    password: offline-fixture
proxy-groups:
  - name: test-group
    type: select
    proxies: [test-node]
rules:
  - MATCH,test-group
'@
        $resolverPicker.SelectedIndex = 1
        Set-Profile $fixture $true '' 'test-group' 'test-node'
        if ($nodes.SelectedItem -cne 'test-group' -or $memberPicker.SelectedItem -cne 'test-node') {
            throw 'Test profile did not select the expected group and member.'
        }
        $script:loadingNodes = $true
        try {
            $resolverPicker.SelectedIndex = 0
            $nodes.SelectedIndex = -1
            $memberPicker.SelectedIndex = -1
        } finally { $script:loadingNodes = $false }
        $script:yaml = $null
        Restore-SavedProfile
        if ($nodes.SelectedItem -cne 'test-group' -or $memberPicker.SelectedItem -cne 'test-node' -or
            $resolverPicker.SelectedIndex -ne 1 -or $script:yaml -cne $fixture) {
            throw 'The encrypted profile did not restore the expected test settings.'
        }
    } finally {
        $timer.Dispose()
        $window.Dispose()
        if ([IO.Directory]::Exists($store)) { [IO.Directory]::Delete($store, $true) }
    }
    return
}
if ([IO.File]::Exists($profile)) {
    try {
        Restore-SavedProfile
    } catch { $status.Text = 'Saved profile unavailable. Import it again.' }
}
$timer.Start()
try { Restore-SystemProxy }
catch { $status.Text = 'Recovery pending. Check Windows proxy settings.' }
try { [void]$window.ShowDialog() }
finally { $timer.Dispose(); $window.Dispose(); $instanceLock.Dispose() }
