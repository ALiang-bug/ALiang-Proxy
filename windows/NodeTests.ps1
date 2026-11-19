function Show-NodeTests {
    if (!$script:yaml -or $script:process -or [IO.File]::Exists($proxyJournal)) {
        $status.Text = 'Load a profile and stop the proxy before testing.'
        return
    }
    $dialog = New-Object Windows.Forms.Form
    $dialog.Text = 'Batch node tests'
    $dialog.ClientSize = New-Object Drawing.Size(600, 445)
    $dialog.StartPosition = 'CenterParent'
    $dialog.FormBorderStyle = 'FixedDialog'
    $dialog.MaximizeBox = $false
    $dialog.AutoScaleMode = 'Dpi'
    $dialog.Font = $window.Font
    $dialog.BackColor = $window.BackColor
    $dialog.ForeColor = $window.ForeColor
    $items = New-Object Windows.Forms.ListBox
    $items.SetBounds(15, 64, 570, 335)
    $items.HorizontalScrollbar = $true
    $items.BackColor = Get-UIColor '#17283A'
    $items.ForeColor = $dialog.ForeColor
    $dialog.Controls.Add($items)
    $message = New-Object Windows.Forms.Label
    $message.SetBounds(15, 408, 570, 32)
    $message.Text = 'Double-click a successful result to choose that node.'
    $dialog.Controls.Add($message)
    $testButtons = @()
    $state = @{ child = $null; read = $null; rows = (New-Object System.Collections.ArrayList); speed = $false }
    $poll = New-Object Windows.Forms.Timer
    $poll.Interval = 100
    $cleanup = {
        $poll.Stop()
        if ($state.child) {
            try {
                $state.child.StandardInput.Close()
                if (!$state.child.WaitForExit(750)) { $state.child.Kill() }
            } finally { $state.child.Dispose(); $state.child = $null }
        }
        $state.read = $null
        foreach ($button in $testButtons) { $button.Enabled = $true }
    }
    $startTest = {
        param($sender, $eventArgs)
        $speed = [bool]$sender.Tag
        $prompt = if ($speed) { 'Test every node using Cloudflare downloads up to 5 MiB per node?' }
                  else { 'Test every node with a small HTTPS request to Apple?' }
        if ([Windows.Forms.MessageBox]::Show($dialog, $prompt, 'Confirm testing', 'OKCancel') -ne 'OK') { return }
        try {
            $items.Items.Clear()
            $state.rows.Clear()
            $state.speed = $speed
            $state.child = Start-CoreRequest 'probe' $script:yaml '' '' $speed
            $state.read = $state.child.StandardOutput.ReadLineAsync()
            foreach ($button in $testButtons) { $button.Enabled = $false }
            $message.Text = 'Testing nodes one at a time...'
            $poll.Start()
        } catch { & $cleanup; $message.Text = 'Could not start the tests.' }
    }
    foreach ($caption in @('Test latency', 'Test downloads', 'Cancel')) {
        $button = New-Object Windows.Forms.Button
        $button.Text = $caption
        Set-ButtonStyle $button ($caption -eq 'Test latency')
        $button.SetBounds((15 + $dialog.Controls.Count * 135 - 270), 15, 125, 34)
        $dialog.Controls.Add($button)
        if ($caption -eq 'Cancel') {
            $button.Add_Click({ & $cleanup; $message.Text = 'Tests cancelled.' })
        } else {
            $button.Tag = $caption -eq 'Test downloads'
            $button.Add_Click($startTest)
            $testButtons += $button
        }
    }
    $poll.Add_Tick({
        try {
            if (!$state.read.IsCompleted) { return }
            $line = $state.read.Result
            if (!$line) { throw 'Probe stopped without completing.' }
            $row = ConvertFrom-Json $line
            if ($row.done) {
                & $cleanup
                $ordered = if ($state.speed) { $state.rows | Sort-Object mbps -Descending }
                           else { $state.rows | Sort-Object @{ Expression = { if ($_.ok) { $_.ms } else { [long]::MaxValue } } } }
                $items.Items.Clear()
                $state.rows.Clear()
                foreach ($entry in $ordered) {
                    [void]$state.rows.Add($entry)
                    [void]$items.Items.Add([string]$entry.display)
                }
                $message.Text = 'Finished. Double-click a successful result to choose that node.'
                return
            }
            $label = if (!$row.ok) { 'Failed' } elseif ($state.speed) { '{0:F2} MB/s' -f $row.mbps } else { '{0} ms' -f $row.ms }
            Add-Member -InputObject $row -NotePropertyName display -NotePropertyValue ('{0}   {1}' -f $label, $row.tag)
            [void]$state.rows.Add($row)
            [void]$items.Items.Add([string]$row.display)
            $message.Text = 'Tested {0} nodes...' -f $state.rows.Count
            $state.read = $state.child.StandardOutput.ReadLineAsync()
        } catch { & $cleanup; $message.Text = 'The node test process stopped.' }
    })
    $items.Add_DoubleClick({
        $index = $items.SelectedIndex
        if ($index -ge 0 -and $state.rows[$index].ok) {
            $nodes.SelectedItem = [string]$state.rows[$index].tag
            if ($nodes.SelectedIndex -ge 0) { $dialog.Close() }
        }
    })
    try { [void]$dialog.ShowDialog($window) }
    finally { & $cleanup; $poll.Dispose(); $dialog.Dispose() }
}
