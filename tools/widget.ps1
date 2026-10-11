# KEFAR scanner tray widget
# - tray icon with dynamically drawn battery
# - polls device presence (4 HID nodes) + receiver GET_REPORT (read-only)
# - logs payload history to CSV so the battery byte can be identified over time
# - balloon alerts on device loss / payload change / low battery
#
# Run: powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File widget.ps1

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

# ---------------------------------------------------------------- single instance
$mutex = New-Object System.Threading.Mutex($false, 'Global\KEFAR_Widget')
if (-not $mutex.WaitOne(0)) { exit }

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class KHid {
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern IntPtr CreateFile(string n, uint a, uint s, IntPtr sec, uint d, uint f, IntPtr t);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr h);
    [DllImport("hid.dll", SetLastError=true)]
    public static extern bool HidD_GetFeature(IntPtr h, byte[] buf, uint len);
}
'@

# ---------------------------------------------------------------- config
$RecvIid  = 'HID\VID_FFFF&PID_0035&MI_01\8&1E31879B&0&0000'
# receiver nodes = CRITICAL (radio link); scanner wired nodes = charging indicator
$CriticalNodes = @(
    @{ name = 'приёмник/клавиатура'; iid = 'HID\VID_FFFF&PID_0035&MI_00\8&66DFB56&0&0000' },
    @{ name = 'приёмник/vendor';     iid = 'HID\VID_FFFF&PID_0035&MI_01\8&1E31879B&0&0000' }
)
$WiredNodes = @(
    @{ name = 'сканер USB/клавиатура'; iid = 'HID\VID_FFFF&PID_0035&MI_00\8&18C5A530&0&0000' },
    @{ name = 'сканер USB/vendor';     iid = 'HID\VID_FFFF&PID_0035&MI_01\8&311A06BF&0&0000' }
)
$PollSeconds      = 30
$LogDir           = 'C:\Users\777\scanner_monitor'
$PayloadLog       = Join-Path $LogDir 'payload_history.csv'
$MaxLogLines      = 5000
$ReportLen        = 256
$BatteryOffset    = 8      # candidate byte in the 15-byte transfer (0-based)
$BatteryConfirmed = $false  # flip to $true once the mapping is proven

function Read-ReceiverPayload {
    $parts = $RecvIid.Split([char]0x5C)
    $path = '\\?\HID#' + $parts[1] + '#' + $parts[2] + '#{4D1E55B2-F16F-11CF-88CB-001111000030}'
    $h = [KHid]::CreateFile($path, [uint32]0, 3, [IntPtr]::Zero, 3, 0, [IntPtr]::Zero)
    if ($h -eq [IntPtr]::MinusOne -or $h -eq [IntPtr]::Zero) { return $null }
    $buf = New-Object byte[] $ReportLen
    for ($i = 0; $i -lt $ReportLen; $i++) { $buf[$i] = 0x55 }
    $buf[0] = 1
    $ok = [KHid]::HidD_GetFeature($h, $buf, $ReportLen)
    [void][KHid]::CloseHandle($h)
    if (-not $ok) { return $null }
    $last = -1
    for ($i = 1; $i -lt $ReportLen; $i++) { if ($buf[$i] -ne 0x55) { $last = $i } }
    if ($last -lt 0) { return $null }
    return ,$buf[0..$last]
}

function Get-NodeHealth {
    foreach ($n in ($CriticalNodes + $WiredNodes)) {
        $d = Get-PnpDevice -InstanceId $n.iid -ErrorAction SilentlyContinue
        if (-not $d -or -not $d.Present) { $n.present = $false; $n.status = 'absent' }
        else { $n.present = $true; $n.status = $d.Status }
    }
    $missing = @($CriticalNodes | Where-Object { -not $_.present })
    $errored = @($CriticalNodes | Where-Object { $_.present -and $_.status -ne 'OK' })
    $wired   = @($WiredNodes | Where-Object { $_.present })
    return @{ missing = $missing; errored = $errored; wired = $wired }
}

function Append-Log([string]$hex) {
    $line = '{0},{1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $hex
    if (Test-Path $PayloadLog) {
        $all = @(Get-Content $PayloadLog -ErrorAction SilentlyContinue) + $line
        if ($all.Count -gt $MaxLogLines) { $all = $all[-$MaxLogLines..-1] }
        Set-Content -Path $PayloadLog -Value $all -Encoding ASCII
    } else {
        Set-Content -Path $PayloadLog -Value $line -Encoding ASCII
    }
}

# ---------------------------------------------------------------- icon cache
function New-BatteryIcon([int]$pct, [bool]$unknown) {
    $bmp = New-Object System.Drawing.Bitmap 16, 16
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'
    $g.Clear([System.Drawing.Color]::Transparent)
    $pen = New-Object System.Drawing.Pen ([System.Drawing.Color]::White), 1
    $g.DrawRectangle($pen, 1, 4, 12, 8)
    $g.FillRectangle([System.Drawing.Brushes]::White, 13, 6, 2, 4)
    if ($unknown) {
        $f = New-Object System.Drawing.Font 'Segoe UI', 7, ([System.Drawing.FontStyle]::Bold)
        $g.DrawString('?', $f, [System.Drawing.Brushes]::Orange, 4, 3)
        $f.Dispose()
    } elseif ($pct -gt 0) {
        $col = if ($pct -gt 50) { [System.Drawing.Color]::LimeGreen }
               elseif ($pct -gt 20) { [System.Drawing.Color]::Orange }
               else { [System.Drawing.Color]::Red }
        $w = [Math]::Max(1, [int][Math]::Round(10 * $pct / 100.0))
        $br = New-Object System.Drawing.SolidBrush $col
        $g.FillRectangle($br, 3, 6, $w, 4)
        $br.Dispose()
    }
    $pen.Dispose()
    $g.Dispose()
    $ico = [System.Drawing.Icon]::FromHandle($bmp.GetHicon())
    $bmp.Dispose()
    return $ico
}

$script:iconsUnknown = New-BatteryIcon 0 $true
$script:iconsPct = @{}
foreach ($p in 0..100) {
    if (($p % 5) -eq 0) { $script:iconsPct[$p] = New-BatteryIcon $p $false }
}
function Icon-For([int]$pct, [bool]$unknown) {
    if ($unknown) { return $script:iconsUnknown }
    $p5 = [int][Math]::Floor($pct / 5) * 5
    return $script:iconsPct[[Math]::Min($p5, 100)]
}

# ---------------------------------------------------------------- tray UI
$ni = New-Object System.Windows.Forms.NotifyIcon
$ni.Visible = $true
$ni.Icon = Icon-For 0 $true
$ni.Text = 'KEFAR: запуск...'

$menu = New-Object System.Windows.Forms.ContextMenuStrip
$miDetails = New-Object System.Windows.Forms.ToolStripMenuItem 'Детали'
$miLog     = New-Object System.Windows.Forms.ToolStripMenuItem 'Открыть лог батареи'
$miExit    = New-Object System.Windows.Forms.ToolStripMenuItem 'Выход'
[void]$menu.Items.Add($miDetails)
[void]$menu.Items.Add($miLog)
[void]$menu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator))
[void]$menu.Items.Add($miExit)
$ni.ContextMenuStrip = $menu

$detailForm = New-Object System.Windows.Forms.Form
$detailForm.Text = 'KEFAR сканер — детали'
$detailForm.Size = New-Object System.Drawing.Size 420, 320
$detailForm.StartPosition = 'CenterScreen'
$detailForm.TopMost = $true
$detailBox = New-Object System.Windows.Forms.TextBox
$detailBox.Multiline = $true
$detailBox.ReadOnly = $true
$detailBox.Font = New-Object System.Drawing.Font 'Consolas', 9
$detailBox.Dock = 'Fill'
$detailBox.ScrollBars = 'Vertical'
[void]$detailForm.Controls.Add($detailBox)

$script:lastPayloadHex = ''
$script:lastBalloonKind = ''

function Show-Balloon([string]$title, [string]$text, [string]$kind) {
    if ($script:lastBalloonKind -eq $kind -and $kind -ne '') { return }
    $script:lastBalloonKind = $kind
    $ni.BalloonTipTitle = $title
    $ni.BalloonTipText = $text
    $ni.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Warning
    $ni.ShowBalloonTip(5000)
}

function Invoke-Poll {
    $h = Get-NodeHealth
    $payload = Read-ReceiverPayload
    $hex = ''
    if ($payload) { $hex = ($payload | ForEach-Object { '{0:X2}' -f $_ }) -join ' ' }

    # battery estimate (candidate byte, honest about confidence)
    $pct = -1
    $unknown = $true
    if ($payload -and $payload.Count -gt $BatteryOffset) {
        $raw = $payload[$BatteryOffset]
        if ($BatteryConfirmed) {
            $pct = [int][Math]::Round(100.0 * $raw / 255.0)
            $unknown = $false
        }
    }

    # payload change detection -> research hook (battery-byte identification)
    if ($hex -ne '') {
        if ($script:lastPayloadHex -eq '') {
            Append-Log ('SESSION-START ' + $hex)
            $script:lastPayloadHex = $hex
        } elseif ($hex -ne $script:lastPayloadHex) {
            Append-Log ('CHANGED from [' + $script:lastPayloadHex + '] to [' + $hex + ']')
            Show-Balloon 'KEFAR: данные изменились' ("payload: " + $hex) 'payload-change'
            $script:lastPayloadHex = $hex
        }
    }

    # device health: only the RECEIVER is critical (it is the radio link)
    if ($h.missing.Count -gt 0) {
        $names = ($h.missing | ForEach-Object { $_.name }) -join ', '
        Show-Balloon 'KEFAR: приёмник отключён' ("Нет узлов: " + $names) 'missing'
    } elseif ($h.errored.Count -gt 0) {
        Show-Balloon 'KEFAR: ошибка приёмника' ($h.errored[0].name + " статус " + $h.errored[0].status) 'error'
    } else {
        $script:lastBalloonKind = ''
    }

    $batText = if ($unknown) { 'батарея: неизвестно' }
               else { ('батарея: {0}%' -f $pct) }
    $recvText = if ($payload) { 'приёмник: отвечает' } else { 'приёмник: НЕТ ОТВЕТА' }
    $scanText = if ($h.wired.Count -gt 0) { 'сканер: USB (зарядка)' } else { 'сканер: по радио' }

    $ni.Icon = Icon-For ([Math]::Max($pct, 0)) $unknown
    $ni.Text = ('KEFAR | ' + $scanText + ' | ' + $recvText)

    $detailBox.Text = ('Время: ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + "`r`n" +
        '-- приёмник (критично) --' + "`r`n" +
        (($CriticalNodes | ForEach-Object { ('{0,-24} {1} [{2}]' -f $_.name, $(if ($_.present) { 'есть' } else { 'НЕТ' }), $_.status) }) -join "`r`n") + "`r`n" +
        '-- сканер USB (зарядка) --' + "`r`n" +
        (($WiredNodes | ForEach-Object { ('{0,-24} {1} [{2}]' -f $_.name, $(if ($_.present) { 'есть' } else { 'НЕТ' }), $_.status) }) -join "`r`n") + "`r`n" +
        "`r`nPayload приёмника (GET_REPORT):`r`n" + $(if ($hex) { $hex } else { 'нет ответа' }) + "`r`n" +
        "`r`nБатарея: " + $batText + $(if (-not $BatteryConfirmed) { " (байт[$BatteryOffset] — гипотеза, ждём дрейфа в логе)" }) + "`r`n" +
        "`r`nЛог: " + $PayloadLog)
}

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = $PollSeconds * 1000
$timer.Add_Tick({ Invoke-Poll })

$miDetails.Add_Click({ Invoke-Poll; [void]$detailForm.Show() })
$miLog.Add_Click({ if (Test-Path $PayloadLog) { Start-Process notepad.exe $PayloadLog } })
$miExit.Add_Click({ $timer.Stop(); $ni.Visible = $false; $ni.Dispose(); [System.Windows.Forms.Application]::Exit() })
$ni.Add_DoubleClick({ Invoke-Poll; [void]$detailForm.Show() })

Invoke-Poll
$timer.Start()
[System.Windows.Forms.Application]::Run()
$mutex.ReleaseMutex()
