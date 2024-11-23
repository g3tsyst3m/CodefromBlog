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


Add-Type @"
using System;
using System.Runtime.InteropServices;

public class User32 {

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetForegroundWindow(IntPtr hWnd);
}
"@

Start-Process "cmd.exe" -ArgumentList "/C start taskschd.msc" -NoNewWindow

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
    [void][System.Windows.Forms.SendKeys]::SendWait("{DOWN}")
    [void][System.Windows.Forms.SendKeys]::SendWait("{DOWN}")
	#[void][System.Windows.Forms.SendKeys]::SendWait("{DOWN}") #this can change depending on your version of win11 (22h2, 23h2, 24h2) 
	[void][System.Windows.Forms.SendKeys]::SendWait("{ENTER}")
	Start-Sleep -Seconds 2
	[void][System.Windows.Forms.SendKeys]::SendWait("{TAB}")
	[void][System.Windows.Forms.SendKeys]::SendWait("{TAB}")
	[void][System.Windows.Forms.SendKeys]::SendWait("{TAB}")
	[void][System.Windows.Forms.SendKeys]::SendWait("{TAB}")
	[void][System.Windows.Forms.SendKeys]::SendWait("{TAB}")
	[void][System.Windows.Forms.SendKeys]::SendWait("{TAB}")
	[void][System.Windows.Forms.SendKeys]::SendWait(" ")
	Start-Sleep -Seconds 1
	[void][System.Windows.Forms.SendKeys]::SendWait("%USERPROFILE%\AppData\Local\Programs\Python\Python313\python.exe %USERPROFILE%\documents\github\elevationstation_local\elev8cli.py{ENTER}")
} else {
    Write-Host "taskschd/mmc is not running."
}

     $form.Close()
