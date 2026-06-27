"""
One-time setup script per machine.

Usage:
  py setup_agent.py <agent-id>

Example:
  py setup_agent.py pc1
  py setup_agent.py pc2
  py setup_agent.py office-box

Requires:
  - cloudflared installed and authenticated (run 'cloudflared tunnel login' first)
  - pip install requests
"""

import json
import os
import platform
import re
import subprocess
import sys

DOMAIN        = "yourdomain.com"
SECRET        = "your-secret-key-here"
ENROLL_KEY    = "your-enroll-key-here"
MCP_PORT      = 8765
LISTENER_PORT = 8080


def run(cmd, **kwargs):
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    agent_id       = sys.argv[1].lower().strip()
    tunnel_name    = f"remote-agent-{agent_id}"
    listener_host  = f"agent-{agent_id}.{DOMAIN}"
    mcp_host       = f"mcp-{agent_id}.{DOMAIN}"
    init_host      = f"init-{agent_id}.{DOMAIN}"
    mcp_name       = f"remote-{agent_id}"
    is_windows     = platform.system() == "Windows"
    cf_dir         = os.path.join(os.path.expanduser("~"), ".cloudflared")
    here           = os.path.dirname(os.path.abspath(__file__))

    print(f"\n{'='*60}")
    print(f"  Remote Agent Setup — {agent_id}")
    print(f"{'='*60}")
    print(f"  Tunnel:   {tunnel_name}")
    print(f"  Listener: https://{listener_host}")
    print(f"  Init:     https://{init_host}")
    print(f"  MCP:      https://{mcp_host}/mcp\n")

    # ------------------------------------------------------------------
    # 1. Create cloudflared tunnel
    # ------------------------------------------------------------------
    print("[1/5] Creating cloudflared tunnel...")
    result = run(["cloudflared", "tunnel", "create", tunnel_name])
    if result.returncode != 0:
        if "already exist" in result.stderr.lower():
            print(f"  [OK] Tunnel '{tunnel_name}' already exists")
        else:
            print(f"  [!] Failed: {result.stderr.strip()}")
            sys.exit(1)
    else:
        print(f"  {result.stdout.strip()}")

    # Extract tunnel UUID from credentials files
    tunnel_uuid = None
    creds_path  = None
    for fname in os.listdir(cf_dir):
        if not fname.endswith(".json") or fname == "cert.json":
            continue
        fpath = os.path.join(cf_dir, fname)
        try:
            with open(fpath) as f:
                data = json.load(f)
            if data.get("TunnelID"):
                r = run(["cloudflared", "tunnel", "info", tunnel_name])
                if data["TunnelID"] in r.stdout:
                    tunnel_uuid = data["TunnelID"]
                    creds_path  = fpath
                    break
        except Exception:
            continue

    if not tunnel_uuid:
        r = run(["cloudflared", "tunnel", "info", tunnel_name])
        match = re.search(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", r.stdout)
        if match:
            tunnel_uuid = match.group(0)
            creds_path  = os.path.join(cf_dir, f"{tunnel_uuid}.json")
        else:
            print("  [!] Could not determine tunnel UUID. Check cloudflared tunnel list.")
            sys.exit(1)

    print(f"  [OK] Tunnel UUID: {tunnel_uuid}")
    print(f"  [OK] Credentials: {creds_path}")

    # ------------------------------------------------------------------
    # 2. Write cloudflared config.yml
    # ------------------------------------------------------------------
    print("\n[2/5] Writing cloudflared config.yml...")
    config_path    = os.path.join(cf_dir, "config.yml")
    creds_forward  = creds_path.replace("\\", "/")
    config_content = (
        f"tunnel: {tunnel_uuid}\n"
        f"credentials-file: {creds_forward}\n\n"
        f"ingress:\n"
        f"  - hostname: {mcp_host}\n"
        f"    service: http://localhost:{MCP_PORT}\n"
        f"  - hostname: {init_host}\n"
        f"    service: http://localhost:{LISTENER_PORT}\n"
        f"  - hostname: {listener_host}\n"
        f"    service: http://localhost:{LISTENER_PORT}\n"
        f"  - service: http_status:404\n"
    )
    with open(config_path, "w") as f:
        f.write(config_content)
    print(f"  [OK] Written to {config_path}")

    # ------------------------------------------------------------------
    # 3. Create DNS routes
    # ------------------------------------------------------------------
    print("\n[3/5] Creating DNS routes...")
    for hostname in [listener_host, mcp_host, init_host]:
        r = run(["cloudflared", "tunnel", "route", "dns", tunnel_name, hostname])
        if r.returncode == 0 or "already" in r.stdout.lower() or "already" in r.stderr.lower():
            print(f"  [OK] {hostname}")
        else:
            print(f"  [!] {hostname}: {r.stderr.strip()}")

    # ------------------------------------------------------------------
    # 4. Write agent_config.py
    # ------------------------------------------------------------------
    print("\n[4/5] Writing agent_config.py...")
    config_py = os.path.join(here, "agent_config.py")
    with open(config_py, "w") as f:
        f.write(
            f'AGENT_ID = "{agent_id}"\n\n'
            f'DOMAIN        = "{DOMAIN}"\n'
            f'SECRET        = "{SECRET}"\n'
            f'ENROLL_KEY    = "{ENROLL_KEY}"\n'
            f'MCP_PORT      = {MCP_PORT}\n'
            f'LISTENER_PORT = {LISTENER_PORT}\n\n'
            f'TUNNEL_NAME  = f"remote-agent-{{AGENT_ID}}"\n'
            f'LISTENER_URL = f"https://agent-{{AGENT_ID}}.{{DOMAIN}}"\n'
            f'MCP_URL      = f"https://mcp-{{AGENT_ID}}.{{DOMAIN}}"\n'
            f'INIT_URL     = f"https://init-{{AGENT_ID}}.{{DOMAIN}}"\n'
        )
    print(f"  [OK] AGENT_ID set to '{agent_id}'")

    # ------------------------------------------------------------------
    # 5. Register with Claude Code
    # ------------------------------------------------------------------
    print("\n[5/5] Registering with Claude Code...")
    mcp_url     = f"https://{mcp_host}/mcp"
    auth_header = f"Authorization:Bearer {SECRET}"
    run(["claude", "mcp", "remove", mcp_name])
    r = run(["claude", "mcp", "add", "--transport", "http",
             mcp_name, mcp_url, "--header", auth_header])
    if r.returncode == 0:
        print(f"  [OK] Registered as '{mcp_name}'")
    else:
        print(f"  [!] Registration failed: {r.stderr.strip()}")
        print(f"      Run manually: claude mcp add --transport http {mcp_name} \"{mcp_url}\" --header \"{auth_header}\"")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print(f"\n{'='*60}")
    print(f"  Setup complete for agent '{agent_id}'!")
    print(f"{'='*60}")

    listener_py = os.path.join(here, "listener.py")

    if is_windows:
        bat_path   = os.path.join(here, "start_listener.bat")
        python_exe = sys.executable.replace("python.exe", "pythonw.exe")
        with open(bat_path, "w") as f:
            f.write(f'@echo off\n"{python_exe}" "{listener_py}"\n')

        task_name = f"RemoteAgent-{agent_id}"
        print(f"\n  To auto-start on Windows login, run:")
        print(f'  schtasks /create /tn "{task_name}" /tr "{bat_path}" /sc onlogon /ru {os.getenv("USERNAME","$USER")} /f')
        print(f"\n  Or manually start with:")
        print(f"  py listener.py")
    else:
        print(f"\n  To auto-start on Linux boot:")
        print(f"  systemctl enable listener.service")

    print(f"\n  Start MCP server (from commander machine):")
    print(f"  py commander.py -a {agent_id} mcp-start")
    print(f"\n  Then restart Claude Code: claude --resume")


if __name__ == "__main__":
    main()
