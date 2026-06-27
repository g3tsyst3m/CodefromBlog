"""
commander.py - runs on YOUR machine
Requirements: pip install requests

Usage:
  python commander.py [-a AGENT_ID] <command> [args]

Commands:
  execute "whoami"
  download /remote/file.txt [local_name.txt]
  upload local_file.txt /remote/dest.txt
  mcp-start
  mcp-stop
  mcp-status
  mcp-logs
  mcp-setup        (one-time: registers agent with Claude Code)

Agent targeting:
  py commander.py mcp-start                  # uses default AGENT_ID from agent_config.py
  py commander.py -a pc1 mcp-start           # targets agent-pc1.yourdomain.com
  py commander.py -a pc2 execute "whoami"    # targets agent-pc2.yourdomain.com
"""

import os
import subprocess
import sys

import requests
from agent_config import SECRET, DOMAIN, AGENT_ID, LISTENER_URL, MCP_URL


def _urls_for(agent_id):
    return (
        f"https://agent-{agent_id}.{DOMAIN}",
        f"https://mcp-{agent_id}.{DOMAIN}",
    )


def _parse_args():
    args = sys.argv[1:]
    agent_id = AGENT_ID
    listener = LISTENER_URL
    mcp = MCP_URL

    if args and args[0] in ("-a", "--agent"):
        if len(args) < 2:
            print("[!] -a requires an agent ID")
            sys.exit(1)
        agent_id = args[1]
        listener, mcp = _urls_for(agent_id)
        args = args[2:]

    if not args:
        print(__doc__)
        sys.exit(1)

    return agent_id, listener, mcp, args[0].lower(), args[1:]


def execute(listener_url, command):
    print(f"[>] execute: {command}")
    try:
        resp = requests.post(
            f"{listener_url}/execute",
            json={"command": command, "secret": SECRET},
            timeout=70,
        )
        data = resp.json()
        tag = "OK" if data["status"] == "ok" else "ERROR"
        print(f"[{tag}]\n{data['output']}")
    except Exception as e:
        print(f"[!] {e}")


def download(listener_url, remote_path, local_dest=None):
    dest = local_dest or os.path.basename(remote_path)
    print(f"[>] download: {remote_path} -> {dest}")
    try:
        resp = requests.post(
            f"{listener_url}/download",
            json={"path": remote_path, "secret": SECRET},
            stream=True, timeout=120,
        )
        if resp.status_code != 200:
            print(f"[ERROR] {resp.json().get('output', resp.status_code)}")
            return
        with open(dest, "wb") as f:
            for chunk in resp.iter_content(chunk_size=8192):
                f.write(chunk)
        print(f"[OK] Saved to {dest}  ({os.path.getsize(dest):,} bytes)")
    except Exception as e:
        print(f"[!] {e}")


def upload(listener_url, local_path, remote_dest=None):
    dest = remote_dest or os.path.basename(local_path)
    print(f"[>] upload: {local_path} -> {dest}")
    if not os.path.exists(local_path):
        print(f"[!] File not found: {local_path}")
        return
    try:
        with open(local_path, "rb") as f:
            resp = requests.post(
                f"{listener_url}/upload",
                data={"secret": SECRET, "dest": dest},
                files={"file": (os.path.basename(local_path), f)},
                timeout=120,
            )
        data = resp.json()
        tag = "OK" if data["status"] == "ok" else "ERROR"
        print(f"[{tag}] {data['output']}")
    except Exception as e:
        print(f"[!] {e}")


def mcp_start(listener_url, mcp_url):
    print("[>] Starting MCP server on remote machine...")
    try:
        resp = requests.post(
            f"{listener_url}/mcp/start",
            json={"secret": SECRET}, timeout=15,
        )
        data = resp.json()
        status = data.get("status")
        if status in ("started", "already_running"):
            tag = "OK" if status == "started" else "ALREADY RUNNING"
            print(f"[{tag}] MCP server running at: {mcp_url}/mcp")
        else:
            print(f"[ERROR] {data.get('output', data)}")
    except Exception as e:
        print(f"[!] {e}")


def mcp_stop(listener_url):
    print("[>] Stopping MCP server...")
    try:
        resp = requests.post(
            f"{listener_url}/mcp/stop",
            json={"secret": SECRET}, timeout=15,
        )
        print(f"[OK] {resp.json()}")
    except Exception as e:
        print(f"[!] {e}")


def mcp_status(listener_url, mcp_url):
    try:
        resp = requests.post(
            f"{listener_url}/mcp/status",
            json={"secret": SECRET}, timeout=10,
        )
        data = resp.json()
        if data.get("running"):
            print(f"[OK] MCP server is RUNNING - {mcp_url}/mcp")
        else:
            print("[OK] MCP server is NOT running")
    except Exception as e:
        print(f"[!] {e}")


def mcp_logs(listener_url):
    try:
        resp = requests.post(
            f"{listener_url}/mcp/logs",
            json={"secret": SECRET}, timeout=10,
        )
        print(resp.json().get("output", "(empty)"))
    except Exception as e:
        print(f"[!] {e}")


def mcp_setup(agent_id, mcp_url):
    url = f"{mcp_url}/mcp"
    auth_header = f"Authorization:Bearer {SECRET}"
    mcp_name = f"remote-{agent_id}"
    print(f"[>] Registering '{mcp_name}' with Claude Code...")
    subprocess.run(["claude", "mcp", "remove", mcp_name], capture_output=True)
    result = subprocess.run(
        ["claude", "mcp", "add", "--transport", "http",
         mcp_name, url, "--header", auth_header],
        capture_output=True, text=True,
    )
    if result.returncode == 0:
        print(f"[OK] Registered: {url}")
        print("[OK] Restart Claude Code once to connect.")
    else:
        print(f"[!] Registration failed: {result.stderr.strip()}")
        print(f"    Run manually: claude mcp add --transport http {mcp_name} \"{url}\" --header \"{auth_header}\"")


if __name__ == "__main__":
    agent_id, listener, mcp, cmd, extra = _parse_args()

    if cmd == "execute":
        execute(listener, " ".join(extra))
    elif cmd == "download":
        download(listener, extra[0], extra[1] if len(extra) > 1 else None)
    elif cmd == "upload":
        upload(listener, extra[0], extra[1] if len(extra) > 1 else None)
    elif cmd == "mcp-start":
        mcp_start(listener, mcp)
    elif cmd == "mcp-stop":
        mcp_stop(listener)
    elif cmd == "mcp-status":
        mcp_status(listener, mcp)
    elif cmd == "mcp-logs":
        mcp_logs(listener)
    elif cmd == "mcp-setup":
        mcp_setup(agent_id, mcp)
    else:
        print(f"[!] Unknown command: {cmd}")
        print("Available: execute, download, upload, mcp-start, mcp-stop, mcp-status, mcp-logs, mcp-setup")
        sys.exit(1)
