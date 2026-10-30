#!/usr/bin/env python3
"""
ws_listener — WebSocket relay on the VPS (port 8766).

Routes connected WebSocket peers by clientId so the 3-way flow works with
multiple internet clients at once:

    HTML client A (internet) <--> ws_listener (VPS) <--> ws_server.py (local)
    HTML client B (internet) <--> ws_listener (VPS) <--> ws_server.py (local)

Each peer is identified by the clientId it reports in its first
`client_info` frame (HTML clients send a random `c-xxxxxx`; the local
server identifies itself as `server`).

Routing rules for every frame:
  * JSON with a `"to"` field  -> delivered only to the peer whose clientId
                                 matches `"to"`
  * JSON without `"to"`       -> broadcast to every other peer
  * non-JSON                  -> broadcast raw to every other peer

`client_info` frames are forwarded with an extra `_src` field carrying the
peer's real IP (the Cloudflare CF-Connecting-IP header when the peer comes
through the tunnel, otherwise the TCP peer address), so the server can
display internet clients' IP addresses.

When a peer with a known clientId disconnects, the relay broadcasts
`{"type":"peer_left","clientId":...}` so the server can drop its row.

    python ws_listener.py [--host 0.0.0.0] [--port 8766]
"""

import sys
import json
import time
import asyncio
import argparse

from websockets.asyncio.server import serve
from websockets.exceptions import ConnectionClosed


def ts():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def peer_ip(ws):
    """Best-effort real IP of a peer: CF-Connecting-IP behind the tunnel,
    X-Forwarded-For, or the TCP peer address."""
    try:
        h = ws.request.headers
        ip = h.get("CF-Connecting-IP") or h.get("X-Forwarded-For")
        if ip:
            return ip.split(",")[0].strip()
    except Exception:
        pass
    try:
        return str(ws.remote_address[0])
    except Exception:
        return "?"


class Listener:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.by_cid = {}    # clientId -> connection
        self.conn_cid = {}  # connection -> clientId (once known)

    def log(self, msg):
        print(f"[{ts()}] {msg}", flush=True)

    async def handler(self, ws):
        addr = getattr(ws, "remote_address", None) or ("?", 0)
        self.log(f"+ peer {addr[0]}:{addr[1]}  (ids={len(self.by_cid)})")
        try:
            async for raw in ws:
                msg = None
                try:
                    msg = json.loads(raw)
                except Exception:
                    msg = None

                # Learn (or refresh) the peer's clientId and stamp its IP.
                if isinstance(msg, dict) and msg.get("type") == "client_info":
                    cid = (msg.get("info") or {}).get("clientId")
                    if cid and self.conn_cid.get(ws) is None:
                        self.conn_cid[ws] = cid
                        old = self.by_cid.get(cid)
                        if old is not None and old is not ws:
                            try:
                                await old.close(code=4000, reason="replaced")
                            except Exception:
                                pass
                        self.by_cid[cid] = ws
                        self.log(f"  id {cid}  ip={peer_ip(ws)}")
                    msg["_src"] = {"ip": peer_ip(ws)}
                    out = json.dumps(msg)
                else:
                    out = raw

                who = self.conn_cid.get(ws) or f"{addr[0]}:{addr[1]}"

                # Addressed frames go to exactly one peer.
                if isinstance(msg, dict) and msg.get("to") not in (None, "all"):
                    to = msg["to"]
                    target = self.by_cid.get(to)
                    if target is not None and target is not ws:
                        try:
                            await target.send(out)
                            self.log(f"  fwd {who} -> {to} ({len(out)} B)")
                        except Exception:
                            self.log(f"  fwd {who} -> {to} (failed)")
                    else:
                        self.log(f"  drop {who} -> {to} (not connected)")
                    continue

                # Unaddressed frames: broadcast to every other peer.
                n = 0
                for w in list(self.by_cid.values()):
                    if w is ws:
                        continue
                    try:
                        await w.send(out)
                        n += 1
                    except Exception:
                        pass
                self.log(f"  fwd {who} -> all ({n} peer(s), {len(out)} B)")
        except ConnectionClosed:
            pass
        finally:
            cid = self.conn_cid.pop(ws, None)
            if cid and self.by_cid.get(cid) is ws:
                self.by_cid.pop(cid, None)
            self.log(f"- peer {addr[0]}:{addr[1]}  (ids={len(self.by_cid)})")
            if cid:
                frame = json.dumps({"type": "peer_left", "clientId": cid})
                for w in list(self.by_cid.values()):
                    try:
                        await w.send(frame)
                    except Exception:
                        pass
                self.log(f"  notified peers of peer_left {cid}")

    async def run(self):
        async with serve(self.handler, self.host, self.port):
            self.log(f"listening on ws://{self.host}:{self.port}")
            await asyncio.Future()  # run forever


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="ws_console VPS relay")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8766)
    a = ap.parse_args()
    try:
        asyncio.run(Listener(a.host, a.port).run())
    except KeyboardInterrupt:
        pass
