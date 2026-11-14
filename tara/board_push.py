"""Talk to the XiaoZhi board (firmware with TARA Link).

The board keeps one WebSocket open to <public_url>/tara/events (the Tailscale Funnel to this
server), so it works whether or not the board and the laptop share a network. Down that link
this laptop sends:
  - prompts: "task done" and the like, which the board hands to its model at once if idle,
             or at the user's next pause in a conversation
  - audio:   an Ogg Opus URL to play (a spoken message, or the laptop's live sound)
  - call:    join the WhatsApp call this laptop placed
The board acknowledges each one. The link and audio URLs need the shared token or a random
path, so others cannot trigger the board or listen in.
"""
import hmac
import http.server
import json
import os
import queue
import secrets
import shutil
import socket
import subprocess
import tempfile
import threading
import time

import ws_server
from core import ROOT, load_secret

BOARD_CONFIG = os.path.join(ROOT, "board.json")     # {"public_url": "https://<name>.ts.net"}
SERVE_PORT = 8766
FRAME_MS = 20
HEARTBEAT = 10      # seconds between keep-alive messages; the board drops a link silent for 30 s


def board_config():
    with open(BOARD_CONFIG, encoding="utf-8") as f:
        return json.load(f)


def ffmpeg_path():
    return shutil.which("ffmpeg") or "ffmpeg"


class LiveCapture:
    """Laptop speaker output -> mono Ogg Opus bytes, with silence filled in so the stream never stalls."""

    def __init__(self):
        import pyaudiowpatch as pyaudio
        self.pa = pyaudio.PyAudio()
        dev = self.pa.get_default_wasapi_loopback()
        self.rate = int(dev["defaultSampleRate"])
        self.channels = min(2, dev["maxInputChannels"])     # the Realtek loopback reports 8 but opens as stereo
        self.frame_bytes = self.rate * FRAME_MS // 1000 * self.channels * 2
        self.chunks = queue.Queue(maxsize=200)
        self.stopped = threading.Event()
        self.encoder = subprocess.Popen(
            [ffmpeg_path(), "-loglevel", "error", "-f", "s16le", "-ar", str(self.rate), "-ac", str(self.channels),
             "-i", "pipe:0", "-ac", "1", "-ar", "48000", "-c:a", "libopus", "-b:a", "64k",
             "-application", "audio", "-frame_duration", "60", "-page_duration", "100000",
             "-flush_packets", "1", "-f", "ogg", "pipe:1"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW)
        self.stream = self.pa.open(format=pyaudio.paInt16, channels=self.channels, rate=self.rate, input=True,
                                   input_device_index=dev["index"], stream_callback=self._captured,
                                   frames_per_buffer=self.rate * FRAME_MS // 1000)
        threading.Thread(target=self._feed, daemon=True).start()

    def _captured(self, data, frames, info, status):
        try:
            self.chunks.put_nowait(data)
        except queue.Full:
            pass
        import pyaudiowpatch as pyaudio
        return (None, pyaudio.paContinue)

    def _feed(self):
        # WASAPI loopback sends nothing during silence; feed zeros at real-time pace instead.
        silence = bytes(self.frame_bytes)
        next_tick = time.monotonic()
        while not self.stopped.is_set():
            try:
                data = self.chunks.get(timeout=FRAME_MS / 1000)
            except queue.Empty:
                data = silence
            try:
                self.encoder.stdin.write(data)
            except OSError:
                break
            next_tick += FRAME_MS / 1000
            delay = next_tick - time.monotonic()
            if delay > 0 and data is silence:
                time.sleep(delay)
            elif delay < -1:
                next_tick = time.monotonic()

    def read(self, n=4096):
        return self.encoder.stdout.read1(n)

    def close(self):
        self.stopped.set()
        for step in (self.stream.stop_stream, self.stream.close, self.pa.terminate, self.encoder.kill):
            try:
                step()
            except Exception:
                pass


class BoardPush:
    def __init__(self, log=print):
        self.log = log
        self.token = load_secret("board_notify_token.txt")
        self.public_url = board_config().get("public_url", "").rstrip("/")
        self.routes = {}            # random path -> ("file", path) or ("live", None)
        self.live = None
        self.live_path = None
        self.commands = queue.Queue()       # waiting to go down the board's link
        self.acks = {}                      # command id -> [Event, ok, still_needed]
        self.events = None                  # the board's open link (ws_server.WebSocketConn)
        self.direct_call = None             # call_bridge.DirectCall; the board joins calls at /tara/call
        self.on_board_event = None          # set by the bridge: on_board_event(event, text)
        self.on_wake_audio = None           # set by the bridge: on_wake_audio(frames_b64, sample_rate)
        self.on_connect = None              # set by the bridge: called when the board (re)connects
        handler = self._handler()
        # The Tailscale Funnel reaches this server on 127.0.0.1.
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", SERVE_PORT), handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def remote_connected(self):
        return self.events is not None

    def _serve_events(self, ws):
        """Runs for as long as the board's link is open: sends commands, reads acks."""
        old, self.events = self.events, ws
        if old:
            old.close()
        self.log("board connected")
        if self.on_connect:                 # let the bridge re-send anything still unread
            threading.Thread(target=self.on_connect, daemon=True).start()
        closed = threading.Event()

        def read_acks():
            try:
                while True:
                    _, data = ws.recv()
                    try:
                        msg = json.loads(data)
                    except ValueError:
                        continue
                    if msg.get("kind") == "board_event":        # the board telling us something
                        if self.on_board_event:
                            threading.Thread(target=self.on_board_event, daemon=True,
                                             args=(str(msg.get("event", "")), str(msg.get("text", "")))).start()
                        continue
                    if msg.get("kind") == "wake_audio":         # wake-word audio for the voice check
                        if self.on_wake_audio:
                            threading.Thread(target=self.on_wake_audio, daemon=True,
                                             args=(msg.get("frames") or [], int(msg.get("sr", 16000)))).start()
                        continue
                    entry = self.acks.get(str(msg.get("id")))
                    if msg.get("type") == "ack" and entry:
                        entry[1] = bool(msg.get("ok"))
                        if len(entry) > 3:                      # approval acks carry the matched finger id
                            try:
                                entry[3] = int(msg.get("finger_id", -1))
                            except (TypeError, ValueError):
                                entry[3] = -1
                        if len(entry) > 4:                      # ...and whether a finger actually touched
                            entry[4] = bool(msg.get("present", False))
                        entry[0].set()
            except (EOFError, OSError):
                pass
            closed.set()

        threading.Thread(target=read_acks, daemon=True).start()
        last_sent = time.monotonic()
        try:
            while not closed.is_set() and self.events is ws:
                try:
                    command = self.commands.get(timeout=1)
                except queue.Empty:
                    if time.monotonic() - last_sent > HEARTBEAT:
                        ws.send('{"kind":"heartbeat"}')
                        last_sent = time.monotonic()
                    continue
                entry = self.acks.get(command["id"])
                if entry is None:                   # the sender gave up
                    continue
                if entry[2] and not entry[2]():     # no longer needed; tell the sender
                    entry[1] = False
                    entry[0].set()
                    continue
                try:
                    ws.send(json.dumps(command))
                except OSError:
                    self.commands.put(command)      # goes out once the board reconnects
                    break
                last_sent = time.monotonic()
        except OSError:
            pass
        finally:
            if self.events is ws:
                self.events = None
            self.log("board disconnected")

    def _handler(self):
        push = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt, *args):
                pass

            def authorized(self):
                return hmac.compare_digest(self.headers.get("X-TARA-Token", ""), push.token)

            def do_GET(self):
                if self.path == "/tara/call":
                    if not self.authorized():
                        return self.send_error(404)
                    if push.direct_call is None:
                        return self.send_error(409)
                    return push.direct_call.attach(self)
                if self.path == "/tara/events":
                    if not self.authorized():
                        return self.send_error(404)
                    ws = ws_server.WebSocketConn.accept(self)
                    if ws is None:
                        return self.send_error(400)
                    return push._serve_events(ws)
                kind, value = push.routes.get(self.path, (None, None))
                if kind == "file":
                    with open(value, "rb") as f:
                        body = f.read()
                    self.send_response(200)
                    self.send_header("Content-Type", "audio/ogg")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                elif kind == "live" and push.live:
                    self.send_response(200)
                    self.send_header("Content-Type", "audio/ogg")
                    self.send_header("Transfer-Encoding", "chunked")
                    self.end_headers()
                    try:
                        while push.live and push.live_path == self.path:
                            data = push.live.read()
                            if not data:
                                break
                            self.wfile.write(b"%x\r\n%s\r\n" % (len(data), data))
                        self.wfile.write(b"0\r\n\r\n")
                    except OSError:
                        # The board stopped listening (wake word); stop capturing too.
                        if push.live_path == self.path:
                            push.stop_live()
                else:
                    self.send_error(404)

        return Handler

    def _notify(self, path, text, wait_idle, end_conversation=False):
        """Ask the board to play <public_url><path> once it is idle.

        end_conversation: the user asked for this, so the board may end a conversation that is
        only waiting for them to speak (it never cuts off its own speech)."""
        return self._send_command({"audio_url": self.public_url + path, "text": text,
                                   "end_conversation": end_conversation}, wait_idle)

    def prompt(self, text, wait_idle=180, still_needed=None, urgent=False):
        """Tell the board's AI model something (e.g. a task finished) so it tells the user itself.

        The board delivers it without ever dropping it: it waits briefly for a natural pause so it
        does not talk over the user, then interrupts if no pause comes. urgent=True skips the wait
        and interrupts right away (alarms, emergencies).
        still_needed() is checked until the board has it, so a prompt that became pointless
        (the user already heard the result) is dropped, even while the board holds it."""
        return self._send_command({"kind": "prompt", "text": text, "urgent": bool(urgent)},
                                  wait_idle, still_needed)

    def _send_command(self, command, wait_idle, still_needed=None):
        command_id = secrets.token_hex(8)
        entry = [threading.Event(), False, still_needed, -1]
        self.acks[command_id] = entry
        self.commands.put({**command, "id": command_id, "wait_s": int(wait_idle)})
        deadline = time.monotonic() + wait_idle + 30
        try:
            while not entry[0].wait(1):
                if still_needed and not still_needed():
                    ws = self.events
                    if ws:                      # the board may be holding it for a pause
                        try:
                            ws.send(json.dumps({"kind": "cancel", "id": command_id}))
                        except OSError:
                            pass
                    return False
                if time.monotonic() > deadline:
                    self.log("board did not answer" if self.events else "board is not connected")
                    return False
            return entry[1]
        finally:
            self.acks.pop(command_id, None)

    def request_fingerprint(self, summary, wait_s=60):
        """Ask the board to capture a fingerprint to approve <summary>. Blocks until the board
        answers or times out. Returns (matched, finger_id, present): present is True when a finger
        actually touched the sensor (matched or not), False when none did within the window."""
        command_id = secrets.token_hex(8)
        entry = [threading.Event(), False, None, -1, False]
        self.acks[command_id] = entry
        self.commands.put({"kind": "approve", "summary": str(summary)[:200],
                           "id": command_id, "wait_s": int(wait_s)})
        deadline = time.monotonic() + wait_s + 30
        try:
            while not entry[0].wait(1):
                if time.monotonic() > deadline:
                    self.log("board did not answer the fingerprint request"
                             if self.events else "board is not connected")
                    return (False, -1, False)
            return (bool(entry[1]), int(entry[3]), bool(entry[4]))
        finally:
            self.acks.pop(command_id, None)

    def say(self, text, wait_idle=60):
        """Speak a short message on the board. Blocking; returns True if the board accepted it."""
        folder = tempfile.mkdtemp(prefix="tara-say-")
        wav, ogg = os.path.join(folder, "say.wav"), os.path.join(folder, "say.ogg")
        safe = text.replace("'", "''")
        subprocess.run(["powershell", "-NoProfile", "-Command",
                        "Add-Type -AssemblyName System.Speech; $s = New-Object System.Speech.Synthesis.SpeechSynthesizer; "
                        f"try {{ $s.SelectVoiceByHints('Female') }} catch {{}}; $s.SetOutputToWaveFile('{wav}'); "
                        f"$s.Speak('{safe}'); $s.Dispose()"],
                       creationflags=subprocess.CREATE_NO_WINDOW, check=True, timeout=60)
        subprocess.run([ffmpeg_path(), "-y", "-loglevel", "error", "-i", wav, "-ac", "1", "-ar", "24000",
                        "-c:a", "libopus", "-b:a", "32k", "-frame_duration", "60", "-application", "voip", ogg],
                       creationflags=subprocess.CREATE_NO_WINDOW, check=True, timeout=60)
        path = f"/say/{secrets.token_urlsafe(16)}.ogg"
        self.routes[path] = ("file", ogg)
        return self._notify(path, text[:200], wait_idle)

    def start_live(self, wait_idle=90):
        """Mirror the laptop's sound on the board until stop_live() or the wake word."""
        self.stop_live()
        self.live = LiveCapture()
        self.live_path = f"/live/{secrets.token_urlsafe(16)}.ogg"
        self.routes = {k: v for k, v in self.routes.items() if v[0] != "live"}
        self.routes[self.live_path] = ("live", None)
        if not self._notify(self.live_path, "Laptop sound", wait_idle, end_conversation=True):
            self.stop_live()
            return False
        return True

    def stop_live(self):
        live, self.live, self.live_path = self.live, None, None
        if live:
            live.close()
