"""Direct calls: the user talks to someone over WhatsApp through the board itself.

The laptop places the WhatsApp call (call_agent.WhatsAppCall) and bridges audio:
board mic (Opus 16 kHz) -> VB-Cable "CABLE Input" -> WhatsApp's microphone, and
WhatsApp's sound (loopback of the laptop speakers) -> Opus 24 kHz -> board speaker.
The laptop speakers are muted during the call so the board's mic does not pick the
other person up twice. The board connects with a WebSocket to /tara/call on the
board_push server (port 8766, also reachable through the Tailscale Funnel).
"""
import audioop
import json
import os
import queue
import threading
import time

import pyaudiowpatch as pyaudio

import call_agent
from ws_server import WebSocketConn

_dll_dir = os.path.dirname(__import__("pyogg").__file__)     # pyogg ships opus.dll for Windows
os.add_dll_directory(_dll_dir)
os.environ["PATH"] = _dll_dir + os.pathsep + os.environ["PATH"]
import opuslib  # noqa: E402

BOARD_RATE, BOARD_FRAME = 16000, 960          # board mic: 16 kHz mono, 60 ms frames
SPEAKER_RATE, SPEAKER_FRAME = 24000, 1440     # to the board speaker: 24 kHz mono, 60 ms frames
JOIN_TIMEOUT = 90           # seconds for the board to connect after the call is approved
MAX_CALL = 3600
MAX_PLAY_BACKLOG = 5        # 60 ms frames queued for WhatsApp's mic before old ones are dropped


# --- the call ------------------------------------------------------------------------------

def set_speakers_muted(muted):
    """Returns the previous mute state, or None if it could not be read."""
    try:
        from pycaw.pycaw import AudioUtilities
        vol = AudioUtilities.GetSpeakers().EndpointVolume
        was = bool(vol.GetMute())
        vol.SetMute(1 if muted else 0, None)
        return was
    except Exception:
        return None


class DirectCall:
    """At most one call at a time; start() places it, attach() runs the board's audio."""

    def __init__(self, push, log):
        self.push, self.log = push, log
        self.lock = threading.Lock()
        self.current = None

    def busy(self):
        return self.current is not None

    def start(self, contact, phone=""):
        """Place the call in the background. Returns False if a call is already running."""
        with self.lock:
            if self.current:
                return False
            self.current = {"contact": contact, "phone": phone, "ended": threading.Event(),
                            "joined": threading.Event(), "ws": None, "why": "", "started": time.time()}
        threading.Thread(target=self._run, args=(self.current,), daemon=True).start()
        if self.push:   # backup route in case the model does not call self.tara.join_call
            threading.Thread(target=self.push._send_command, args=({"kind": "call"}, 60,
                             lambda c=self.current: not c["joined"].is_set() and not c["ended"].is_set()),
                             daemon=True).start()
        return True

    def end(self, why):
        c = self.current
        if c and not c["ended"].is_set():
            c["why"] = c["why"] or why
            c["ended"].set()

    def _run(self, c):
        call = call_agent.WhatsAppCall(c["phone"], self.log)
        was_muted = None
        placed = False
        try:
            call_agent.set_default_mic("CABLE Output")       # WhatsApp's mic = the board's mic
            call_agent.restart_whatsapp(self.log)
            if c["ended"].is_set():
                return
            call.place(c["contact"])
            placed = True
            was_muted = set_speakers_muted(True)
            self.log(f"direct call to {c['contact']} placed")
            if not c["joined"].wait(JOIN_TIMEOUT):
                self.end("the board did not join")
            gone, last, answered = 0, None, False
            while not c["ended"].wait(1):
                state = call.state()
                if state != last:
                    self.log(f"direct call to {c['contact']}: {state}")
                    last = state
                answered = answered or state == "connected"
                gone = gone + 1 if state == "ended" else 0
                if gone >= 3:
                    self.end("the other person hung up" if answered else "not answered or declined")
                if time.time() - c["started"] > MAX_CALL:
                    self.end("time limit")
        except Exception as e:
            self.log(f"direct call failed: {type(e).__name__}: {e}")
            self.end(f"error: {e}")
        finally:
            c["ended"].set()
            if placed:
                call.hang_up()
            if c["ws"]:
                try:
                    c["ws"].send(json.dumps({"type": "end"}))
                except OSError:
                    pass
            if was_muted is not None:
                set_speakers_muted(was_muted)
            call_agent.set_default_mic(r"Microphone \(Realtek")
            try:
                call_agent.restart_whatsapp(self.log)
            except Exception as e:
                self.log(f"restart WhatsApp yourself before your next call: {e}")
            self.log(f"direct call to {c['contact']} ended: {c['why']} "
                     f"({round(time.time() - c['started'])} s)")
            with self.lock:
                self.current = None

    def attach(self, handler):
        """Runs in the HTTP handler thread for the board's WebSocket until the call ends."""
        c = self.current
        if not c or c["ended"].is_set() or c["joined"].is_set():
            handler.send_error(409)
            return
        ws = WebSocketConn.accept(handler)
        if ws is None:
            handler.send_error(400)
            return
        c["ws"] = ws
        c["joined"].set()
        self.log("board joined the call")
        pa = pyaudio.PyAudio()
        streams = []
        try:
            cable = call_agent.find_device(pa, "CABLE Input", output=True)
            out_rate, out_ch = int(cable["defaultSampleRate"]), min(2, cable["maxOutputChannels"])
            to_whatsapp = pa.open(format=pyaudio.paInt16, channels=out_ch, rate=out_rate, output=True,
                                  output_device_index=cable["index"])
            streams.append(to_whatsapp)
            play_q = queue.Queue()
            decoder = opuslib.Decoder(BOARD_RATE, 1)
            encoder = opuslib.Encoder(SPEAKER_RATE, 1, opuslib.APPLICATION_VOIP)
            state = {"up": None, "down": None, "buf": b""}

            def player():
                while not c["ended"].is_set():
                    try:
                        pcm = play_q.get(timeout=0.2)
                    except queue.Empty:
                        continue
                    to_whatsapp.write(pcm)

            lb = pa.get_default_wasapi_loopback()          # what WhatsApp plays = the other person
            lb_rate, lb_ch = int(lb["defaultSampleRate"]), min(2, lb["maxInputChannels"])

            def captured(data, frames, info, status):
                if c["ended"].is_set():
                    return (None, pyaudio.paComplete)
                if lb_ch == 2:
                    data = audioop.tomono(data, 2, 0.5, 0.5)
                data, state["down"] = audioop.ratecv(data, 2, 1, lb_rate, SPEAKER_RATE, state["down"])
                buf = state["buf"] + data
                frame = SPEAKER_FRAME * 2
                try:
                    while len(buf) >= frame:
                        ws.send(encoder.encode(buf[:frame], SPEAKER_FRAME))
                        buf = buf[frame:]
                except OSError:
                    self.end("the board disconnected")
                    return (None, pyaudio.paComplete)
                state["buf"] = buf
                return (None, pyaudio.paContinue)

            threading.Thread(target=player, daemon=True).start()
            streams.append(pa.open(format=pyaudio.paInt16, channels=lb_ch, rate=lb_rate, input=True,
                                   input_device_index=lb["index"], frames_per_buffer=lb_rate // 50,
                                   stream_callback=captured))

            while not c["ended"].is_set():
                try:
                    opcode, data = ws.recv()
                except (EOFError, OSError):
                    self.end("the board left the call")
                    break
                if opcode == 0x1:
                    if json.loads(data or b"{}").get("type") == "end":
                        self.end("you hung up on the board")
                    continue
                pcm = decoder.decode(data, BOARD_FRAME)
                pcm, state["up"] = audioop.ratecv(pcm, 2, 1, BOARD_RATE, out_rate, state["up"])
                if out_ch == 2:
                    pcm = audioop.tostereo(pcm, 2, 1, 1)
                while play_q.qsize() > MAX_PLAY_BACKLOG:     # keep the delay low
                    play_q.get_nowait()
                play_q.put(pcm)
        except Exception as e:
            self.log(f"call audio failed: {type(e).__name__}: {e}")
            self.end(f"audio error: {e}")
        finally:
            c["ended"].wait(5)
            for s in streams:
                try:
                    s.stop_stream()
                    s.close()
                except Exception:
                    pass
            pa.terminate()
            ws.close()
