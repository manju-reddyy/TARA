"""Tells the board when a WhatsApp voice/video call is ringing IN to the laptop.

WhatsApp Desktop shows an incoming call with an "Accept"/"Answer" button (an outbound
call never has one -- it only ever shows "End call"). This watcher polls WhatsApp's
windows through UI Automation; when it first sees that Accept button it reads the
caller's name from the same window and hands it to deliver(caller, kind) ONCE per ring.
It never touches the call -- it only notifies; the user accepts or declines on WhatsApp.

The caller name comes from WhatsApp's own UI (a contact name or number): it is data, not
an instruction, and the board model is told to treat it as such.
"""
import re
import threading
import time

POLL = 1.5          # seconds between checks; a call rings for ~30-45 s

# Controls/labels that are never the caller's name.
_NOISE = re.compile(
    r"(?i)^((accept|answer|decline|ignore|reject)( call)?|incoming( (voice|video))? call|(voice|video) call|"
    r"whatsapp( (voice|video) call)?|end[- ]to[- ]end encrypted|ringing\.*|calling\.*|connecting\.*|"
    r"mute|unmute|speaker|camera|add contact|ask meta ai|send document|resize.*|new chat|menu|you|"
    r"media|meta ai|archived|communities|channels|status|calls|chats|close|minimi[sz]e|maximi[sz]e|"
    r"restore)$")
_TIMER = re.compile(r"^\d{1,2}[:∶]\d{2}([:∶]\d{2})?$")
# The incoming-call window's answer button is labelled "Accept call" / "Answer call".
_ACCEPT = re.compile(r"(?i)^(accept|answer)( call)?$")
_PHONEISH = re.compile(r"^\+?[\d\s()-]{7,}$")


def _norm(s):
    """WhatsApp mixes in non-breaking spaces and private-use icon glyphs; drop both."""
    s = "".join(ch for ch in (s or "") if not (0xE000 <= ord(ch) <= 0xF8FF))
    return " ".join(s.replace("\xa0", " ").split())


def _scan_window(win, depth=45):
    """Return (buttons, texts) under one top-level window."""
    buttons, texts = [], []
    stack = [(win, 0)]
    while stack:
        c, d = stack.pop()
        if d > depth:
            continue
        try:
            name = (c.Name or "").strip()
            ctype = c.ControlTypeName
            children = c.GetChildren()
        except Exception:
            continue                    # a control vanished mid-walk (call screen redraws)
        if ctype == "ButtonControl":
            buttons.append(name)
        elif name and ctype == "TextControl":
            texts.append(name)
        stack.extend((ch, d + 1) for ch in children)
    return buttons, texts


def _caller_name(texts):
    """Best-effort caller name from the call window's texts, or '' if unsure."""
    for t in texts:
        t = _norm(t)
        if not t or _TIMER.match(t) or _NOISE.match(t) or len(t) > 40:
            continue
        if not re.search(r"[A-Za-z0-9]", t):                # icon glyph / punctuation only
            continue
        if _PHONEISH.match(t) or not re.search(r"\d", t):   # a name, or a phone number
            return t
    return ""


class Watcher:
    def __init__(self, deliver, log, busy=lambda: False):
        self.deliver, self.log, self.busy = deliver, log, busy
        self.active = None              # key of the call currently ringing, so we fire once per ring
        self.dumped = False             # one-time control dump the first time a call screen is seen
        threading.Thread(target=self._run, daemon=True).start()
        log("watching for incoming WhatsApp calls")

    def _detect(self):
        """Return (caller, kind) for a ringing incoming call, or None."""
        import uiautomation as auto
        root = auto.GetRootControl()
        for win in root.GetChildren():
            try:
                wname = win.Name or ""
                wclass = win.ClassName or ""
            except Exception:
                continue
            if "WhatsApp" not in wname and wclass != "WinUIDesktopWin32WindowClass":
                continue
            buttons, texts = _scan_window(win)
            if not any(_ACCEPT.match(_norm(b)) for b in buttons):
                continue                # no Accept button -> not an incoming call
            blob = " ".join(buttons + texts).lower()
            if not self.dumped:         # first real call screen: record it so labels can be checked
                self.dumped = True
                self.log(f"incoming-call screen seen. buttons={buttons} texts={texts[:12]}")
            kind = "video" if "video" in blob else "voice"
            return _caller_name(texts), kind
        return None

    def _run(self):
        while True:
            time.sleep(POLL)
            try:
                hit = self._detect()
            except Exception as e:
                self.log(f"call watch: skipped a check ({type(e).__name__}: {e})")
                self.active = None
                continue
            if not hit:
                self.active = None      # the call window is gone; ready for the next ring
                continue
            caller, kind = hit
            key = (caller, kind)
            if key == self.active:
                continue                # same ring, already announced
            self.active = key
            if self.busy():             # user is already on a call through the board
                self.log(f"incoming {kind} call from {caller or 'unknown'} (holding: board is on a call)")
                continue
            self.log(f"incoming {kind} call from {caller or 'unknown'}")
            try:
                self.deliver(caller, kind)
            except Exception as e:
                self.log(f"call watch: could not notify the board ({type(e).__name__}: {e})")
