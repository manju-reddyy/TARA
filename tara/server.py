"""TARA authorization server and approval window.

Listens on 127.0.0.1 only. The Claude Code hook calls /authorize, /wait and
/consume. The voice bridge calls /pending, /approve and /deny, and must send
the bridge token. One-time approval codes are shown only in this window.
"""
import hmac
import json
import os
import socket
import sys
import threading
import time
import tkinter as tk
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import risk_agent
from core import AUDIT_PATH, PORT, TaraCore, load_secret

BRIDGE_ROUTES = ("/pending", "/approve", "/approve_fingerprint", "/deny", "/confirm", "/freeze", "/emergency", "/receipt", "/speaker")


class Handler(BaseHTTPRequestHandler):
    core = None
    bridge_token = ""

    def log_message(self, *args):
        pass

    def _send(self, status, obj):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # Public: the signing public keys, so anyone can verify receipts and the audit log.
        if self.path.split("?")[0] == "/pubkey":
            return self._send(200, self.core.public_key_info())
        return self._send(404, {"error": "unknown route"})

    def do_POST(self):
        route = self.path.split("?")[0]
        try:
            data = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        except ValueError:
            return self._send(400, {"error": "bad json"})
        if route in BRIDGE_ROUTES and not hmac.compare_digest(
                self.headers.get("X-TARA-Bridge", ""), self.bridge_token):
            return self._send(403, {"error": "bridge token required"})
        c = self.core
        try:
            if route == "/authorize":
                r = c.authorize(data.get("job_id", "unknown"), data.get("session_id", ""),
                                data.get("agent", "claude-code"), data["tool_name"],
                                data.get("tool_input") or {}, data.get("cwd"), data.get("task", ""))
            elif route == "/wait":
                r = c.wait(data["request_id"], min(float(data.get("timeout", 25)), 30))
            elif route == "/consume":
                r = c.consume(data.get("grant", ""), data.get("session_id", ""), data["tool_name"],
                              data.get("tool_input") or {})
            elif route == "/pending":
                r = {"pending": c.pending_public(data.get("job_id"))}
            elif route == "/approve":
                r = c.approve_code(data.get("code", ""), data.get("job_id"), via="voice")
            elif route == "/approve_fingerprint":
                r = c.approve_fingerprint(data.get("finger_id", -1), data.get("job_id"),
                                          data.get("request_id"), via="fingerprint")
            elif route == "/deny":
                r = c.deny(job_id=data.get("job_id"), request_id=data.get("request_id"), via="voice")
            elif route == "/observe":       # after a tool ran; can only add labels (stricter)
                r = c.observe(data.get("session_id", ""), data.get("job_id", ""), data.get("tool_name", ""),
                              data.get("tool_input") or {}, data.get("tool_response", ""))
            elif route == "/confirm":
                r = c.confirm(data.get("request_id"), via="voice")
            elif route == "/freeze":
                r = c.freeze(str(data.get("reason", "stop everything"))[:200], via="voice")
            elif route == "/emergency":
                r = c.declare_emergency(str(data.get("situation", "emergency"))[:200], via="voice")
            elif route == "/receipt":
                r = c.verify_receipt(str(data.get("receipt", "")))
            elif route == "/speaker":       # voice-identity verdict from the bridge
                r = c.set_speaker(data.get("enrolled"), data.get("known"), data.get("name"),
                                  data.get("score"))
            else:
                return self._send(404, {"error": "unknown route"})
        except (KeyError, TypeError, ValueError) as e:
            return self._send(400, {"error": f"bad request: {e}"})
        self._send(200, r)


class ApprovalWindow:
    BG, FG, ACCENT, DIM = "#14161a", "#e8e6e3", "#f2b84b", "#8a8f98"

    def __init__(self, core):
        self.core = core
        self.root = tk.Tk()
        self.root.title("TARA - Human Authorization")
        self.root.geometry("620x440")
        self.root.configure(bg=self.BG)
        # Closing the window must not switch TARA off (the agent would be blocked); minimize instead.
        self.root.protocol("WM_DELETE_WINDOW", self.root.iconify)
        tk.Label(self.root, text="TARA  ·  human authorization", bg=self.BG, fg=self.DIM,
                 font=("Segoe UI", 10)).pack(anchor="w", padx=16, pady=(12, 0))
        self.body = tk.Frame(self.root, bg=self.BG)
        self.body.pack(fill="both", expand=True, padx=16, pady=8)
        self.log = tk.Label(self.root, text="", bg=self.BG, fg=self.DIM, justify="left", anchor="w",
                            font=("Consolas", 8))
        self.log.pack(fill="x", padx=16, pady=(0, 10))
        self._rows = {}
        self._frozen_shown = False
        self._sig = []
        self._rebuild({})
        self.root.after(300, self.refresh)

    def _rebuild(self, reqs):
        for w in self.body.winfo_children():
            w.destroy()
        self._rows = {}
        frozen = self.core.frozen()
        self._frozen_shown = bool(frozen)
        if frozen:
            box = tk.Frame(self.body, bg="#5a2a2a", padx=14, pady=10)
            box.pack(fill="x", pady=6)
            tk.Label(box, text=f"TARA IS FROZEN (kill switch): {frozen.get('why', '')}", bg="#5a2a2a", fg=self.FG,
                     font=("Segoe UI", 12, "bold"), wraplength=560, justify="left").pack(anchor="w")
            tk.Label(box, text="Nothing can run. Only this button, here on the laptop, can unfreeze TARA.",
                     bg="#5a2a2a", fg=self.FG, font=("Segoe UI", 9)).pack(anchor="w")
            tk.Button(box, text="Unfreeze", command=lambda: self.core.unfreeze("laptop-window"),
                      bg="#2a5a2a", fg=self.FG, relief="flat", padx=14).pack(anchor="e")
            return
        if not reqs:
            tk.Label(self.body, text="No pending approvals.\n\nRisky actions will appear here with a one-time "
                     "code.\nSay the code to your board to approve, or say \"deny\".",
                     bg=self.BG, fg=self.FG, font=("Segoe UI", 12), justify="left").pack(anchor="w", pady=20)
            return
        for rid, r in reqs.items():
            card = tk.Frame(self.body, bg="#1e2127", padx=14, pady=10)
            card.pack(fill="x", pady=6)
            tk.Label(card, text=f"Agent wants to: {r['summary']}", bg="#1e2127", fg=self.FG,
                     font=("Segoe UI", 11), wraplength=560, justify="left").pack(anchor="w")
            tk.Label(card, text=f"risk: {r['risk']}   ·   rule: {r['rule']}", bg="#1e2127", fg=self.DIM,
                     font=("Segoe UI", 9)).pack(anchor="w", pady=(2, 0))
            tk.Label(card, text=r["reason"], bg="#1e2127", fg=self.DIM, font=("Segoe UI", 9, "italic"),
                     wraplength=560, justify="left").pack(anchor="w", pady=(0, 6))
            if r["level"] == "confirm":
                tk.Label(card, text="Medium risk: say \"yes\" to your board to approve (or use this code).",
                         bg="#1e2127", fg=self.DIM, font=("Segoe UI", 9)).pack(anchor="w")
            elif r["level"] == "two_person":
                tk.Label(card, text="Critical: needs TWO approvers. Each says their own code to the board.",
                         bg="#1e2127", fg=self.ACCENT, font=("Segoe UI", 9, "bold")).pack(anchor="w")
            else:
                tk.Label(card, text="Say this code to your board to approve:", bg="#1e2127", fg=self.DIM,
                         font=("Segoe UI", 9)).pack(anchor="w")
            codes = [("", r["code"])] if r["level"] != "two_person" else \
                [("Approver 1: ", r["code"]), ("Approver 2: ", r["code2"])]
            for who, code in codes:
                tk.Label(card, text=f"{who}{code[:3]} {code[3:]}", bg="#1e2127", fg=self.ACCENT,
                         font=("Consolas", 26 if who else 38, "bold")).pack(anchor="w")
            row = tk.Frame(card, bg="#1e2127")
            row.pack(fill="x")
            left = tk.Label(row, text="", bg="#1e2127", fg=self.DIM, font=("Segoe UI", 9))
            left.pack(side="left")
            tk.Button(row, text="Deny", command=lambda rid=rid: self.core.deny(request_id=rid, via="laptop-window"),
                      bg="#5a2a2a", fg=self.FG, relief="flat", padx=14).pack(side="right")
            self._rows[rid] = left

    def _alert(self):
        self.root.deiconify()
        self.root.lift()
        self.root.attributes("-topmost", True)
        self.root.after(1500, lambda: self.root.attributes("-topmost", False))
        self.root.bell()

    def refresh(self):
        reqs = {r["request_id"]: r for r in self.core.snapshot()}
        while self.core.alerts:
            self.log.config(text=self.core.alerts.popleft())
            self._alert()
        sig = sorted((k, v["approved_by"]) for k, v in reqs.items())
        if set(reqs) != set(self._rows) or bool(self.core.frozen()) != self._frozen_shown or sig != self._sig:
            self._sig = sig
            new = set(reqs) - set(self._rows)
            self._rebuild(reqs)
            if new:
                self._alert()
        for rid, label in self._rows.items():
            label.config(text=f"expires in {max(0, int(reqs[rid]['expires'] - time.time()))}s")
        self.log.config(text="\n".join(self.core.recent))
        self.root.after(500, self.refresh)


class ExclusiveServer(ThreadingHTTPServer):
    # http.server allows address reuse by default; on Windows that lets a second process listen
    # on the same port, so two TARA servers could run at once. Claim the port exclusively.
    allow_reuse_address = False

    def server_bind(self):
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


def main():
    try:
        httpd = ExclusiveServer(("127.0.0.1", PORT), Handler)
        core = TaraCore(risk_assessor=risk_agent.assess)
    except (OSError, RuntimeError):
        sys.exit(f"TARA: port {PORT} or the audit log is in use - is TARA already running?")
    Handler.core = core
    Handler.bridge_token = load_secret("bridge_token.txt", generate=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    core._log({"event": "server_start", "port": PORT})
    print(f"TARA authorization server on 127.0.0.1:{PORT}")
    ApprovalWindow(core).root.mainloop()
    httpd.shutdown()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        import traceback
        with open(os.path.join(os.path.dirname(AUDIT_PATH), "server-crash.log"), "a", encoding="utf-8") as f:
            f.write(time.strftime("%Y-%m-%d %H:%M:%S ") + traceback.format_exc() + "\n")
        raise
