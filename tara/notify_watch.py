"""Passes the laptop's new Windows notifications to the board, so its model tells the user.

Windows keeps notifications in a local SQLite database; new toasts are read from it every
few seconds and handed to deliver(text). A notification is text from someone else: the
caller must mark it so the model reads it out and never follows instructions in it.
"""
import os
import re
import sqlite3
import threading
import time
import xml.etree.ElementTree as ET

DB = os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Windows\Notifications\wpndatabase.db")
POLL = 3            # seconds between checks
GATHER = 4          # seconds to wait for more notifications arriving together, spoken as one message
MAX_SPOKEN = 3      # notifications read out per message; the rest are counted
SKIP_APPS = ("TARA",)       # TARA's own notifications are already told on the board


KNOWN_APPS = {"whatsapp": "WhatsApp", "outlook": "Outlook", "teams": "Teams", "chrome": "Chrome",
              "brave": "Brave", "msedge": "Edge", "powershell": "PowerShell", "slack": "Slack"}


def app_name(primary_id):
    """'5319275A.WhatsAppDesktop_cv1g1gvanyjgm!App' -> 'WhatsApp'; '...\\chrome.exe' -> 'Chrome'."""
    name = re.split(r"[\\/]", primary_id.split("!")[0])[-1]
    name = re.sub(r"(?i)\.exe$", "", name).split("_")[0]
    name = name.split(".")[-1] if "." in name else name
    for key, nice in KNOWN_APPS.items():
        if key in name.lower():
            return nice
    name = re.sub(r"(Desktop|App)$", "", name) or name
    return re.sub(r"(?<=[a-z])(?=[A-Z])", " ", name)


def toast_text(payload):
    """The visible lines of a toast's XML."""
    try:
        root = ET.fromstring(payload.decode("utf-8", "replace") if isinstance(payload, bytes) else payload)
    except ET.ParseError:
        return []
    return [" ".join(t.text.split()) for t in root.iter("text") if t.text and t.text.strip()]


class Watcher:
    def __init__(self, deliver, log, busy=lambda: False):
        self.deliver, self.log, self.busy = deliver, log, busy
        self.last = self._newest()      # only notifications that arrive from now on
        threading.Thread(target=self._run, daemon=True).start()
        log("reading new laptop notifications on the board")

    def _query(self, sql, args=()):
        con = sqlite3.connect(f"file:{DB}?mode=ro", uri=True, timeout=2)
        try:
            return con.execute(sql, args).fetchall()
        finally:
            con.close()

    def _newest(self):
        # Watermark on ArrivalTime (a monotonic FILETIME), NOT "Order". Windows renumbers "Order"
        # when notifications are dismissed/compacted, so a brand-new toast can get a LOWER "Order"
        # than an older one -- which made `"Order" > last` silently miss every new notification.
        try:
            return self._query("SELECT COALESCE(MAX(ArrivalTime), 0) FROM Notification")[0][0]
        except sqlite3.Error:
            return 0

    def _new_toasts(self):
        rows = self._query(
            "SELECT n.ArrivalTime, h.PrimaryId, n.Payload FROM Notification n "
            "JOIN NotificationHandler h ON h.RecordId = n.HandlerId "
            "WHERE n.Type = 'toast' AND n.ArrivalTime > ? ORDER BY n.ArrivalTime", (self.last,))
        found = []
        for arrival, primary_id, payload in rows:
            self.last = max(self.last, arrival)
            if primary_id in SKIP_APPS:
                continue
            lines = toast_text(payload)
            if lines:
                found.append(f"{app_name(primary_id)}: {'. '.join(lines[:2])}"[:160])
        return found

    def _run(self):
        pending = []        # held across "busy" periods and delivery failures so nothing is lost
        while True:
            time.sleep(POLL)
            # Read new toasts. Catch EVERYTHING: a single bad toast must never kill the watcher
            # thread (that silently stops all future notifications).
            try:
                found = self._new_toasts()
                if found:
                    time.sleep(GATHER)
                    found += self._new_toasts()
            except sqlite3.Error as e:
                self.log(f"notifications: database not readable ({e})")
                continue
            except Exception as e:
                self.log(f"notifications: skipped a bad one ({type(e).__name__}: {e})")
                continue
            pending += found
            if not pending:
                continue
            if self.busy():         # board is on a call: hold them, do NOT drop, deliver later
                continue
            text = "; ".join(pending[:MAX_SPOKEN])
            if len(pending) > MAX_SPOKEN:
                text += f"; and {len(pending) - MAX_SPOKEN} more"
            self.log(f"{len(pending)} new laptop notification(s)")
            try:
                self.deliver(text)
                pending = []        # delivered: clear only on success
            except Exception as e:
                self.log(f"notifications: could not pass them on, keeping for retry ({type(e).__name__})")
