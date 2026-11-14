"""The second approver's page: a phone opens a private link (/tara/approve?k=<token>) and sees the
critical requests waiting for a second person. Approving needs their PIN. The page itself holds no
authority: it only relays to TARA, which checks the link token and the PIN."""
import html
import json
import urllib.parse

PAGE = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>TARA second approver</title>
<style>
body{{font-family:system-ui,sans-serif;background:#14161a;color:#e8e6e3;margin:0;padding:16px;max-width:560px}}
h1{{font-size:18px;color:#8a8f98;font-weight:500}} .card{{background:#1e2127;border-radius:10px;padding:14px;margin:12px 0}}
.what{{font-size:16px}} .why{{color:#8a8f98;font-size:13px;margin:6px 0}} .msg{{padding:10px;border-radius:8px;
background:#2a3a2a}} .err{{background:#5a2a2a}} input{{font-size:20px;width:8em;padding:8px;border-radius:6px;
border:0}} button{{font-size:16px;padding:10px 16px;border:0;border-radius:6px;margin:6px 6px 0 0}}
.ok{{background:#2a7a3a;color:#fff}} .no{{background:#7a2a2a;color:#fff}}
</style>{refresh}</head><body><h1>TARA &middot; second approver: {name}</h1>{msg}{body}</body></html>"""


def render(state, token, msg="", error=False):
    m = f