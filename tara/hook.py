"""Claude Code hooks: PreToolUse (every tool call must be authorized by TARA) and, with --post,
PostToolUse (what a tool returned is reported so TARA can label the data).

Fails closed: if TARA can't be reached or anything goes wrong, the call is denied.
"""
import json
import os
import sys
import time
import urllib.request

TARA = os.environ.get("TARA_URL", "http://127.0.0.1:8765")
MAX_WAIT = 140   # a little longer than APPROVAL_TTL so TARA, not the hook, decides expiry


def call(route, payload, timeout=40):
    req = urllib.request.Request(TARA + route, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def decide(decision, reason):
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                             "permissionDecision": decision,
                                             "permissionDecisionReason": reason}}))
    sys.exit(0)


def observe(event):
    """PostToolUse: tell TARA what the tool returned so it can label the task's data (CUI, PHI,
    untrusted). Never blocks; the next PreToolUse check applies the labels."""
    try:
        call("/observe", {"job_id": os.environ.get("TARA_JOB_ID", "interactive"),
                          "session_id": event.get("session_id", ""), "tool_name": event.get("tool_name", ""),
                          "tool_input": event.get("tool_input") or {},
                          "tool_response": json.dumps(event.get("tool_response", ""))[:200000]}, timeout=20)
    except Exception:
        pass
    sys.exit(0)


def main():
    try:
        event = json.loads(sys.stdin.buffer.read().decode("utf-8"))
    except ValueError:
        decide("deny", "TARA: unreadable hook input; failing closed")
    if "--post" in sys.argv:
        observe(event)
    tool, tool_input = event.get("tool_name", ""), event.get("tool_input") or {}
    session = event.get("session_id", "")
    try:
        r = call("/authorize", {"job_id": os.environ.get("TARA_JOB_ID", "interactive"), "session_id": session,
                                "agent": "claude-code", "tool_name": tool, "tool_input": tool_input,
                                "cwd": event.get("cwd"), "task": os.environ.get("TARA_TASK", "")}, timeout=90)
        if r["decision"] == "allow":
            decide("allow", r["reason"])
        if r["decision"] != "pending":
            decide("deny", r["reason"] + ". Do not try another way to do this; tell the user it is blocked.")
        deadline = time.time() + MAX_WAIT
        while time.time() < deadline:
            w = call("/wait", {"request_id": r["request_id"], "timeout": 25})
            if w["status"] == "pending":
                continue
            if w["status"] != "approved":
                decide("deny", f"TARA: human approval {w['status']}. Do not retry; tell the user it was not approved.")
            c = call("/consume", {"grant": w["grant"], "session_id": session, "tool_name": tool,
                                  "tool_input": tool_input})
            if c.get("ok"):
                decide("allow", "TARA: approved by the human with a one-time code")
            decide("deny", "TARA: grant rejected: " + c.get("reason", "unknown"))
        decide("deny", "TARA: approval timed out")
    except Exception as e:
        decide("deny", f"TARA unreachable or failed ({type(e).__name__}); failing closed")


if __name__ == "__main__":
    main()
