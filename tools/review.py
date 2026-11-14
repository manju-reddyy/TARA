"""TARA daily review.

Default: list every task the board was asked to do and when it was triggered
         (from ~/agent-workspace/memory/history.jsonl).

--audit: a security pass over the tamper-evident audit log (~/tara/audit/audit.jsonl):
         1. chain integrity (verify the hash chain),
         2. security events (denials, wrong codes, duress, freezes, emergencies),
         3. sensitive actions that were approved with your code and actually ran
            -- the consequential, outward actions worth checking you asked for.

Usage:
  python review.py                tasks, newest last
  python review.py --today        only today
  python review.py --full         tasks + each result
  python review.py --audit        integrity + security events + anomalies
  python review.py --audit --today  the same, limited to today
"""
import hashlib
import json
import os
import sys
from datetime import date, datetime

try:
    sys.stdout.reconfigure(encoding="utf-8")        # so dashes/accents render right
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
HISTORY = os.path.expanduser(os.path.join("~", "agent-workspace", "memory", "history.jsonl"))
AUDIT = os.path.normpath(os.path.join(HERE, "..", "audit", "audit.jsonl"))

SECURITY_EVENTS = {"deny", "code_rejected", "duress", "approver_pin_rejected",
                   "freeze", "unfreeze", "emergency"}


# --- helpers -------------------------------------------------------------------------------

def read_jsonl(path):
    rows = []
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        rows.append(json.loads(line))
                    except ValueError:
                        pass
    return rows


def clock(ts):
    try:
        return datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts)


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def verify_audit(path):
    """Same check TARA uses: every record's hash and its link to the one before."""
    prev, seq = "0" * 64, 0
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            e = json.loads(line)
            h = e.pop("hash", "")
            if e.get("prev") != prev or e.get("seq") != seq + 1:
                return False, seq, f"line {n}: chain broken (entry removed, reordered or inserted)"
            if hashlib.sha256(canonical(e).encode()).hexdigest() != h:
                return False, seq, f"line {n}: entry was modified"
            prev, seq = h, e["seq"]
    return True, seq, "ok"


def descr(e):
    """A short human description of an audit event for the security list."""
    for k in ("action", "situation", "reason"):
        if e.get(k):
            return str(e[k])
    return e.get("result", "")


# --- the task list (default) ---------------------------------------------------------------

def show_tasks(today, full):
    jobs = {}
    for r in read_jsonl(HISTORY):
        job = r.get("job", "?")
        slot = jobs.setdefault(job, {"triggered": None, "task": r.get("task", ""),
                                     "status": "running", "result": ""})
        slot["task"] = r.get("task") or slot["task"]
        if r.get("event") == "asked":
            slot["triggered"] = r.get("ts", "")
        else:
            slot["status"] = r.get("event", "done")
            slot["result"] = r.get("result", "")

    items = sorted(jobs.values(), key=lambda s: s["triggered"] or "")
    if today:
        stamp = date.today().isoformat()
        items = [s for s in items if (s["triggered"] or "").startswith(stamp)]
    if not items:
        print("No tasks recorded" + (" today." if today else "."))
        return
    print(f"{'Triggered at':<21}  {'Status':<8}  Task")
    print("-" * 78)
    for s in items:
        print(f"{s['triggered'] or '(unknown time)':<21}  {s['status']:<8}  {s['task']}")
        if full and s["result"]:
            print(f"{'':<31}-> {s['result']}")
    print("-" * 78)
    print(f"{len(items)} task(s)" + (" today." if today else " total."))


# --- the audit / anomaly pass (--audit) ----------------------------------------------------

def show_audit(today):
    if not os.path.exists(AUDIT):
        print(f"No audit log at {AUDIT}")
        return
    ok, seq, msg = verify_audit(AUDIT)
    recs = read_jsonl(AUDIT)
    if today:
        stamp = date.today().isoformat()
        recs = [e for e in recs if clock(e.get("ts", 0)).startswith(stamp)]

    print("=" * 78)
    print("1. CHAIN INTEGRITY")
    mark = "OK - not tampered with" if ok else "*** BROKEN ***"
    print(f"   {mark}   ({seq} records checked; {msg})")

    print("\n2. SECURITY EVENTS" + (" (today)" if today else ""))
    sec = [e for e in recs if e.get("event") in SECURITY_EVENTS]
    if not sec:
        print("   none.")
    else:
        for e in sec:
            via = f" [{e['via']}]" if e.get("via") else ""
            print(f"   {clock(e.get('ts',0))}  {e['event'].upper():<16}{via}  {descr(e)}")

    print("\n3. SENSITIVE ACTIONS CARRIED OUT (approved with your code, then executed)"
          + (" (today)" if today else ""))
    # A 'consume' means a one-time grant was spent: a code-gated action actually ran. Pair each
    # with its 'approve' so we can tell what it was. These are the consequential, outward actions -
    # the ones worth checking you actually asked for. (Denied / refused ones are in section 2.)
    approvals = {e.get("request_id"): e for e in recs if e.get("event") == "approve"}
    done = [e for e in recs if e.get("event") == "consume" and e.get("result") == "ok"]
    # Also surface anything ALLOWED outright at medium+ risk (rare, but worth seeing).
    allowed_risky = [e for e in recs if e.get("event") == "authorize" and e.get("decision") == "allow"
                     and e.get("risk") in ("medium", "high", "critical")]
    if not done and not allowed_risky:
        print("   none.")
    else:
        for e in done:
            action = e.get("action") or (approvals.get(e.get("request_id"), {}).get("action", "")) or e.get("tool", "")
            print(f"   {clock(e.get('ts',0))}  APPROVED+RAN   {action}")
        for e in allowed_risky:
            print(f"   {clock(e.get('ts',0))}  allowed({e.get('risk')})  {e.get('action','')}")
    print("\n   Reminder: everything you say and every result still goes to the xiaozhi.me cloud in")
    print("   real time - this log catches unwanted ACTIONS, not data already sent. The self-hosted")
    print("   voice server is the fix for that.")
    print("=" * 78)


def main():
    today = "--today" in sys.argv
    if "--audit" in sys.argv:
        show_audit(today)
    else:
        show_tasks(today, "--full" in sys.argv)


if __name__ == "__main__":
    main()
