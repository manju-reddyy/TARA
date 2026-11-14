"""TARA core: policy evaluation, human approval requests, single-use grants, audit log.

Nothing here trusts text produced by the agent. Decisions come from the policy
file; approvals come only from a one-time code shown in the TARA window, which
the agent never sees.
"""
import base64
import collections
import fnmatch
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass

import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POLICY_PATH = os.path.join(ROOT, "policy.yaml")
AUDIT_PATH = os.path.join(ROOT, "audit", "audit.jsonl")
SECRETS_DIR = os.path.join(ROOT, "secrets")
PORT = 8765

APPROVAL_TTL = 120      # seconds a human has to approve a request
GRANT_TTL = 30          # seconds an issued grant stays usable
MAX_CODE_ATTEMPTS = 3   # wrong codes before the request is denied
SIGNING_KEY_MAX_AGE = 30 * 86400    # rotate the Ed25519 signing key after this many seconds

TEST_CODE_PATH = os.path.join(SECRETS_DIR, "test_code.txt")


def test_code():
    """TESTING ONLY: one fixed approval code while secrets/test_code.txt exists. Delete it to go back
    to a fresh random code per request."""
    try:
        with open(TEST_CODE_PATH, encoding="utf-8") as f:
            return re.sub(r"\D", "", f.read()) or None
    except OSError:
        return None


PATH_KEYS = ("file_path", "notebook_path", "path")
SHELL_TOOLS = ("Bash", "PowerShell")


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def action_hash(tool_name, tool_input):
    """Binds a grant to one exact action: same tool, same arguments."""
    return hashlib.sha256(canonical({"tool": tool_name, "input": tool_input}).encode()).hexdigest()


def norm_path(p, cwd=None):
    p = os.path.expandvars(os.path.expanduser(str(p)))
    if cwd and not os.path.isabs(p):
        p = os.path.join(cwd, p)
    return os.path.normpath(p).replace("\\", "/").lower()


RISK_ORDER = ("low", "medium", "high", "critical")


def higher_risk(a, b):
    return max(a, b, key=lambda r: RISK_ORDER.index(r) if r in RISK_ORDER else 1)


GMAIL = "mcp__claude_ai_Gmail__"


def _people(v):
    return ", ".join(v) if isinstance(v, list) else str(v or "?")


def summarize(tool_name, tool_input, limit=160):
    t = tool_input
    if tool_name == GMAIL + "send_message":
        s = (f"send the Gmail draft {t['draftId']}" if t.get("draftId") else
             f"send an email to {_people(t.get('to'))} with subject \"{t.get('subject', '')}\"")
    elif tool_name == GMAIL + "reply":
        s = f"reply{' to everyone' if t.get('replyAll') else ''} to an email: \"{t.get('body', '')}\""
    elif tool_name == GMAIL + "forward":
        s = f"forward an email to {_people(t.get('to'))}"
    elif tool_name == GMAIL + "create_draft":
        s = f"save an email draft to {_people(t.get('to'))} with subject \"{t.get('subject', '')}\""
    elif tool_name == "mcp__playwright__browser_click":
        s = f"click \"{t.get('element', '?')}\" in the browser"
    elif tool_name in ("mcp__playwright__browser_type", "mcp__playwright__browser_press_key"):
        s = (f"type \"{t.get('text', '')}\" into {t.get('element', 'the page')} and submit"
             if tool_name.endswith("type") else f"press {t.get('key', '?')} in the browser")
    elif tool_name == "mcp__playwright__browser_navigate":
        s = f"open {t.get('url', '?')} in the browser"
    elif tool_name == "mcp__comms__whatsapp_send":
        s = f"send a WhatsApp message to {t.get('to', '?')}: \"{t.get('message', '')}\""
    elif tool_name in SHELL_TOOLS:
        s = f"run command: {tool_input.get('command', '')}"
    elif any(k in tool_input for k in PATH_KEYS):
        verb = {"Write": "write file", "Edit": "edit file", "Read": "read file"}.get(tool_name, tool_name)
        s = f"{verb} {next(tool_input[k] for k in PATH_KEYS if k in tool_input)}"
    elif tool_name == "WebFetch":
        s = f"fetch web page {tool_input.get('url', '')}"
    else:
        s = f"use tool {tool_name} with {canonical(tool_input)}"
    s = " ".join(s.split())
    return s if len(s) <= limit else s[:limit - 3] + "..."


def load_secret(name, generate=False):
    path = os.path.join(SECRETS_DIR, name)
    if not os.path.exists(path) and generate:
        os.makedirs(SECRETS_DIR, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(secrets.token_urlsafe(32))
    with open(path, encoding="utf-8") as f:
        return f.read().strip()


class Signer:
    """Ed25519 signing identity for the audit log and receipts. The private key stays in
    secrets/ (which the agent may not touch); the public key is distributable, so anyone can
    verify a receipt or the whole audit log WITHOUT holding any secret. This is what makes the
    records non-repudiable and the audit log tamper-proof rather than merely tamper-evident:
    rewriting history would require the private key, not just recomputing SHA-256 hashes.

    The key can be rotated. Old public keys are kept (signing_pubs.json) so historical entries
    still verify, and on rotation the OLD key signs the NEW public key, so anyone who trusts the
    old key can extend that trust to the new one without any out-of-band step."""

    def __init__(self, secrets_dir):
        self.secrets_dir = secrets_dir
        self._priv = self._load_or_create_priv()
        self._pub = self._priv.public_key()
        self.pubs, self.current_since = self._load_meta()
        self._save_meta()

    @property
    def _priv_path(self):
        return os.path.join(self.secrets_dir, "signing_key.hex")

    @property
    def _meta_path(self):
        return os.path.join(self.secrets_dir, "signing_pubs.json")

    def _load_or_create_priv(self):
        try:
            with open(self._priv_path, encoding="utf-8") as f:
                return ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(f.read().strip()))
        except (OSError, ValueError):
            priv = ed25519.Ed25519PrivateKey.generate()
            self._write_priv(priv)
            return priv

    def _write_priv(self, priv):
        os.makedirs(self.secrets_dir, exist_ok=True)
        raw = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                 serialization.NoEncryption())
        with open(self._priv_path, "w", encoding="utf-8") as f:
            f.write(raw.hex())
        try:
            os.chmod(self._priv_path, 0o600)
        except OSError:
            pass

    def _load_meta(self):
        cur = self.public_hex()
        try:
            with open(self._meta_path, encoding="utf-8") as f:
                m = json.load(f)
            pubs = list(m.get("pubs") or [])
            since = float(m.get("current_since") or time.time())
        except (OSError, ValueError):
            pubs, since = [], time.time()
        if cur not in pubs:                     # a key that appeared without a recorded rotation
            pubs.append(cur)
            since = time.time()
        return pubs, since

    def _save_meta(self):
        os.makedirs(self.secrets_dir, exist_ok=True)
        with open(self._meta_path, "w", encoding="utf-8") as f:
            json.dump({"pubs": self.pubs, "current_since": self.current_since}, f)
        try:
            with open(os.path.join(self.secrets_dir, "signing_pub.hex"), "w", encoding="utf-8") as f:
                f.write(self.public_hex())
        except OSError:
            pass

    def public_hex(self):
        return self._pub.public_bytes(serialization.Encoding.Raw,
                                      serialization.PublicFormat.Raw).hex()

    def public_history(self):
        return list(self.pubs)

    def age(self):
        return time.time() - self.current_since

    def sign(self, msg):
        return self._priv.sign(msg.encode()).hex()

    def rotate(self):
        """Generate a new keypair; the OLD key signs the NEW public key (the transition signature)
        so trust in the old key extends to the new one. Returns the old/new keys and that signature."""
        old_priv, old_pub = self._priv, self.public_hex()
        new_priv = ed25519.Ed25519PrivateKey.generate()
        new_pub = new_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        transition_sig = old_priv.sign(new_pub.encode()).hex()
        self._write_priv(new_priv)
        self._priv, self._pub = new_priv, new_priv.public_key()
        self.pubs.append(new_pub)
        self.current_since = time.time()
        self._save_meta()
        return {"old_pub": old_pub, "new_pub": new_pub, "transition_sig": transition_sig}


def verify_sig(pub_hex, msg, sig_hex):
    """True iff sig_hex is a valid Ed25519 signature over msg by pub_hex. Needs no secret."""
    try:
        pub = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
        pub.verify(bytes.fromhex(sig_hex), msg.encode())
        return True
    except Exception:
        return False


LEVELS = ("confirm", "code", "two_person")      # how a human approves: a spoken yes, a code, two codes


def matches(tool_name, patterns):
    return any(fnmatch.fnmatchcase(tool_name, p) for p in patterns or [])


class Policy:
    def __init__(self, path=POLICY_PATH):
        with open(path, encoding="utf-8") as f:
            doc = yaml.safe_load(f)
        self.default = doc.get("default", "approve")
        # Phase 1 controls; every section is optional.
        self.levels = {"low": "code", "medium": "code", "high": "code", "critical": "two_person",
                       **(doc.get("approval_levels") or {})}
        self.labels = {k: re.compile(v) for k, v in (doc.get("data_labels") or {}).items()}
        self.label_rules = doc.get("label_rules") or {}
        self.outbound = doc.get("outbound_tools") or []
        self.untrusted_sources = doc.get("untrusted_sources") or []
        self.untrusted_outbound = doc.get("untrusted_outbound_tools") or []
        self.limits = doc.get("limits") or []
        self.budgets = doc.get("budgets") or []
        self.emergency = doc.get("emergency") or {}
        self.protected = [norm_path(p) for p in doc.get("protected_paths", [])]
        self.protected_shell = [re.compile(p, re.I) for p in doc.get("protected_shell_patterns", [])]
        self.rules = doc.get("rules", [])
        for r in self.rules:
            r["_paths"] = [norm_path(p) for p in r.get("paths", [])]
            if "command_regex" in r:
                r["_re"] = re.compile(r["command_regex"])
            if "input_regex" in r:      # matched against the whole tool input as JSON
                r["_input_re"] = re.compile(r["input_regex"])

    def _is_protected(self, p):
        return any(fnmatch.fnmatch(p, g) or p == g.rstrip("/*") for g in self.protected)

    def evaluate(self, tool_name, tool_input, cwd=None):
        """Return (decision, rule_name, risk); decision is allow, approve, deny or ai."""
        paths = [norm_path(tool_input[k], cwd) for k in PATH_KEYS if tool_input.get(k)]
        pattern = tool_input.get("pattern")
        if tool_name == "Glob" and pattern and os.path.isabs(os.path.expanduser(str(pattern))):
            paths.append(norm_path(pattern))
        if not paths and tool_name in ("Glob", "Grep", "LS") and cwd:
            paths.append(norm_path(cwd))
        command = str(tool_input.get("command", "")) if tool_name in SHELL_TOOLS else ""
        command_norm = command.replace("\\", "/")

        # Protected resources are denied outright; approval cannot unlock them.
        if any(self._is_protected(p) for p in paths):
            return "deny", "protected path", "critical"
        if command and any(rx.search(command_norm) for rx in self.protected_shell):
            return "deny", "protected resource in shell command", "critical"

        for r in self.rules:
            if not any(fnmatch.fnmatchcase(tool_name, t) for t in r["tools"]):
                continue
            if r["_paths"] and not (paths and all(any(fnmatch.fnmatch(p, g) for g in r["_paths"]) for p in paths)):
                continue
            if "_re" in r and not r["_re"].search(command):
                continue
            if "_input_re" in r and not r["_input_re"].search(canonical(tool_input)):
                continue
            risk = r.get("risk", "medium" if r["decision"] == "approve" else "low")
            return r["decision"], r["name"], risk
        return self.default, "default (unlisted action)", "medium"


class AuditLog:
    """Append-only JSONL; each entry carries the hash of the previous one, and — when a signer is
    given — an Ed25519 signature over that hash, so the chain cannot be rewritten without the key."""

    GENESIS = "0" * 64

    def __init__(self, path=AUDIT_PATH, signer=None):
        self.path = path
        self.signer = signer
        self._lock = threading.Lock()
        self._prev, self._seq = self.GENESIS, 0
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self._writer = self._claim(path + ".lock")
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        e = json.loads(line)
                        self._prev, self._seq = e["hash"], e["seq"]

    @staticmethod
    def _claim(lock_path):
        """One writer per audit log: a second process would fork the hash chain (seen in testing,
        when two TARA servers ran at once and both appended)."""
        handle = open(lock_path, "a+")
        try:
            if os.name == "nt":
                import msvcrt
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            handle.close()
            raise RuntimeError(f"another TARA process is already writing {lock_path[:-5]}")
        return handle       # kept open: the lock lasts as long as this process

    def append(self, event):
        with self._lock:
            entry = {"seq": self._seq + 1, "ts": round(time.time(), 3), "prev": self._prev, **event}
            entry["hash"] = hashlib.sha256(canonical(entry).encode()).hexdigest()
            if self.signer:                      # sign the hash: forging history needs the private key,
                entry["sig"] = self.signer.sign(entry["hash"])   # not just recomputing the chain
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(canonical(entry) + "\n")
            self._prev, self._seq = entry["hash"], entry["seq"]
            return entry


def verify_audit(path=AUDIT_PATH, pub_hex=None, require_signed=False):
    """Return (ok, entries_checked, message). Always checks the hash chain. pub_hex may be one key
    or a list of keys (a rotation history); a signed entry must verify under at least one of them.
    With require_signed, an unsigned entry is itself a failure (so stripping signatures can't pass).
    Signatures make the log tamper-proof: the hash chain alone can be rewritten wholesale by
    recomputing hashes, but not re-signed."""
    candidates = [pub_hex] if isinstance(pub_hex, str) else (list(pub_hex) if pub_hex else [])
    prev, seq, signed, unsigned = AuditLog.GENESIS, 0, 0, 0
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            if not line.strip():
                continue
            e = json.loads(line)
            h = e.pop("hash", "")
            sig = e.pop("sig", None)
            if e.get("prev") != prev or e.get("seq") != seq + 1:
                return False, seq, f"line {n}: chain broken (entry removed, reordered or inserted)"
            if hashlib.sha256(canonical(e).encode()).hexdigest() != h:
                return False, seq, f"line {n}: entry was modified"
            if sig is None:
                if require_signed:
                    return False, seq, f"line {n}: entry is not signed"
                unsigned += 1
            elif candidates and not any(verify_sig(p, h, sig) for p in candidates):
                return False, seq, f"line {n}: bad signature (entry forged or wrong key)"
            else:
                signed += 1
            prev, seq = h, e["seq"]
    return True, seq, f"ok ({signed} signed, {unsigned} unsigned)"


@dataclass
class Request:
    request_id: str
    job_id: str
    session_id: str
    agent: str
    tool_name: str
    action_hash: str
    summary: str
    risk: str
    rule: str
    reason: str
    code: str
    expires: float
    status: str = "pending"     # pending | approved | denied | expired
    attempts: int = 0
    grant: str = ""
    level: str = "code"         # confirm | code | two_person
    code2: str = ""             # second approver's code (two_person)
    approved_by: tuple = ()     # which codes were given so far
    amount: float = 0.0         # spend to charge to a budget once approved
    budget: str = ""


def amount_of(tool_input):
    """A payment amount in the action: an 'amount' field, else the first $ figure."""
    if isinstance(tool_input.get("amount"), (int, float)):
        return float(tool_input["amount"])
    m = re.search(r"\$\s?(\d[\d,]*(?:\.\d+)?)", canonical(tool_input))
    return float(m.group(1).replace(",", "")) if m else 0.0


class State:
    """TARA's own state that must survive restarts: frozen, spending, message counts, labels,
    emergency window. Kept under ~/tara, which the agent may not touch."""

    def __init__(self, path):
        self.path = path
        self.data = {"frozen": None, "spend": [], "events": [], "labels": {}, "emergency": None,
                     "used_grants": []}
        if path and os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as f:
                    self.data.update(json.load(f))
            except (OSError, ValueError):
                self.data["frozen"] = {"why": "state file unreadable; frozen to be safe", "at": time.time()}
        self.save()

    def save(self):
        if not self.path:
            return
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.data, f)
        os.replace(tmp, self.path)


class TaraCore:
    def __init__(self, policy_path=POLICY_PATH, audit_path=AUDIT_PATH, risk_assessor=None,
                 secrets_dir=SECRETS_DIR, on_alert=None):
        self.policy = Policy(policy_path)
        self.secrets_dir = secrets_dir
        self.signer = Signer(secrets_dir)       # Ed25519: signs the audit log and receipts
        self.audit = AuditLog(audit_path, signer=self.signer)
        # risk_assessor(tool_name, tool_input, task, action_hash) -> {decision, risk, reason, source}
        self.risk_assessor = risk_assessor
        self._key = secrets.token_bytes(32)     # grant signing key; never leaves this process
        self._requests = {}
        self._cv = threading.Condition()
        self.recent = collections.deque(maxlen=6)
        self.state = State(os.path.join(os.path.dirname(audit_path), "state.json"))
        now = time.time()                       # consumed grants survive a restart: no replay window
        self.state.data["used_grants"] = [[g, e] for g, e in self.state.data.get("used_grants", []) if e > now]
        self._used_grants = {g for g, e in self.state.data["used_grants"]}
        self.state.save()
        self.alerts = collections.deque(maxlen=20)         # shown by the approval window
        self.on_alert = on_alert or self.alerts.append
        self.receipts_path = os.path.join(os.path.dirname(audit_path), "receipts.jsonl")
        self._maybe_rotate_signing_key()        # scheduled rotation when the key is too old
        self._attest(policy_path)               # record the policy hash into the signed log

    def _secret(self, name, generate=False):
        path = os.path.join(self.secrets_dir, name)
        if not os.path.exists(path) and generate:
            os.makedirs(self.secrets_dir, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(secrets.token_urlsafe(32))
        try:
            with open(path, encoding="utf-8") as f:
                return f.read().strip()
        except OSError:
            return ""

    def _attest(self, policy_path):
        """Startup integrity attestation into the signed audit log: the policy file's SHA-256 and
        the signing public key. Any later edit to the policy appears as a different hash on the
        next start, and the attestation itself cannot be forged without the signing key."""
        try:
            with open(policy_path, "rb") as f:
                psha = hashlib.sha256(f.read()).hexdigest()
        except OSError:
            psha = "unreadable"
        self._log({"event": "attest", "policy_sha256": psha, "pubkey": self.signer.public_hex(),
                   "result": "startup integrity attestation"})

    def rotate_signing_key(self, reason="manual"):
        """Rotate the Ed25519 signing identity and record it in the signed audit log. The entry
        carries the old and new public keys and the transition signature linking them."""
        info = self.signer.rotate()
        self._log({"event": "key_rotation", "reason": reason, "old_pubkey": info["old_pub"],
                   "new_pubkey": info["new_pub"], "transition_sig": info["transition_sig"],
                   "result": "signing key rotated"})
        return info

    def _maybe_rotate_signing_key(self):
        if self.signer.age() > SIGNING_KEY_MAX_AGE:
            self.rotate_signing_key(reason="scheduled (signing key exceeded max age)")

    def public_key_info(self):
        """Public signing keys (current plus retired), safe to hand to anyone for verification."""
        return {"pubkey": self.signer.public_hex(), "history": self.signer.public_history()}

    # --- kill switch -------------------------------------------------------------------------

    def frozen(self):
        return self.state.data.get("frozen")

    def freeze(self, why, via="voice"):
        """Stop everything: deny all pending requests and void every grant already issued."""
        with self._cv:
            self.state.data["frozen"] = {"why": why, "at": time.time(), "via": via}
            self.state.save()
            for r in self._requests.values():
                if r.status == "pending":
                    r.status = "denied"
            self._key = secrets.token_bytes(32)     # grants signed with the old key no longer verify
            self._log({"event": "freeze", "via": via, "reason": why, "result": "frozen"})
            self._cv.notify_all()
        self.on_alert(f"TARA is frozen: {why}")
        return {"ok": True, "frozen": True}

    def unfreeze(self, via):
        """Only the human at the laptop window may unfreeze; a voice or agent request cannot."""
        if via != "laptop-window":
            return {"ok": False, "reason": "unfreeze only from the TARA window on the laptop"}
        self.state.data["frozen"] = None
        self.state.save()
        self._log({"event": "unfreeze", "via": via, "result": "unfrozen"})
        return {"ok": True}

    # --- data labels and where data came from -------------------------------------------------

    def observe(self, session_id, job_id, tool_name, tool_input, response):
        """After a tool ran: label the session with what it read (CUI, PHI, ...) and whether the
        content came from an untrusted source. Labels only ever add up within a session."""
        text = response if isinstance(response, str) else canonical(response)
        found = {name for name, rx in self.policy.labels.items() if rx.search(text or "")}
        if matches(tool_name, self.policy.untrusted_sources):
            found.add("untrusted")
        if not found:
            return {"labels": sorted(self.session_labels(session_id))}
        with self._cv:
            have = set(self.state.data["labels"].get(session_id, []))
            new = found - have
            self.state.data["labels"][session_id] = sorted(have | found)
            self.state.save()
        if new:
            self._log({"event": "label", "session": session_id, "job": job_id, "tool": tool_name,
                       "labels": sorted(new), "result": "labelled"})
        return {"labels": sorted(self.session_labels(session_id))}

    def session_labels(self, session_id):
        return set(self.state.data["labels"].get(session_id, []))

    def _flow_check(self, session_id, tool_name, decision, risk, rule):
        """Data read in this session limits where actions may send things."""
        labels = self.session_labels(session_id)
        if matches(tool_name, self.policy.outbound):
            for label in sorted(labels):
                need = self.policy.label_rules.get(label)
                if need == "deny":
                    return "deny", f"{label} data may not leave (read earlier in this task)", "critical"
                if need == "two_person" and decision != "deny":
                    return "approve", f"{label} data leaving needs two approvers", "critical"
        if "untrusted" in labels and decision == "allow" and matches(tool_name, self.policy.untrusted_outbound):
            return "approve", f"{rule}; untrusted content was read earlier in this task", higher_risk(risk, "high")
        return decision, rule, risk

    # --- rate limits and budgets ----------------------------------------------------------------

    @staticmethod
    def _window(per):
        return {"minute": 60, "hour": 3600, "day": 86400, "week": 7 * 86400}.get(per, 3600)

    def _limit_check(self, tool_name, decision, rule, risk):
        now = time.time()
        for lim in self.policy.limits:
            if not matches(tool_name, lim.get("tools")):
                continue
            since = now - self._window(lim.get("per", "hour"))
            used = sum(1 for e in self.state.data["events"] if e["limit"] == lim["name"] and e["at"] > since)
            if used >= int(lim.get("max", 10)):
                over = lim.get("over", "deny")
                return over, f"limit '{lim['name']}' reached ({used} per {lim.get('per', 'hour')})", "high"
        return decision, rule, risk

    def _count(self, tool_name):
        now = time.time()
        keep = now - 8 * 86400
        self.state.data["events"] = [e for e in self.state.data["events"] if e["at"] > keep]
        for lim in self.policy.limits:
            if matches(tool_name, lim.get("tools")):
                self.state.data["events"].append({"limit": lim["name"], "at": now})
        self.state.save()

    def _budget(self, tool_name, tool_input):
        """(budget, amount, remaining) for a payment this budget covers, else None."""
        for b in self.policy.budgets:
            if matches(tool_name, b.get("tools")):
                amount = amount_of(tool_input)
                since = time.time() - self._window(b.get("per", "week"))
                spent = sum(s["amount"] for s in self.state.data["spend"] if s["budget"] == b["name"] and s["at"] > since)
                return b, amount, float(b.get("limit", 0)) - spent
        return None

    def _spend(self, budget, amount):
        if budget and amount:
            self.state.data["spend"].append({"budget": budget, "amount": amount, "at": time.time()})
            self.state.save()

    # --- voice identity (may only make rules STRICTER, never looser) -------------------------
    # The bridge checks the wake-word audio against enrolled voices and reports the verdict here.
    # An unknown speaker (only when voices are enrolled) adds friction; it never grants anything.

    SPEAKER_FRESH = 180        # seconds a speaker verdict stays relevant after someone speaks

    def set_speaker(self, enrolled, known, name, score):
        self.current_speaker = {"enrolled": bool(enrolled), "known": bool(known), "name": name,
                                "score": score, "at": time.time()}
        self._log({"event": "speaker", "known": bool(known), "name": name or "", "score": score,
                   "result": "known voice" if known else ("unknown voice" if enrolled else "no voices enrolled")})
        return {"ok": True}

    def _unknown_speaker(self):
        """True only when voices are enrolled and the most recent one was NOT recognized."""
        s = getattr(self, "current_speaker", None)
        return bool(s and s["enrolled"] and not s["known"] and time.time() - s["at"] < self.SPEAKER_FRESH)

    SENSITIVE_IF_UNKNOWN = ("mcp__comms__*", "mcp__claude_ai_Gmail__send_*", "mcp__claude_ai_Gmail__reply",
                            "mcp__claude_ai_Gmail__forward", "mcp__playwright__browser_*", "talk_on_whatsapp",
                            "pay_*", "Bash", "PowerShell", "Write", "Edit")

    # --- emergency override ---------------------------------------------------------------------

    def cancel_emergency(self, via="voice"):
        if self.state.data.get("emergency"):
            self.state.data["emergency"] = None
            self.state.save()
            self._log({"event": "emergency", "via": via, "result": "emergency override cancelled"})
        return {"ok": True}

    def declare_emergency(self, situation, via="voice"):
        if situation == "__cancel__":
            return self.cancel_emergency(via)
        minutes = float(self.policy.emergency.get("minutes", 15))
        self.state.data["emergency"] = {"situation": situation, "until": time.time() + minutes * 60, "via": via}
        self.state.save()
        self._log({"event": "emergency", "via": via, "situation": situation, "minutes": minutes,
                   "result": "emergency override on (review afterwards)"})
        self.on_alert(f"TARA emergency override on for {minutes:g} minutes: {situation}")
        return {"ok": True, "minutes": minutes, "contacts": self._emergency_contacts()}

    def _emergency_contacts(self):
        return [c for a in self.policy.emergency.get("allow", []) for c in a.get("to", [])]

    def _emergency_allows(self, tool_name, tool_input):
        e = self.state.data.get("emergency")
        if not e or e["until"] < time.time():
            return False
        to = str(tool_input.get("to", "")).strip().lower()
        return any(matches(tool_name, a.get("tools")) and to in [c.lower() for c in a.get("to", [])]
                   for a in self.policy.emergency.get("allow", []))

    # --- receipts -------------------------------------------------------------------------------

    def _receipt(self, req, via):
        body = {"request_id": req.request_id, "job": req.job_id, "action": req.summary,
                "action_hash": req.action_hash, "level": req.level, "via": via, "at": round(time.time(), 3)}
        key = self._secret("receipt_key.txt", generate=True).encode()
        sig = hmac.new(key, canonical(body).encode(), hashlib.sha256).hexdigest()
        rec = {**body, "receipt": "R-" + sig[:8].upper(), "sig": sig,
               "ed25519": self.signer.sign(canonical(body)), "pubkey": self.signer.public_hex()}
        with open(self.receipts_path, "a", encoding="utf-8") as f:
            f.write(canonical(rec) + "\n")
        return rec

    def verify_receipt(self, receipt_id):
        if not os.path.exists(self.receipts_path):
            return {"ok": False, "reason": "no receipts"}
        with open(self.receipts_path, encoding="utf-8") as f:
            for line in f:
                rec = json.loads(line)
                if rec["receipt"] == receipt_id:
                    body = {k: rec[k] for k in ("request_id", "job", "action", "action_hash", "level", "via", "at")}
                    if rec.get("ed25519"):      # public-key verifiable: no secret needed to check it
                        ok = verify_sig(rec.get("pubkey", ""), canonical(body), rec["ed25519"])
                    else:                       # legacy receipts: fall back to the HMAC
                        key = self._secret("receipt_key.txt").encode()
                        ok = bool(key) and hmac.compare_digest(
                            rec["sig"], hmac.new(key, canonical(body).encode(), hashlib.sha256).hexdigest())
                    return {"ok": ok, **body}
        return {"ok": False, "reason": "unknown receipt"}

    def _log(self, event):
        self.audit.append(event)
        if event["event"] in ("authorize", "approve", "deny", "expire", "consume", "code_rejected"):
            self.recent.appendleft(f"{time.strftime('%H:%M:%S')}  {event['event']:<13} "
                                   f"{event.get('decision') or event.get('result', '')}  {event.get('action', '')}")

    def _expire_locked(self):
        now = time.time()
        for r in self._requests.values():
            if r.status == "pending" and r.expires <= now:
                r.status = "expired"
                self._log({"event": "expire", "request_id": r.request_id, "job": r.job_id, "action": r.summary})
                self._cv.notify_all()

    # --- called by the agent-side hook ---------------------------------------------------

    def _assess(self, decision, risk, tool_name, tool_input, task, ahash):
        """Apply the AI risk agent within the policy's limits.

        Policy 'ai'      -> the agent's verdict decides (no agent or failure -> approve).
        Policy 'approve' -> stays approve; the agent only adds a risk level and a reason.
        Policy 'allow'/'deny' and protected resources are never sent to the agent.
        """
        if decision not in ("ai", "approve"):
            return decision, risk, None
        if self.risk_assessor is None:
            return "approve", risk, None
        v = self.risk_assessor(tool_name, tool_input, task, ahash)
        if decision == "ai":
            return v["decision"], v["risk"], v
        return "approve", higher_risk(risk, v["risk"]), v

    def authorize(self, job_id, session_id, agent, tool_name, tool_input, cwd=None, task=""):
        ahash = action_hash(tool_name, tool_input)
        summary = summarize(tool_name, tool_input)
        event = {"event": "authorize", "job": job_id, "session": session_id, "agent": agent, "tool": tool_name,
                 "action": summary, "action_hash": ahash}
        if self.frozen():
            event.update(decision="deny", rule="kill switch", risk="critical")
            self._log(event)
            return {"decision": "deny", "rule": "kill switch", "risk": "critical",
                    "reason": "TARA is frozen (kill switch); nothing can run until the human unfreezes it"}
        decision, rule, risk = self.policy.evaluate(tool_name, tool_input, cwd)
        policy_decision = decision
        decision, risk, verdict = self._assess(decision, risk, tool_name, tool_input, task, ahash)
        reason = verdict["reason"] if verdict else f"TARA policy '{rule}' -> {decision}"
        controls = []
        # Data labels and untrusted sources can only make a decision stricter.
        d2, rule2, risk2 = self._flow_check(session_id, tool_name, decision, risk, rule)
        if (d2, rule2) != (decision, rule):
            controls.append(rule2)
            decision, rule, risk, reason = d2, rule2, risk2, f"TARA: {rule2}"
        d2, rule2, risk2 = self._limit_check(tool_name, decision, rule, risk) if decision != "deny" else (decision, rule, risk)
        if d2 != decision:
            controls.append(rule2)
            decision, rule, risk, reason = d2, rule2, risk2, f"TARA: {rule2}"
        budget = self._budget(tool_name, tool_input) if decision != "deny" else None
        amount = 0.0
        if budget:
            b, amount, remaining = budget
            if decision == "approve" and 0 < amount <= remaining and not controls:
                decision, reason = "allow", f"TARA: within the '{b['name']}' budget (${remaining - amount:,.2f} left)"
                controls.append("within budget")
            elif decision == "approve":
                reason = f"TARA: over the '{b['name']}' budget (${max(0, remaining):,.2f} left); needs approval"
                controls.append("over budget")
        if decision == "approve" and not controls and self._emergency_allows(tool_name, tool_input):
            decision, reason = "allow", "TARA: emergency override (logged for review)"
            controls.append("emergency override")
        # Voice identity, last and only ever stricter: an unknown speaker (with voices enrolled)
        # can't auto-run a sensitive action, and a spoken "yes" is no longer enough.
        if self._unknown_speaker() and matches(tool_name, self.SENSITIVE_IF_UNKNOWN) \
                and "emergency override" not in controls:
            if decision == "allow":
                decision, risk = "approve", higher_risk(risk, "high")
            reason = reason + " (unrecognized voice: human approval required)"
            controls.append("unknown speaker")
        level = self.policy.levels.get(risk, "code") if decision == "approve" else ""
        if decision == "approve" and (level not in LEVELS or
                                      (self._unknown_speaker() and level == "confirm")):
            level = "code"
        event.update(decision=decision, rule=rule, risk=risk, policy_decision=policy_decision)
        if controls:
            event["controls"] = controls
        if verdict:
            event["risk_agent"] = verdict
        if decision != "approve":
            self._log(event)
            if decision == "allow":
                self._count(tool_name)
                if budget:
                    self._spend(budget[0]["name"], amount)
            return {"decision": decision, "rule": rule, "risk": risk, "reason": reason}
        with self._cv:
            self._expire_locked()
            new_code = lambda: test_code() or f"{secrets.randbelow(10 ** 6):06d}"
            code = new_code()
            req = Request(request_id=secrets.token_hex(8), job_id=job_id, session_id=session_id, agent=agent,
                          tool_name=tool_name, action_hash=ahash, summary=summary, risk=risk, rule=rule,
                          reason=reason, code=code, expires=time.time() + APPROVAL_TTL, level=level,
                          code2=f"{secrets.randbelow(10 ** 6):06d}" if level == "two_person" else "",
                          amount=amount, budget=budget[0]["name"] if budget else "")
            self._requests[req.request_id] = req
            event.update(decision="pending-approval", request_id=req.request_id, level=level)
            self._log(event)
            self._cv.notify_all()
        return {"decision": "pending", "request_id": req.request_id, "rule": rule, "summary": summary,
                "expires_in": APPROVAL_TTL, "level": level}

    def wait(self, request_id, timeout=25):
        deadline = time.time() + timeout
        with self._cv:
            while True:
                self._expire_locked()
                req = self._requests.get(request_id)
                if req is None:
                    return {"status": "unknown"}
                if req.status != "pending" or time.time() >= deadline:
                    return {"status": req.status, "grant": req.grant if req.status == "approved" else ""}
                self._cv.wait(min(1.0, max(0.0, deadline - time.time())))

    def consume(self, grant, session_id, tool_name, tool_input):
        """Verify a grant at the execution boundary and burn it (single use)."""
        def reject(reason):
            self._log({"event": "consume", "result": "rejected", "reason": reason, "tool": tool_name,
                       "action": summarize(tool_name, tool_input)})
            return {"ok": False, "reason": reason}

        try:
            body, sig = grant.rsplit(".", 1)
            expected = hmac.new(self._key, body.encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(sig, expected):
                return reject("invalid signature")
            payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        except (ValueError, TypeError):
            return reject("malformed grant")
        if payload["exp"] < time.time():
            return reject("grant expired")
        if payload["session"] != session_id:
            return reject("grant belongs to a different session")
        if payload["action_hash"] != action_hash(tool_name, tool_input):
            return reject("grant was issued for a different action")
        with self._cv:
            if payload["gid"] in self._used_grants:
                return reject("grant already used (replay)")
            self._used_grants.add(payload["gid"])
            self.state.data["used_grants"] = [[g, e] for g, e in self.state.data["used_grants"]
                                              if e > time.time()] + [[payload["gid"], payload["exp"]]]
            self.state.save()
        self._log({"event": "consume", "result": "ok", "grant": payload["gid"], "request_id": payload["rid"],
                   "tool": tool_name, "action": summarize(tool_name, tool_input)})
        return {"ok": True}

    def _issue_grant(self, req):
        payload = {"gid": secrets.token_hex(8), "rid": req.request_id, "job": req.job_id, "session": req.session_id,
                   "action_hash": req.action_hash, "exp": time.time() + GRANT_TTL}
        body = base64.urlsafe_b64encode(canonical(payload).encode()).decode().rstrip("=")
        return body + "." + hmac.new(self._key, body.encode(), hashlib.sha256).hexdigest()

    # --- called by the human-facing side (voice bridge, approval window) ------------------

    def _approved(self, req, via):
        """Mark a request approved (lock held): grant, budget spend, message count, receipt."""
        req.status = "approved"
        req.grant = self._issue_grant(req)
        self._spend(req.budget, req.amount)
        self._count(req.tool_name)
        rec = self._receipt(req, via)
        self._log({"event": "approve", "via": via, "request_id": req.request_id, "job": req.job_id,
                   "action": req.summary, "level": req.level, "receipt": rec["receipt"], "result": "approved"})
        self._cv.notify_all()
        return {"ok": True, "request_id": req.request_id, "job_id": req.job_id, "summary": req.summary,
                "receipt": rec["receipt"]}

    def confirm(self, request_id=None, via="voice"):
        """A spoken yes: enough only for requests whose level is 'confirm' (medium risk)."""
        with self._cv:
            self._expire_locked()
            live = [r for r in self._requests.values() if r.status == "pending" and r.level == "confirm"
                    and (request_id is None or r.request_id == request_id)]
            if not live:
                return {"ok": False, "reason": "nothing waiting that a spoken yes can approve"}
            return self._approved(live[0], via)

    def approve_code(self, code, job_id=None, via="voice"):
        code = re.sub(r"\D", "", str(code))
        duress = re.sub(r"\D", "", self._secret("duress_code.txt"))
        if duress and hmac.compare_digest(code, duress):
            return self._duress(via)
        with self._cv:
            self._expire_locked()
            live = [r for r in self._requests.values()
                    if r.status == "pending" and (job_id is None or r.job_id == job_id)]
            if not live:
                return {"ok": False, "reason": "no approval is pending"}
            match = next((r for r in live if hmac.compare_digest(r.code, code) or
                          (r.code2 and hmac.compare_digest(r.code2, code))), None)
            if match is not None and match.level == "two_person":
                which = "1" if hmac.compare_digest(match.code, code) else "2"
                match.approved_by = tuple(sorted(set(match.approved_by) | {which}))
                if len(match.approved_by) < 2:
                    self._log({"event": "approve_partial", "via": via, "request_id": match.request_id,
                               "action": match.summary, "approver": which, "result": "one of two approvals"})
                    return {"ok": False, "partial": True, "request_id": match.request_id,
                            "reason": "first approval recorded; the second approver's code is still needed"}
                return self._approved(match, via)
            if match is not None and match.level == "confirm":
                return self._approved(match, via)      # a code is stronger than the spoken yes it needs
            if match is None:
                locked = []
                for r in live:
                    r.attempts += 1
                    if r.attempts >= MAX_CODE_ATTEMPTS:
                        r.status = "denied"
                        locked.append(r.request_id)
                self._log({"event": "code_rejected", "via": via, "requests": [r.request_id for r in live],
                           "locked": locked, "result": "wrong code"})
                self._cv.notify_all()
                left = max(0, MAX_CODE_ATTEMPTS - max(r.attempts for r in live))
                return {"ok": False, "reason": "wrong code", "attempts_left": left, "locked": bool(locked)}
            return self._approved(match, via)

    def approve_fingerprint(self, finger_id, job_id=None, request_id=None, via="fingerprint"):
        """A fingerprint match from the board approves a pending request, replacing the typed code.
        A specific enrolled finger (secrets/duress_finger.txt) triggers the duress path; a second
        finger (secrets/second_finger.txt) counts as the second approver for two_person."""
        try:
            fid = int(finger_id)
        except (TypeError, ValueError):
            fid = -1
        duress = re.sub(r"\D", "", self._secret("duress_finger.txt"))
        if duress and fid >= 0 and str(fid) == duress:
            return self._duress(via)
        with self._cv:
            self._expire_locked()
            live = [r for r in self._requests.values()
                    if r.status == "pending" and (job_id is None or r.job_id == job_id)
                    and (request_id is None or r.request_id == request_id)]
            if not live:
                return {"ok": False, "reason": "no approval is pending"}
            if fid < 0:                         # no finger, or an unrecognized one: a failed attempt
                locked = []
                for r in live:
                    r.attempts += 1
                    if r.attempts >= MAX_CODE_ATTEMPTS:
                        r.status = "denied"
                        locked.append(r.request_id)
                self._log({"event": "fingerprint_rejected", "via": via,
                           "requests": [r.request_id for r in live], "locked": locked,
                           "result": "no fingerprint match"})
                self._cv.notify_all()
                left = max(0, MAX_CODE_ATTEMPTS - max(r.attempts for r in live))
                return {"ok": False, "reason": "fingerprint not recognized", "attempts_left": left,
                        "locked": bool(locked)}
            req = live[0]
            if req.level == "two_person":
                second = re.sub(r"\D", "", self._secret("second_finger.txt"))
                which = "2" if (second and str(fid) == second) else "1"
                req.approved_by = tuple(sorted(set(req.approved_by) | {which}))
                if len(req.approved_by) < 2:
                    self._log({"event": "approve_partial", "via": via, "request_id": req.request_id,
                               "action": req.summary, "approver": which, "result": "one of two approvals"})
                    return {"ok": False, "partial": True, "request_id": req.request_id,
                            "reason": "first fingerprint recorded; a second, different enrolled finger is needed"}
            return self._approved(req, via)

    def _duress(self, via):
        """The duress code: answer as if approved, but block everything and raise the alarm.
        Meant for someone forced to approve (a scammer on the phone, coercion in the field)."""
        with self._cv:
            hit = [r for r in self._requests.values() if r.status == "pending"]
            summary = hit[0].summary if hit else "nothing pending"
            for r in hit:
                r.status = "denied"
            self._log({"event": "duress", "via": via, "requests": [r.request_id for r in hit],
                       "action": summary, "result": "blocked silently; frozen; alert raised"})
            self._cv.notify_all()
        self.freeze("duress code used", via="duress")
        self.on_alert(f"TARA DURESS ALERT: someone used the duress code ({summary})")
        # To the voice side this looks like an ordinary approval.
        return {"ok": True, "request_id": hit[0].request_id if hit else "", "job_id": hit[0].job_id if hit else "",
                "summary": summary, "receipt": "R-" + secrets.token_hex(4).upper()}

    def deny(self, job_id=None, request_id=None, via="voice"):
        with self._cv:
            self._expire_locked()
            hit = [r for r in self._requests.values() if r.status == "pending"
                   and (request_id is None or r.request_id == request_id)
                   and (job_id is None or r.job_id == job_id)]
            for r in hit:
                r.status = "denied"
                self._log({"event": "deny", "via": via, "request_id": r.request_id, "job": r.job_id,
                           "action": r.summary, "result": "denied"})
            self._cv.notify_all()
        return {"ok": bool(hit), "denied": [r.summary for r in hit]}

    def pending_public(self, job_id=None):
        """Pending requests WITHOUT their codes (safe to hand to the voice side)."""
        with self._cv:
            self._expire_locked()
            return [{"request_id": r.request_id, "job_id": r.job_id, "summary": r.summary, "risk": r.risk,
                     "reason": r.reason, "expires_in": int(r.expires - time.time()), "level": r.level,
                     "approvals_given": len(r.approved_by),
                     "attempts_left": max(0, MAX_CODE_ATTEMPTS - r.attempts)}
                    for r in self._requests.values()
                    if r.status == "pending" and (job_id is None or r.job_id == job_id)]

    def snapshot(self):
        """Pending requests WITH codes, for the in-process approval window only."""
        with self._cv:
            self._expire_locked()
            return [dict(vars(r)) for r in self._requests.values() if r.status == "pending"]
