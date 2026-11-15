# Installation & setup

TARA has two things you can run:

1. **The authorization engine + test suite + demo** — pure Python, two dependencies, no GUI needed. Enough to inspect every decision TARA makes and to reproduce the 213-test suite.
2. **The authorization server** — a local HTTP service plus a desktop approval window, which a real agent adapter talks to.

This guide covers both, then wiring the shipped **Claude Code** adapter.

---

## Requirements

- **Python 3.10 or newer** (developed and tested on CPython **3.12.6**).
- Two Python packages: **PyYAML** and **cryptography** (see [`requirements.txt`](requirements.txt)).
- **tkinter** for the approval *window* only. It ships with the official python.org installers on Windows and macOS. On Debian/Ubuntu: `sudo apt-get install python3-tk`. You do **not** need tkinter to run the demo or the tests.

Check your Python:

```bash
python --version        # should print 3.10+ (3.12 recommended)
```

## 1. Clone and install dependencies

```bash
git clone https://github.com/manju-reddyy/tara.git
cd tara
python -m pip install -r requirements.txt
```

Verify the core imports and dependencies resolve:

```bash
python -c "import yaml, cryptography; print('deps OK')"
```

## 2. Run the demo (no server, no GUI, no API keys)

```bash
python examples/demo.py
```

This exercises the real engine against five scenarios (allow, hard-deny, ignored injection, human-approved send, grant replay) and prints whether each action would actually run. See [`docs/DEMO.md`](docs/DEMO.md) for annotated output.

## 3. Run the security test suite

```bash
python tests/test_tara.py
```

Expected tail:

```
Ran 213 tests in ~10s

OK
```

> Run the suite with `python tests/test_tara.py` (the file puts `tara/` on `sys.path` itself). On some setups `python -m unittest tests.test_tara` fails to resolve that import path; prefer the direct invocation. To see each scenario name, add `-v`:
> `python tests/test_tara.py -v`

## 4. Run the authorization server

The server listens on **`127.0.0.1:8765`** (loopback only) and opens a desktop **approval window** that shows each pending request. Primary approval is a **biometric (a fingerprint) on a separate approval device**; a one-time code in this window is available as a fallback.

```bash
python tara/server.py
```

You should see `TARA authorization server on 127.0.0.1:8765` and a window titled **"TARA — Human Authorization."** Leave it running; an agent adapter talks to it.

Endpoints (all POST unless noted; JSON in, JSON out):

| Route | Caller | Purpose |
|-------|--------|---------|
| `/authorize` | adapter | Decide an action: `allow` / `deny` / `pending` |
| `/wait` | adapter | Long-poll a pending request until a human decides |
| `/consume` | adapter | Redeem a single-use grant at the execution boundary |
| `/observe` | adapter | Report what a tool returned, so TARA can label the data |
| `/pubkey` (GET) | anyone | The Ed25519 public key(s) for verifying the audit log |

Human-approval routes (`/approve`, `/deny`, `/pending`, …) require a bridge token and are used by the approval channels, not by the agent.

### Configuration

- **Policy** lives in [`policy.yaml`](policy.yaml): protected paths, rules (first match wins), data labels, approval levels, budgets. Edit it to fit your environment; the comments explain each section.
- **Port / server URL**: adapters read `TARA_URL` (default `http://127.0.0.1:8765`).
- **Secrets** (signing key, bridge token) are generated on first run under a `secrets/` directory and are **git-ignored** — they never leave the machine.
- **Audit log** is written to `audit/audit.jsonl` (also git-ignored).

## 5. Wire the Claude Code adapter

The adapter ([`tara/hook.py`](tara/hook.py)) runs as a Claude Code **PreToolUse** hook (every tool call must be authorized) and, with `--post`, a **PostToolUse** hook (so TARA can label returned data). It fails closed: if TARA cannot be reached, the call is denied.

Add hooks to your Claude Code settings so each tool call is routed through TARA. Conceptually:

```jsonc
{
  "hooks": {
    "PreToolUse":  [{ "matcher": "*", "hooks": [{ "type": "command",
        "command": "python /absolute/path/to/tara/tara/hook.py" }] }],
    "PostToolUse": [{ "matcher": "*", "hooks": [{ "type": "command",
        "command": "python /absolute/path/to/tara/tara/hook.py --post" }] }]
  }
}
```

With the server running and the hooks in place, Claude Code will block on TARA for every tool call: allowed actions proceed, risky ones wait for a human **biometric approval** (a fingerprint on the TARA device; a one-time code in the window is a fallback), and denied ones never execute.

> **Windows hardware/voice bridge (optional).** `start_tara.ps1` launches the server together with the bridge to the hardware approval device and an optional voice/speaker component (which only adds friction — an unrecognized voice asks for more — and never grants approval). That path has additional, optional dependencies and machine-specific paths; it is not required to use TARA's authorization core.

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `ModuleNotFoundError: No module named 'yaml'` | `pip install -r requirements.txt` (into the same interpreter you run with). |
| `No module named 'tkinter'` when starting the server | Install tkinter (`sudo apt-get install python3-tk` on Debian/Ubuntu). Not needed for the demo/tests. |
| `port 8765 ... is in use — is TARA already running?` | A server is already bound to the port. Stop the other instance. |
| Tests can't import `core` under `python -m unittest` | Use `python tests/test_tara.py` (it sets up `sys.path` itself). |
