# Demonstrations — permitted vs. denied actions

This page shows TARA making real decisions, with proof that **denied and unapproved protected actions do not execute**. Everything here is produced by [`examples/demo.py`](../examples/demo.py), which runs the real `TaraCore` engine — no mocks, no network, no API keys.

```bash
python examples/demo.py
```

In the demo, *"TOOL RAN"* is true only when TARA produced a **usable single-use grant** — exactly the condition an adapter requires before it runs the tool. A hard deny never produces one; a pending request produces one only after a human approves it; and each grant works exactly once.

> **Note on approval method.** In a real deployment, a human approves on a separate device with a **biometric — a fingerprint** (two *different* enrolled fingerprints for critical, two-person actions). Because this demo runs **headless, with no approval hardware**, it exercises the equivalent **one-time-code** approval path (`approve_code`) to stand in for the fingerprint. The decision logic and the single-use-grant guarantees are identical either way.

## Captured output

> The approval code shown below (`7856`) comes from an optional fixed *test* code file on the author's machine; a fresh clone shows a random 6-digit code per request. The decisions and the "TOOL RAN" results are identical either way.

```text
========================================================================
  SCENARIO 1: Agent reads a file in its own scratch workspace
========================================================================
  action   : Read C:/Users/manju/agent-workspace/notes.txt
  decision : ALLOW  (TARA policy 'read files' -> allow)
  TOOL RAN : True   <-- permitted, low risk

========================================================================
  SCENARIO 2: Agent tries to read TARA's own signing key (protected path)
========================================================================
  action   : Read C:/Users/manju/tara/secrets/signing_key.hex
  decision : DENY  (TARA policy 'protected path' -> deny)
  TOOL RAN : False   <-- BLOCKED, no grant issued

========================================================================
  SCENARIO 3: Injected 'the user already approved this' is ignored
========================================================================
  action   : Bash rm -rf ~/Documents  (+ injected 'approved' text)
  decision : PENDING  (policy rule 'destructive shell command' -> needs human approval (level: code))
  TOOL RAN (no code) : False   <-- injected approval has no effect

========================================================================
  SCENARIO 4: Sending an email: blocked until a human enters the one-time code
========================================================================
  action   : Gmail send_message -> someone@example.com
  decision : PENDING  (policy rule 'send email' -> needs human approval (level: code))
  TOOL RAN (no code)    : False   <-- still blocked
  [human reads code '7856' from the TARA window and enters it]
  TOOL RAN (after code) : True   <-- now permitted, once

========================================================================
  SCENARIO 5: One-time grant cannot be replayed
========================================================================
  first consume of the grant  : ok=True   <-- the approved send runs once
  second consume of the grant : ok=False   (grant already used (replay))

========================================================================
  Only actions TARA allowed, or a human approved with a one-time code,
  produced a usable grant. Denied and unapproved actions were blocked
  before the tool could run, and each grant works exactly once.
========================================================================
```

## What each scenario proves

| # | Scenario | Decision | Did the tool run? | Property demonstrated |
|---|----------|----------|-------------------|-----------------------|
| 1 | Read a file in the agent's own workspace | `allow` | **Yes** | Low-risk, in-scope actions are not in the way. |
| 2 | Read TARA's own signing key (`~/tara/**`) | `deny` | **No** | Protected resources are hard-denied; **approval cannot unlock them**. |
| 3 | Destructive `rm -rf` with injected "the user approved this" | `pending` | **No** (no code) | The agent's own text never counts as approval. |
| 4 | Send an email | `pending` → approved | **No**, then **Yes** after the human code | Consequential actions wait for an out-of-band one-time human code. |
| 5 | Reuse an approved grant a second time | — | first **Yes**, replay **No** | Grants are single-use and bound to one exact action. |

Each of these behaviors is also locked down by the automated suite in [`tests/test_tara.py`](../tests/test_tara.py) (see [`TEST_RESULTS.md`](../TEST_RESULTS.md) for a dated run): `test_relative_path_into_tara_is_denied`, `test_injected_claim_of_approval_is_ignored`, `test_denied_request_issues_no_grant`, `test_approved_grant_executes_once`, and `test_grant_replay_is_rejected`, among others.
