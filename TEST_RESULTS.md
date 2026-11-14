# Test results

This is a dated, reproducible record of running TARA's security test suite. Each of the tests is an attack or failure scenario from the threat model; the expected outcome is that TARA blocks or safely handles it.

## Latest run

| Field | Value |
|-------|-------|
| **Date (UTC)** | 2026-11-14T21:21:19Z |
| **Command** | `python tests/test_tara.py` |
| **Scenarios run** | **213** |
| **Passed** | **213** |
| **Failed / errored** | **0** |
| **Wall time** | 10.132 s |
| **Result** | `OK` |
| **Python** | CPython 3.12.6 (Windows, AMD64) |
| **Dependencies** | PyYAML 6.0.3, cryptography 50.0.2 |
| **Software revision tested** | `d5de900` (initial commit; `tests/test_tara.py` and `tara/core.py` unchanged since) |

### Console output (tail)

```text
----------------------------------------------------------------------
Ran 213 tests in 10.132s

OK
```

> The run also prints a few Python `ResourceWarning` lines about temporary audit-log lock files left open during test teardown. These are cosmetic (temp files in a throwaway directory) and do not affect any assertion or the `OK` result.

## How to reproduce

```bash
git clone https://github.com/manju-reddyy/tara.git
cd tara
python -m pip install -r requirements.txt
python tests/test_tara.py            # add -v to print every scenario name
```

The suite is self-contained: it constructs `TaraCore` instances against temporary audit logs and secrets directories, so it needs no running server, no GUI, and no network or API keys.

## What the suite covers

The 213 scenarios exercise, among others:

- **Policy evaluation** — allow / deny / approve decisions, first-match-wins rule ordering, and the default path.
- **Protected resources** — TARA's own files, keys, audit log, and the agent's credentials cannot be read or written, including via relative paths and shell patterns; approval cannot unlock them.
- **Grants** — single-use, bound to one exact action (tool + arguments) by hash, session-bound, time-limited; replays and cross-action reuse are rejected.
- **Human approval** — one-time codes, wrong-code lockout, the spoken-yes (`confirm`) level, and two-person approval (two different codes / two different fingerprints) for critical actions.
- **Prompt-injection resistance** — text in the action claiming prior approval, or instructing the reviewer, is ignored.
- **Fail-closed behavior** — when TARA is down, frozen (kill switch), or returns an error, the hook denies.
- **Data-aware escalation** — reading controlled (CUI), PHI, or SSN-shaped data escalates or denies later outbound actions.
- **Adapter behavior** — the Claude Code hook's PreToolUse/PostToolUse handling and its closed-failure path.

Continuous integration runs this same command on every push and pull request; see [`.github/workflows/ci.yml`](.github/workflows/ci.yml) and the build badge in the README.
