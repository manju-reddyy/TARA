# Changelog

All notable changes to TARA are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it
reaches 1.0.

## [0.1.0] — 2026-11-14

First public release of the working prototype.

### Added
- **Authorization engine** (`tara/core.py`): policy evaluation with first-match-wins rules; hard-denied protected paths and shell patterns; single-use, action-bound, session-bound, time-limited grants; tiered biometric human approval (fingerprint; two-person via two different enrolled fingerprints; a lighter confirm for medium risk; one-time-code fallback); data-aware escalation for CUI, PHI, and SSN-shaped data; append-only Ed25519-signed audit log; kill switch; and fail-closed behavior throughout.
- **Local authorization server** (`tara/server.py`): loopback HTTP API (`/authorize`, `/wait`, `/consume`, `/observe`, and `GET /pubkey`) plus a desktop approval window that shows each pending request (with a fallback one-time code).
- **Claude Code adapter** (`tara/hook.py`): PreToolUse and PostToolUse hooks that route every tool call through TARA and fail closed if it is unreachable.
- **Advisory AI risk agent** (`tara/risk_agent.py`): an optional, tool-less reviewer that can classify an action in context but never overrides policy or a required approval.
- **Security test suite** (`tests/test_tara.py`): 213 passing attack/failure scenarios.
- **Runnable demonstration** (`examples/demo.py`) and annotated output in `docs/DEMO.md`.
- **Documentation**: README, INSTALL, SECURITY, CONTRIBUTING, ROADMAP, a dated TEST_RESULTS report, and an architecture diagram (`docs/architecture.svg`).
- **Project scaffolding**: Apache-2.0 license, GitHub Actions CI, issue templates, and staged `pyproject.toml` for future PyPI distribution.

### Security
- Verified invariants under test: approval cannot unlock protected resources; the agent's own text never counts as approval; grants cannot be replayed or reused for a different action; the hook denies when TARA is down or frozen.

[0.1.0]: https://github.com/manju-reddyy/tara/releases/tag/v0.1.0
