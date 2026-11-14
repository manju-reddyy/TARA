# Roadmap

TARA is a working prototype today: the authorization engine and one adapter (Claude Code) are implemented and covered by 213 passing security tests. This roadmap lists what exists, what is next, and what is planned. Items marked **planned** are not yet implemented.

## Implemented (today)

- **Authorization engine** (`tara/core.py`) — policy evaluation, protected-resource denial, single-use action-bound grants, tiered human approval (code / confirm / two-person), data-aware escalation (CUI / PHI / SSN), signed append-only audit log, kill switch, and fail-closed behavior.
- **Local server** (`tara/server.py`) — `127.0.0.1:8765` HTTP API (`/authorize`, `/wait`, `/consume`, `/observe`, `/pubkey`) and a desktop approval window.
- **Claude Code adapter** (`tara/hook.py`) — PreToolUse / PostToolUse hooks; fails closed.
- **Advisory AI risk agent** (`tara/risk_agent.py`) — optional, never overrides policy.
- **213-scenario security test suite** (`tests/test_tara.py`) and a runnable demo (`examples/demo.py`).

## Recommended next

- [ ] **Continuous integration** — GitHub Actions runs the suite on every push/PR. *(Workflow added in [`.github/workflows/ci.yml`](.github/workflows/ci.yml); badge in the README.)*
- [ ] **Contributor on-ramp** — issue templates and [CONTRIBUTING.md](CONTRIBUTING.md). *(Added.)*
- [ ] **Versioned releases** — tagged, reproducible releases with notes. First tag: `v0.1.0` (see [CHANGELOG.md](CHANGELOG.md)).
- [ ] Linux/macOS CI coverage in addition to the primary Windows development target.

## Planned expansion

### Framework adapters (planned)

The engine is model-agnostic and authorizes on `(tool_name, tool_input)`; onboarding a framework means writing a thin adapter, as the Claude Code hook demonstrates. Planned adapters:

- [ ] **MCP (Model Context Protocol)** — gate tool invocations flowing through an MCP server/proxy.
- [ ] **LangGraph** — authorize tool/node execution within a LangGraph agent.
- [ ] **Microsoft Agent Framework** — authorize actions in Microsoft's agent runtime.

Each will ship with its own tests and will be marked experimental until it reaches parity with the Claude Code adapter.

### Distribution (planned)

- [ ] **PyPI package** — restructure `tara/` into an importable package and publish `tara-authz` so it installs with `pip`. Metadata is already staged in [`pyproject.toml`](pyproject.toml).

### External validation (planned)

- [ ] Independent testing / third-party review reports.
- [ ] Documented integrations in real agent deployments.
- [ ] Community contributions (adapters, policy packs, test scenarios).

---

*This roadmap is indicative, not a commitment to dates. Planned items are implemented and verified with tests before their status changes.*
