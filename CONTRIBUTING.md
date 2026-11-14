# Contributing to TARA

Thanks for your interest in TARA. It is an independently developed research prototype exploring an **independent authorization boundary** for autonomous AI agents, and outside feedback, tests, and adapters are welcome.

## Ways to contribute

- **Report a security weakness** — see [SECURITY.md](SECURITY.md). Please report these privately, not as public issues.
- **File a bug or request a feature** — open an issue using the templates.
- **Add a test scenario** — the most valuable contributions are new attack/failure scenarios the engine should block. Every test in [`tests/test_tara.py`](tests/test_tara.py) is one such scenario.
- **Write an adapter** — a thin translator from another agent framework's tool-call events to TARA's `/authorize`, `/wait`, and `/consume` calls (see the Claude Code adapter in [`tara/hook.py`](tara/hook.py) as the reference). MCP, LangGraph, and Microsoft Agent Framework adapters are on the [roadmap](ROADMAP.md).

## Development setup

```bash
git clone https://github.com/manju-reddyy/tara.git
cd tara
python -m pip install -r requirements.txt
python tests/test_tara.py      # 213 tests should pass
python examples/demo.py        # see decisions live
```

See [INSTALL.md](INSTALL.md) for the full setup, including running the server and wiring the Claude Code adapter.

## Guidelines

### Tests are the contract

- **Every behavioral change must come with tests.** A change to authorization logic without a test that would fail before and pass after will not be merged.
- Run the full suite before opening a PR: `python tests/test_tara.py`. It must print `OK` with no failures.
- Prefer adding a scenario that captures the real threat, named after what it defends against (e.g. `test_injected_claim_of_approval_is_ignored`).

### The security model is not negotiable

Changes must preserve these invariants. If your change appears to require breaking one, open an issue to discuss it first:

- **Fail closed.** Any error, timeout, or unreachable dependency results in `deny`.
- **The agent's text never authorizes.** Approval comes only from the out-of-band human channel; nothing in a tool call's content can grant it.
- **Protected resources stay protected.** Approval cannot unlock TARA's own files, keys, audit log, or the agent's credentials.
- **Grants are single-use and action-bound.** One grant authorizes one execution of one exact action.
- **The audit log stays append-only and signed.**

### Code style

- Standard-library-first; keep third-party dependencies minimal (currently just PyYAML and cryptography for the core).
- Match the existing style in `tara/` — clear names, short functions, comments that explain *why*.
- Keep the engine model-agnostic: no coupling to a specific model or vendor in `core.py`.

### Pull requests

1. Branch from `main`.
2. Make the change plus tests; run the suite.
3. Describe the threat or behavior your change addresses, and note any invariant it touches.
4. Keep PRs focused — one logical change per PR.

By contributing, you agree that your contributions are licensed under the project's [Apache License 2.0](LICENSE).

## Code of conduct

Be respectful and constructive. This is a small research project; assume good faith, keep discussions technical, and focus on the security properties.
