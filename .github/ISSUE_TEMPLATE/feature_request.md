---
name: Feature request / adapter proposal
about: Suggest a capability, policy improvement, or a new framework adapter
title: "[feature] "
labels: enhancement
---

**What problem would this solve?**
Describe the use case or the gap. What can't you do today?

**Proposed change**
What you'd like TARA to do.

**Does it touch the security model?**
TARA preserves a few invariants (fail closed; the agent's text never authorizes;
protected resources cannot be unlocked by approval; grants are single-use and
action-bound; the audit log is append-only and signed). Note if your proposal
interacts with any of these — it doesn't disqualify the idea, it just needs
discussion. See [CONTRIBUTING.md](../../CONTRIBUTING.md).

**New adapter? (if applicable)**
- Framework:
- How tool calls are intercepted in that framework:
- Anything that would make `/authorize` / `/wait` / `/consume` hard to map:

**Alternatives considered**
Other approaches you thought about.
