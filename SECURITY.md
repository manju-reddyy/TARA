# Security policy

TARA is a security project, and I welcome reports of vulnerabilities in it.

## Reporting a vulnerability

**Please report security issues privately. Do not open a public GitHub issue, pull request, or discussion for a suspected vulnerability.**

Two private channels:

1. **GitHub private advisory (preferred).** Go to the repository's **Security** tab → **Report a vulnerability**. This opens a private advisory visible only to you and the maintainer.
2. **Email.** Send details to **manjureddy.katha@gmail.com** with a subject beginning `TARA SECURITY:`.

### What to include

- A description of the issue and the security impact (what an attacker could do).
- Steps to reproduce, or a proof-of-concept, against a known revision (a commit SHA).
- The affected component (e.g. `tara/core.py`, the policy evaluation, a grant/approval path, the Claude Code adapter).
- Any suggested remediation, if you have one.

### What to expect

- **Acknowledgement** within **5 business days**.
- An initial assessment (confirmed / needs-info / not-a-vulnerability) within **10 business days**.
- Coordinated disclosure: I will work with you on a fix and a disclosure timeline, and credit you in the release notes and advisory unless you prefer to remain anonymous.

Because TARA is an independently maintained research prototype, I cannot offer a paid bug bounty, but genuine reports are genuinely appreciated.

## Scope

In scope: the authorization core (`tara/core.py`), the server (`tara/server.py`), the grant/approval/audit mechanisms, the policy engine and default `policy.yaml`, and the Claude Code adapter (`tara/hook.py`). Reports that demonstrate a way to get a protected or consequential action to execute **without** the required authorization are especially valuable.

Out of scope / expected behavior:

- TARA **fails closed** by design: making it deny an action (e.g. by taking the server down) is not a vulnerability.
- The experimental voice-approval subsystem is a prototype and not part of the hardened core.
- The approval window and one-time codes assume a trusted local display; an attacker who already fully controls the user's desktop is outside the threat model.

## Supported versions

This is a pre-1.0 prototype; security fixes are applied to the `main` branch and the latest tagged release. See [CHANGELOG.md](CHANGELOG.md).
