# TARA — Security & AI-Governance Control Crosswalk

**What this is:** a self-assessment crosswalk from TARA's implemented controls to U.S. federal
security and AI-governance requirements. It is a *design/implementation mapping*, not a
certification or an Authorization to Operate (ATO). "Met" means the prototype implements the
control's intent on the laptop-hosted server; "Partial" means the mechanism exists but needs
production hardening; "Gap" means not yet built.

**Why it maps cleanly:** the government's agentic-AI bar — stated in OMB M-25-21, the 2026 DoD
"AI Strategy for the Department of War," DoD Directive 3000.09, and America's AI Action Plan —
is *human control over what the AI does, the ability to stop it, and provable accountability.*
TARA is a concrete implementation of that control layer. It does **not** make the model refuse
tasks (which the 2026 DoD strategy explicitly rejects); it makes a **human authorize actions**
and records who did.

---

## 1. NIST AI Risk Management Framework (AI RMF 1.0)

| Function | What it asks | TARA control | Status |
|---|---|---|---|
| GOVERN 1.1 / 1.2 — accountability & roles | Clear accountability for AI actions | Every action is attributed (agent, session, tool) and authorized by a named human role; tamper-evident audit | Met |
| GOVERN 4.1 — risk culture, ability to supersede/stop | Mechanisms to override/disengage | **Kill switch** (freeze all, void grants); human **deny**; duress code | Met |
| MANAGE 2.1 — human oversight of deployed AI | Human-in-the-loop on consequential actions | Biometric approval (fingerprint) on a separate device; two-person (two different enrolled fingerprints) for critical; lighter confirm for medium | Met |
| MANAGE 2.4 — ability to decommission/deactivate | Turn the system off safely | Kill switch; fail-closed hook (no TARA = deny) | Met |
| MANAGE 4.1 — post-deployment monitoring | Track what the AI does | Append-only hash-chained audit log + approval receipts | Met |
| MAP / MEASURE | Context & measurement of risk | Policy assigns a risk level per action; AI risk-agent adds context | Partial (no formal metrics yet) |

## 2. OMB M-25-21 — minimum practices for "high-impact" federal AI

| Requirement | TARA control | Status |
|---|---|---|
| Human oversight, intervention, and accountability | Human approval; deny; kill switch; audit + receipts | Met |
| Ability to discontinue non-compliant AI | Kill switch freezes everything; only the human unfreezes | Met |
| Ongoing monitoring | Audit log of every decision; AI risk-agent review | Partial |
| Human review / appeal of AI decisions | Human approves/denies each gated action before it happens | Partial (pre-action gate, not a formal post-hoc appeal) |
| Pre-deployment testing + impact assessment | 75 automated tests of the control logic | Partial (tests yes; formal impact assessment doc = Gap) |

## 3. NIST SP 800-53 Rev 5 (FISMA / ATO control families)

| Control | Title | TARA implementation | Status |
|---|---|---|---|
| AC-3 | Access Enforcement | Policy decides allow/approve/deny per tool call | Met |
| **AC-3(2)** | **Dual Authorization** | **Two-person approval for critical actions** | Met |
| AC-4 | Information Flow Enforcement | Data labels (CUI/PHI/SSN) block data from leaving via outbound tools | Met |
| AC-6 | Least Privilege | Default-deny for unlisted/outside actions; scoped allow-list | Met |
| AC-7 | Unsuccessful Logon Attempts | 3 wrong codes locks the request | Met (analogue) |
| AC-17 | Remote Access | Token-authenticated link; server bound to localhost + tunnel | Partial |
| AU-2 / AU-3 / AU-12 | Audit events, content, generation | Every authorize/approve/deny/consume logged with who/what/when | Met |
| AU-9 | Protection of Audit Information | Hash-chained, tamper-evident log; single-writer lock | Met |
| AU-10 | Non-repudiation | HMAC-signed approval receipts | Met |
| IA-2 / IA-5 | Identification & Authenticator Mgmt | Biometric authenticator (fingerprint) + duress finger; one-time-code fallback; (no CAC/PIV yet) | Partial |
| SI-10 | Information Input Validation | Untrusted-source gating; prompt-injection resistance (agent-read text cannot authorize) | Met |
| IR-4 | Incident Handling | Duress code + kill switch + operator alerts | Partial |
| SC-7 | Boundary Protection | Only the tunnel port is exposed; TARA server stays private | Partial |
| CM / CP / SR | Config mgmt, contingency, supply chain | — | Gap |

## 4. NIST SP 800-171 / CMMC (protecting CUI)

| 800-171 practice | TARA implementation | Status |
|---|---|---|
| 3.1.1 limit access to authorized users/processes | Policy + token-gated routes | Met |
| 3.1.2 limit to authorized functions | Allow-list; default deny | Met |
| 3.1.3 **control the flow of CUI** | CUI label → outbound send denied; copy/upload gated | Met |
| 3.1.7 least privilege / privileged functions audited | Approval + audit for privileged actions | Met |
| 3.3.1 / 3.3.2 audit logs traceable to individuals | Per-action audit; receipts | Met (needs real identity for "individual") |
| 3.3.8 protect audit information | Tamper-evident chain | Met |
| 3.14.x system & information integrity | Fail-closed hook; input validation | Partial |

CMMC Level 2 is the 110 practices of 800-171; the above are the AC/AU practices TARA most
directly supports. Full CMMC requires the whole catalog plus organizational process.

---

## 5. Honest gaps to reach a real government deployment

| Gap | What it blocks | Work |
|---|---|---|
| **Sovereign brain/model** (replace xiaozhi.me + consumer clouds with our own / on-prem endpoint) | Any DoD or CUI use | Swap the voice endpoint (config) + host the server + an approved model |
| **Offline / degraded-comms operation** | Battlefield / denied comms | Local model + action queueing |
| **CAC/PIV identity binding** (IA-2) | Attributing approvals to a real person | Integrate the government smart-card credential |
| **Accredited hosting (FedRAMP) + ATO** | Lawful federal operation | Host in gov cloud; complete the ATO package |
| **Hardware root of trust** (secure boot, device keys) | Device trust / anti-tamper | Enable on the ESP32-S3 |
| **Formal artifacts** (AI impact assessment, SSP, POA&M) | OMB M-25-21 / FISMA | Author the documents |

## 6. The claim this supports
TARA is a working reduction-to-practice of **human-authorized, auditable, stoppable agentic AI** —
the control infrastructure the U.S. government requires for fielding AI agents (OMB M-25-21; 2026
DoD AI Strategy; DoDD 3000.09; America's AI Action Plan, Pillar I "AI Control"). The prototype
demonstrates the mechanism on everyday tasks today; the gaps above are the defined path to a
sovereign, accredited deployment.
