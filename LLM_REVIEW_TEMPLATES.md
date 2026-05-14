# LLM Cross-Validation Prompt Templates
## TriageForge — Purple-Team Review Protocol

**Purpose:** Multi-LLM adversarial review before committing C6/C7 effort or drafting ASB submissions.  
**When to use:** After C3 returns a high-confidence hit, before writing C6 PoC.  
**Recommended LLMs:** GPT-4o, Gemini 1.5 Pro, Grok-3, Claude Opus (separately from working session).  
**Decision rule:** If 2+ LLMs independently flag the same weakness → address it before proceeding. If all 4 say "looks solid" → proceed with high confidence.

---

## Template 1 — Exploitability Gate (use BEFORE drafting ASB report)

> Replace ALL `[bracketed]` fields with real data before sending.

---

```
You are a senior Apple Platform Security engineer reviewing a potential vulnerability report.
Your job is to argue as a skeptical reviewer — find every reason this is NOT exploitable.
Do NOT be encouraging. Be adversarial.

=== FINDING SUMMARY ===

Binary: [e.g. /usr/libexec/biometrickitd]
macOS version: [e.g. macOS 26.4.1 (25E5200d)]
Finding class: [e.g. XPC message → unvalidated data field → OOB heap read]
C3 template hit: [e.g. XPC_OOB — source: xpc_dictionary_get_data(), sink: memcpy() with attacker-controlled length]
Taint path summary: [paste the C6 taint chain — function names and addresses]

Concrete PoC input: [describe what you send — e.g. "XPC message to com.apple.biometrickit with 'enrollmentData' field set to NSData of length 0x1, where the handler reads sizeof(expected_struct)=0x48 bytes"]

=== QUESTIONS — ANSWER EACH SEPARATELY ===

1. ENTITLEMENT CHECK: Is there an entitlement or privilege check BEFORE the vulnerable code
   path is reached? What entitlement? Is it enforced at the Mach port level (making client
   connection impossible without it) or at the application level (potentially bypassable)?

2. ATTACKER REACHABILITY: Can an unentitled process running as uid=501 (standard user)
   actually deliver this input? Are there sandbox rules, Mach port send-right restrictions,
   or service-level validation that would block the connection before the vulnerable code runs?

3. IMPACT REALITY CHECK: If the code path fires, is the impact actually a security issue?
   Specifically:
   - OOB read: does the read cross a page boundary, or is it within a mapped region?
     Will it crash or silently return garbage data?
   - Crash: is this a DoS (service restarts automatically), or can the crash be turned
     into code execution? What's the heap layout requirement?
   - Info disclose: what data is exposed — is it secret, or is it already available via
     public APIs?

4. APPLE'S LIKELY RESPONSE: Apple closes reports as "not a security issue" if:
   (a) the calling process requires higher privilege than gained
   (b) the impact is crash/DoS only in a non-critical service
   (c) the issue is in a third-party library (OpenLDAP, OpenSSH, etc.) not Apple code
   (d) the attack requires physical access or social engineering
   Which of these apply here?

5. COMPARABLE CVEs: Is there a published CVE for a similar pattern in this binary or
   related Apple subsystem? If so, what was the actual impact and how did Apple classify it?

=== YOUR VERDICT ===

After answering the above: does this meet the bar for an Apple ASB submission?
Rate confidence: HIGH (file it) / MEDIUM (needs C7 on-device evidence first) / LOW (park it).
Give one sentence explaining the rating.
```

---

## Template 2 — Positive Z-Score Interpretation Challenge

> For the Tier 1 batch sweep candidates (findmydeviced z_energy=+17σ, feedbackd +11σ, etc.)
> This validates our RMT interpretation before investing C3/C6 time.

---

```
We are applying Random Matrix Theory (RMT) to macOS binary call graphs as a pre-screening
tool to identify structurally anomalous binaries for security research.

=== METHODOLOGY ===

For each binary:
1. Extract the call graph (directed, nodes=functions, edges=direct BL calls)
2. Compute the adjacency matrix eigenvalue spectrum
3. Compare to a null model: 50 random graphs preserving the exact degree sequence
   (configuration model — same in-degree and out-degree per node)
4. Report z-scores for three spectral metrics:
   - z_radius:  (λ_max_observed - λ_max_null_mean) / λ_max_null_std
   - z_energy:  (spectral_energy_observed - energy_null_mean) / energy_null_std
   - z_entropy: (spectral_entropy_observed - entropy_null_mean) / entropy_null_std

=== OBSERVED RESULTS ===

Binary: findmydeviced (Find My Device daemon, /usr/libexec/)
z_radius:  +14.35σ
z_energy:  +17.45σ  ← extreme positive
z_entropy: -4.41σ

Binary: feedbackd (Feedback Assistant daemon, /usr/libexec/)
z_radius:  +3.23σ
z_energy:  +11.08σ  ← extreme positive
z_entropy: +0.53σ

For context: a typical "boring" binary has all three z-scores within ±2σ.
Negative z_energy means the call graph is LESS structured than random (sparse, flat).
Positive z_energy means MORE structured than random (dense internal call clusters).

=== OUR INTERPRETATION ===

We interpret extreme POSITIVE z_energy as a higher-than-normal structural complexity
signal — the binary has dense, organised internal call clusters that deviate significantly
from a random graph with the same degree sequence. This could indicate:
(a) Complex stateful protocol parsing with many internal helpers — a larger attack surface
(b) Intentional architectural complexity around a sensitive operation
(c) A measurement artifact from our analysis method

We chose to prioritise POSITIVE z-score binaries (more structured) alongside NEGATIVE
ones (less structured), because both deviate from the null and both warrant inspection.

=== CHALLENGE QUESTIONS ===

1. STATISTICAL VALIDITY: Is our interpretation of positive z_energy correct?
   In spectral graph theory, what does high λ_max (leading eigenvalue) actually indicate
   about a directed call graph? Does it correlate with security-relevant complexity,
   or could it be explained by benign structural features (e.g., a hub function called
   by many others, a single high-degree node dominating the spectrum)?

2. CONFOUNDERS: What legitimate engineering patterns would produce z_energy = +17σ
   without indicating higher vulnerability? For example: a binary with one dispatcher
   function that calls 200 specialised handlers (star topology) — does this produce
   extreme positive z_energy? What does the degree distribution look like for such a graph?

3. PRIORITISATION LOGIC: Given our 4 GB VRAM constraint and limited C3/C6 capacity,
   should we prioritise:
   (a) Extreme positive z (findmydeviced +17σ) — most structurally anomalous
   (b) Moderate negative z_entropy (securityd -4σ) — less entropic than random
   (c) Both equally
   What's the theoretical argument for each?

4. FALSE POSITIVE RISK: What class of binaries commonly produce high positive z_energy
   as a benign artifact? Should we add any pre-filter to exclude them before C3 analysis?

5. PUBLISHED PRECEDENT: Is there published work applying RMT to software call graphs
   for vulnerability detection? What metrics do those papers use, and how does our
   approach compare?

=== OUR DECISION THRESHOLD ===

We proceed with C3 template analysis on any binary where |z| > 2.0 on any metric,
AND the binary is Apple-written (not a bundled third-party like OpenLDAP, mDNSResponder).

Is this threshold appropriate? Too aggressive (too many false positives for C3)
or too conservative (missing real anomalies)?
```

---

## Template 3 — C7 Evidence Review (use AFTER C7 runs, before ASB submission)

> Paste actual C7 output. Validates that crash evidence is sufficient for Apple.

---

```
I have a crash report from macOS dynamic analysis. I need to know if this is sufficient
evidence for an Apple Security Bounty (ASB) submission, and what the realistic CVSS score is.

=== C7 EVIDENCE ===

[Paste verdict.json contents here]

[Paste first 40 lines of crash_report.ips here]

[Paste registers.txt here]

=== QUESTIONS ===

1. CRASH CLASSIFICATION: What class is this crash?
   - Null dereference (usually low severity — service restarts)
   - Stack OOB write (potentially exploitable to RCE)
   - Heap OOB read (potentially exploitable to info disclose)
   - Use-after-free (potentially exploitable)
   - Type confusion (potentially exploitable)

2. EXPLOITABILITY: From the register state and faulting address, is this likely:
   (a) Deterministically exploitable — attacker controls PC or a heap pointer
   (b) Crash-to-exploit gap — additional heap spray / ASLR bypass needed
   (c) Crash-only — DoS, service restarts, no escalation path

3. CVSS v3.1 ESTIMATE: Based on the evidence, estimate:
   - AV (Attack Vector): Network / Adjacent / Local / Physical
   - AC (Attack Complexity): Low / High
   - PR (Privileges Required): None / Low / High
   - UI (User Interaction): None / Required
   - S (Scope): Unchanged / Changed
   - C/I/A (Impact): None / Low / High
   And the resulting base score.

4. ASB CATEGORY: Which Apple ASB area does this belong in?
   Standard: Userland → Daemons and Frameworks
   Only deviate if: clear kernel path, WebKit/JavaScriptCore, FileVault, Gatekeeper, TCC.

5. REPORT GAP: What is missing from this evidence that Apple's team will ask for?
   What should we add before submission?
```

---

## Usage Notes

- **Send each template to 3–4 LLMs independently** — don't share the other models' responses
  until you've collected all four. Anchoring bias kills the value of independent review.
- **Record verdicts in `project_active_audits.md`** — note which model said what, and
  whether they agreed. Disagreement is signal, not noise.
- **Template 1** is the gate. If the exploitability review comes back LOW from 2+ models,
  park the finding and move to the next C3 candidate.
- **Template 2** is one-time. Run it now on the batch sweep interpretation, then update
  the methodology based on the consensus answer.
- **Template 3** is per-finding. Run it immediately before drafting the ASB submission.
