# Legal Review — Metis Public Release

**Prepared by:** Claude (Anthropic) on behalf of Stuart Thomas  
**Date:** 2026-04-17  
**Jurisdiction focus:** England and Wales, with material international considerations  
**Documents reviewed:**
- `TOOLCHAIN_DOCUMENTATION.md`
- `BLOG_POST.md`
- `OPERATIONS_MANUAL.md`
- `generate_toolchain_docs.py` / `generate_opsmanual.py` / `generate_briefing.py`
- Case studies: `cve_2022_23093_darwin.md`, `windows_ping_icmp_surface.md`

**Status:** FINDINGS FOR REVIEW — no amendments made yet. Amendments to follow after author approval.

---

## Summary Verdict

The documents are broadly publishable but carry **five issues that should be fixed before any public release**, two of which are substantive legal risks rather than formalities. A further five are best-practice improvements. The documents are not currently in a state that would survive commercial due diligence (e.g., an NCC Group acquisition), largely due to missing licence declarations and incomplete academic attribution.

---

## Issues by Priority

---

### PRIORITY 1 — Fix before any public release

---

#### 1.1 No copyright notice — any document

**Issue:** None of the four documents carry a copyright notice or a licence declaration. This is the single biggest gap for both IP protection and open-source release.

**Law:** Under the Copyright, Designs and Patents Act 1988 (CDPA 1988), copyright arises automatically upon creation of an original literary work (s.1(1)(a)). No registration or notice is required. However, the absence of a notice:
- Creates genuine ambiguity about ownership if any commercial dispute arises
- Prevents downstream users from knowing under what terms they may use the work
- Is fatal to a future NCC/commercial licensing negotiation (they will require clear IP provenance)
- Does not affect your rights, but significantly complicates enforcement

**Proposed fix:** Add to all documents:

```
© 2026 Stuart Thomas. All rights reserved.
```

And choose a licence. For code (`metis/`): **MIT (Non-Commercial) / Paid (Commercial)** — permissive for research, revenue-generating for commercial use, includes a patent grant (via the dual-grant structure), compatible with the BSD 2-Clause licences of angr and its dependencies. For documentation (the MD files and PDFs): **Creative Commons Attribution 4.0 International (CC BY 4.0)** — allows sharing and adaptation with attribution required.

---

#### 1.2 Lockheed Martin "Cyber Kill Chain®" — trademark use without acknowledgement

**Issue:** The phrase "Cyber Kill Chain" appears multiple times across `TOOLCHAIN_DOCUMENTATION.md` and `BLOG_POST.md` without any trademark acknowledgement.

**Verified registration:**
> CYBER KILL CHAIN  
> USPTO Registration No. 4,409,609  
> Owner: Lockheed Martin Corporation  
> Registration Date: 1 October 2013  
> Status: Active  

UK position: UKIPO registration not confirmed by automated search, but Lockheed Martin could assert rights in the UK under:
- Passing off (goodwill in the mark exists in the UK security/defence market)
- Potential Madrid Protocol international registration (would cover UK)
- Post-Brexit, any EUIPO registration from before 31 December 2020 would have been cloned to a comparable UK right under the Trade Marks (Amendment etc.) (EU Exit) Regulations 2019

**Risk under Trade Marks Act 1994:** Use of a registered mark in a commercial context — which publishing a toolchain document linked to a commercial pitch to NCC clearly is — requires either a licence or reliance on the s.11(2)(b) descriptive use defence ("use of indications concerning the kind... of goods or services"). That defence requires the use to be "in accordance with honest practices in industrial or commercial matters" (*L'Oréal SA v Bellure NV* [2007] EWCA Civ 968). The use in the documentation is descriptive and acknowledges the origin — this is arguably protected. But the risk increases the moment this is attached to a commercial product pitch.

**Proposed fix:** Add at first mention in each document:

> "Cyber Kill Chain® is a registered trademark of Lockheed Martin Corporation. Use of the name here is purely descriptive of the conceptual inspiration for the C1–C6 naming convention and does not imply any endorsement by or affiliation with Lockheed Martin Corporation."

Change all subsequent uses of "Cyber Kill Chain" to "Lockheed Martin Cyber Kill Chain®" (first use per document only; subsequent uses can remain as-is with the disclaimer having been entered).

---

#### 1.3 Computer Misuse Act 1990 — no responsible use disclaimer

**Issue:** All three documents describe tools capable of finding vulnerabilities in compiled binaries. The toolchain is a dual-use article: legitimate for security research, potentially unlawful if used for unauthorised access.

**Law:** Computer Misuse Act 1990 s.3A (inserted by Police and Justice Act 2006 s.37):
> "A person is guilty of an offence if he makes, adapts, supplies or offers to supply any article — (a) intending it to be used to commit, or to assist in the commission of, an offence under section 1 or 3, or (b) believing that it is likely to be used to commit, or to assist in the commission of, an offence under section 1 or 3."

The **Crown Prosecution Service** guidance on the Computer Misuse Act (updated 2019) makes clear that security research tools with documented legitimate use are generally not prosecuted under s.3A where:
1. The tool is designed for legitimate security research
2. It is used within authorised testing frameworks
3. There is credible evidence of responsible disclosure intent

Your Apache/Responsible Disclosure track record (Apple ASB, Chrome VRP) provides exactly that evidence. However, the documentation itself currently contains no warning that the toolchain is for use only on systems the operator owns or has written authorisation to test.

**Risk:** Without a disclaimer, the documentation is more vulnerable to a s.3A argument — particularly if a commercial release follows and is used by a third party for unauthorised testing.

**Proposed fix:** Add the following to `OPERATIONS_MANUAL.md` §1 and to the front matter of `TOOLCHAIN_DOCUMENTATION.md`:

> **Legal Notice — Authorised Use Only**  
> This toolchain is intended exclusively for use on systems you own or have received explicit written authorisation to test. Unauthorised use of this software against systems you do not own or do not have permission to test may constitute a criminal offence under the Computer Misuse Act 1990 (England and Wales), the Computer Fraud and Abuse Act (United States), or equivalent legislation in other jurisdictions. The author accepts no liability for use of this software outside the scope of legitimate, authorised security research.

---

#### 1.4 Missing open-source licence file for angr dependencies — attribution obligation

**Issue:** The toolchain directly depends on angr, which is licenced under BSD 2-Clause. The BSD 2-Clause requires that any redistribution — including as part of a distributed package or a product that includes or references the source — carries the copyright notice and the licence text.

**angr BSD 2-Clause copyright notice** (required in redistribution):
```
Copyright (c) 2013, Shellphish
All rights reserved.
```

**z3 MIT Licence** (Microsoft Research):
```
Copyright (c) Microsoft Corporation
```

**networkx BSD 3-Clause:**
```
Copyright (C) 2004-2024, NetworkX Developers
```

**numpy/scipy BSD 3-Clause:**
```
Copyright (c) 2005-2024, NumPy Developers
```

**Law:** The BSD 2-Clause condition (clause 1): *"Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer."* If the `metis/` package is released on GitHub, it must include a `LICENSE` file and a `THIRD_PARTY_NOTICES.txt` or equivalent.

**Proposed fix:** Add two new files to the repository root:
- `LICENSE` — Dual-licence text (MIT Non-Commercial / Paid Commercial)
- `THIRD_PARTY_NOTICES.md` — listing angr, z3, networkx, numpy, scipy, reportlab, matplotlib with their respective licence texts or URLs

---

#### 1.5 Incomplete and imprecise academic citations

**Issue:** The documentation cites academic works in an imprecise form that is not verifiable by a reader and would not meet publication standards for any journal or conference submission. Incorrect citations also carry a reputational risk.

**Verified correct citations** (confirmed via web search against primary sources):

| As cited in document | Correct full citation |
|---|---|
| "Mézard, Montanari, Zecchina 2002" | Mézard, M., Parisi, G., & Zecchina, R. (2002). Analytic and Algorithmic Solution of Random Satisfiability Problems. *Science*, 297(5582), 812–815. DOI: 10.1126/science.1073287 |
| "Bollobás 1980" | Bollobás, B. (1980). A Probabilistic Proof of an Asymptotic Formula for the Number of Labelled Regular Graphs. *European Journal of Combinatorics*, 1(4), 311–316. |
| "McCabe 1976" | McCabe, T. J. (1976). A Complexity Measure. *IEEE Transactions on Software Engineering*, SE-2(4), 308–320. DOI: 10.1109/TSE.1976.233837 |
| "Shoshitaishvili et al." (angr — implied but not cited) | Shoshitaishvili, Y., Wang, R., Salls, C., Stephens, N., Polino, M., et al. (2016). SoK: (State of) The Art of War: Offensive Techniques in Binary Analysis. *IEEE Symposium on Security and Privacy (S&P 2016)*, 138–157. DOI: 10.1109/SP.2016.17 |

Note: The Mézard et al. document cites "Montanari" in the text but the verified co-author is "Parisi" (Giorgio Parisi, Nobel Prize in Physics 2021). This is a substantive error in the current documentation that must be corrected.

**Additional required citation:** The configuration model null model should also cite:
> Newman, M. E. J., Strogatz, S. H., & Watts, D. J. (2001). Random graphs with arbitrary degree distributions and their applications. *Physical Review E*, 64(2), 026118.

This is the more commonly cited source for the directed configuration model as used in network science.

**Proposed fix:** Add a formal `## References` section to `TOOLCHAIN_DOCUMENTATION.md` with full citations in a consistent format (Chicago/IEEE), and correct "Montanari" to "Parisi" at the Mézard citation.

---

### PRIORITY 2 — Fix before commercial use or NCC approach

---

#### 2.1 Potential defamation issue — "NCC on instruction sequences → WRONG"

**Issue:** The docstring in `metis/c3_templates.py` contains:
```
NCC on instruction sequences → WRONG (discrete symbolic objects, not signals).
```

If "NCC" here refers to NCC Group (the cybersecurity consultancy), this is a statement that NCC Group gave incorrect technical advice. Publishing this could constitute defamatory matter under the Defamation Act 2013 (s.1: a statement that tends to lower a person/company in the estimation of right-thinking members of society, causing or likely to cause serious harm to reputation).

**Analysis:** Defamation Act 2013 provides defences including:
- Truth (s.2): the statement is substantially true
- Honest opinion (s.5): the statement is a matter of opinion  
- Publication on a matter of public interest (s.4)

The "honest opinion" and "public interest" defences are plausible here — it is a matter of methodology opinion in a technical research context. However, the *serious harm* threshold introduced by the 2013 Act (s.1) means that for a company like NCC Group to succeed, they would need to show serious financial or reputational harm — unlikely for a technical methodology comment.

**Risk rating:** Low-moderate. Most likely outcome if NCC Group ever read this: they'd email to ask for a clarification rather than litigate. However, if you are about to approach NCC Group with a commercial pitch, having this in your published source code is professionally awkward at minimum.

**Proposed fix:** Change to neutral technical language:
```
Instruction-sequence matching rejected: discrete symbolic objects are not 
continuous signals; NCC-style (instruction-pattern) matching produces high 
false-positive rates. Call-level VEX IR dataflow is the correct framing.
```

If "NCC" does not refer to NCC Group but to a different abbreviation used internally, clarify the abbreviation.

---

#### 2.2 Microsoft Symbol Server — Windows binaries in repository

**Issue:** The `windows-ping-audit/` directory in the maths folder contains `ping_w11_24h2_x64.exe` and `iphlpapi_w11_24h2_x64.dll` — actual Windows system binaries downloaded from Microsoft's Symbol Server (MSDL).

Microsoft's Symbol Server terms permit downloads for *debugging purposes*. Redistributing Windows system binaries — including in a research GitHub repository — almost certainly violates:
- Microsoft's Software License Agreement for Windows (redistribution prohibition)
- Microsoft's Symbol Server terms of service

**Law:** Copyright infringement under CDPA 1988 s.16 (reproduction of a substantial part without licence). The downloaded binaries are copyrighted works of Microsoft Corporation.

**Proposed fix:** 
1. **Do not include** the `.exe` or `.dll` files in any public GitHub release
2. Add them to `.gitignore`  
3. The documentation describing *how* to download them via MSDL URL construction is fine — describing a public download process is not infringement. The files themselves are not

---

#### 2.3 Apple EULA and reverse engineering — note on legal basis

**Issue:** The toolchain performs binary analysis of macOS system daemons (angr CFGFast, VEX IR lifting, disassembly). Apple's macOS Software License Agreement prohibits "reverse engineering, decompiling or disassembling the Apple Software."

**However**, under English law this contractual restriction is overridden by statute:

**CDPA 1988 s.50B (Decompilation exception):**
> "It is not an infringement of copyright for a lawful user of a copy of a computer program... to decompile it... if it is necessary to decompile it to obtain information necessary to create an independent program which can operate with the program decompiled or with another program..."

The interoperability exception (s.50B) and the permitted act for observing, studying and testing (s.50BA) provide a statutory floor that contractual terms cannot override (CDPA 1988 s.296A: "a term or condition in an agreement is void in so far as it purports to prohibit or restrict the doing of any act which... cannot be prohibited").

Security research for the purpose of identifying vulnerabilities and improving software interoperability is within the spirit of s.50B and s.50BA, and is supported by the Cybersecurity Directive (NIS Regulations 2018 in UK law, though primarily directed at operators of essential services).

**Risk rating:** Low in England and Wales, given the statutory override. Higher if targeting US market — the DMCA (17 U.S.C. § 1201) is more restrictive, though the security research exemption (17 C.F.R. § 201.40) applies.

**Proposed fix:** Add a note to the documentation acknowledging this:

> "Binary analysis of macOS system software is conducted in accordance with the Copyright, Designs and Patents Act 1988 (UK) ss.50B and 50BA, which permit decompilation and study of computer programs for the purposes of interoperability and security research. Apple's macOS Software License Agreement terms purporting to prohibit such analysis are unenforceable in England and Wales to the extent they conflict with these statutory provisions."

This is defensive documentation, not a cure-all — but it demonstrates awareness of the legal basis and is good practice.

---

### PRIORITY 3 — Best practice before commercial engagement

---

#### 3.1 VEX IR / Valgrind attribution

The documentation references "VEX IR" extensively. VEX IR was developed by the Valgrind project (GPL v2). pyvex (used by angr) contains a stripped-down version of LibVEX. The conceptual description of VEX IR in the documentation is fine (concepts are not copyrightable). However, a clean attribution sentence should appear:

> "VEX IR is the intermediate representation used by the Valgrind instrumentation framework (© 2000–2024 Julian Seward and the Valgrind Developers) and is used by the angr binary analysis platform via the pyvex library."

#### 3.2 Personal data — own name in documentation

Stuart Thomas is named as author throughout. Under UK GDPR (UK GDPR, retained post-Brexit via European Union (Withdrawal) Act 2018), publishing your own name in your own research documentation is clearly within legitimate interest. No issue.

#### 3.3 The "four LLMs" design claim

The documentation states that four LLMs were used for architecture review. This is a factual claim about methodology. No legal issue. However, for commercial purposes, if this is represented as a formal validation methodology to a client, caveats should be clear.

#### 3.4 No warranty disclaimer

Standard for open-source release. Add to all code files:

> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.

This is already part of the Apache 2.0 and MIT licence texts if those are adopted (Issue 1.1 above).

---

## Proposed Amendments — Summary Table

| # | Document(s) | Change | Priority |
|---|---|---|---|
| 1.1 | All | Add © notice + choose MIT/Paid (code) / CC BY 4.0 (docs) | **Essential** |
| 1.2 | TOOLCHAIN_DOCUMENTATION.md, BLOG_POST.md | Add Cyber Kill Chain® trademark acknowledgement | **Essential** |
| 1.3 | OPERATIONS_MANUAL.md, TOOLCHAIN_DOCUMENTATION.md | Add CMA 1990 authorised-use disclaimer | **Essential** |
| 1.4 | Repository root | Add LICENSE + THIRD_PARTY_NOTICES.md | **Essential** |
| 1.5 | TOOLCHAIN_DOCUMENTATION.md | Correct "Montanari" → "Parisi"; add full references section | **Essential** |
| 2.1 | c3_templates.py docstring | Remove/neutralise "NCC → WRONG" text | **Before NCC approach** |
| 2.2 | windows-ping-audit/ | Add .gitignore for *.exe, *.dll; do not publish Windows binaries | **Before GitHub publish** |
| 2.3 | TOOLCHAIN_DOCUMENTATION.md, OPERATIONS_MANUAL.md | Add CDPA s.50B note on legal basis for binary analysis | **Before commercial use** |
| 3.1 | TOOLCHAIN_DOCUMENTATION.md | Add VEX/Valgrind attribution sentence | Good practice |
| 3.2 | All | n/a — no action required | n/a |
| 3.3 | All | n/a — no action required | n/a |
| 3.4 | All | Covered by Apache 2.0 adoption (1.1) | Covered |

---

## What is Not an Issue

For completeness — things that were checked and are fine:

- **Describing Microsoft Symbol Server URL format**: Not infringement. Describing how to access publicly available resources is lawful.
- **Referencing Apple daemons and XPC APIs by name**: Names and APIs are not copyrightable. Observable system behaviour description is lawful.
- **Referencing Marchenko-Pastur, Wigner semicircle, McCabe**: Named mathematical concepts in the public domain. Citing them correctly is all that's required.
- **Four-LLM purple-team methodology**: Novel but no IP issues.
- **Responsible disclosure references (Apple ASB, Chrome VRP)**: These are public programmes. Naming them is fine.
- **CVE numbers, once published**: Public record. Fine.
- **Stuart Thomas named as author**: Fine under UK GDPR.
- **angr being named and linked**: Open-source project; describing its use is fine. Attribution required only if distributing code that includes it.

---

## Recommended Next Steps

1. **Review this document** — confirm which amendments you approve
2. **Choose the licences** (Apache 2.0 for code, CC BY 4.0 for docs is the recommendation)
3. **Advise on the "NCC" abbreviation** — confirm whether this refers to NCC Group or something else; determines severity of 2.1
4. **Confirm GitHub is the intended publication route** — if so, the `.gitignore` for Windows binaries (2.2) needs to be in place before the first `git push`
5. **Amendments made** to all documents per your approval

---

*This review is prepared to assist with practical publication decisions. It does not constitute formal legal advice. For matters involving commercial acquisition, patent searches, or litigation risk, a qualified intellectual property solicitor (England and Wales) should be engaged.*
