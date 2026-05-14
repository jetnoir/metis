# Metis — Frequently Asked Questions (FAQ)

## What is Metis?
Metis is a macOS binary vulnerability toolchain. It acts as an automated triage pipeline that applies mathematical concepts (such as Random Matrix Theory and statistical mechanics) alongside symbolic execution to identify structurally unusual or suspicious patterns within compiled macOS system daemons. It is designed to prioritize binaries for manual security research.

## Is it legal to use this toolchain?
**Legal Notice — Authorised Use Only**
This toolchain is intended exclusively for legitimate security research. **You may only use this software on systems and binaries that you own, or for which you have explicit written authorisation to test.** 

Unauthorised use of this software to analyse or exploit systems you do not own or do not have permission to test may constitute a criminal offence under the Computer Misuse Act 1990 (England and Wales), the Computer Fraud and Abuse Act (United States), or equivalent legislation in your jurisdiction. The author accepts no liability for the misuse of this software or for any actions taken outside the scope of authorised, legal security research.

## What are the licensing terms?
Metis is distributed under a **Dual-Licence Model**:
*   **Non-Commercial Use:** Available under an MIT-style licence for personal research, educational purposes, and hobbyist projects where no revenue is generated.
*   **Commercial Use:** If you are using Metis in a professional, corporate, or revenue-generating capacity, you must obtain a separate Paid Commercial Licence.

Please review the `LICENSE` file in the root of this repository for full terms.

## Does this tool automatically find zero-day vulnerabilities?
No. Metis is a **triage tool**, not an automated exploit generator or a magic bug-finding button. It uses mathematical analysis (spectral radius, graph energy) to highlight binaries that have unusually tangled call graphs, and applies vulnerability templates to identify potentially dangerous code patterns (e.g., untrusted inputs reaching a `malloc` without bounds checks). 

It narrows down hundreds of functions to a handful of highly suspicious ones. Human expertise is still required to manually review these flagged functions and confirm if a vulnerability exists.

## Can I use this on non-macOS binaries?
Metis is heavily optimized for macOS Mach-O binaries, specifically focusing on XPC interactions, Mach messages, and Objective-C dispatch mechanisms. While the underlying RMT mathematical models and symbolic execution (via `angr`) are platform-agnostic, the `C3` templates are specifically tuned for macOS IPC architectures.

## Do I need the source code of the targets?
No. Metis operates purely on compiled binary executables (black-box analysis) using VEX IR lifting and control-flow graph extraction. No symbols or source code are required.
