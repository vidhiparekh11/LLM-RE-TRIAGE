# Security policy

## Reporting a vulnerability
Please report privately using GitHub's **"Report a vulnerability"** (Security tab) rather than a public issue. Include a minimal reproduction
(a benign test binary or crafted tool arguments are ideal). Do not attach live malware.

In scope: bypasses of argument validation or the radare2 sandbox, ways a sample can cause code execution through retriage, secret leakage
into transcripts/reports, and MCP server exposure problems. Out of scope: vulnerabilities in radare2 itself (report upstream), and wrong analysis conclusions.

## Supported versions
Only the latest release receives fixes (pre-1.0).

## Using retriage safely
Read [docs/threat-model.md](docs/threat-model.md): analyze samples only in a disposable, isolated environment and only if you are authorized to do so.
