# Contributing

Thanks for helping! Setup: `pip install -e ".[mcp,dev]"`, install radare2 and gcc, then `pytest -q`.

## Rules
- **Never commit malware samples**, other binaries, archives, credentials or API keys. `python scripts/check_public.py` (also in CI) enforces this. Tests build their own benign target from `examples/demo.c.in`.
- **Only contribute what you have the right to contribute.** Do not submit code, prompts, data or analysis that belongs to an employer or another third party, or that is confidential. Write your own implementation.
- Every tool argument must go through `retriage/safety.py`. New tools need tests, including hostile-input tests.
- Keep reports honest: new analysis features must add evidence and limitations, not confident-sounding guesses.
- Run `python scripts/gen_docs.py` after changing tools or schemas (a test fails if docs are stale).
- Be respectful and constructive. Security issues: see [SECURITY.md](SECURITY.md) (do not open public issues for vulnerabilities).
