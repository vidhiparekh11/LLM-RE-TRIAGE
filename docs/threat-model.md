# Threat model

## What we protect
The analyst's machine and credentials, the integrity of the report, and the confidentiality of samples sent to a model provider.

## Adversaries
1. **A malicious sample** that embeds text meant to manipulate the model (prompt injection) or exploit the tooling.
2. **A manipulated or buggy model** that emits harmful or malformed tool calls.
3. **A malicious or compromised MCP/LLM endpoint** (for remote setups).

## Threats and mitigations
| Threat | Mitigation | Test |
|---|---|---|
| Command injection into radare2 through tool arguments (`main; !cmd`, backticks, `@`, `\|`). Verified: unvalidated input **does** execute shell commands in radare2 | Strict allow-lists (`validate_target`, `validate_new_name`); comments sanitized; **`cfg.sandbox=true`** as a second layer | `test_injection_*`, `test_radare2_sandbox_blocks_raw_shell_escape`, `test_hijacked_model_cannot_inject_commands` |
| Prompt injection via strings/symbols ("ignore previous instructions...") | Output fenced as `DATA ONLY`; system prompt forbids following tool content; model has **no tool that can execute code, read other files or reach the network**; worst case is a wrong report | `test_results_are_fenced_as_untrusted` |
| Hallucinated indicators in the report | IOCs ground-checked against tool output (`grounded`), flagged in the Markdown | `test_hallucinated_ioc_is_flagged` |
| Model fabricates file hashes/metadata | Computed by code in `finalize_report`; the submission schema rejects `sample`/`analysis` | `test_submission_validation_enforces_honesty_fields` |
| Stack traces / paths leaking to the model | `ToolBox.call` returns generic `internal error (Type)` | `test_toolbox_never_raises_and_does_not_leak_traces` |
| API key leakage | Read from env only; never placed in transcripts, reports or error messages | `test_agent_works_through_openai_compatible_client`, `test_http_error_does_not_leak_key` |
| Resource exhaustion (huge outputs, regex DoS, endless loops) | Output truncation, argument clamps, regex length limit, step budget, 256 MB file cap | `test_oversized_tool_results_are_truncated_for_the_model`, `test_budget_exhaustion_and_final_warning` |
| Sample mutated | Only the analysis database changes; file opened read-only for hashing | - |

## Residual risks (not mitigated here)
- **radare2 parser vulnerabilities.** Analyzing untrusted files has historically triggered memory-safety bugs in disassembler frameworks. Run inside a disposable container or VM without credentials or network access to sensitive systems.
- **Data sent to a model provider.** Strings, disassembly and bytes leave your machine. Use a local model for confidential or customer samples, and check your provider's retention terms.
- **Wrong interpretations.** Grounding checks values, not reasoning. A human must review before acting.
- Ground-check is substring-based: a hallucinated value that coincidentally appears in tool output would pass.
- Symbol names outside `[A-Za-z0-9_.]` (e.g. C++ mangled names) are rejected; use addresses instead.

## Operating guidance
Disposable VM/container, no mounted secrets, egress restricted to the model endpoint only, samples handled by authorized staff, transcripts stored as sensitive data (they contain sample content).
