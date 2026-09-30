# Architecture

```
src/retriage/
  safety.py      argument allow-lists, comment sanitizing, output fencing, size limits
  backend.py     R2Backend: radare2 via r2pipe (read-only queries + rename/comment in the analysis DB)
  tools.py       TOOL_SPECS (JSON Schema) and ToolBox.call(): never raises, returns {ok, data|error, ms}
  report.py      report schema v1, submission validation, finalize (hashes, grounding), Markdown rendering
  ioc.py         indicator extraction and defanging
  agent.py       the loop, step budget, audit transcript
  llm.py         OpenAIChat (any compatible endpoint), ScriptedLLM (tests), HeuristicLLM (offline baseline)
  mcp_server.py  the same tools over MCP (stdio)
  cli.py         analyze | mcp | validate | tools
```

## The loop
1. The agent sends the system prompt + goal and the tool specs to the model.
2. For each tool call the model makes, `ToolBox.call` validates arguments, runs the backend, and wraps the result as untrusted data.
   Results over `--max-tool-chars` (12k) are truncated with a visible `truncated` marker.
3. A step budget applies; two steps before the end the agent tells the model to submit. A model that stops without submitting is nudged twice.
4. `submit_report` validates the model-supplied part against `schemas/submission.schema.json`. Errors go back to the model so it can fix them.
5. On success, `finalize_report` adds facts computed by code (hashes, size, format, tool counts, renames), marks each IOC `grounded`
   (did the value appear in any tool output?), and validates the full report against `schemas/report.schema.json`.

## Why renaming matters
`rename_function` edits the analysis database. Because callers' disassembly and `get_callees` output use the new name, each confident rename
adds context to every later query. The tests assert this propagation (`test_rename_propagates_to_callers_and_callees`).

## Audit transcript (JSONL)
Events: `start` (model, backend, sample SHA-256, budget), `assistant` (content + tool calls), `tool` (name, arguments, ok, ms, **exact text the model saw**), `end` (status, steps, errors).
Statuses: `ok`, `budget_exhausted`, `no_report`, `invalid_report`.

## Adding a backend
Implement the methods `R2Backend` exposes (`binary_info, sections, functions, imports, strings, disassembly, pseudocode, xrefs_to, callees, read_bytes,
rename_function, add_comment, close`, plus `name`) and pass it to `ToolBox`. Keep all argument validation in `safety.py`: backends must treat inputs as already validated but must never build shell commands from free text.
