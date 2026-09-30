from __future__ import annotations

import argparse
import json
import sys

from . import __version__, report as report_mod
from .agent import Agent
from .backend import BackendError, R2Backend
from .llm import HeuristicLLM, LLMError, OpenAIChat
from .tools import TOOL_SPECS, ToolBox


def _progress(ev: dict) -> None:
    if ev["event"] == "tool":
        print(f"  [{ev['step']:>2}] {ev['name']}({', '.join(f'{k}={v!r}'[:40] for k, v in ev['arguments'].items() if k != 'report')}) "
              f"-> {'ok' if ev['ok'] else 'ERROR'}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="retriage", description="LLM-assisted static triage with radare2 (binaries are never executed).")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="run the agent on a binary and write a report")
    a.add_argument("binary")
    a.add_argument("--llm", choices=["heuristic", "openai"], default="heuristic",
                   help="heuristic = offline baseline policy (no API key); openai = any OpenAI-compatible endpoint (env: RETRIAGE_API_BASE/KEY/MODEL)")
    a.add_argument("--model", help="override RETRIAGE_MODEL")
    a.add_argument("--max-steps", type=int, default=40)
    a.add_argument("--analysis", choices=["aa", "aaa", "aaaa"], default="aaaa", help="radare2 analysis depth (aaaa finds more functions, slower)")
    a.add_argument("-o", "--out", help="write JSON report here")
    a.add_argument("--md", help="write Markdown report here")
    a.add_argument("--transcript", help="write the full audit transcript (JSONL) here")
    a.add_argument("-q", "--quiet", action="store_true")

    m = sub.add_parser("mcp", help="serve the tools over MCP (stdio) for Claude Desktop / Cursor")
    m.add_argument("binary")
    m.add_argument("--analysis", choices=["aa", "aaa", "aaaa"], default="aaaa")

    v = sub.add_parser("validate", help="validate a report JSON file against the schema")
    v.add_argument("report")

    sub.add_parser("tools", help="list available tools")
    args = ap.parse_args(argv)

    if args.cmd == "tools":
        for t in TOOL_SPECS:
            print(f"{t['name']:<18} {t['description']}")
        return 0
    if args.cmd == "validate":
        errs = report_mod.validate_report(json.load(open(args.report, encoding="utf-8")))
        print("valid" if not errs else "INVALID:\n  " + "\n  ".join(errs))
        return 0 if not errs else 1
    if args.cmd == "mcp":
        from .mcp_server import serve
        serve(args.binary, args.analysis)
        return 0

    try:
        backend = R2Backend(args.binary, analysis=args.analysis)
    except BackendError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    try:
        llm = HeuristicLLM() if args.llm == "heuristic" else OpenAIChat(model=args.model)
        res = Agent(ToolBox(backend), llm, max_steps=args.max_steps, on_event=None if args.quiet else _progress).run()
    except LLMError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    finally:
        backend.close()
    if args.transcript:
        res.write_transcript(args.transcript)
    if res.report is None:
        print(f"no report produced: status={res.status} errors={res.errors}", file=sys.stderr)
        return 3
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(res.report, fh, indent=2)
            fh.write("\n")
    md = report_mod.to_markdown(res.report)
    if args.md:
        with open(args.md, "w", encoding="utf-8") as fh:
            fh.write(md)
    if not args.out and not args.md:
        print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
