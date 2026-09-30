#!/usr/bin/env python3
"""Regenerate schemas/*.json and docs/tools.md from the code (so docs cannot drift). Run: python scripts/gen_docs.py"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from retriage.report import dump_schema_files  # noqa: E402
from retriage.tools import TOOL_SPECS  # noqa: E402


def tools_markdown() -> str:
    L = ["# Tool reference", "",
         "_Generated from `src/retriage/tools.py` by `scripts/gen_docs.py`; do not edit by hand._", "",
         "All tools are read-only against the sample. `rename_function` and `add_comment` modify only the analysis database. "
         "Every result is wrapped as `{ok, _notice, data}` where `data` is **untrusted** content from the binary.", "",
         "| Tool | Arguments | What it does |", "|---|---|---|"]
    for t in TOOL_SPECS:
        props = t["parameters"]["properties"]
        req = set(t["parameters"]["required"])
        args = ", ".join(f"`{k}`" + ("" if k in req else "?") for k in props if k != "report") or "-"
        if t["name"] == "submit_report":
            args = "`report` (see [report schema](../schemas/submission.schema.json))"
        L.append(f"| `{t['name']}` | {args} | {t['description']} |")
    L += ["", "`?` marks optional arguments. `target` accepts a symbol name (`[A-Za-z_.][A-Za-z0-9_.]*`) or a `0x` hex address; anything else is rejected.", ""]
    return "\n".join(L)


def main() -> None:
    dump_schema_files(os.path.join(ROOT, "schemas"))
    with open(os.path.join(ROOT, "docs", "tools.md"), "w", encoding="utf-8") as fh:
        fh.write(tools_markdown())
    print("wrote schemas/*.json and docs/tools.md")


if __name__ == "__main__":
    main()
