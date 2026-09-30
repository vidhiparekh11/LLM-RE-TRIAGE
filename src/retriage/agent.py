"""The agent loop: model <-> tools, with a step budget, a full audit transcript and ground-checked output."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from . import report as report_mod
from .prompts import DEFAULT_GOAL, SYSTEM_PROMPT
from .safety import dumps_limited
from .tools import TOOL_SPECS, ToolBox


@dataclass
class AgentResult:
    status: str                       # ok | budget_exhausted | no_report | invalid_report
    report: Optional[dict]
    steps: int
    transcript: list = field(default_factory=list)
    errors: list = field(default_factory=list)

    def write_transcript(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            for ev in self.transcript:
                fh.write(json.dumps(ev, ensure_ascii=True) + "\n")


class Agent:
    def __init__(self, toolbox: ToolBox, llm, max_steps: int = 40, max_tool_chars: int = 12000,
                 on_event: Optional[Callable[[dict], None]] = None):
        self.tb, self.llm = toolbox, llm
        self.max_steps, self.max_tool_chars, self.on_event = max_steps, max_tool_chars, on_event

    def _emit(self, log: list, ev: dict) -> None:
        ev["t"] = round(time.time(), 3)
        log.append(ev)
        if self.on_event:
            self.on_event(ev)

    def run(self, goal: str | None = None) -> AgentResult:
        info = self.tb.b.binary_info()
        messages = [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": goal or DEFAULT_GOAL}]
        log: list = []
        self._emit(log, {"event": "start", "llm": self.llm.name, "backend": self.tb.b.name, "sha256": info["sha256"],
                         "max_steps": self.max_steps})
        tool_text: list[str] = []
        nudges, status, step = 0, "budget_exhausted", 0
        for step in range(1, self.max_steps + 1):
            if step == self.max_steps - 1:
                messages.append({"role": "user", "content": "Only 2 steps remain. Call submit_report now with what you have, stating limitations."})
            reply = self.llm.chat(messages, TOOL_SPECS)
            calls = reply.get("tool_calls") or []
            messages.append({"role": "assistant", "content": reply.get("content"),
                             **({"tool_calls": [{"id": c["id"], "type": "function",
                                                 "function": {"name": c["name"], "arguments": json.dumps(c["arguments"])}} for c in calls]} if calls else {})})
            self._emit(log, {"event": "assistant", "step": step, "content": reply.get("content"),
                             "tool_calls": [{"name": c["name"], "arguments": c["arguments"]} for c in calls]})
            if not calls:
                nudges += 1
                if nudges > 2:
                    status = "no_report"
                    break
                messages.append({"role": "user", "content": "You must finish by calling submit_report."})
                continue
            for c in calls:
                result = self.tb.call(c["name"], c["arguments"])
                text = dumps_limited(result, self.max_tool_chars)
                tool_text.append(text)
                messages.append({"role": "tool", "tool_call_id": c["id"], "content": text})
                self._emit(log, {"event": "tool", "step": step, "name": c["name"], "arguments": c["arguments"],
                                 "ok": result.get("ok", False), "ms": result.get("ms"), "result": text})
                if self.tb.submitted:
                    break
            if self.tb.submitted:
                status = "ok"
                break
        report, errors = None, []
        if status == "ok":
            report = report_mod.finalize_report(self.tb.submitted, info, llm=self.llm.name, backend=self.tb.b.name, steps=step,
                                                tool_calls=self.tb.calls, renames=self.tb.renames,
                                                tool_output_text="\n".join(tool_text))
            errors = report_mod.validate_report(report)
            if errors:
                status, report = "invalid_report", None
        self._emit(log, {"event": "end", "status": status, "steps": step, "tool_calls": self.tb.calls, "errors": errors})
        return AgentResult(status, report, step, log, errors)
