import json
import os

import pytest

from conftest import requires_r2, valid_submission
from retriage.agent import Agent
from retriage.llm import HeuristicLLM, ScriptedLLM, has_xor_loop
from retriage.tools import ToolBox

pytestmark = requires_r2


def call(name, **args):
    return {"content": None, "tool_calls": [{"name": name, "arguments": args}]}


def test_heuristic_end_to_end_recovers_url_and_renames(toolbox):
    res = Agent(toolbox, HeuristicLLM(), max_steps=40).run()
    assert res.status == "ok" and res.report
    rep = res.report
    urls = [i for i in rep["iocs"] if i["type"] == "url"]
    assert urls and urls[0]["value"] == "http://c2.example.invalid/gate.php" and urls[0]["grounded"] is True
    assert rep["analysis"]["ungrounded_iocs"] == []
    assert [r["new_name"] for r in rep["analysis"]["renamed_functions"]] == ["xor_decode_routine"]
    assert rep["behaviors"][0]["attack_id"] == "T1140" and len(rep["behaviors"][0]["evidence"]) >= 2
    assert rep["limitations"] and rep["verdict"]["confidence"] == "low"
    # audit transcript: start + (assistant, tool)* + end; every tool call recorded with its result
    kinds = [e["event"] for e in res.transcript]
    assert kinds[0] == "start" and kinds[-1] == "end" and kinds.count("tool") == rep["analysis"]["tool_calls"]
    assert all("result" in e for e in res.transcript if e["event"] == "tool")


def test_rename_compounds_in_later_tool_output(toolbox):
    res = Agent(toolbox, HeuristicLLM()).run()
    tool_events = [e for e in res.transcript if e["event"] == "tool"]
    rename_i = next(i for i, e in enumerate(tool_events) if e["name"] == "rename_function")
    later = " ".join(e["result"] for e in tool_events[rename_i + 1:] if e["name"] == "get_disassembly")
    assert "xor_decode_routine" in later            # the caller's disassembly now shows the new name


def test_budget_exhaustion_and_final_warning(toolbox):
    seen = []
    def spy(messages):
        seen.append(messages[-1]["content"] if messages[-1]["role"] == "user" else "")
        return call("list_functions")
    res = Agent(toolbox, ScriptedLLM([spy] * 10), max_steps=5).run()
    assert res.status == "budget_exhausted" and res.report is None and res.steps == 5
    assert any("Only 2 steps remain" in s for s in seen)


def test_model_that_never_submits_gets_nudged_then_stops(toolbox):
    res = Agent(toolbox, ScriptedLLM([{"content": "I think it is malware.", "tool_calls": []}] * 5), max_steps=10).run()
    assert res.status == "no_report" and res.report is None


def test_hijacked_model_cannot_inject_commands(toolbox, tmp_path):
    marker = tmp_path / "pwned"
    script = [call("get_disassembly", target=f"main; !touch {marker}"),
              call("rename_function", target="0x1149", new_name=f"x; !touch {marker}"),
              call("submit_report", report=valid_submission())]
    res = Agent(toolbox, ScriptedLLM(script), max_steps=6).run()
    assert res.status == "ok" and not marker.exists()
    bad = [e for e in res.transcript if e["event"] == "tool" and not e["ok"]]
    assert len(bad) == 2


def test_invalid_report_is_fed_back_and_can_be_fixed(toolbox):
    script = [call("submit_report", report=valid_submission(limitations=[])), call("submit_report", report=valid_submission())]
    res = Agent(toolbox, ScriptedLLM(script), max_steps=5).run()
    assert res.status == "ok"
    first = [e for e in res.transcript if e["event"] == "tool"][0]
    assert first["ok"] is False and "limitations" in first["result"]


def test_hallucinated_ioc_is_flagged(toolbox):
    sub = valid_submission(iocs=[{"type": "domain", "value": "totally-invented.example"}])
    res = Agent(toolbox, ScriptedLLM([call("submit_report", report=sub)]), max_steps=3).run()
    assert res.status == "ok" and res.report["iocs"][0]["grounded"] is False
    assert res.report["analysis"]["ungrounded_iocs"] == ["totally-invented.example"]


def test_oversized_tool_results_are_truncated_for_the_model(toolbox):
    res = Agent(toolbox, ScriptedLLM([call("get_strings", min_len=3, limit=500), call("submit_report", report=valid_submission())]),
                max_steps=4, max_tool_chars=1500).run()
    ev = [e for e in res.transcript if e["event"] == "tool"][0]
    assert len(ev["result"]) <= 1600


def test_transcript_file_roundtrip(toolbox, tmp_path):
    res = Agent(toolbox, HeuristicLLM()).run()
    path = str(tmp_path / "t.jsonl")
    res.write_transcript(path)
    lines = [json.loads(l) for l in open(path)]
    assert lines[0]["event"] == "start" and lines[-1]["status"] == "ok"


def test_xor_loop_detector_unit():
    loop = [{"address": "0x10", "text": "movzx eax, byte [rax]"}, {"address": "0x14", "text": "xor eax, edx"}, {"address": "0x18", "text": "jl 0x10"}]
    assert has_xor_loop(loop)
    assert not has_xor_loop([{"address": "0x10", "text": "xor eax, eax"}, {"address": "0x12", "text": "jl 0x10"}])       # zeroing idiom
    assert not has_xor_loop([{"address": "0x10", "text": "xor eax, edx"}, {"address": "0x12", "text": "jmp 0x40"}])     # no back-edge
