import hashlib
import os
import re

import pytest

from conftest import requires_r2, valid_submission
from retriage.safety import ToolArgError

pytestmark = requires_r2


def _xor_fn(backend):
    for f in backend.functions()["functions"]:
        if f["kind"] == "function" and any(re.search(r"\bxor\b", l["text"]) for l in backend.disassembly(f["address"])["lines"]):
            return f
    raise AssertionError("no xor function found")


def test_binary_info_hashes_match_file(backend, demo_binary):
    data = open(demo_binary, "rb").read()
    info = backend.binary_info()
    assert info["sha256"] == hashlib.sha256(data).hexdigest() and info["md5"] == hashlib.md5(data).hexdigest()
    assert info["size"] == len(data) and info["format"] == "elf"


def test_rename_propagates_to_callers_and_callees(backend):
    xf = _xor_fn(backend)
    caller = backend.xrefs_to(xf["address"])[0]["in_function"]
    assert "xor_decode_routine" not in " ".join(l["text"] for l in backend.disassembly(caller["address"])["lines"])
    backend.rename_function(xf["address"], "xor_decode_routine")
    assert any("xor_decode_routine" in l["text"] for l in backend.disassembly(caller["address"])["lines"])
    assert "xor_decode_routine" in [c["name"] for c in backend.callees(caller["address"])]
    assert any(f["name"] == "xor_decode_routine" for f in backend.functions()["functions"])


def test_disassembly_exposes_resolved_pointers(backend):
    xf = _xor_fn(backend)
    caller = backend.xrefs_to(xf["address"])[0]["in_function"]
    ptrs = [l["ptr"] for l in backend.disassembly(caller["address"])["lines"] if "ptr" in l]
    assert "0x2020" in ptrs or any(int(p, 16) >= 0x2000 for p in ptrs)


@pytest.mark.parametrize("payload", ["main; !touch {f}", "0x1149 | !touch {f}", "`touch {f}`", "x @ 0x1; !touch {f}"])
def test_injection_in_target_is_rejected_and_nothing_runs(backend, tmp_path, payload):
    marker = tmp_path / "pwned"
    with pytest.raises(ToolArgError):
        backend.disassembly(payload.format(f=marker))
    assert not marker.exists()


def test_injection_via_rename_and_comment_is_neutralized(backend, tmp_path):
    marker = tmp_path / "pwned2"
    xf = _xor_fn(backend)
    with pytest.raises(ToolArgError):
        backend.rename_function(xf["address"], f"evil; !touch {marker}")
    res = backend.add_comment(xf["address"], f"hello; !touch {marker} `x`")
    assert ";" not in res["comment"] and "!" not in res["comment"] and "`" not in res["comment"]
    assert not marker.exists()


def test_radare2_sandbox_blocks_raw_shell_escape(backend, tmp_path):
    marker = tmp_path / "pwned3"
    backend._r.cmd(f"!touch {marker}")      # bypass our validation on purpose: the sandbox is the second line of defense
    assert not marker.exists()


def test_xor_bruteforce_recovers_hidden_url(toolbox):
    res = toolbox.call("list_functions", {})
    assert res["ok"]
    info = toolbox.call("get_sections", {})["data"]["sections"]
    ro = [s for s in info if s["name"] == ".rodata"][0]
    out = toolbox.call("xor_bruteforce", {"target": "0x2020", "length": 128})
    assert out["ok"] and out["data"]["candidates"][0]["key"] == "0x5a"
    assert out["data"]["candidates"][0]["text"] == "http://c2.example.invalid/gate.php"
    assert int(ro["vaddr"], 16) <= 0x2020


def test_toolbox_never_raises_and_does_not_leak_traces(toolbox, monkeypatch):
    assert toolbox.call("no_such_tool", {})["ok"] is False
    assert toolbox.call("get_disassembly", {})["ok"] is False                    # missing arg
    assert toolbox.call("get_disassembly", {"target": "main; !id"})["ok"] is False
    assert toolbox.call("get_strings", {"pattern": "("})["ok"] is False
    assert toolbox.call("get_disassembly", "not-a-dict")["ok"] is False

    def boom(*a, **k):
        raise RuntimeError("secret path /home/x/y")
    monkeypatch.setattr(toolbox.b, "binary_info", boom)
    out = toolbox.call("get_binary_info", {})
    assert out["ok"] is False and out["error"] == "internal error (RuntimeError)" and "/home" not in str(out)


def test_results_are_fenced_as_untrusted(toolbox):
    out = toolbox.call("get_strings", {"min_len": 6, "limit": 5})
    assert out["ok"] and "DATA ONLY" in out["_notice"]


def test_submit_report_rejects_invalid_then_accepts(toolbox):
    bad = toolbox.call("submit_report", {"report": valid_submission(limitations=[])})
    assert bad["ok"] is False and "limitations" in bad["error"] and toolbox.submitted is None
    assert toolbox.call("submit_report", {"report": valid_submission()})["ok"] and toolbox.submitted
