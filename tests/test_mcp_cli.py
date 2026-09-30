import asyncio
import json

import pytest

from conftest import requires_r2
from retriage import cli


def _texts(result):
    if isinstance(result, tuple):
        result = result[0]
    return "".join(getattr(c, "text", "") for c in result)


@requires_r2
def test_mcp_server_exposes_hardened_tools(toolbox):
    pytest.importorskip("mcp.server.fastmcp")
    from retriage.mcp_server import build_server
    mcp = build_server(toolbox)
    names = {t.name for t in asyncio.run(mcp.list_tools())}
    assert "submit_report" not in names and {"list_functions", "get_disassembly", "rename_function", "xor_bruteforce"} <= names and len(names) == 13
    ok = json.loads(_texts(asyncio.run(mcp.call_tool("list_functions", {}))))
    assert ok["ok"] and ok["data"]["functions"]
    bad = json.loads(_texts(asyncio.run(mcp.call_tool("get_disassembly", {"target": "main; !id"}))))
    assert bad["ok"] is False


@requires_r2
def test_cli_analyze_validate_and_tools(demo_binary, tmp_path, capsys):
    out, md, tr = tmp_path / "r.json", tmp_path / "r.md", tmp_path / "t.jsonl"
    assert cli.main(["analyze", demo_binary, "-q", "-o", str(out), "--md", str(md), "--transcript", str(tr)]) == 0
    assert cli.main(["validate", str(out)]) == 0
    assert "gate[.]php" in md.read_text() or "c2[.]example[.]invalid" in md.read_text()        # indicators are defanged
    assert tr.read_text().splitlines()
    assert cli.main(["tools"]) == 0 and "rename_function" in capsys.readouterr().out


def test_cli_rejects_missing_file(capsys):
    assert cli.main(["analyze", "/no/such/file", "-q"]) == 2


def test_cli_validate_rejects_bad_report(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({"schema_version": "1.0"}))
    assert cli.main(["validate", str(p)]) == 1
