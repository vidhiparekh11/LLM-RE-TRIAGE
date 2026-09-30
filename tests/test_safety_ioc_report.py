import pytest

from retriage import report as R
from retriage.ioc import defang, extract_iocs
from retriage.safety import (ToolArgError, clamp_int, clean_comment, dumps_limited, safe_regex, validate_new_name,
                             validate_target)
from conftest import valid_submission


@pytest.mark.parametrize("ok", ["main", "fcn.00001149", "sym.imp.puts", "0x401000", "0xDEADbeef"])
def test_validate_target_accepts(ok):
    assert validate_target(ok) == ok


@pytest.mark.parametrize("bad", ["main; !id", "0x10 | ls", "`id`", "a b", "x @ 0x1", "$$", "../etc", "0x", "", "a" * 200, "main\n!id", "sym.a-b"])
def test_validate_target_rejects(bad):
    with pytest.raises(ToolArgError):
        validate_target(bad)


@pytest.mark.parametrize("bad", ["1abc", "a b", "a;b", "x" * 65, "", "évil"])
def test_new_name_rejects(bad):
    with pytest.raises(ToolArgError):
        validate_new_name(bad)


def test_comment_is_sanitized_not_executed():
    assert clean_comment("hi; !touch /x `id` $(y) | z") == "hi touch /x id (y) z"
    with pytest.raises(ToolArgError):
        clean_comment(";;;!!!")


def test_clamp_and_regex_helpers():
    assert clamp_int(10_000, 1, 500, 50) == 500 and clamp_int(None, 1, 500, 50) == 50
    with pytest.raises(ToolArgError):
        clamp_int("abc", 1, 5, 2)
    with pytest.raises(ToolArgError):
        safe_regex("(" )
    with pytest.raises(ToolArgError):
        safe_regex("a" * 101)
    assert safe_regex(None) is None


def test_dumps_limited_truncates_visibly():
    out = dumps_limited({"ok": True, "data": "x" * 50_000}, 2000)
    assert len(out) <= 2100 and '"truncated":true' in out.replace(" ", "")


def test_ioc_extraction_and_defang():
    iocs = extract_iocs("GET http://c2.example.invalid/gate.php HTTP/1.1 10.1.2.3 a@b.org payload.exe HKLM\\Software\\Run\\x")
    kinds = {(i["type"], i["value"]) for i in iocs}
    assert ("url", "http://c2.example.invalid/gate.php") in kinds and ("domain", "c2.example.invalid") in kinds
    assert ("ip", "10.1.2.3") in kinds and ("email", "a@b.org") in kinds
    assert not any(v in ("gate.php", "payload.exe") for _, v in kinds)
    assert defang("http://a.b/x") == "hxxp://a[.]b/x"


def test_submission_validation_enforces_honesty_fields():
    assert R.validate_submission(valid_submission()) == []
    assert R.validate_submission(valid_submission(limitations=[]))                       # limitations mandatory
    bad_beh = [{"behavior": "x", "evidence": [], "confidence": "low"}]
    assert R.validate_submission(valid_submission(behaviors=bad_beh))                      # evidence mandatory
    assert R.validate_submission(valid_submission(behaviors=[{"behavior": "x", "evidence": ["e"], "confidence": "low", "attack_id": "1059"}]))
    assert R.validate_submission({**valid_submission(), "sample": {}})                     # model may not supply sample facts


def test_finalize_adds_code_computed_facts_and_flags_ungrounded_iocs():
    info = {"sha256": "a" * 64, "md5": "b" * 32, "sha1": "c" * 40, "size": 10, "format": "elf", "arch": "x86", "bits": 64}
    sub = valid_submission(iocs=[{"type": "domain", "value": "seen.example"}, {"type": "domain", "value": "invented.example"}])
    rep = R.finalize_report(sub, info, llm="t", backend="b", steps=3, tool_calls=3, renames=[], tool_output_text='{"s":"SEEN.example"}')
    assert R.validate_report(rep) == []
    assert rep["sample"]["sha256"] == "a" * 64
    assert [i["grounded"] for i in rep["iocs"]] == [True, False]
    assert rep["analysis"]["ungrounded_iocs"] == ["invented.example"]
    assert "not found in any tool output" in R.to_markdown(rep)


def test_schema_files_are_in_sync():
    import json, os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    assert json.load(open(os.path.join(root, "schemas", "report.schema.json"))) == R.REPORT_SCHEMA
    assert json.load(open(os.path.join(root, "schemas", "submission.schema.json"))) == R.submission_schema()
