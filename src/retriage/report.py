"""Report schema (v1), validation, finalization and Markdown rendering.

Design rules that keep reports honest:
* Facts computed by code (hashes, size, format, tool counts, renames) are added by ``finalize_report``; the model
  is never asked to supply them.
* ``limitations`` is mandatory, and every behavior needs at least one evidence string.
* Each IOC is checked against the transcript: ``grounded: false`` means the value never appeared in a tool result.
"""
from __future__ import annotations

import copy
import json
from typing import Any

from jsonschema import Draft202012Validator

from . import __version__
from .ioc import defang

_CONF = {"enum": ["low", "medium", "high"]}
_STR = {"type": "string"}

REPORT_SCHEMA: dict = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://example.org/retriage/report.schema.json",
    "title": "retriage triage report v1",
    "type": "object",
    "additionalProperties": False,
    "required": ["schema_version", "sample", "verdict", "summary", "behaviors", "iocs", "obfuscation",
                 "limitations", "recommendations", "analysis"],
    "properties": {
        "schema_version": {"const": "1.0"},
        "sample": {
            "type": "object", "additionalProperties": False,
            "required": ["sha256", "md5", "sha1", "size"],
            "properties": {"sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                           "md5": {"type": "string", "pattern": "^[0-9a-f]{32}$"},
                           "sha1": {"type": "string", "pattern": "^[0-9a-f]{40}$"},
                           "size": {"type": "integer", "minimum": 0},
                           "format": {"type": ["string", "null"]}, "arch": {"type": ["string", "null"]},
                           "bits": {"type": ["integer", "null"]}}},
        "verdict": {
            "type": "object", "additionalProperties": False, "required": ["classification", "confidence", "risk"],
            "properties": {"classification": {"enum": ["malicious", "suspicious", "benign", "unknown"]},
                           "confidence": _CONF,
                           "risk": {"enum": ["critical", "high", "medium", "low", "unrated"]}}},
        "summary": {"type": "string", "minLength": 1, "maxLength": 2000},
        "behaviors": {"type": "array", "items": {
            "type": "object", "additionalProperties": False, "required": ["behavior", "evidence", "confidence"],
            "properties": {"behavior": _STR,
                           "evidence": {"type": "array", "items": _STR, "minItems": 1},
                           "function": {"type": ["string", "null"]},
                           "attack_id": {"type": ["string", "null"], "pattern": "^T[0-9]{4}(\\.[0-9]{3})?$"},
                           "confidence": _CONF}}},
        "iocs": {"type": "array", "items": {
            "type": "object", "additionalProperties": False, "required": ["type", "value"],
            "properties": {"type": {"enum": ["ip", "domain", "url", "email", "registry_key", "mutex", "file_path", "hash", "other"]},
                           "value": {"type": "string", "minLength": 1}, "context": {"type": "string"},
                           "grounded": {"type": "boolean"}}}},
        "obfuscation": {"type": "array", "items": _STR},
        "limitations": {"type": "array", "items": _STR, "minItems": 1},
        "recommendations": {"type": "array", "items": _STR},
        "analysis": {
            "type": "object", "additionalProperties": False, "required": ["tool", "backend", "llm", "steps", "tool_calls"],
            "properties": {"tool": _STR, "backend": _STR, "llm": _STR, "steps": {"type": "integer"},
                           "tool_calls": {"type": "integer"},
                           "renamed_functions": {"type": "array", "items": {"type": "object"}},
                           "ungrounded_iocs": {"type": "array", "items": _STR}}},
    },
}

_MODEL_FIELDS = ("verdict", "summary", "behaviors", "iocs", "obfuscation", "limitations", "recommendations")


def submission_schema() -> dict:
    """The part of the report the model supplies (no schema_version, sample or analysis)."""
    s = copy.deepcopy(REPORT_SCHEMA)
    s["required"] = list(_MODEL_FIELDS)
    s["properties"] = {k: v for k, v in s["properties"].items() if k in _MODEL_FIELDS}
    s["title"] = "retriage report submission (model-supplied fields)"
    return s


def _errors(schema: dict, obj: Any) -> list[str]:
    v = Draft202012Validator(schema)
    return [f"{'/'.join(map(str, e.absolute_path)) or '<root>'}: {e.message}" for e in sorted(v.iter_errors(obj), key=lambda e: list(e.absolute_path))]


def validate_submission(obj: Any) -> list[str]:
    return _errors(submission_schema(), obj)


def validate_report(obj: Any) -> list[str]:
    return _errors(REPORT_SCHEMA, obj)


def finalize_report(submitted: dict, info: dict, *, llm: str, backend: str, steps: int, tool_calls: int,
                    renames: list, tool_output_text: str) -> dict:
    """Merge model-supplied content with code-computed facts and ground-check IOCs."""
    hay = tool_output_text.lower()
    iocs, ungrounded = [], []
    for ioc in submitted.get("iocs", []):
        g = ioc["value"].lower() in hay
        iocs.append({**ioc, "grounded": g})
        if not g:
            ungrounded.append(ioc["value"])
    report = {
        "schema_version": "1.0",
        "sample": {"sha256": info["sha256"], "md5": info["md5"], "sha1": info["sha1"], "size": info["size"],
                   "format": info.get("format"), "arch": info.get("arch"), "bits": info.get("bits")},
        **{k: submitted[k] for k in _MODEL_FIELDS if k != "iocs"},
        "iocs": iocs,
        "analysis": {"tool": f"retriage {__version__}", "backend": backend, "llm": llm, "steps": steps,
                     "tool_calls": tool_calls, "renamed_functions": renames, "ungrounded_iocs": ungrounded},
    }
    return report


def to_markdown(r: dict) -> str:
    v, s, a = r["verdict"], r["sample"], r["analysis"]
    L = [f"# Triage report: `{s['sha256'][:16]}…`", "",
         f"**Verdict:** {v['classification']} (confidence {v['confidence']}) · **Risk:** {v['risk']}", "",
         f"- SHA-256: `{s['sha256']}`", f"- MD5: `{s['md5']}` · SHA-1: `{s['sha1']}`",
         f"- Size: {s['size']:,} bytes · {s.get('format') or '?'} {s.get('arch') or ''} {s.get('bits') or ''}-bit", "",
         "## Summary", "", r["summary"], "", "## Behaviors", ""]
    if not r["behaviors"]:
        L.append("_None reported._")
    for b in r["behaviors"]:
        head = f"- **{b['behavior']}** ({b['confidence']})" + (f" · {b['attack_id']}" if b.get("attack_id") else "") \
               + (f" · `{b['function']}`" if b.get("function") else "")
        L += [head] + [f"  - evidence: {e}" for e in b["evidence"]]
    L += ["", "## Indicators", ""]
    if not r["iocs"]:
        L.append("_None reported._")
    for i in r["iocs"]:
        flag = "" if i.get("grounded", True) else " ⚠️ **not found in any tool output**"
        L.append(f"- {i['type']}: `{defang(i['value'])}`" + (f" - {i['context']}" if i.get("context") else "") + flag)
    if r["obfuscation"]:
        L += ["", "## Obfuscation", ""] + [f"- {o}" for o in r["obfuscation"]]
    L += ["", "## Limitations", ""] + [f"- {x}" for x in r["limitations"]]
    if r["recommendations"]:
        L += ["", "## Recommendations", ""] + [f"- {x}" for x in r["recommendations"]]
    L += ["", "## Analysis metadata", "",
          f"{a['tool']} · backend {a['backend']} · model/policy `{a['llm']}` · {a['steps']} steps · {a['tool_calls']} tool calls"]
    if a.get("renamed_functions"):
        L.append("- renamed: " + ", ".join(f"`{x['old_name']}` → `{x['new_name']}`" for x in a["renamed_functions"]))
    L += ["", "_Static analysis only; indicators are defanged. Verify before acting._", ""]
    return "\n".join(L)


def dump_schema_files(directory: str) -> None:
    import os
    os.makedirs(directory, exist_ok=True)
    for name, obj in (("report.schema.json", REPORT_SCHEMA), ("submission.schema.json", submission_schema())):
        with open(os.path.join(directory, name), "w", encoding="utf-8") as fh:
            json.dump(obj, fh, indent=2)
            fh.write("\n")
