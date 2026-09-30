"""LLM adapters. All expose ``name`` and ``chat(messages, tools) -> {'content', 'tool_calls': [{'id','name','arguments'}]}``."""
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Generator, Iterable

from .ioc import extract_iocs


class LLMError(RuntimeError):
    pass


class OpenAIChat:
    """Any OpenAI-compatible /chat/completions endpoint with tool calling (OpenAI, Azure gateways, LiteLLM,
    Ollama, LM Studio, vLLM ...). Configuration comes from the environment; the key is never logged."""

    def __init__(self, base_url: str | None = None, api_key: str | None = None, model: str | None = None,
                 timeout: float = 120.0, max_retries: int = 2):
        self.base_url = (base_url or os.environ.get("RETRIAGE_API_BASE") or "https://api.openai.com/v1").rstrip("/")
        self._key = api_key if api_key is not None else (os.environ.get("RETRIAGE_API_KEY") or os.environ.get("OPENAI_API_KEY") or "")
        self.model = model or os.environ.get("RETRIAGE_MODEL") or "gpt-4o"
        self.timeout, self.max_retries = timeout, max_retries
        self.name = f"openai-compatible:{self.model}"

    def chat(self, messages: list, tools: list) -> dict:
        body = {"model": self.model, "messages": messages, "temperature": 0, "tool_choice": "auto",
                "tools": [{"type": "function", "function": t} for t in tools]}
        headers = {"Content-Type": "application/json"}
        if self._key:
            headers["Authorization"] = f"Bearer {self._key}"
        req = urllib.request.Request(f"{self.base_url}/chat/completions", data=json.dumps(body).encode(), headers=headers, method="POST")
        last: Exception | None = None
        for attempt in range(self.max_retries + 1):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    payload = json.loads(resp.read().decode())
                break
            except urllib.error.HTTPError as exc:
                last = exc
                if exc.code in (429, 500, 502, 503, 504) and attempt < self.max_retries:
                    time.sleep(1.5 * (attempt + 1))
                    continue
                raise LLMError(f"LLM HTTP {exc.code}") from None
            except (urllib.error.URLError, TimeoutError) as exc:
                last = exc
                if attempt < self.max_retries:
                    time.sleep(1.5 * (attempt + 1))
                    continue
                raise LLMError(f"LLM connection error: {type(exc).__name__}") from None
        else:  # pragma: no cover
            raise LLMError(f"LLM request failed: {last}")
        try:
            msg = payload["choices"][0]["message"]
        except (KeyError, IndexError, TypeError):
            raise LLMError("unexpected LLM response shape") from None
        calls = []
        for i, tc in enumerate(msg.get("tool_calls") or []):
            fn = tc.get("function", {})
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {"_unparseable_arguments": True}
            calls.append({"id": tc.get("id") or f"call_{i}", "name": fn.get("name", ""), "arguments": args})
        return {"content": msg.get("content"), "tool_calls": calls}


class ScriptedLLM:
    """Replays a fixed script; used in tests. Items are dicts or callables(messages) -> dict."""
    name = "scripted"

    def __init__(self, script: Iterable[dict | Callable[[list], dict]]):
        self._script = list(script)
        self._i = 0

    def chat(self, messages: list, tools: list) -> dict:
        if self._i >= len(self._script):
            return {"content": "script exhausted", "tool_calls": []}
        item = self._script[self._i]
        self._i += 1
        out = item(messages) if callable(item) else item
        for n, c in enumerate(out.get("tool_calls", [])):
            c.setdefault("id", f"s{self._i}_{n}")
        return out


# ---------------------------------------------------------------------------------------------------
# Offline baseline: a deterministic policy, NOT a language model. It exists so the pipeline can be run
# and tested without an API key, and to show the rename-compounding loop end to end.
# ---------------------------------------------------------------------------------------------------
_NET_IMPORTS = {"connect", "send", "recv", "socket", "WSAStartup", "InternetOpenA", "InternetOpenW", "URLDownloadToFileA",
                "HttpSendRequestA", "getaddrinfo", "gethostbyname", "WinHttpOpen", "curl_easy_perform"}
_DATA_SECTIONS = {".rodata", ".data", ".rdata", ".data.rel.ro"}
_JUMP = re.compile(r"^j[a-z]{1,3}\s+(0x[0-9a-fA-F]+)")
_XOR = re.compile(r"^xor\s+([^,]+),\s*(.+)$")


def has_xor_loop(lines: list[dict]) -> bool:
    """True if a non-zeroing XOR is followed (later in the function) by a backward jump."""
    for i, ln in enumerate(lines):
        m = _XOR.match(ln["text"])
        if not m or m.group(1).strip() == m.group(2).strip():
            continue
        here = int(ln["address"], 16)
        for later in lines[i + 1:]:
            j = _JUMP.match(later["text"])
            if j and int(j.group(1), 16) <= here:
                return True
    return False


def _call(name: str, **args) -> tuple[str, dict]:
    return name, args


def _policy() -> Generator[tuple[str, dict], dict, None]:
    info = yield _call("get_binary_info")
    secs = yield _call("get_sections")
    funcs = yield _call("list_functions", limit=200)
    imps = yield _call("get_imports")
    yield _call("get_strings", min_len=6, limit=100)
    ranges = [(int(s["vaddr"], 16), int(s["vaddr"], 16) + s["vsize"]) for s in secs["sections"] if s["name"] in _DATA_SECTIONS]
    app = [f for f in funcs["functions"] if f["kind"] == "function"]
    decoders = []
    for f in app[:40]:
        dis = yield _call("get_disassembly", target=f["address"], max_lines=200)
        if has_xor_loop(dis["lines"]):
            decoders.append(f)
    findings, renames = [], []
    for n, d in enumerate(decoders):
        new = "xor_decode_routine" if n == 0 else f"xor_decode_routine_{d['address'][2:]}"
        r = yield _call("rename_function", target=d["address"], new_name=new)
        if r.get("ok"):
            renames.append(new)
        yield _call("add_comment", target=d["address"], text="loop applying XOR to a buffer: string/config decoder candidate")
        xr = yield _call("get_xrefs_to", target=d["address"])
        for x in xr["xrefs"]:
            if not x.get("in_function"):
                continue
            caller = x["in_function"]
            dis = yield _call("get_disassembly", target=caller["address"], max_lines=200)  # now shows the new name
            cands = {int(t, 16) for ln in dis["lines"] for t in re.findall(r"0x[0-9a-fA-F]{3,}", ln["text"])}
            cands |= {int(ln["ptr"], 16) for ln in dis["lines"] if ln.get("ptr")}
            covered_until = 0
            for a in sorted(c for c in cands if any(lo <= c < hi for lo, hi in ranges)):
                if a < covered_until:          # inside a blob we already decoded
                    continue
                bf = yield _call("xor_bruteforce", target=hex(a), length=128)
                top = (bf.get("candidates") or [None])[0]
                if top and top["score"] >= 1.2 and extract_iocs(top["text"]):
                    covered_until = a + len(top["text"]) + 1
                    findings.append({"decoder": d["address"], "decoder_name": new, "caller": caller["address"],
                                     "data": hex(a), "key": top["key"], "text": top["text"]})
    net = sorted({i["name"] for i in imps["imports"]} & _NET_IMPORTS)
    yield _call("submit_report", report=_build_report(info, findings, decoders, net))


def _build_report(info: dict, findings: list, decoders: list, net: list) -> dict:
    limits = ["Produced by the offline heuristic policy (not a language model): it only recognizes single-byte XOR decode loops. "
              "No finding does not mean benign.",
              "Static analysis only; nothing was executed and no network lookups were made.",
              "Pseudo-code fidelity is low; conclusions rely on disassembly and decoded bytes."]
    if not findings:
        return {"verdict": {"classification": "unknown", "confidence": "low", "risk": "unrated"},
                "summary": "No XOR string-decoding pattern was found by the heuristic policy. This run cannot characterize the sample.",
                "behaviors": [], "iocs": [], "obfuscation": [], "limitations": limits,
                "recommendations": ["Run with an LLM backend (--llm openai) for deeper analysis."]}
    f = findings[0]
    iocs = []
    for x in findings:
        for i in extract_iocs(x["text"]):
            iocs.append({**i, "context": f"decoded with key {x['key']} from data at {x['data']}"})
    return {
        "verdict": {"classification": "suspicious", "confidence": "low", "risk": "low"},
        "summary": (f"Stripped binary with {len(decoders)} function(s) that XOR-decode data at runtime. The routine at {f['decoder']} with key "
                    f"{f['key']} recovers '{f['text']}' from {f['data']}, called from {f['caller']}. Network-related imports: "
                    f"{', '.join(net) if net else 'none observed'}."),
        "behaviors": [{"behavior": "Runtime decoding of an obfuscated string (single-byte XOR)", "function": f["decoder"], "attack_id": "T1140",
                       "confidence": "medium",
                       "evidence": [f"{f['decoder']} contains a loop with a non-zeroing XOR (renamed {f['decoder_name']})",
                                    f"xor_bruteforce at {f['data']}: key {f['key']} -> '{f['text']}'",
                                    f"caller {f['caller']} references {f['data']} and calls {f['decoder']}"]}],
        "iocs": iocs,
        "obfuscation": [f"single-byte XOR string encoding (key {f['key']})"],
        "limitations": limits,
        "recommendations": ["Validate the decoded indicator against threat intelligence before blocking.",
                            "Run with an LLM backend (--llm openai) to characterize the rest of the program."],
    }


class HeuristicLLM:
    name = "heuristic-offline-policy"

    def __init__(self):
        self._gen = _policy()
        self._started = False
        self._n = 0

    def chat(self, messages: list, tools: list) -> dict:
        try:
            if not self._started:
                self._started = True
                name, args = next(self._gen)
            else:
                last = json.loads(messages[-1]["content"]) if messages[-1]["role"] == "tool" else {}
                data = last.get("data") if isinstance(last.get("data"), dict) else {}
                data = {"ok": True, **data} if last.get("ok") else {"ok": False, "error": last.get("error", "no result")}
                name, args = self._gen.send(data)
        except StopIteration:
            return {"content": "Analysis complete.", "tool_calls": []}
        self._n += 1
        return {"content": None, "tool_calls": [{"id": f"h{self._n}", "name": name, "arguments": args}]}
