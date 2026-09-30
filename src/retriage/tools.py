"""Tool specifications (JSON Schema, OpenAI function-calling compatible) and the dispatcher."""
from __future__ import annotations

import re
import time
from typing import Any, Callable

from . import report as report_mod
from .backend import BackendError, R2Backend
from .safety import ToolArgError, clamp_int, fence

_T = {"type": "string", "description": "Function/symbol name (e.g. 'main', 'fcn.00001149') or hex address (e.g. '0x1149')."}


def _spec(name: str, description: str, props: dict | None = None, required: list | None = None) -> dict:
    return {"name": name, "description": description,
            "parameters": {"type": "object", "properties": props or {}, "required": required or [], "additionalProperties": False}}


TOOL_SPECS: list[dict] = [
    _spec("get_binary_info", "File hashes, size, format, architecture, bitness, stripped/PIE/NX flags."),
    _spec("get_sections", "Sections with virtual address, size, permissions and Shannon entropy (>7.0 suggests packing/encryption)."),
    _spec("list_functions", "Functions found by analysis (address, name, size, basic blocks, kind=function|import|entry). Renamed functions appear with their new names.",
          {"limit": {"type": "integer", "minimum": 1, "maximum": 500}, "name_filter": {"type": "string", "description": "Regex on function names."}}),
    _spec("get_imports", "Imported functions and libraries."),
    _spec("get_strings", "Strings found in the file with addresses. Use pattern (regex) to narrow.",
          {"min_len": {"type": "integer", "minimum": 3, "maximum": 100}, "limit": {"type": "integer", "minimum": 1, "maximum": 500},
           "pattern": {"type": "string"}}),
    _spec("get_disassembly", "Disassembly of the function containing target (or of the address if not in a function).",
          {"target": _T, "max_lines": {"type": "integer", "minimum": 1, "maximum": 400}}, ["target"]),
    _spec("get_pseudocode", "Approximate pseudo-C for the function (radare2 'pdc': LOW fidelity, always cross-check the disassembly).",
          {"target": _T, "max_lines": {"type": "integer", "minimum": 1, "maximum": 400}}, ["target"]),
    _spec("get_xrefs_to", "Code/data references to target, with the function containing each reference.", {"target": _T}, ["target"]),
    _spec("get_callees", "Functions called by the function containing target (call graph, one level).", {"target": _T}, ["target"]),
    _spec("read_bytes", "Read up to 256 bytes at an address (hex + printable preview).",
          {"target": _T, "length": {"type": "integer", "minimum": 1, "maximum": 256}}, ["target"]),
    _spec("xor_bruteforce", "Try all single-byte XOR keys on the bytes at an address (stops at the first NUL byte) and return readable candidates. Use on suspected encoded strings.",
          {"target": _T, "length": {"type": "integer", "minimum": 4, "maximum": 256}}, ["target"]),
    _spec("rename_function", "Rename a function in the analysis database once you understand it (e.g. 'xor_decode_routine'). Renames appear in callers' disassembly, so later analysis becomes easier.",
          {"target": _T, "new_name": {"type": "string", "description": "[A-Za-z_][A-Za-z0-9_]{0,63}"}}, ["target", "new_name"]),
    _spec("add_comment", "Attach a short note to an address in the analysis database.",
          {"target": _T, "text": {"type": "string", "maxLength": 200}}, ["target", "text"]),
    _spec("submit_report", "Finish the analysis. Provide verdict, summary, behaviors (each with evidence citing addresses/tool results), iocs, obfuscation, limitations (required), recommendations. Hashes and metadata are added automatically.",
          {"report": report_mod.submission_schema()}, ["report"]),
]
TOOL_NAMES = [t["name"] for t in TOOL_SPECS]


def _printable_prefix(b: bytes) -> int:
    n = 0
    for c in b:
        if 32 <= c < 127:
            n += 1
        else:
            break
    return n


class ToolBox:
    """Executes tool calls against a backend. ``call`` never raises; errors are returned as {ok: false}."""

    def __init__(self, backend: R2Backend):
        self.b = backend
        self.renames: list[dict] = []
        self.submitted: dict | None = None
        self.calls = 0
        self._handlers: dict[str, Callable[[dict], Any]] = {
            "get_binary_info": lambda a: self.b.binary_info(),
            "get_sections": lambda a: {"sections": self.b.sections()},
            "list_functions": lambda a: self.b.functions(clamp_int(a.get("limit"), 1, 500, 200), a.get("name_filter")),
            "get_imports": lambda a: {"imports": self.b.imports()},
            "get_strings": lambda a: self.b.strings(clamp_int(a.get("min_len"), 3, 100, 6), clamp_int(a.get("limit"), 1, 500, 100), a.get("pattern")),
            "get_disassembly": lambda a: self.b.disassembly(self._need(a, "target"), clamp_int(a.get("max_lines"), 1, 400, 120)),
            "get_pseudocode": lambda a: self.b.pseudocode(self._need(a, "target"), clamp_int(a.get("max_lines"), 1, 400, 150)),
            "get_xrefs_to": lambda a: {"xrefs": self.b.xrefs_to(self._need(a, "target"))},
            "get_callees": lambda a: {"callees": self.b.callees(self._need(a, "target"))},
            "read_bytes": self._read_bytes,
            "xor_bruteforce": self._xor_bruteforce,
            "rename_function": self._rename,
            "add_comment": lambda a: self.b.add_comment(self._need(a, "target"), self._need(a, "text")),
            "submit_report": self._submit,
        }

    @staticmethod
    def _need(args: dict, key: str) -> Any:
        if key not in args:
            raise ToolArgError(f"missing required argument: {key}")
        return args[key]

    def _read_bytes(self, a: dict) -> dict:
        n = clamp_int(a.get("length"), 1, 256, 64)
        raw = self.b.read_bytes(self._need(a, "target"), n)
        return {"length": len(raw), "hex": raw.hex(), "ascii": "".join(chr(c) if 32 <= c < 127 else "." for c in raw)}

    def _xor_bruteforce(self, a: dict) -> dict:
        n = clamp_int(a.get("length"), 4, 256, 128)
        raw = self.b.read_bytes(self._need(a, "target"), n).split(b"\x00")[0]
        if len(raw) < 4:
            return {"candidates": [], "note": "fewer than 4 bytes before the first NUL"}
        cands = []
        for key in range(1, 256):
            dec = bytes(c ^ key for c in raw)
            pre = _printable_prefix(dec)
            if pre < max(8, int(len(raw) * 0.9)):
                continue
            text = dec[:pre].decode("ascii")
            texty = sum(ch.isalnum() or ch in " ./:_-?=&%@" for ch in text) / len(text)   # symbol-heavy output is noise
            if texty < 0.85:
                continue
            bonus = 0.5 if re.search(r"https?://|\b[a-z0-9-]+(\.[a-z0-9-]+)+\b|[\\/][\w.-]+\.[a-z]{2,4}\b", text, re.I) else 0.0
            cands.append({"key": f"0x{key:02x}", "score": round(pre / len(raw) * 0.5 + texty * 0.5 + bonus, 3), "text": text[:200]})
        cands.sort(key=lambda c: -c["score"])
        return {"input_length": len(raw), "candidates": cands[:5]}

    def _rename(self, a: dict) -> dict:
        res = self.b.rename_function(self._need(a, "target"), self._need(a, "new_name"))
        self.renames.append(res)
        return res

    def _submit(self, a: dict) -> dict:
        errors = report_mod.validate_submission(a.get("report"))
        if errors:
            raise ToolArgError("report rejected; fix these and call submit_report again: " + "; ".join(errors[:8]))
        self.submitted = a["report"]
        return {"accepted": True}

    def call(self, name: str, args: dict | None) -> dict:
        self.calls += 1
        args = args if isinstance(args, dict) else {}
        handler = self._handlers.get(name)
        if handler is None:
            return {"ok": False, "error": f"unknown tool '{name}'. Available: {', '.join(TOOL_NAMES)}"}
        t0 = time.time()
        try:
            data = handler(args)
            out = fence(data) if name != "submit_report" else {"ok": True, "data": data}
        except (ToolArgError, BackendError) as exc:
            out = {"ok": False, "error": str(exc)}
        except Exception as exc:  # never leak stack traces or paths to the model
            out = {"ok": False, "error": f"internal error ({type(exc).__name__})"}
        out["ms"] = int((time.time() - t0) * 1000)
        return out
