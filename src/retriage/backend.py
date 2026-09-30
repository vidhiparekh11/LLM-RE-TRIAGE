"""radare2 backend (via r2pipe). All methods return plain dicts/lists.

The binary is analyzed statically and never executed. Arguments reaching radare2 must already be validated
by ``retriage.safety``; the backend also turns on ``cfg.sandbox`` after analysis as defense in depth.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
from collections import Counter
from typing import Any, Optional

from .safety import ToolArgError, safe_regex, validate_new_name, validate_target, clean_comment, clamp_int

_ANALYSIS = {"aa", "aaa", "aaaa"}
MAX_FILE_BYTES = 256 * 1024 * 1024


class BackendError(RuntimeError):
    pass


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return round(-sum(c / n * math.log2(c / n) for c in Counter(data).values()), 3)


class R2Backend:
    name = "radare2"

    def __init__(self, path: str, analysis: str = "aaaa", sandbox: bool = True):
        if analysis not in _ANALYSIS:
            raise BackendError(f"analysis must be one of {sorted(_ANALYSIS)}")
        self.path = os.path.abspath(path)
        if not os.path.isfile(self.path):
            raise BackendError(f"not a file: {path}")
        if os.path.getsize(self.path) > MAX_FILE_BYTES:
            raise BackendError("file too large (limit 256 MB)")
        with open(self.path, "rb") as fh:
            self._data = fh.read()
        try:
            import r2pipe
        except ImportError as exc:  # pragma: no cover
            raise BackendError("r2pipe is not installed (pip install r2pipe)") from exc
        try:
            self._r = r2pipe.open(self.path, flags=["-e", "bin.cache=true", "-e", "scr.color=0"])
        except Exception as exc:  # pragma: no cover
            raise BackendError(f"could not start radare2: {exc}") from exc
        self._cmd(analysis)
        self._funcs_cache: Optional[list] = None
        if sandbox:
            self._cmd("e cfg.sandbox=true")

    # ---- plumbing -------------------------------------------------------------------------
    def _cmd(self, command: str) -> str:
        if "\n" in command or "\r" in command:
            raise BackendError("newline in command")
        return self._r.cmd(command) or ""

    def _cmdj(self, command: str) -> Any:
        out = self._cmd(command).strip()
        if not out:
            return None
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            return None

    def close(self) -> None:
        try:
            self._r.quit()
        except Exception:  # pragma: no cover
            pass

    def __enter__(self) -> "R2Backend":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ---- helpers --------------------------------------------------------------------------
    def resolve(self, target: str) -> int:
        t = validate_target(target)
        if t.lower().startswith("0x"):
            return int(t, 16)
        out = self._cmd(f"?v {t}").strip()
        try:
            val = int(out, 16)
        except ValueError:
            val = 0
        if val == 0:
            raise ToolArgError(f"unknown symbol or address: {t}")
        return val

    def _functions(self) -> list:
        if self._funcs_cache is None:
            self._funcs_cache = self._cmdj("aflj") or []
        return self._funcs_cache

    def _invalidate(self) -> None:
        self._funcs_cache = None

    def _function_at(self, addr: int) -> Optional[dict]:
        info = self._cmdj(f"afij @ {addr}")
        return info[0] if info else None

    @staticmethod
    def _kind(name: str) -> str:
        if name.startswith("sym.imp.") or name.startswith("imp."):
            return "import"
        if name.startswith("entry"):
            return "entry"
        return "function"

    # ---- read-only queries ----------------------------------------------------------------
    def binary_info(self) -> dict:
        ij = (self._cmdj("ij") or {}).get("bin", {})
        keep = ("arch", "bits", "class", "machine", "os", "subsys", "stripped", "static", "canary", "nx", "pic",
                "relro", "compiler", "lang", "endian", "baddr", "binsz")
        return {
            "path_name": os.path.basename(self.path),
            "size": len(self._data),
            "md5": hashlib.md5(self._data).hexdigest(),
            "sha1": hashlib.sha1(self._data).hexdigest(),
            "sha256": hashlib.sha256(self._data).hexdigest(),
            "format": ij.get("bintype") or ij.get("class"),
            **{k: ij.get(k) for k in keep if k in ij},
        }

    def sections(self) -> list:
        out = []
        for s in self._cmdj("iSj") or []:
            if not s.get("name") and not s.get("size"):
                continue
            paddr, size = int(s.get("paddr", 0)), int(s.get("size", 0))
            blob = self._data[paddr: paddr + size] if size and paddr + size <= len(self._data) else b""
            out.append({"name": s.get("name", ""), "vaddr": hex(int(s.get("vaddr", 0))), "vsize": int(s.get("vsize", 0)),
                        "size": size, "perm": s.get("perm", ""), "entropy": _entropy(blob)})
        return out

    def functions(self, limit: int = 200, name_filter: Optional[str] = None) -> dict:
        rx = safe_regex(name_filter)
        rows = []
        for f in sorted(self._functions(), key=lambda f: f["offset"]):
            if rx and not rx.search(f["name"]):
                continue
            rows.append({"address": hex(f["offset"]), "name": f["name"], "size": f.get("size", 0),
                         "blocks": f.get("nbbs", 0), "kind": self._kind(f["name"])})
        return {"total": len(rows), "returned": min(limit, len(rows)), "functions": rows[:limit]}

    def imports(self) -> list:
        return [{"name": i.get("name", ""), "plt": hex(i["plt"]) if i.get("plt") else None, "type": i.get("type"),
                 "library": i.get("libname")} for i in (self._cmdj("iij") or [])]

    def strings(self, min_len: int = 6, limit: int = 100, pattern: Optional[str] = None) -> dict:
        rx = safe_regex(pattern)
        rows = []
        for z in self._cmdj("izzj") or []:
            s = z.get("string", "")
            if len(s) < min_len or (rx and not rx.search(s)):
                continue
            rows.append({"address": hex(z.get("vaddr", 0)), "section": z.get("section", ""), "length": z.get("length", len(s)),
                         "string": s[:300]})
        return {"total": len(rows), "returned": min(limit, len(rows)), "strings": rows[:limit]}

    def disassembly(self, target: str, max_lines: int = 120) -> dict:
        addr = self.resolve(target)
        fn = self._function_at(addr)
        if fn:
            data = self._cmdj(f"pdfj @ {fn['offset']}") or {}
            ops = data.get("ops", [])
            scope = {"function": fn["name"], "function_address": hex(fn["offset"])}
        else:
            ops = self._cmdj(f"pdj {max_lines} @ {addr}") or []
            scope = {"function": None, "note": "address is not inside a recognized function"}
        lines = []
        for o in ops[:max_lines]:
            line = {"address": hex(o["offset"]), "text": o.get("disasm", "")}
            if o.get("ptr"):   # resolved memory operand; radare2 may show a flag/string name in the text instead of the address
                line["ptr"] = hex(int(o["ptr"]))
            lines.append(line)
        return {**scope, "total_instructions": len(ops), "returned": len(lines), "lines": lines}

    def pseudocode(self, target: str, max_lines: int = 150) -> dict:
        addr = self.resolve(target)
        text = self._cmd(f"pdc @ {addr}")
        lines = [ln.rstrip() for ln in text.splitlines() if ln.strip()]
        if not lines:
            d = self.disassembly(target, max_lines)
            return {"fidelity": "none: pseudo-decompiler returned nothing, showing disassembly", "lines": [l["text"] for l in d["lines"]]}
        return {"fidelity": "low (radare2 pdc, plain pseudo-C; verify against disassembly)", "lines": lines[:max_lines]}

    def xrefs_to(self, target: str) -> list:
        addr = self.resolve(target)
        out = []
        for x in self._cmdj(f"axtj @ {addr}") or []:
            src = int(x.get("from", 0))
            fn = self._function_at(src)
            out.append({"from": hex(src), "type": x.get("type"), "opcode": x.get("opcode"),
                        "in_function": ({"address": hex(fn["offset"]), "name": fn["name"]} if fn else None)})
        return out

    def callees(self, target: str) -> list:
        addr = self.resolve(target)
        fn = self._function_at(addr)
        if not fn:
            raise ToolArgError("target is not inside a recognized function")
        names = {f["offset"]: f["name"] for f in self._functions()}
        seen, out = set(), []
        for o in (self._cmdj(f"pdfj @ {fn['offset']}") or {}).get("ops", []):
            if o.get("type") in ("call", "ucall", "rcall") and o.get("jump"):
                j = int(o["jump"])
                if j not in seen:
                    seen.add(j)
                    out.append({"address": hex(j), "name": names.get(j, o.get("disasm", "").split()[-1]), "call_site": hex(o["offset"])})
        return out

    def read_bytes(self, target: str, length: int = 64) -> bytes:
        addr = self.resolve(target)
        n = clamp_int(length, 1, 4096, 64)
        hexs = self._cmd(f"p8 {n} @ {addr}").strip()
        try:
            return bytes.fromhex(hexs)
        except ValueError:
            raise ToolArgError("could not read bytes at that address") from None

    # ---- mutations (analysis database only; the sample is never modified) --------------------
    def rename_function(self, target: str, new_name: str) -> dict:
        addr = self.resolve(target)
        new = validate_new_name(new_name)
        fn = self._function_at(addr)
        if not fn:
            raise ToolArgError("target is not inside a recognized function")
        old = fn["name"]
        self._cmd(f"afn {new} @ {fn['offset']}")
        self._invalidate()
        check = self._function_at(fn["offset"])
        if not check or check["name"] != new:
            raise ToolArgError("rename was not applied (name may already be in use)")
        return {"address": hex(fn["offset"]), "old_name": old, "new_name": new}

    def add_comment(self, target: str, text: str) -> dict:
        addr = self.resolve(target)
        clean = clean_comment(text)
        self._cmd(f"CC {clean} @ {addr}")
        return {"address": hex(addr), "comment": clean}
