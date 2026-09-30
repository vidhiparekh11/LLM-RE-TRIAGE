#!/usr/bin/env python3
"""Pre-publish hygiene check: no secrets, no binaries/archives, no oversized files. Exit 1 on any problem."""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", "build", "dist", ".venv", "node_modules"}
MAGIC = {b"MZ": "PE/DOS executable", b"\x7fELF": "ELF binary", b"PK\x03\x04": "zip archive", b"\xca\xfe\xba\xbe": "Mach-O/Java class",
         b"\xcf\xfa\xed\xfe": "Mach-O binary", b"\xfe\xed\xfa\xcf": "Mach-O binary", b"7z\xbc\xaf": "7z archive", b"Rar!": "rar archive"}
SECRETS = {
    "API key (sk-...)": re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}"),
    "AWS access key id": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"),
    "Slack token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),
    "private key block": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "presigned URL token": re.compile(r"X-Amz-(?:Security-Token|Credential)="),
    "hardcoded credential": re.compile(r"(?i)\b(?:password|passwd|api[_-]?key|secret)\s*=\s*['\"][^'\"\s]{8,}['\"]"),
}
MAX_BYTES = 2_000_000


def main() -> int:
    problems = []
    for base, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.endswith(".egg-info")]
        for f in files:
            path = os.path.join(base, f)
            rel = os.path.relpath(path, ROOT).replace(os.sep, "/")
            if rel == "scripts/check_public.py":
                continue
            if os.path.getsize(path) > MAX_BYTES:
                problems.append(f"{rel}: larger than {MAX_BYTES // 1_000_000} MB")
            with open(path, "rb") as fh:
                head = fh.read(4)
            for magic, label in MAGIC.items():
                if head.startswith(magic):
                    problems.append(f"{rel}: looks like a {label} (binaries and samples must not be committed)")
            if f == ".env" or (f.startswith(".env.") and not f.endswith(".example")):
                problems.append(f"{rel}: environment file")
            try:
                text = open(path, encoding="utf-8").read()
            except (UnicodeDecodeError, OSError):
                continue
            for label, rx in SECRETS.items():
                m = rx.search(text)
                if m:
                    problems.append(f"{rel}: possible {label}: {m.group()[:24]!r}")
    if problems:
        print(f"FAIL: {len(problems)} problem(s)")
        for p in problems:
            print("  -", p)
        return 1
    print("OK: no secrets, binaries, archives or oversized files found")
    return 0


if __name__ == "__main__":
    sys.exit(main())
