"""Indicator extraction and defanging."""
from __future__ import annotations

import re

_URL = re.compile(r"\bhttps?://[^\s'\"<>\\\x00-\x1f]{4,200}", re.I)
_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b")
_DOMAIN = re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+(?:[A-Za-z]{2,24})\b")
_REGKEY = re.compile(r"\b(?:HKEY_[A-Z_]+|HKLM|HKCU)\\[^\s'\"]{3,200}", re.I)
_FILE_EXT_NOISE = {"exe", "dll", "sys", "txt", "log", "dat", "tmp", "bin", "c", "h", "so", "py", "o", "php", "asp", "aspx", "jsp",
                   "html", "htm", "js", "json", "xml", "cgi", "ini", "cfg", "conf", "lnk", "bat", "ps1", "vbs", "zip", "rar", "png", "jpg"}


def extract_iocs(text: str) -> list[dict]:
    """Return [{'type', 'value'}] found in free text (deduplicated, stable order)."""
    found: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str) -> None:
        key = (kind, value.lower())
        if key not in seen:
            seen.add(key)
            found.append({"type": kind, "value": value})

    url_spans = []
    for m in _URL.finditer(text):
        url = m.group().rstrip(".,;)")
        url_spans.append((m.start(), m.end()))
        add("url", url)
        host = re.sub(r"^https?://", "", url, flags=re.I).split("/")[0].split(":")[0]
        if host and not re.fullmatch(r"[\d.]+", host):
            add("domain", host)
    for m in _EMAIL.finditer(text):
        add("email", m.group())
    for m in _IPV4.finditer(text):
        add("ip", m.group())
    for m in _REGKEY.finditer(text):
        add("registry_key", m.group())
    for m in _DOMAIN.finditer(text):
        if any(lo <= m.start() < hi for lo, hi in url_spans):      # hosts were added above; paths are not domains
            continue
        d = m.group().lower()
        tld = d.rsplit(".", 1)[-1]
        if tld in _FILE_EXT_NOISE or re.fullmatch(r"[\d.]+", d):
            continue
        add("domain", m.group())
    return found


def defang(value: str) -> str:
    return (value.replace("http://", "hxxp://").replace("https://", "hxxps://")
            .replace(".", "[.]").replace("@", "[@]"))
