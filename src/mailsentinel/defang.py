"""Defang indicators so they can be pasted into tickets and chats without becoming links.

    https://login.example.net/a.php  ->  hxxps[://]login[.]example[.]net/a.php
    203.0.113.5                      ->  203[.]0[.]113[.]5
    alerts@example.net               ->  alerts[@]example[.]net
"""
from __future__ import annotations

import re

# scheme, host[:port], then the rest of the URL (kept as is: "a.php" is a path, not a domain).
_URL = re.compile(r"\b([a-z][a-z0-9+.-]*)://([^/\s?#\"'<>]+)([^\s\"'<>]*)", re.IGNORECASE)
_EMAIL = re.compile(r"\b([\w.+-]+)@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)\b")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN = re.compile(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}\b")
_SCHEMES = {"http": "hxxp", "https": "hxxps", "ftp": "fxp"}


def _dots(text: str) -> str:
    return text.replace(".", "[.]")


def _url(m: re.Match) -> str:
    scheme = _SCHEMES.get(m.group(1).lower(), m.group(1))
    return f"{scheme}[://]{_dots(m.group(2))}{m.group(3)}"


def defang(text: str) -> str:
    """Defang every URL, email address, IPv4 address and domain found in text."""
    if not text:
        return text
    # Placeholders protect what was already defanged from the later, broader patterns.
    parts: list[str] = []

    def keep(value: str) -> str:
        parts.append(value)
        return f"\x00{len(parts) - 1}\x00"

    text = _URL.sub(lambda m: keep(_url(m)), text)
    text = _EMAIL.sub(lambda m: keep(f"{m.group(1)}[@]{_dots(m.group(2))}"), text)
    text = _IPV4.sub(lambda m: keep(_dots(m.group(0))), text)
    text = _DOMAIN.sub(lambda m: keep(_dots(m.group(0))), text)
    return re.sub(r"\x00(\d+)\x00", lambda m: parts[int(m.group(1))], text)


def defang_ip(ip: str) -> str:
    return ip.replace(".", "[.]").replace(":", "[:]")
