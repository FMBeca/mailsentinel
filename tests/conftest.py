"""Helpers to build small synthetic messages for the tests (documentation domains and IPs only)."""
from __future__ import annotations

from pathlib import Path

import pytest

from mailsentinel.parser import parse_bytes

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def make_eml(headers: dict[str, str] | list[tuple[str, str]], body: str = "Hello.\n",
             content_type: str = 'text/plain; charset="utf-8"') -> bytes:
    items = headers.items() if isinstance(headers, dict) else headers
    lines = [f"{k}: {v}" for k, v in items]
    names = {k.lower() for k, _ in items}
    if "content-type" not in names:
        lines += ["MIME-Version: 1.0", f"Content-Type: {content_type}"]
    return ("\r\n".join(lines) + "\r\n\r\n" + body).encode("utf-8")


def email_from(headers, body: str = "Hello.\n", **kw):
    return parse_bytes(make_eml(headers, body, **kw))


@pytest.fixture
def samples() -> Path:
    return SAMPLES
