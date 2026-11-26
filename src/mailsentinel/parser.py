"""Turn a raw .eml file into a ParsedEmail, using only the standard library."""
from __future__ import annotations

import ipaddress
import re
from email import policy
from email.errors import HeaderParseError
from email.header import decode_header, make_header
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses

from mailsentinel import auth, files, urls
from mailsentinel.models import Address, Attachment, Hop, ParsedEmail

# Headers that almost every real message has. A file with none of them is not an email
# (or not one we understand): saying "clean" about it would be a silent false negative.
_EXPECTED = ("from", "to", "subject", "date", "received", "message-id", "return-path")

# Outlook's .msg format is a binary OLE2 container, not RFC 5322 text.
_OLE2_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

_RECEIVED_FROM = re.compile(r"\bfrom\s+(\S+)", re.IGNORECASE)
_RECEIVED_BY = re.compile(r"\bby\s+(\S+)", re.IGNORECASE)
# "from host (host [203.0.113.5])" in most MTAs; "from host (203.0.113.5)" in Microsoft 365.
_COMMENT = re.compile(r"\(([^()]*)\)")
_BRACKETED = re.compile(r"\[(?:IPv6:)?([0-9A-Fa-f:.]+)\]|\(([0-9A-Fa-f:.]+)\)", re.IGNORECASE)


class NotAnEmailError(ValueError):
    """The input does not look like an RFC 5322 message."""


def _address(name: str, addr: str) -> Address | None:
    addr = addr.strip()
    if "@" not in addr:
        return None
    local, _, domain = addr.rpartition("@")
    domain = domain.lower().rstrip(".")
    return Address(display_name=name.strip(), address=f"{local}@{domain}", domain=domain)


def _raw_all(msg: EmailMessage, name: str) -> list[str]:
    """Header values exactly as written (unfolded), before the policy's structured parsing."""
    wanted = name.lower()
    # Raw 8-bit bytes (UTF-8 headers, RFC 6532) arrive as surrogate escapes: turn them back into text.
    return [" ".join(str(v).encode("utf-8", "surrogateescape").decode("utf-8", "replace").split())
            for k, v in msg.raw_items() if k.lower() == wanted]


def _decode_words(text: str) -> str:
    """Decode RFC 2047 encoded words ("=?utf-8?q?Servi=C3=A7o?=")."""
    try:
        return str(make_header(decode_header(text)))
    except (LookupError, UnicodeError, ValueError, HeaderParseError):
        return text


def _addresses(msg: EmailMessage, name: str) -> list[Address]:
    # The structured header objects drop the address of a malformed header and keep only
    # the display name ('"Alice" <a@example.com.>' becomes 'Alice'). Malformed headers are
    # common in phishing, so parse the raw text instead.
    values = _raw_all(msg, name)
    if not values:
        return []
    found = [_address(_decode_words(n), a) for n, a in getaddresses(values)]
    return [a for a in found if a is not None]


def _valid_ip(text: str) -> str:
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return ""


def _hop(raw: str) -> Hop:
    flat = " ".join(raw.split())
    from_part, _, rest = flat.partition(" by ")
    from_m = _RECEIVED_FROM.search(from_part)
    by_m = _RECEIVED_BY.search(" by " + rest) if rest else None
    # "from [192.0.2.9] (unknown [203.0.113.7])": the first brackets hold what the sender
    # *claimed* (HELO); the comment holds the address the receiving server actually saw.
    ip = ""
    candidates = [c for comment in _COMMENT.findall(from_part) for c in _BRACKETED.findall(f"({comment})")]
    candidates += _BRACKETED.findall(from_part)
    for in_brackets, in_parens in candidates:
        ip = _valid_ip(in_brackets or in_parens)
        if ip:
            break
    return Hop(
        from_host=from_m.group(1).strip("()[]").lower() if from_m else "",
        by_host=by_m.group(1).strip("()[];").lower() if by_m else "",
        ip=ip,
        raw=flat,
    )


def _text(part: EmailMessage) -> str:
    try:
        return part.get_content()
    except (LookupError, UnicodeError, AssertionError):
        # Unknown or wrong charset: decode the bytes ourselves rather than lose the body.
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", errors="replace")


def _filename(part: EmailMessage) -> str:
    try:
        return part.get_filename() or ""
    except (LookupError, UnicodeError, ValueError):
        return ""


def _attachment(part: EmailMessage, filename: str) -> Attachment:
    try:
        data = part.get_payload(decode=True) or b""
    except (ValueError, TypeError):
        data = b""
    return files.inspect(filename, part.get_content_type(), data, inline=part.get_content_disposition() == "inline")


def _parts(msg: EmailMessage) -> tuple[str, str, list[Attachment]]:
    """Text bodies, HTML bodies and attachments (any part with a filename or marked as attachment)."""
    text: list[str] = []
    html: list[str] = []
    attachments: list[Attachment] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = _filename(part)
        if filename or part.get_content_disposition() == "attachment":
            attachments.append(_attachment(part, filename))
            continue
        ctype = part.get_content_type()
        if ctype == "text/plain":
            text.append(_text(part))
        elif ctype == "text/html":
            html.append(_text(part))
    return "\n".join(text), "\n".join(html), attachments


def parse_bytes(data: bytes) -> ParsedEmail:
    """Parse a raw message. Raises NotAnEmailError if it does not look like one."""
    if data.startswith(_OLE2_MAGIC):
        raise NotAnEmailError("this is an Outlook .msg file; save the message as .eml and try again")

    msg = BytesParser(policy=policy.default).parsebytes(data)
    keys = {k.lower() for k in msg}
    if not keys.intersection(_EXPECTED):
        raise NotAnEmailError("no email headers found (From, Subject, Received...): is this an .eml file?")

    senders = _addresses(msg, "From")
    raw_return_path = _raw_all(msg, "Return-Path")
    return_path = raw_return_path[0].strip().strip("<>").strip() if raw_return_path else ""
    text_body, html_body, attachments = _parts(msg)
    links, forms = urls.extract(text_body, html_body)

    defects = [type(d).__name__ for d in msg.defects]
    if len(senders) > 1:
        defects.append("MultipleFromAddresses")

    return ParsedEmail(
        subject=str(msg.get("Subject", "")),
        date=str(msg.get("Date", "")),
        message_id=str(msg.get("Message-ID", "")).strip(),
        from_=senders[0] if senders else None,
        reply_to=_addresses(msg, "Reply-To"),
        recipients=_addresses(msg, "To") + _addresses(msg, "Cc"),
        return_path=return_path,
        auth=auth.from_headers(
            [str(v) for v in msg.get_all("Authentication-Results", [])],
            [str(v) for v in msg.get_all("Received-SPF", [])],
        ),
        hops=[_hop(str(v)) for v in msg.get_all("Received", [])],
        text_body=text_body,
        html_body=html_body,
        links=links,
        forms=forms,
        attachments=attachments,
        defects=defects,
    )


def parse_file(path: str) -> ParsedEmail:
    with open(path, "rb") as fh:          # bytes: the message declares its own charsets
        return parse_bytes(fh.read())
