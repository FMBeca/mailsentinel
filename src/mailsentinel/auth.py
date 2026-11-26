"""Read SPF / DKIM / DMARC results from Authentication-Results and Received-SPF.

Authentication-Results (RFC 8601) is written by the receiving server, for example:

    Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=example.org;
        dkim=pass header.d=example.org header.s=s1; dmarc=pass (p=reject) header.from=example.org

Microsoft 365 omits the leading server name ("authserv-id") and starts directly with
"spf=...". Only the topmost header is trusted: it was added by the last server, the one
that received the message for the user. Headers further down were added earlier, and a
sender can write anything there, including a fake "spf=pass".
"""
from __future__ import annotations

import re
from dataclasses import replace

from mailsentinel.models import AuthResults

_COMMENT = re.compile(r"\([^()]*\)")
_METHOD = re.compile(r"^\s*([A-Za-z][\w.-]*)\s*=\s*([A-Za-z]+)")
_PROPERTY = re.compile(r"\b([a-z]+\.[a-z-]+)\s*=\s*([^\s;]+)", re.IGNORECASE)

_KNOWN = {"pass", "fail", "softfail", "neutral", "none", "temperror", "permerror", "policy", "bestguesspass"}


def _strip_comments(value: str) -> str:
    # Comments may nest; remove the innermost ones until none are left.
    previous = None
    while previous != value:
        previous, value = value, _COMMENT.sub(" ", value)
    return value


def _clean_domain(value: str) -> str:
    value = value.strip().strip('"').lower()
    value = value.rpartition("@")[2]            # smtp.mailfrom may be a full address, header.i is "@domain"
    return value.rstrip(".")


def parse_authentication_results(header: str) -> AuthResults:
    """Parse one Authentication-Results header value."""
    segments = _strip_comments(header).split(";")
    # The first segment is the authserv-id ("mx.example.com"), unless it already holds a result.
    if segments and not _METHOD.match(segments[0]):
        segments = segments[1:]

    spf = dkim = dmarc = "none"
    spf_domain = dmarc_domain = ""
    dkim_results: list[tuple[str, str]] = []
    for segment in segments:
        m = _METHOD.match(segment)
        if not m:
            continue
        method, result = m.group(1).lower(), m.group(2).lower()
        if result not in _KNOWN:
            continue
        props = {k.lower(): _clean_domain(v) for k, v in _PROPERTY.findall(segment[m.end():])}
        if method == "spf" and spf == "none":
            spf = result
            spf_domain = props.get("smtp.mailfrom") or props.get("smtp.helo", "")
        elif method == "dkim":
            dkim_results.append((result, props.get("header.d") or props.get("header.i", "")))
        elif method == "dmarc" and dmarc == "none":
            dmarc, dmarc_domain = result, props.get("header.from", "")

    if dkim_results:
        # A message can carry several signatures; one valid signature is enough for DKIM to pass.
        results = [r for r, _ in dkim_results]
        dkim = "pass" if "pass" in results else results[0]

    return AuthResults(
        spf=spf, dkim=dkim, dmarc=dmarc,
        spf_domain=spf_domain,
        dkim_domains=tuple(d for _, d in dkim_results if d),
        dmarc_domain=dmarc_domain,
        source="Authentication-Results",
    )


def parse_received_spf(header: str) -> str:
    """Return the result word of a Received-SPF header ("pass", "fail"...), or "none"."""
    word = header.strip().split(None, 1)[0].lower() if header.strip() else ""
    return word if word in _KNOWN else "none"


def from_headers(auth_results: list[str], received_spf: list[str]) -> AuthResults:
    """Combine the message's authentication headers, trusting only the topmost of each."""
    if auth_results:
        result = parse_authentication_results(auth_results[0])
        if result.spf == "none" and received_spf:
            spf = parse_received_spf(received_spf[0])
            if spf != "none":
                return replace(result, spf=spf)
        return result
    if received_spf:
        spf = parse_received_spf(received_spf[0])
        return AuthResults(spf=spf, source="Received-SPF")
    return AuthResults()
