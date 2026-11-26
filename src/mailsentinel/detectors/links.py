"""Links and forms in the body: where would a click, or typed data, really go?

    MAIL-URL-001  Link text shows one address, the link goes to another   T1566.002
    MAIL-URL-002  Link to a bare IP address instead of a domain           T1566.002
    MAIL-URL-003  "@" in the address: everything before it is ignored     T1566.002
    MAIL-URL-004  URL shortener hides the destination                     T1566.002
    MAIL-URL-005  HTML form inside the email (worse with a password box)  T1598

Each rule produces at most one finding per message, listing a few examples, so that an
email with twenty identical links does not score twenty times.
"""
from __future__ import annotations

from urllib.parse import urlsplit

from mailsentinel.domains import org_domain, same_org
from mailsentinel.models import Finding, Form, Link, ParsedEmail, Severity
from mailsentinel.urls import hosts_in_text, ip_host

PHISHING_LINK = "T1566.002"
PHISHING_FOR_INFO = "T1598"
MAX_EXAMPLES = 5

SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "s.id", "tiny.cc", "v.gd", "shorte.st",
})


def _examples(items: list[str]) -> str:
    items = list(dict.fromkeys(items))
    shown = "; ".join(items[:MAX_EXAMPLES])
    return shown + (f" (+{len(items) - MAX_EXAMPLES} more)" if len(items) > MAX_EXAMPLES else "")


def _mismatched(links: list[Link], dmarc: str) -> list[Finding]:
    bad = []
    for link in links:
        if link.source != "html-link" or not link.host or not link.text:
            continue
        claimed = hosts_in_text(link.text)
        if claimed and not any(same_org(c, link.host) for c in claimed):
            bad.append(f"{link.text} -> {link.url}")
    if not bad:
        return []
    details = {"links": _examples(bad)}
    if dmarc == "pass":
        # Authenticated senders (newsletters) often route links through a click-tracking domain.
        details["note"] = "sender passed DMARC; may be click tracking"
        return [Finding("MAIL-URL-001", "Link text shows a different address than the real destination",
                        Severity.LOW, 10, PHISHING_LINK, details)]
    return [Finding("MAIL-URL-001", "Link text shows a different address than the real destination",
                    Severity.HIGH, 30, PHISHING_LINK, details)]


def _ip_links(links: list[Link]) -> list[Finding]:
    bad = [link.url for link in links if link.host and ip_host(link.host)]
    if not bad:
        return []
    return [Finding("MAIL-URL-002", "Link points to a bare IP address instead of a domain",
                    Severity.HIGH, 25, PHISHING_LINK, {"urls": _examples(bad)})]


def _userinfo(links: list[Link]) -> list[Finding]:
    # "https://login.example.com@203.0.113.9/" opens 203.0.113.9: the part before "@" is a user name.
    bad = []
    for link in links:
        try:
            if urlsplit(link.url).username is not None:
                bad.append(link.url)
        except ValueError:
            continue
    if not bad:
        return []
    return [Finding("MAIL-URL-003", "Link hides its real host behind an '@' (user-info trick)",
                    Severity.HIGH, 25, PHISHING_LINK, {"urls": _examples(bad)})]


def _shorteners(links: list[Link]) -> list[Finding]:
    bad = [link.url for link in links if link.host in SHORTENERS or org_domain(link.host) in SHORTENERS]
    if not bad:
        return []
    return [Finding("MAIL-URL-004", "URL shortener hides the real destination",
                    Severity.LOW, 10, PHISHING_LINK, {"urls": _examples(bad)})]


def _forms(forms: list[Form]) -> list[Finding]:
    if not forms:
        return []
    actions = _examples([f.action or "(no action)" for f in forms])
    if any(f.has_password for f in forms):
        return [Finding("MAIL-URL-005", "HTML form asking for a password inside the email",
                        Severity.HIGH, 35, PHISHING_FOR_INFO, {"form_action": actions})]
    return [Finding("MAIL-URL-005", "HTML form inside the email sends typed data elsewhere",
                    Severity.MEDIUM, 15, PHISHING_FOR_INFO, {"form_action": actions})]


def detect(email: ParsedEmail) -> list[Finding]:
    links, forms = email.links, email.forms
    return (
        _mismatched(links, email.auth.dmarc)
        + _ip_links(links)
        + _userinfo(links)
        + _shorteners(links)
        + _forms(forms)
    )
