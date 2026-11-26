"""Look-alike domains in the sender addresses and in the links.

    MAIL-LOOK-001  Sender domain imitates a brand or the recipient's domain   High    T1656
    MAIL-LOOK-002  Link domain imitates a brand or the recipient's domain     High    T1566.002
    MAIL-LOOK-003  Brand name inside an unrelated domain (combosquatting)     Medium  T1656
    MAIL-LOOK-004  Domain mixes alphabets (e.g. Latin and Cyrillic)           High    T1656

References are the brands in brands.py plus the recipients' own domains (To and Cc): a
supplier fraud often comes from a domain one letter away from the victim's company.
"""
from __future__ import annotations

from mailsentinel.brands import BRANDS, Brand
from mailsentinel.lookalike import Match, Reference, check
from mailsentinel.models import Finding, ParsedEmail, Severity
from mailsentinel.urls import ip_host

IMPERSONATION = "T1656"
PHISHING_LINK = "T1566.002"
MAX_EXAMPLES = 5


def references(email: ParsedEmail, brands: tuple[Brand, ...] = BRANDS) -> list[Reference]:
    refs = [Reference(d, b.name, b.any_tld) for b in brands for d in b.domains]
    seen = set()
    for r in email.recipients:
        if r.domain and r.domain not in seen:
            seen.add(r.domain)
            refs.append(Reference(r.domain, "the recipient's domain", combo=False))
    return refs


def _visible(text: str) -> str:
    """Show exactly which characters are not plain ASCII: "p<U+0430>ypal.example"."""
    return "".join(ch if ch.isascii() else f"<U+{ord(ch):04X}>" for ch in text)


def _describe(m: Match) -> str:
    shown = f"{m.domain} = {_visible(m.unicode)}" if m.unicode else _visible(m.domain)
    if m.kind == "combosquat" or not m.reference:
        return f"{shown}: {m.reason}"
    return f"{shown} looks like {m.reference} [{m.owner}]: {m.reason}"


def _examples(matches: list[Match]) -> str:
    lines = list(dict.fromkeys(_describe(m) for m in matches))
    shown = "; ".join(lines[:MAX_EXAMPLES])
    return shown + (f" (+{len(lines) - MAX_EXAMPLES} more)" if len(lines) > MAX_EXAMPLES else "")


def detect(email: ParsedEmail, brands: tuple[Brand, ...] = BRANDS) -> list[Finding]:
    refs = references(email, brands)

    sender_domains = [email.from_.domain] if email.from_ else []
    sender_domains += [a.domain for a in email.reply_to]
    if email.return_path_domain:
        sender_domains.append(email.return_path_domain)
    link_domains = [link.host for link in email.links if link.host and not ip_host(link.host)]

    def matches(domains: list[str]) -> list[Match]:
        found = (check(d, refs) for d in dict.fromkeys(domains))
        return [m for m in found if m is not None]

    sender, links = matches(sender_domains), matches(link_domains)
    by_kind = {k: ([m for m in sender if m.kind == k], [m for m in links if m.kind == k])
               for k in ("lookalike", "combosquat", "mixed-script")}
    findings: list[Finding] = []

    look_sender, look_links = by_kind["lookalike"]
    if look_sender:
        findings.append(Finding("MAIL-LOOK-001", "Sender domain imitates a known brand or the recipient's domain",
                                Severity.HIGH, 35, IMPERSONATION, {"domains": _examples(look_sender)}))
    if look_links:
        findings.append(Finding("MAIL-LOOK-002", "Link domain imitates a known brand or the recipient's domain",
                                Severity.HIGH, 30, PHISHING_LINK, {"domains": _examples(look_links)}))

    combo = by_kind["combosquat"][0] + by_kind["combosquat"][1]
    if combo:
        findings.append(Finding("MAIL-LOOK-003", "Brand name used inside an unrelated domain",
                                Severity.MEDIUM, 20, IMPERSONATION, {"domains": _examples(combo)}))

    mixed = by_kind["mixed-script"][0] + by_kind["mixed-script"][1]
    if mixed:
        findings.append(Finding("MAIL-LOOK-004", "Domain mixes letters from different alphabets",
                                Severity.HIGH, 30, IMPERSONATION, {"domains": _examples(mixed)}))
    return findings
