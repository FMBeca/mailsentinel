"""Sender consistency: does the From line tell the truth about who sent the message?

    MAIL-SND-001  Reply-To points to another organisation          replies go to the attacker
    MAIL-SND-002  Return-Path from another organisation, no DMARC  envelope and From disagree
    MAIL-SND-003  Display name holds a different address/domain    "support@bank.example" <x@other.example>
    MAIL-SND-004  Display name claims a brand the address isn't    "PayPal" <alerts@other.example>

Domains are compared by organisation, so "news.example.com" and "example.com" match.
"""
from __future__ import annotations

import re

from mailsentinel.brands import BRANDS, Brand, mentioned
from mailsentinel.domains import find_domains, org_domain, same_org
from mailsentinel.models import Finding, ParsedEmail, Severity

PHISHING = "T1566"
IMPERSONATION = "T1656"

_EMAIL_IN_NAME = re.compile(r"[\w.+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")


def _reply_to(email: ParsedEmail, from_domain: str) -> list[Finding]:
    others = [a for a in email.reply_to if not same_org(a.domain, from_domain)]
    if not others:
        return []
    return [Finding(
        rule_id="MAIL-SND-001",
        title="Reply-To points to a different organisation than From",
        severity=Severity.MEDIUM,
        score=20,
        mitre_technique=PHISHING,
        details={"from": email.from_.address, "reply_to": ", ".join(a.address for a in others)},
    )]


def _return_path(email: ParsedEmail, from_domain: str) -> list[Finding]:
    rp = email.return_path_domain
    # Newsletters and ticketing tools legitimately bounce to their provider's domain; DMARC
    # alignment is how the receiving server confirms that is fine, so trust a DMARC pass.
    if not rp or same_org(rp, from_domain) or email.auth.dmarc == "pass":
        return []
    return [Finding(
        rule_id="MAIL-SND-002",
        title="Return-Path (envelope sender) belongs to a different organisation than From",
        severity=Severity.LOW,
        score=10,
        mitre_technique=PHISHING,
        details={"from": email.from_.address, "return_path": email.return_path, "dmarc": email.auth.dmarc},
    )]


def _display_name(email: ParsedEmail, from_domain: str, brands: tuple[Brand, ...]) -> list[Finding]:
    name = email.from_.display_name
    if not name:
        return []

    claimed = [m.group(1) for m in _EMAIL_IN_NAME.finditer(name)]
    claimed += find_domains(_EMAIL_IN_NAME.sub(" ", name))
    foreign = sorted({org_domain(d) for d in claimed if not same_org(d, from_domain)})
    if foreign:
        return [Finding(
            rule_id="MAIL-SND-003",
            title="Display name shows an address or domain different from the real sender",
            severity=Severity.HIGH,
            score=30,
            mitre_technique=IMPERSONATION,
            details={"display_name": name, "claimed_domain": ", ".join(foreign), "from": email.from_.address},
        )]

    impersonated = [b.name for b in mentioned(name, brands) if not b.owns(from_domain)]
    if impersonated:
        return [Finding(
            rule_id="MAIL-SND-004",
            title="Display name claims a brand that does not match the sending domain",
            severity=Severity.MEDIUM,
            score=20,
            mitre_technique=IMPERSONATION,
            details={"display_name": name, "brand": ", ".join(impersonated), "from": email.from_.address},
        )]
    return []


def detect(email: ParsedEmail, brands: tuple[Brand, ...] = BRANDS) -> list[Finding]:
    if email.from_ is None:
        return []
    from_domain = email.from_.domain
    return (
        _reply_to(email, from_domain)
        + _return_path(email, from_domain)
        + _display_name(email, from_domain, brands)
    )
