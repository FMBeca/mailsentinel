"""Sender authentication: SPF, DKIM and DMARC results reported by the receiving server.

    MAIL-AUTH-001  SPF fail / softfail     the sending server is not allowed to send for that domain
    MAIL-AUTH-002  DKIM fail                the signature is broken or the content was changed
    MAIL-AUTH-003  DMARC fail               the From domain could not be authenticated (spoofing)

All map to T1566 (Phishing): forging the sender is how a phishing email gets delivered
under someone else's name. A message without any results gets no finding: plenty of
mail is saved without those headers, and missing evidence is not evidence of phishing.
"""
from __future__ import annotations

from mailsentinel.models import Finding, ParsedEmail, Severity

PHISHING = "T1566"


def detect(email: ParsedEmail) -> list[Finding]:
    a = email.auth
    findings: list[Finding] = []

    if a.spf in ("fail", "softfail"):
        hard = a.spf == "fail"
        findings.append(Finding(
            rule_id="MAIL-AUTH-001",
            title="SPF failed: server not authorised to send for the envelope domain" if hard
            else "SPF soft fail: server probably not authorised for the envelope domain",
            severity=Severity.HIGH if hard else Severity.LOW,
            score=25 if hard else 10,
            mitre_technique=PHISHING,
            details={"spf": a.spf, "envelope_domain": a.spf_domain or email.return_path_domain},
        ))

    if a.dkim in ("fail", "permerror"):
        findings.append(Finding(
            rule_id="MAIL-AUTH-002",
            title="DKIM signature failed: content changed or signature forged",
            # Mailing lists and forwarding break signatures too, hence medium.
            severity=Severity.MEDIUM,
            score=15,
            mitre_technique=PHISHING,
            details={"dkim": a.dkim, "signing_domains": ", ".join(a.dkim_domains)},
        ))

    if a.dmarc in ("fail", "permerror"):
        findings.append(Finding(
            rule_id="MAIL-AUTH-003",
            title="DMARC failed: the From domain could not be authenticated (possible spoofing)",
            severity=Severity.HIGH,
            score=30,
            mitre_technique=PHISHING,
            details={"dmarc": a.dmarc, "from_domain": a.dmarc_domain or (email.from_.domain if email.from_ else "")},
        ))

    return findings
