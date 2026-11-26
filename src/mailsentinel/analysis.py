"""Run every detector on a message and turn the findings into a verdict."""
from __future__ import annotations

from dataclasses import dataclass, field

from mailsentinel.defang import defang, defang_ip
from mailsentinel.detectors import authentication, links, sender
from mailsentinel.models import Finding, ParsedEmail, Verdict

# The score is the sum of the findings' points, capped at 100. These thresholds mean:
# one strong signal (e.g. DMARC fail) makes a message suspicious; two strong signals, or
# one strong plus some weaker ones, make it likely phishing.
SUSPICIOUS_AT = 20
PHISHING_AT = 50
MAX_SCORE = 100


def verdict_for(score: int) -> Verdict:
    if score >= PHISHING_AT:
        return Verdict.PHISHING
    if score >= SUSPICIOUS_AT:
        return Verdict.SUSPICIOUS
    return Verdict.CLEAN


@dataclass
class Analysis:
    email: ParsedEmail
    findings: list[Finding] = field(default_factory=list)

    @property
    def score(self) -> int:
        return min(MAX_SCORE, sum(f.score for f in self.findings))

    @property
    def verdict(self) -> Verdict:
        return verdict_for(self.score)

    def received_ips(self) -> list[str]:
        """Relay IPs from the Received chain, oldest hop (closest to the sender) first."""
        seen: list[str] = []
        for hop in reversed(self.email.hops):
            if hop.ip and hop.ip not in seen:
                seen.append(hop.ip)
        return seen

    def sender_domains(self) -> list[str]:
        e = self.email
        domains = [e.from_.domain] if e.from_ else []
        domains += [a.domain for a in e.reply_to]
        if e.return_path_domain:
            domains.append(e.return_path_domain)
        return list(dict.fromkeys(d for d in domains if d))

    def urls(self) -> list[dict[str, str]]:
        """Each distinct URL once, with where it was found and the link text it was shown with."""
        seen: dict[str, dict[str, str]] = {}
        for link in self.email.links:
            entry = seen.setdefault(link.url, {"url": link.url, "host": link.host, "source": link.source, "text": ""})
            if link.text and not entry["text"]:
                entry["text"] = link.text
        return list(seen.values())

    def url_domains(self) -> list[str]:
        return list(dict.fromkeys(u["host"] for u in self.urls() if u["host"]))

    def to_dict(self, safe: bool = True) -> dict:
        """JSON-ready dict. With safe=True every IOC is defanged."""
        e = self.email
        fang = defang if safe else (lambda s: s)
        ip = defang_ip if safe else (lambda s: s)
        return {
            "verdict": self.verdict.value,
            "score": self.score,
            "defanged": safe,
            "headers": {
                "subject": e.subject,
                "from": fang(str(e.from_)) if e.from_ else "",
                "reply_to": [fang(str(a)) for a in e.reply_to],
                "return_path": fang(e.return_path),
                "date": e.date,
                "message_id": e.message_id,
            },
            "authentication": {
                "spf": e.auth.spf,
                "dkim": e.auth.dkim,
                "dmarc": e.auth.dmarc,
                "source": e.auth.source or "absent",
            },
            "findings": [
                {**f.to_dict(), "details": {k: fang(v) for k, v in f.details.items()}}
                for f in sorted(self.findings, key=lambda f: f.score, reverse=True)
            ],
            "iocs": {
                "received_ips": [ip(x) for x in self.received_ips()],
                "sender_domains": [fang(d) for d in self.sender_domains()],
                "url_domains": [fang(d) for d in self.url_domains()],
                "urls": [{k: fang(v) for k, v in u.items()} for u in self.urls()],
            },
            "defects": list(e.defects),
        }


def analyze(email: ParsedEmail) -> Analysis:
    findings = authentication.detect(email) + sender.detect(email) + links.detect(email)
    return Analysis(email=email, findings=findings)
