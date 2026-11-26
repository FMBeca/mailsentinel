"""Core data models shared by the parser, the detectors and the CLI."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Verdict(str, Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    PHISHING = "phishing"


@dataclass(frozen=True)
class Address:
    """One mailbox from a header such as From or Reply-To."""

    display_name: str
    address: str                 # "user@example.com", lowercased domain
    domain: str                  # "example.com", lowercased, no trailing dot

    def __str__(self) -> str:
        return f'"{self.display_name}" <{self.address}>' if self.display_name else f"<{self.address}>"


@dataclass(frozen=True)
class AuthResults:
    """SPF / DKIM / DMARC results as reported by the receiving mail server.

    MailSentinel does not re-check signatures or DNS: it reads what the receiving
    server wrote in Authentication-Results (or Received-SPF). "none" means the
    message carries no result for that mechanism.
    """

    spf: str = "none"
    dkim: str = "none"
    dmarc: str = "none"
    spf_domain: str = ""         # smtp.mailfrom
    dkim_domains: tuple[str, ...] = ()   # header.d of each DKIM result
    dmarc_domain: str = ""       # header.from
    source: str = ""             # "Authentication-Results", "Received-SPF" or "" if absent

    @property
    def present(self) -> bool:
        return bool(self.source)


@dataclass(frozen=True)
class Hop:
    """One Received header: a server that relayed the message."""

    from_host: str
    by_host: str
    ip: str                      # address in brackets after the "from" host, "" if none
    raw: str = ""


@dataclass(frozen=True)
class Link:
    """A URL found in the message body."""

    url: str
    host: str                    # lowercased hostname, "" if it cannot be parsed
    source: str                  # "text", "html-text", "html-link", "html-form"
    text: str = ""               # visible text of an HTML link


@dataclass(frozen=True)
class Form:
    """An HTML form inside the message: data typed into it goes to `action`."""

    action: str
    host: str
    has_password: bool


@dataclass
class ParsedEmail:
    """The parts of a message the detectors look at."""

    subject: str = ""
    date: str = ""
    message_id: str = ""
    from_: Address | None = None
    reply_to: list[Address] = field(default_factory=list)
    return_path: str = ""        # envelope sender, without angle brackets
    auth: AuthResults = field(default_factory=AuthResults)
    hops: list[Hop] = field(default_factory=list)   # topmost (latest) first, as in the message
    text_body: str = ""
    html_body: str = ""
    links: list[Link] = field(default_factory=list)
    forms: list[Form] = field(default_factory=list)
    defects: list[str] = field(default_factory=list)  # parsing problems worth reporting

    @property
    def return_path_domain(self) -> str:
        return self.return_path.rpartition("@")[2].lower().rstrip(".") if "@" in self.return_path else ""


@dataclass
class Finding:
    """One reason why a message looks suspicious."""

    rule_id: str
    title: str
    severity: Severity
    score: int                   # points added to the message's risk score
    mitre_technique: str
    details: dict[str, str] = field(default_factory=dict)  # evidence; values may hold IOCs

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "score": self.score,
            "mitre_technique": self.mitre_technique,
            "details": dict(self.details),
        }
