"""Domain helpers: comparing domains the way a person reading the From line would."""
from __future__ import annotations

import re

# Domains written in free text (a display name, the visible text of a link). Only common TLDs,
# so that "Support.Team", "J.Smith" or a file name like "invoice.pdf" are not taken for domains.
_DOMAIN_IN_TEXT = re.compile(
    r"(?<![\w@.-])((?:[A-Za-z0-9-]+\.)+(?:com|net|org|info|biz|io|co|me|app|online|site|xyz|top|"
    r"pt|br|es|uk|de|fr|it|nl|eu|us|gov|edu|example|test|invalid))(?![\w-])",
    re.IGNORECASE,
)

# Second-level labels under which organisations register their names, e.g. "bank.co.uk".
# A full Public Suffix List would be more precise; this short list keeps the tool
# dependency-free and covers the common cases. Unknown suffixes fall back to the last two labels.
_MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "me.uk",
    "com.pt", "org.pt", "gov.pt", "edu.pt",
    "com.br", "net.br", "org.br", "gov.br",
    "com.au", "net.au", "org.au", "co.nz", "co.jp", "ne.jp", "co.za", "co.in",
    "com.mx", "com.ar", "com.tr", "com.cn", "com.hk", "com.sg", "co.kr",
}


def normalise(domain: str) -> str:
    return domain.strip().strip(".").lower()


def org_domain(domain: str) -> str:
    """The registrable part of a domain: "mail.example.co.uk" -> "example.co.uk"."""
    labels = normalise(domain).split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in _MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def same_org(a: str, b: str) -> bool:
    """True when both domains belong to the same organisation (subdomains included)."""
    return bool(a and b) and org_domain(a) == org_domain(b)


def find_domains(text: str) -> list[str]:
    """Domain-looking words in free text, lowercased, in order of appearance."""
    return [normalise(m.group(1)) for m in _DOMAIN_IN_TEXT.finditer(text)]
