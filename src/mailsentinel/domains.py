"""Domain helpers: comparing domains the way a person reading the From line would."""
from __future__ import annotations

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
