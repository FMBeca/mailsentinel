"""Spot domains made to look like another one.

    paypa1.example        a character swapped for a similar one ("1" for "l")
    examp1e.com           the same, against the recipient's own domain
    micros0ft-login.net   brand name inside an unrelated domain ("combosquatting")
    xn--pypal-4ve.com     punycode for "pаypal.com" with a Cyrillic "а" (homoglyph)
    arnazon.com           "rn" reads as "m"
    paypall.com           one character added (typosquatting)

Domains are compared by their registrable label ("example" in "mail.example.co.uk"):
attackers control everything left of it, so subdomains prove nothing.
"""
from __future__ import annotations

import contextlib
import unicodedata
from dataclasses import dataclass

from mailsentinel.domains import org_domain, same_org

# Characters that look alike in most fonts, mapped to the ASCII letter they imitate.
_CONFUSABLES = str.maketrans({
    "0": "o", "1": "l",
    # Cyrillic
    "а": "a", "в": "b", "е": "e", "ё": "e", "һ": "h", "і": "i", "ї": "i", "ј": "j", "к": "k",
    "ӏ": "l", "м": "m", "н": "h", "о": "o", "р": "p", "с": "c", "ѕ": "s", "т": "t", "у": "y",
    "х": "x", "ԁ": "d", "ԛ": "q", "ԝ": "w", "ь": "b",
    # Greek
    "α": "a", "β": "b", "ε": "e", "η": "n", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p",
    "τ": "t", "υ": "u", "χ": "x", "ω": "w",
    # Latin look-alikes
    "ı": "i", "ɩ": "i", "ɡ": "g", "ɑ": "a", "ʟ": "l",
})
_SEQUENCES = (("rn", "m"), ("vv", "w"))

# Brand labels too generic to look for inside other domains.
_GENERIC = frozenset({"office", "outlook", "online", "live", "meta"})


@dataclass(frozen=True)
class Reference:
    domain: str                  # a domain the message may be imitating
    owner: str                   # "PayPal", "the recipient's domain"...
    any_tld: bool = False        # owner.<any TLD> is legitimate
    combo: bool = True           # also look for the name inside other domains (brands, not recipients)


@dataclass(frozen=True)
class Match:
    domain: str                  # the suspicious domain, as written
    unicode: str                 # its Unicode form if it uses punycode, else ""
    kind: str                    # "lookalike", "combosquat" or "mixed-script"
    reference: str               # the domain it imitates ("" for mixed-script without a target)
    owner: str
    reason: str


def to_unicode(domain: str) -> str:
    """Decode punycode labels ("xn--...") so that their real characters can be compared."""
    labels = []
    for label in domain.lower().split("."):
        if label.startswith("xn--"):
            with contextlib.suppress(UnicodeError, ValueError):   # invalid punycode: keep it as written
                label = label[4:].encode("ascii").decode("punycode")
        labels.append(label)
    return ".".join(labels)


def scripts(text: str) -> set[str]:
    """Writing systems used by the letters of a string ("LATIN", "CYRILLIC", "GREEK"...)."""
    found = set()
    for ch in text:
        if ch.isascii():
            if ch.isalpha():
                found.add("LATIN")
            continue
        if not ch.isalpha():
            continue
        try:
            found.add(unicodedata.name(ch).split()[0])
        except ValueError:
            continue
    return found


def skeleton(label: str) -> str:
    """What a label looks like on screen: confusable characters folded to plain ASCII."""
    s = unicodedata.normalize("NFKC", label.lower()).translate(_CONFUSABLES)
    for seq, repl in _SEQUENCES:
        s = s.replace(seq, repl)
    return s


def distance(a: str, b: str) -> int:
    """Edit distance counting insertions, deletions, substitutions and swaps of neighbours."""
    if a == b:
        return 0
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
            if i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        prev2, prev = prev, cur
    return prev[-1]


def _label(domain: str) -> str:
    return org_domain(domain).split(".")[0]


def _max_distance(label: str) -> int:
    # Short names have too many innocent neighbours ("apple"/"apply", "gmail"/"email"): only
    # longer ones are compared by distance. Look-alike characters ("app1e") are still caught.
    if len(label) < 6:
        return 0
    return 1 if len(label) < 9 else 2


def _owned(domain: str, ref: Reference) -> bool:
    if same_org(domain, ref.domain):
        return True
    return ref.any_tld and _label(domain) == _label(ref.domain)


def check(domain: str, references: list[Reference]) -> Match | None:
    """Return how `domain` imitates one of the references, or None."""
    if not domain or "." not in domain or any(_owned(domain, r) for r in references):
        return None
    uni = to_unicode(domain)
    shown_uni = uni if uni != domain.lower() else ""
    label = _label(uni)
    mixed = len(scripts(label)) > 1

    for ref in references:
        ref_label = _label(ref.domain)
        if label == ref_label:
            continue                  # same name under another TLD: too common to call (example.com/.org)
        if skeleton(label) == skeleton(ref_label):
            why = "mixed alphabets: " + " + ".join(sorted(scripts(label))) if mixed else "look-alike characters"
            return Match(domain, shown_uni, "lookalike", ref.domain, ref.owner, why)
        limit = _max_distance(ref_label)
        if limit:
            d = distance(skeleton(label), skeleton(ref_label))
            if 0 < d <= limit:
                return Match(domain, shown_uni, "lookalike", ref.domain, ref.owner,
                             f"{d} character{'s' if d > 1 else ''} different")

    if mixed:
        return Match(domain, shown_uni, "mixed-script", "", "",
                     "mixed alphabets: " + " + ".join(sorted(scripts(label))))

    tokens = set(uni.replace("-", ".").split("."))
    for ref in references:
        ref_label = _label(ref.domain)
        if not ref.combo or label == ref_label or len(ref_label) < 5 or ref_label in _GENERIC:
            continue
        if ref_label in tokens or ref.domain in uni:
            return Match(domain, shown_uni, "combosquat", ref.domain, ref.owner,
                         f"contains '{ref_label}' but does not belong to {ref.owner}")
    return None
