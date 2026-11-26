"""Brands that phishing commonly impersonates, with the domains they really send from.

This list is deliberately short: it is used to spot a display name that claims to be a
brand ("PayPal Support") while the address behind it belongs to someone else. Extend it
with the brands that matter to your organisation (banks, suppliers, your own company).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from mailsentinel.domains import org_domain, same_org


@dataclass(frozen=True)
class Brand:
    name: str
    keywords: tuple[str, ...]        # matched as whole words in the display name, case-insensitive
    domains: tuple[str, ...]         # domains the brand legitimately sends from
    any_tld: bool = False            # brand.<any country TLD> is also legitimate (amazon.de, dhl.pt)

    def owns(self, domain: str) -> bool:
        if any(same_org(domain, d) for d in self.domains):
            return True
        if self.any_tld:
            label = org_domain(domain).split(".")[0]
            return label in {org_domain(d).split(".")[0] for d in self.domains}
        return False

    def mentioned_in(self, text: str) -> bool:
        return any(re.search(rf"(?<![\w-]){re.escape(k)}(?![\w-])", text, re.IGNORECASE) for k in self.keywords)


BRANDS: tuple[Brand, ...] = (
    Brand("Microsoft", ("microsoft", "microsoft 365", "office 365", "onedrive", "sharepoint"),
          ("microsoft.com", "office.com", "office365.com", "outlook.com", "microsoftonline.com",
           "sharepoint.com", "onedrive.com", "live.com", "hotmail.com")),
    Brand("Google", ("google", "gmail"), ("google.com", "gmail.com", "googlemail.com"), any_tld=True),
    Brand("Apple", ("apple", "icloud", "apple id"), ("apple.com", "icloud.com", "me.com")),
    Brand("Amazon", ("amazon", "amazon prime"), ("amazon.com", "amazonses.com"), any_tld=True),
    Brand("PayPal", ("paypal",), ("paypal.com",), any_tld=True),
    Brand("Netflix", ("netflix",), ("netflix.com",)),
    Brand("DHL", ("dhl",), ("dhl.com",), any_tld=True),
    Brand("FedEx", ("fedex",), ("fedex.com",)),
    Brand("DocuSign", ("docusign",), ("docusign.com", "docusign.net")),
    Brand("Dropbox", ("dropbox",), ("dropbox.com", "dropboxmail.com")),
    Brand("Adobe", ("adobe", "adobe sign"), ("adobe.com", "adobesign.com")),
    Brand("LinkedIn", ("linkedin",), ("linkedin.com",)),
    Brand("Meta", ("facebook", "instagram", "whatsapp", "meta"),
          ("facebook.com", "facebookmail.com", "instagram.com", "whatsapp.com", "meta.com")),
    # Portugal
    Brand("CTT", ("ctt", "ctt expresso"), ("ctt.pt",)),
    Brand("Caixa Geral de Depositos", ("cgd", "caixa geral", "caixadirecta"), ("cgd.pt",)),
    Brand("Millennium bcp", ("millennium", "millennium bcp"), ("millenniumbcp.pt",)),
    Brand("Novo Banco", ("novo banco", "novobanco"), ("novobanco.pt",)),
    Brand("Autoridade Tributaria", ("financas", "finanças", "portal das financas", "portal das finanças",
                                    "autoridade tributaria", "autoridade tributária"),
          ("portaldasfinancas.gov.pt", "at.gov.pt")),
)


def mentioned(text: str, brands: tuple[Brand, ...] = BRANDS) -> list[Brand]:
    return [b for b in brands if b.mentioned_in(text)]
