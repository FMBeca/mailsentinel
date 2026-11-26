"""Find the URLs in a message body: plain text, HTML link targets, HTML visible text and forms."""
from __future__ import annotations

import ipaddress
import re
from html.parser import HTMLParser
from urllib.parse import urlsplit

from mailsentinel.domains import find_domains
from mailsentinel.models import Form, Link

# http(s)/ftp URLs and bare "www." addresses in free text.
_URL_IN_TEXT = re.compile(r"(?:\b(?:https?|ftp)://|\bwww\.)[^\s<>\"'`]+", re.IGNORECASE)
_TRAILING = ".,;:!?)]}'\"*>"
_SKIP_SCHEMES = ("mailto:", "tel:", "cid:", "#", "sms:", "javascript:")


def _clean(url: str) -> str:
    url = url.strip()
    # A closing parenthesis belongs to the URL only if it opened one ("...wiki/Foo_(bar)").
    while url and url[-1] in _TRAILING:
        if url[-1] == ")" and url.count("(") >= url.count(")"):
            break
        url = url[:-1]
    return url


def host_of(url: str) -> str:
    """Lowercased hostname of a URL ("" if it has none or cannot be parsed)."""
    if url.lower().startswith("www."):
        url = "http://" + url
    try:
        return (urlsplit(url).hostname or "").rstrip(".")
    except ValueError:              # e.g. an unbalanced "[" in an IPv6 host
        return ""


def ip_host(host: str) -> str:
    """The IP address a host stands for, "" if it is a name.

    Browsers also accept an IPv4 address written as a single number ("http://3405803781/"),
    a common way to hide that a link points to a bare IP.
    """
    try:
        if host.isdigit():
            return str(ipaddress.IPv4Address(int(host)))
        return str(ipaddress.ip_address(host.strip("[]")))
    except ValueError:
        return ""


def hosts_in_text(text: str) -> list[str]:
    """Hosts a piece of text promises (the visible text of a link): URLs, or failing that bare domains."""
    hosts = [host_of(_clean(m.group(0))) for m in _URL_IN_TEXT.finditer(text)]
    return [h for h in hosts if h] or find_domains(text)


def urls_in_text(text: str, source: str = "text") -> list[Link]:
    links = []
    for m in _URL_IN_TEXT.finditer(text):
        url = _clean(m.group(0))
        if url:
            links.append(Link(url=url, host=host_of(url), source=source))
    return links


class _HTMLLinks(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[Link] = []
        self.forms: list[Form] = []
        self.text: list[str] = []
        self._anchor: tuple[str, list[str]] | None = None   # (href, text parts) while inside <a>
        self._form: list | None = None                       # [action, has_password] while inside <form>
        self._skip = 0                                       # inside <script>/<style>

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag in ("script", "style"):
            self._skip += 1
        elif tag in ("a", "area") and a.get("href"):
            href = a["href"].strip()
            if not href.lower().startswith(_SKIP_SCHEMES):
                if tag == "area":
                    self.links.append(Link(url=href, host=host_of(href), source="html-link"))
                else:
                    self._close_anchor()
                    self._anchor = (href, [])
        elif tag == "form":
            self._close_form()
            self._form = [a.get("action", "").strip(), False]
        elif tag == "input" and self._form is not None and a.get("type", "").lower() == "password":
            self._form[1] = True

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        elif tag == "a":
            self._close_anchor()
        elif tag == "form":
            self._close_form()

    def handle_data(self, data):
        if self._skip:
            return
        self.text.append(data)
        if self._anchor is not None:
            self._anchor[1].append(data)

    def _close_anchor(self) -> None:
        if self._anchor is not None:
            href, parts = self._anchor
            text = " ".join("".join(parts).split())
            self.links.append(Link(url=href, host=host_of(href), source="html-link", text=text))
            self._anchor = None

    def _close_form(self) -> None:
        if self._form is not None:
            action, has_password = self._form
            self.forms.append(Form(action=action, host=host_of(action), has_password=has_password))
            self._form = None

    def close(self) -> None:
        super().close()
        self._close_anchor()        # unclosed tags are common in hand-made phishing HTML
        self._close_form()


def parse_html(html: str) -> tuple[list[Link], list[Form]]:
    p = _HTMLLinks()
    p.feed(html)
    p.close()
    links = list(p.links)
    # URLs written as visible text (not linked) are still what the reader sees and may copy.
    links += urls_in_text(" ".join(p.text), source="html-text")
    forms_as_links = [Link(url=f.action, host=f.host, source="html-form") for f in p.forms if f.action]
    return links + forms_as_links, p.forms


def extract(text_body: str, html_body: str) -> tuple[list[Link], list[Form]]:
    """All links and forms of a message, in order: text body first, then HTML."""
    links = urls_in_text(text_body)
    forms: list[Form] = []
    if html_body:
        html_links, forms = parse_html(html_body)
        links += html_links
    return links, forms


def unique_urls(links: list[Link]) -> list[str]:
    return list(dict.fromkeys(link.url for link in links))
