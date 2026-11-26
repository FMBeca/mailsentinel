import pytest
from conftest import email_from

from mailsentinel.urls import host_of, hosts_in_text, ip_host, parse_html, urls_in_text


@pytest.mark.parametrize("text, urls", [
    ("Go to https://www.example.com/a?b=1.", ["https://www.example.com/a?b=1"]),
    ("(see http://example.org/x)", ["http://example.org/x"]),
    ("wiki: https://example.org/wiki/Foo_(bar), ok", ["https://example.org/wiki/Foo_(bar)"]),
    ("visit www.example.net today", ["www.example.net"]),
    ('"https://example.com/q"', ["https://example.com/q"]),
    ("two: https://a.example.com and ftp://b.example.org/f", ["https://a.example.com", "ftp://b.example.org/f"]),
    ("no links here, just example text", []),
])
def test_urls_in_text(text, urls):
    assert [link.url for link in urls_in_text(text)] == urls


@pytest.mark.parametrize("url, host", [
    ("https://Login.Example.COM:8443/x", "login.example.com"),
    ("www.example.net/path", "www.example.net"),
    ("https://user@example.org/", "example.org"),
    ("http://[2001:db8::1]/", "2001:db8::1"),
    ("http://[broken/", ""),
    ("/relative/path", ""),
])
def test_host_of(url, host):
    assert host_of(url) == host


@pytest.mark.parametrize("host, ip", [
    ("203.0.113.9", "203.0.113.9"),
    ("3405803781", "203.0.113.5"),       # IPv4 written as one number
    ("2001:db8::1", "2001:db8::1"),
    ("example.com", ""),
    ("", ""),
])
def test_ip_host(host, ip):
    assert ip_host(host) == ip


def test_hosts_in_text():
    assert hosts_in_text("https://accounts.example.com/signin") == ["accounts.example.com"]
    assert hosts_in_text("Go to example.org now") == ["example.org"]
    assert hosts_in_text("Click here") == []


def test_html_links_keep_their_visible_text():
    links, forms = parse_html(
        '<p>Hi <a href="https://t.example.net/c?id=1"><b>https://www.example.com</b>/login</a></p>'
        '<a href="mailto:a@example.com">mail us</a><a href="#top">top</a><a href="javascript:void(0)">x</a>'
    )
    anchors = [link for link in links if link.source == "html-link"]
    assert [(a.url, a.text) for a in anchors] == [("https://t.example.net/c?id=1", "https://www.example.com/login")]
    assert forms == []


def test_html_entities_and_unclosed_anchor():
    links, _ = parse_html('<a href="https://example.com/?a=1&amp;b=2">Example')
    assert links[0].url == "https://example.com/?a=1&b=2"
    assert links[0].text == "Example"


def test_html_visible_urls_and_scripts():
    links, _ = parse_html("<p>Copy https://example.org/x</p><script>var u='https://ignored.example.net';</script>")
    assert [(link.url, link.source) for link in links] == [("https://example.org/x", "html-text")]


def test_html_forms():
    links, forms = parse_html(
        '<form action="https://example.net/c"><input type="password" name="p"></form>'
        '<form action="https://example.org/s"><input name="q"></form>'
    )
    assert [(f.host, f.has_password) for f in forms] == [("example.net", True), ("example.org", False)]
    assert [link.url for link in links if link.source == "html-form"] == ["https://example.net/c", "https://example.org/s"]


def test_image_map_area_links():
    links, _ = parse_html('<map><area href="https://example.net/a" alt="x"></map>')
    assert links[0].url == "https://example.net/a"


def test_parsed_email_has_links_from_both_bodies():
    body = (
        "--b\r\nContent-Type: text/plain\r\n\r\nhttps://example.com/t\r\n"
        "--b\r\nContent-Type: text/html\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n"
        "<a href=3D\"https://example.com/h\">here</a>\r\n--b--\r\n"
    )
    e = email_from({"From": "a@example.org", "Subject": "x"}, body, content_type='multipart/alternative; boundary="b"')
    assert [(link.url, link.source) for link in e.links] == [
        ("https://example.com/t", "text"), ("https://example.com/h", "html-link")]
