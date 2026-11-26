import pytest
from conftest import email_from, make_eml

from mailsentinel.parser import NotAnEmailError, parse_bytes, parse_file


def test_headers_and_encoded_subject(samples):
    e = parse_file(str(samples / "legit-personal.eml"))
    assert e.subject == "Jantar de sábado"
    assert e.from_.address == "john.doe@example.org"
    assert e.from_.display_name == "john.doe@example.org"
    assert "sobremesa" in e.text_body


def test_multipart_bodies(samples):
    e = parse_file(str(samples / "phish-brand-spoof.eml"))
    assert "unusual activity" in e.text_body
    assert 'href="http://203.0.113.45/verify/login.php?id=5521"' in e.html_body


def test_from_reply_to_and_return_path():
    e = email_from({
        "From": '"Alice" <Alice@Mail.Example.COM.>',
        "Reply-To": "a@example.net, b@example.org",
        "Return-Path": "<bounce@example.net>",
        "Subject": "hi",
    })
    assert e.from_.display_name == "Alice"
    assert e.from_.domain == "mail.example.com"
    assert e.from_.address == "Alice@mail.example.com"
    assert [a.domain for a in e.reply_to] == ["example.net", "example.org"]
    assert e.return_path == "bounce@example.net"
    assert e.return_path_domain == "example.net"


def test_encoded_display_name_is_decoded():
    e = email_from({"From": "=?utf-8?q?Servi=C3=A7o_PayPal?= <a@example.net>", "Subject": "x"})
    assert e.from_.display_name == "Serviço PayPal"


def test_missing_from_does_not_crash():
    e = email_from({"Subject": "no sender", "To": "a@example.com"})
    assert e.from_ is None


def test_multiple_from_addresses_are_reported():
    e = email_from({"From": "a@example.com, b@example.net", "Subject": "x"})
    assert e.from_.address == "a@example.com"
    assert "MultipleFromAddresses" in e.defects


def test_received_chain_with_brackets_and_parentheses():
    e = email_from([
        ("Received", "from smtp.example.net (198.51.100.23) by mx.example.com (2001:db8::2) with SMTP"),
        ("Received", "from host.example.org (host.example.org [203.0.113.7])\r\n\tby smtp.example.net with ESMTP id 1"),
        # Postfix: the first brackets are the HELO the sender claimed, the comment is the real peer.
        ("Received", "from [192.0.2.9] (unknown [IPv6:2001:db8::9]) by host.example.org"),
        ("Received", "by localhost with local delivery"),
        ("From", "a@example.org"),
    ])
    assert [h.ip for h in e.hops] == ["198.51.100.23", "203.0.113.7", "2001:db8::9", ""]
    assert e.hops[1].from_host == "host.example.org"
    assert e.hops[1].by_host == "smtp.example.net"
    # The IP of the receiving server ("by ... (2001:db8::2)") is not the sender's.
    assert e.hops[0].ip == "198.51.100.23"


def test_invalid_ip_in_received_is_skipped():
    e = email_from([("Received", "from x (x [999.1.1.1]) by y"), ("From", "a@example.org")])
    assert e.hops[0].ip == ""


def test_unknown_charset_falls_back_to_utf8():
    e = email_from({"From": "a@example.org", "Subject": "x"}, "café\n", content_type='text/plain; charset="x-unknown"')
    assert "caf" in e.text_body


def test_attachment_text_is_not_treated_as_body():
    body = (
        "--b\r\nContent-Type: text/plain\r\n\r\nvisible\r\n"
        "--b\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename=notes.txt\r\n\r\nhidden\r\n--b--\r\n"
    )
    e = email_from({"From": "a@example.org", "Subject": "x"}, body, content_type='multipart/mixed; boundary="b"')
    assert "visible" in e.text_body
    assert "hidden" not in e.text_body


@pytest.mark.parametrize("data", [b"", b"just some text\nwithout headers\n", b"\x00\x01\x02binary"])
def test_non_email_input_is_rejected(data):
    with pytest.raises(NotAnEmailError):
        parse_bytes(data)


def test_outlook_msg_is_rejected_with_a_hint():
    with pytest.raises(NotAnEmailError, match=r"\.msg"):
        parse_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64)


def test_headers_only_message_is_accepted():
    e = parse_bytes(make_eml({"From": "a@example.org", "Subject": "x"}, body=""))
    assert e.subject == "x"
