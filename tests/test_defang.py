import pytest

from mailsentinel.defang import defang, defang_ip


@pytest.mark.parametrize("raw, safe", [
    ("https://login.example.net/a.php?x=1", "hxxps[://]login[.]example[.]net/a.php?x=1"),
    ("http://203.0.113.5:8080/x", "hxxp[://]203[.]0[.]113[.]5:8080/x"),
    ("ftp://files.example.org/f.zip", "fxp[://]files[.]example[.]org/f.zip"),
    ("alerts@account-verify.example.net", "alerts[@]account-verify[.]example[.]net"),
    ("203.0.113.5", "203[.]0[.]113[.]5"),
    ("example.com", "example[.]com"),
    ('"PayPal" <a@example.net>', '"PayPal" <a[@]example[.]net>'),
    ("a@example.com, b@example.org", "a[@]example[.]com, b[@]example[.]org"),
])
def test_defang(raw, safe):
    assert defang(raw) == safe


def test_plain_words_are_untouched():
    assert defang("softfail") == "softfail"
    assert defang("PayPal Service") == "PayPal Service"
    assert defang("") == ""


def test_defang_is_idempotent_on_already_defanged_text():
    once = defang("https://example.com/x")
    assert defang(once) == once


def test_defang_ip():
    assert defang_ip("198.51.100.7") == "198[.]51[.]100[.]7"
    assert defang_ip("2001:db8::1") == "2001[:]db8[:][:]1"
