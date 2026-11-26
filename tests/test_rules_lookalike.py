from conftest import email_from

from mailsentinel.brands import Brand
from mailsentinel.detectors import lookalike
from mailsentinel.models import Severity


def _ids(headers, body: str = "Hello.\n", **kw):
    headers = {"Subject": "x", "To": "finance@northwind.example", **headers}
    return {f.rule_id: f for f in lookalike.detect(email_from(headers, body), **kw)}


# --- MAIL-LOOK-001 sender ---

def test_sender_imitates_recipient_domain():
    f = _ids({"From": "accounts@n0rthwind.example"})["MAIL-LOOK-001"]
    assert f.severity is Severity.HIGH
    assert f.mitre_technique == "T1656"
    assert "looks like northwind.example [the recipient's domain]" in f.details["domains"]


def test_sender_imitates_brand():
    assert "MAIL-LOOK-001" in _ids({"From": '"PayPal" <service@paypa1.example>'})


def test_reply_to_and_return_path_are_checked_too():
    assert "MAIL-LOOK-001" in _ids({"From": "a@example.org", "Reply-To": "ceo@northwlnd.example"})
    assert "MAIL-LOOK-001" in _ids({"From": "a@example.org", "Return-Path": "<b@micros0ft.example>"})


def test_colleague_from_same_domain_is_fine():
    assert _ids({"From": "ceo@northwind.example"}) == {}


def test_brand_from_its_own_domain_is_fine():
    assert _ids({"From": "service@paypal.com"}) == {}


def test_cc_recipients_are_references():
    ids = _ids({"From": "a@contoso-1td.example", "To": "x@example.org", "Cc": "y@contoso-ltd.example"})
    assert "MAIL-LOOK-001" in ids


# --- MAIL-LOOK-002 links ---

def test_link_imitates_brand_with_punycode():
    f = _ids({"From": "a@example.org"}, "Pay here: https://xn--pypal-4ve.example/pay\n")["MAIL-LOOK-002"]
    assert f.mitre_technique == "T1566.002"
    assert "p<U+0430>ypal.example" in f.details["domains"]


def test_link_to_brand_is_fine():
    assert _ids({"From": "a@example.org"}, "https://www.microsoft.com/security\n") == {}


def test_ip_links_are_left_to_the_link_rules():
    assert _ids({"From": "a@example.org"}, "http://203.0.113.9/x\n") == {}


# --- MAIL-LOOK-003 combosquatting ---

def test_brand_inside_unrelated_link_domain():
    f = _ids({"From": "a@example.org"}, "https://microsoft-365-login.example/\n")["MAIL-LOOK-003"]
    assert f.severity is Severity.MEDIUM
    assert "does not belong to Microsoft" in f.details["domains"]


def test_brand_as_subdomain_of_attacker_domain():
    assert "MAIL-LOOK-003" in _ids({"From": "alerts@paypal.com.account-check.example"})


# --- MAIL-LOOK-004 mixed alphabets ---

def test_mixed_alphabets_without_known_target():
    assert "MAIL-LOOK-004" in _ids({"From": "a@example.org"}, "https://xn--exmple-4nf.example/\n")


def test_single_script_international_domain_is_fine():
    assert _ids({"From": "a@example.org"}, "https://xn--caf-dma.example/menu\n") == {}


# --- custom brands and scoring ---

def test_custom_brand_list():
    bank = Brand("Example Bank", ("example bank",), ("examplebank.example",))
    assert "MAIL-LOOK-001" in _ids({"From": "alerts@examp1ebank.example"}, brands=(bank,))


def test_many_lookalike_links_score_once():
    body = "".join(f"https://paypa1.example/{i}\n" for i in range(9))
    ids = _ids({"From": "a@example.org"}, body)
    assert ids["MAIL-LOOK-002"].score == 30
