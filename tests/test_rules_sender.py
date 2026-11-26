import pytest
from conftest import email_from

from mailsentinel.brands import Brand
from mailsentinel.detectors import sender
from mailsentinel.domains import org_domain, same_org
from mailsentinel.models import Severity


def _ids(headers, **kw):
    headers = {"Subject": "x", **headers}
    return {f.rule_id: f for f in sender.detect(email_from(headers), **kw)}


# --- domain helpers ---

@pytest.mark.parametrize("domain, org", [
    ("example.com", "example.com"),
    ("mail.news.example.com", "example.com"),
    ("EXAMPLE.com.", "example.com"),
    ("shop.example.co.uk", "example.co.uk"),
    ("www.example.com.pt", "example.com.pt"),
    ("localhost", "localhost"),
])
def test_org_domain(domain, org):
    assert org_domain(domain) == org


def test_same_org():
    assert same_org("news.example.com", "example.com")
    assert not same_org("example.com", "example.net")
    assert not same_org("", "example.com")


# --- MAIL-SND-001 Reply-To ---

def test_reply_to_other_organisation():
    f = _ids({"From": "ceo@example.com", "Reply-To": "ceo.office@example.net"})["MAIL-SND-001"]
    assert f.severity is Severity.MEDIUM
    assert f.details["reply_to"] == "ceo.office@example.net"


def test_reply_to_same_organisation_is_fine():
    assert "MAIL-SND-001" not in _ids({"From": "newsletter@news.example.com", "Reply-To": "support@example.com"})


def test_only_foreign_reply_to_addresses_are_listed():
    f = _ids({"From": "a@example.com", "Reply-To": "b@example.com, c@example.org"})["MAIL-SND-001"]
    assert f.details["reply_to"] == "c@example.org"


# --- MAIL-SND-002 Return-Path ---

def test_return_path_other_organisation_without_dmarc():
    f = _ids({"From": "billing@example.com", "Return-Path": "<x@example.net>"})["MAIL-SND-002"]
    assert f.severity is Severity.LOW


def test_return_path_of_mailing_provider_with_dmarc_pass_is_fine():
    ids = _ids({
        "Authentication-Results": "mx.example.org; spf=pass smtp.mailfrom=esp.example.net; dmarc=pass header.from=example.com",
        "From": "news@example.com",
        "Return-Path": "<bounces@esp.example.net>",
    })
    assert "MAIL-SND-002" not in ids


def test_return_path_same_organisation_is_fine():
    assert "MAIL-SND-002" not in _ids({"From": "a@example.com", "Return-Path": "<bounce@mail.example.com>"})


def test_empty_return_path_is_fine():
    # Bounces and auto-replies use "<>" as the envelope sender.
    assert "MAIL-SND-002" not in _ids({"From": "a@example.com", "Return-Path": "<>"})


# --- MAIL-SND-003 address or domain in the display name ---

def test_display_name_with_another_address():
    f = _ids({"From": '"it-support@example.com" <helpdesk@example.net>'})["MAIL-SND-003"]
    assert f.severity is Severity.HIGH
    assert f.mitre_technique == "T1656"
    assert f.details["claimed_domain"] == "example.com"


def test_display_name_with_another_domain():
    f = _ids({"From": '"Accounts | billing.example.com" <noreply@example.org>'})["MAIL-SND-003"]
    assert f.details["claimed_domain"] == "example.com"


def test_display_name_repeating_own_address_is_fine():
    assert _ids({"From": '"john.doe@example.org" <john.doe@example.org>'}) == {}


def test_display_name_with_own_brand_domain_is_fine():
    assert _ids({"From": '"Example.com" <orders@shop.example.com>'}) == {}


@pytest.mark.parametrize("name", ["J. Smith", "Support.Team", "Dr. A. Costa", "v2.0 release bot"])
def test_dotted_names_are_not_domains(name):
    assert "MAIL-SND-003" not in _ids({"From": f'"{name}" <a@example.org>'})


# --- MAIL-SND-004 brand in the display name ---

def test_brand_in_display_name_from_other_domain():
    f = _ids({"From": '"PayPal Service" <security@account-verify.example.net>'})["MAIL-SND-004"]
    assert f.details["brand"] == "PayPal"
    assert f.mitre_technique == "T1656"


def test_portuguese_brand_with_accents():
    f = _ids({"From": '"Portal das Finanças" <avisos@example.net>'})["MAIL-SND-004"]
    assert f.details["brand"] == "Autoridade Tributaria"


def test_brand_from_its_own_domain_is_fine():
    assert "MAIL-SND-004" not in _ids({"From": '"PayPal" <service@mail.paypal.com>'})


def test_brand_from_country_domain_is_fine():
    assert "MAIL-SND-004" not in _ids({"From": '"Amazon.de" <versandbestaetigung@amazon.de>'})


def test_brand_name_inside_another_word_is_not_a_match():
    assert "MAIL-SND-004" not in _ids({"From": '"Pineapple Bakery" <hello@example.org>'})


def test_custom_brand_list():
    bank = Brand("Example Bank", ("example bank",), ("examplebank.example",))
    assert "MAIL-SND-004" in _ids({"From": '"Example Bank Security" <alerts@example.net>'}, brands=(bank,))
    assert "MAIL-SND-004" not in _ids({"From": '"Example Bank" <alerts@mail.examplebank.example>'}, brands=(bank,))


def test_domain_in_name_takes_precedence_over_brand():
    ids = _ids({"From": '"paypal.com" <x@example.net>'})
    assert "MAIL-SND-003" in ids
    assert "MAIL-SND-004" not in ids


def test_no_from_header_no_findings():
    assert _ids({"To": "a@example.com"}) == {}
