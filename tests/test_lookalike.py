import pytest

from mailsentinel.lookalike import Reference, check, distance, scripts, skeleton, to_unicode

BRANDS = [
    Reference("paypal.com", "PayPal", any_tld=True),
    Reference("microsoft.com", "Microsoft"),
    Reference("amazon.com", "Amazon", any_tld=True),
    Reference("apple.com", "Apple"),
    Reference("dhl.com", "DHL", any_tld=True),
    Reference("google.com", "Google", any_tld=True),
    Reference("outlook.com", "Microsoft"),
]
RECIPIENT = [Reference("northwind.example", "the recipient's domain", combo=False)]


def test_distance():
    assert distance("paypal", "paypal") == 0
    assert distance("paypal", "paypall") == 1        # insertion
    assert distance("paypal", "paypa") == 1          # deletion
    assert distance("paypal", "paypel") == 1         # substitution
    assert distance("microsoft", "micorsoft") == 1   # swapped neighbours
    assert distance("abc", "xyz") == 3


def test_skeleton_folds_look_alike_characters():
    assert skeleton("paypa1") == "paypal"
    assert skeleton("micros0ft") == "microsoft"
    assert skeleton("arnazon") == "amazon"
    assert skeleton("pаypаl") == "paypal"     # Cyrillic "а"
    assert skeleton("gοοgle") == "google"     # Greek "ο"


def test_to_unicode():
    assert to_unicode("xn--pypal-4ve.example") == "pаypal.example"
    assert to_unicode("mail.example.com") == "mail.example.com"
    assert to_unicode("xn--invalid-!!.example") == "xn--invalid-!!.example"


def test_scripts():
    assert scripts("paypal") == {"LATIN"}
    assert scripts("pаypal") == {"LATIN", "CYRILLIC"}
    assert scripts("café") == {"LATIN"}
    assert scripts("123-") == set()


# --- attacks ---

@pytest.mark.parametrize("domain, reference", [
    ("paypa1.example", "paypal.com"),
    ("secure.paypa1.example", "paypal.com"),
    ("paypall.example", "paypal.com"),
    ("micros0ft.example", "microsoft.com"),
    ("micorsoft.example", "microsoft.com"),
    ("arnazon.example", "amazon.com"),
    ("app1e.example", "apple.com"),
    ("xn--pypal-4ve.example", "paypal.com"),
    ("dh1.example", "dhl.com"),
])
def test_brand_lookalikes(domain, reference):
    m = check(domain, BRANDS)
    assert m is not None and m.kind == "lookalike"
    assert m.reference == reference


def test_punycode_lookalike_reports_unicode_form_and_scripts():
    m = check("xn--pypal-4ve.example", BRANDS)
    assert m.unicode == "pаypal.example"
    assert "CYRILLIC" in m.reason


def test_recipient_domain_lookalike():
    m = check("n0rthwind.example", RECIPIENT)
    assert m.kind == "lookalike" and m.owner == "the recipient's domain"
    assert check("northwlnd.example", RECIPIENT).kind == "lookalike"


@pytest.mark.parametrize("domain", ["paypal-secure.example", "accounts.google.com.verify.example", "microsoft-365-login.example"])
def test_combosquatting(domain):
    assert check(domain, BRANDS).kind == "combosquat"


def test_mixed_script_without_known_target():
    m = check("xn--exmple-4nf.example", BRANDS)    # "exаmple" with a Cyrillic "а"
    assert m.kind == "mixed-script"


# --- legitimate domains ---

@pytest.mark.parametrize("domain", [
    "paypal.com", "www.paypal.com", "paypal.de",          # owned (any TLD for PayPal)
    "microsoft.com", "login.microsoft.com",
    "amazon.co.uk",
    "github.com", "example.net", "mail.example.org",
    "apply.example",                                      # one letter from "apple", but too short to judge by distance
    "dhi.example",                                        # short names are not compared by distance
    "amazonaws.com", "googleusercontent.com",             # brand name only as part of a longer word
    "office-supplies.example", "outlook-weekly.example",  # generic words excluded from combosquatting
    "xn--caf-dma.example",                                # "café": accented Latin, one script
    "xn--mnchen-3ya.example",                             # "münchen"
])
def test_legitimate_domains(domain):
    assert check(domain, BRANDS) is None


def test_same_name_under_another_tld_is_not_called():
    # example.com writing to example.org is normal (and very common in organisations).
    assert check("northwind.org", RECIPIENT) is None


def test_recipient_name_inside_other_domains_is_not_combosquatting():
    assert check("northwind-events.example", RECIPIENT) is None


def test_empty_and_dotless():
    assert check("", BRANDS) is None
    assert check("localhost", BRANDS) is None
