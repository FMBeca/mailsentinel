from conftest import email_from

from mailsentinel.detectors import authentication
from mailsentinel.models import Severity


def _ids(email):
    return {f.rule_id: f for f in authentication.detect(email)}


def _msg(auth_results: str, frm: str = "a@example.net"):
    return email_from({"Authentication-Results": auth_results, "From": frm, "Subject": "x"})


# --- MAIL-AUTH-001 SPF ---

def test_spf_fail_is_high():
    f = _ids(_msg("mx.example.com; spf=fail smtp.mailfrom=example.net"))["MAIL-AUTH-001"]
    assert f.severity is Severity.HIGH
    assert f.details["envelope_domain"] == "example.net"
    assert f.mitre_technique == "T1566"


def test_spf_softfail_is_low():
    f = _ids(_msg("mx.example.com; spf=softfail smtp.mailfrom=example.net"))["MAIL-AUTH-001"]
    assert f.severity is Severity.LOW
    assert f.score < 25


def test_spf_pass_neutral_or_none_is_not_flagged():
    for result in ("pass", "neutral", "none"):
        assert "MAIL-AUTH-001" not in _ids(_msg(f"mx.example.com; spf={result} smtp.mailfrom=example.net"))


# --- MAIL-AUTH-002 DKIM ---

def test_dkim_fail():
    f = _ids(_msg("mx.example.com; dkim=fail header.d=example.net"))["MAIL-AUTH-002"]
    assert f.details["signing_domains"] == "example.net"


def test_dkim_fail_with_another_valid_signature_is_not_flagged():
    assert "MAIL-AUTH-002" not in _ids(_msg("mx.example.com; dkim=fail header.d=example.net; dkim=pass header.d=example.com"))


def test_unsigned_message_is_not_flagged():
    assert "MAIL-AUTH-002" not in _ids(_msg("mx.example.com; dkim=none"))


# --- MAIL-AUTH-003 DMARC ---

def test_dmarc_fail_is_high():
    f = _ids(_msg("mx.example.com; dmarc=fail (p=reject) header.from=example.net"))["MAIL-AUTH-003"]
    assert f.severity is Severity.HIGH
    assert f.details["from_domain"] == "example.net"


def test_dmarc_pass_is_not_flagged():
    assert _ids(_msg("mx.example.com; spf=pass smtp.mailfrom=example.net; dkim=pass header.d=example.net; "
                     "dmarc=pass header.from=example.net")) == {}


def test_missing_authentication_headers_are_not_a_finding():
    # Many saved messages carry no results at all; absence of evidence is not phishing.
    assert authentication.detect(email_from({"From": "a@example.net", "Subject": "x"})) == []


def test_forged_pass_below_a_real_fail_is_ignored():
    e = email_from([
        ("Authentication-Results", "mx.example.com; dmarc=fail header.from=example.net"),
        ("Authentication-Results", "mx.example.com; dmarc=pass header.from=example.net"),
        ("From", "a@example.net"),
    ])
    assert "MAIL-AUTH-003" in _ids(e)
