from mailsentinel.auth import from_headers, parse_authentication_results, parse_received_spf


def test_typical_header_with_authserv_id():
    r = parse_authentication_results(
        "mx.example.com; spf=pass (example.com: domain of a@example.org designates 192.0.2.1 as permitted sender) "
        "smtp.mailfrom=a@example.org; dkim=pass header.i=@example.org header.s=s1; "
        "dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.org"
    )
    assert (r.spf, r.dkim, r.dmarc) == ("pass", "pass", "pass")
    assert r.spf_domain == "example.org"
    assert r.dkim_domains == ("example.org",)
    assert r.dmarc_domain == "example.org"
    assert r.source == "Authentication-Results"


def test_microsoft_style_without_authserv_id():
    r = parse_authentication_results(
        "spf=fail (sender IP is 203.0.113.9) smtp.mailfrom=example.net; dkim=none (message not signed) "
        "header.d=none;dmarc=fail action=quarantine header.from=example.net;compauth=fail reason=000"
    )
    assert (r.spf, r.dkim, r.dmarc) == ("fail", "none", "fail")
    assert r.dmarc_domain == "example.net"


def test_semicolons_and_equals_inside_comments_are_ignored():
    r = parse_authentication_results(
        "mx.example.com; spf=softfail (note; dmarc=pass (nested) here) smtp.mailfrom=example.net; "
        "dmarc=fail header.from=example.net"
    )
    assert r.spf == "softfail"
    assert r.dmarc == "fail"


def test_one_valid_dkim_signature_is_enough():
    r = parse_authentication_results(
        "mx.example.com; dkim=fail header.d=example.net; dkim=pass header.d=example.com; spf=none"
    )
    assert r.dkim == "pass"
    assert r.dkim_domains == ("example.net", "example.com")


def test_unknown_results_are_ignored():
    r = parse_authentication_results("mx.example.com; spf=banana; dmarc=fail header.from=example.net")
    assert r.spf == "none"
    assert r.dmarc == "fail"


def test_only_topmost_authentication_results_is_trusted():
    # A sender can add a fake "pass" header; only the receiving server's (topmost) counts.
    r = from_headers(
        ["mx.example.com; spf=fail smtp.mailfrom=example.net; dmarc=fail header.from=example.net",
         "mx.example.com; spf=pass smtp.mailfrom=example.net; dmarc=pass header.from=example.net"],
        [],
    )
    assert r.spf == "fail"
    assert r.dmarc == "fail"


def test_received_spf():
    assert parse_received_spf("Pass (protection.example.com: domain of example.net designates 192.0.2.4) ...") == "pass"
    assert parse_received_spf("SoftFail (example.com: transitioning)") == "softfail"
    assert parse_received_spf("") == "none"
    assert parse_received_spf("whatever else") == "none"


def test_received_spf_fills_in_missing_spf_result():
    r = from_headers(["mx.example.com; dkim=pass header.d=example.org"], ["Fail (example.com) client-ip=203.0.113.2"])
    assert r.spf == "fail"
    assert r.dkim == "pass"


def test_received_spf_alone():
    r = from_headers([], ["Softfail (example.com) client-ip=203.0.113.2"])
    assert r.spf == "softfail"
    assert r.source == "Received-SPF"


def test_no_headers_means_no_results():
    r = from_headers([], [])
    assert (r.spf, r.dkim, r.dmarc) == ("none", "none", "none")
    assert not r.present
