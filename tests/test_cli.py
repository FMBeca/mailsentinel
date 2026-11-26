import io
import json
import sys

import pytest

from mailsentinel.cli import main


@pytest.mark.parametrize("name, verdict, code", [
    ("legit-newsletter.eml", "clean", 0),
    ("legit-personal.eml", "clean", 0),
    ("phish-display-name.eml", "suspicious", 1),
    ("phish-brand-spoof.eml", "phishing", 1),
    ("phish-credential-form.eml", "phishing", 1),
])
def test_samples_verdict_and_exit_code(samples, capsys, name, verdict, code):
    assert main([str(samples / name), "--json"]) == code
    out = json.loads(capsys.readouterr().out)
    assert out["verdict"] == verdict


def test_brand_spoof_findings(samples, capsys):
    main([str(samples / "phish-brand-spoof.eml"), "--json"])
    out = json.loads(capsys.readouterr().out)
    ids = {f["rule_id"] for f in out["findings"]}
    assert ids == {"MAIL-AUTH-001", "MAIL-AUTH-003", "MAIL-SND-001", "MAIL-SND-002", "MAIL-SND-004",
                   "MAIL-URL-001", "MAIL-URL-002"}
    # The fake "pass" further down the headers is ignored.
    assert out["authentication"] == {"spf": "softfail", "dkim": "none", "dmarc": "fail", "source": "Authentication-Results"}
    assert out["iocs"]["received_ips"] == ["192[.]0[.]2[.]77", "203[.]0[.]113[.]45"]


def test_authenticated_sender_with_credential_form(samples, capsys):
    # SPF, DKIM and DMARC all pass (the attacker owns the domain): the content gives it away.
    main([str(samples / "phish-credential-form.eml"), "--json"])
    out = json.loads(capsys.readouterr().out)
    assert out["authentication"]["dmarc"] == "pass"
    ids = {f["rule_id"] for f in out["findings"]}
    assert {"MAIL-URL-002", "MAIL-URL-003", "MAIL-URL-005"} <= ids
    assert not any(i.startswith("MAIL-AUTH") for i in ids)
    urls = {u["url"]: u for u in out["iocs"]["urls"]}
    assert urls["hxxps[://]198[.]51[.]100[.]201/collect.php"]["source"] == "html-form"


def test_url_iocs_keep_link_text(samples, capsys):
    main([str(samples / "phish-brand-spoof.eml"), "--json", "--no-defang"])
    urls = {u["url"]: u for u in json.loads(capsys.readouterr().out)["iocs"]["urls"]}
    assert urls["http://203.0.113.45/verify/login.php?id=5521"]["text"] == "https://accounts.example.com/signin"
    assert urls["https://accounts.example.com/signin"]["source"] == "text"


def test_findings_sorted_by_score(samples, capsys):
    main([str(samples / "phish-brand-spoof.eml"), "--json"])
    scores = [f["score"] for f in json.loads(capsys.readouterr().out)["findings"]]
    assert scores == sorted(scores, reverse=True)


def test_output_is_defanged_by_default(samples, capsys):
    main([str(samples / "phish-brand-spoof.eml")])
    out = capsys.readouterr().out
    assert "account-verify[.]example[.]net" in out
    assert "account-verify.example.net" not in out
    assert "203.0.113.45" not in out


def test_no_defang(samples, capsys):
    main([str(samples / "phish-brand-spoof.eml"), "--json", "--no-defang"])
    out = json.loads(capsys.readouterr().out)
    assert out["defanged"] is False
    assert "203.0.113.45" in out["iocs"]["received_ips"]


def test_table_output(samples, capsys):
    main([str(samples / "phish-brand-spoof.eml"), "--no-color"])
    out = capsys.readouterr().out
    assert "LIKELY PHISHING" in out
    assert "MAIL-AUTH-003" in out
    assert "T1656" in out


def test_clean_table_output(samples, capsys):
    main([str(samples / "legit-newsletter.eml"), "--no-color"])
    assert "No phishing indicators found." in capsys.readouterr().out


def test_fail_on_phishing(samples, capsys):
    assert main([str(samples / "phish-display-name.eml"), "--fail-on", "phishing"]) == 0
    assert main([str(samples / "phish-brand-spoof.eml"), "--fail-on", "phishing"]) == 1


def test_not_an_email_exits_2(tmp_path, capsys):
    p = tmp_path / "notes.txt"
    p.write_text("this is not an email\n", encoding="utf-8")
    assert main([str(p)]) == 2
    assert "no email headers" in capsys.readouterr().err


def test_missing_file_exits_2(tmp_path, capsys):
    assert main([str(tmp_path / "missing.eml")]) == 2
    assert "cannot read" in capsys.readouterr().err


def test_stdin(samples, monkeypatch, capsys):
    data = (samples / "phish-brand-spoof.eml").read_bytes()
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(data)))
    assert main(["-", "--json"]) == 1
    assert json.loads(capsys.readouterr().out)["file"] == "-"


def test_json_is_ascii_only(samples, capsys):
    main([str(samples / "legit-personal.eml"), "--json"])
    out = capsys.readouterr().out
    assert out.isascii()
    assert json.loads(out)["headers"]["subject"] == "Jantar de sábado"
