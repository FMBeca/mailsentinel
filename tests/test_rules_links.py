from conftest import email_from

from mailsentinel.detectors import links
from mailsentinel.models import Severity


def _ids(html: str = "", text: str = "", dmarc: str = ""):
    headers = {"From": "a@example.com", "Subject": "x"}
    if dmarc:
        headers["Authentication-Results"] = f"mx.example.org; dmarc={dmarc} header.from=example.com"
    if html:
        body = (f"--b\r\nContent-Type: text/plain\r\n\r\n{text}\r\n"
                f"--b\r\nContent-Type: text/html\r\n\r\n{html}\r\n--b--\r\n")
        e = email_from(headers, body, content_type='multipart/alternative; boundary="b"')
    else:
        e = email_from(headers, text)
    return {f.rule_id: f for f in links.detect(e)}


# --- MAIL-URL-001 link text vs destination ---

def test_link_text_url_differs_from_destination():
    f = _ids('<a href="http://login.example.net/x">https://accounts.example.com/signin</a>')["MAIL-URL-001"]
    assert f.severity is Severity.HIGH
    assert f.mitre_technique == "T1566.002"
    assert "accounts.example.com/signin -> http://login.example.net/x" in f.details["links"]


def test_link_text_domain_differs_from_destination():
    assert "MAIL-URL-001" in _ids('<a href="https://example.net/p">Sign in at example.com</a>')


def test_link_text_matching_destination_is_fine():
    assert _ids('<a href="https://www.example.com/blog/1">https://example.com/blog/1</a>') == {}


def test_link_to_subdomain_of_shown_domain_is_fine():
    assert _ids('<a href="https://news.example.com/x">example.com</a>') == {}


def test_plain_link_text_is_fine():
    assert _ids('<a href="https://example.net/x">Read the full post</a>') == {}


def test_click_tracking_from_authenticated_sender_is_low():
    f = _ids('<a href="https://click.esp.example.net/c?u=1">https://www.example.com/offer</a>', dmarc="pass")["MAIL-URL-001"]
    assert f.severity is Severity.LOW
    assert "click tracking" in f.details["note"]


def test_many_mismatched_links_score_once():
    html = "".join(f'<a href="https://example.net/{i}">https://example.com/{i}</a>' for i in range(8))
    f = _ids(html)["MAIL-URL-001"]
    assert f.score == 30
    assert "(+3 more)" in f.details["links"]


# --- MAIL-URL-002 bare IP ---

def test_link_to_ip_address():
    f = _ids(text="Verify here: http://203.0.113.45/login.php")["MAIL-URL-002"]
    assert f.severity is Severity.HIGH
    assert "203.0.113.45" in f.details["urls"]


def test_link_to_ip_written_as_a_number():
    assert "MAIL-URL-002" in _ids('<a href="http://3405803781/x">Open document</a>')


def test_link_to_domain_is_fine():
    assert "MAIL-URL-002" not in _ids(text="Docs: https://docs.example.com/v1.2.3/index.html")


# --- MAIL-URL-003 user-info trick ---

def test_userinfo_hides_real_host():
    f = _ids(text="Login: https://www.example.com@203.0.113.80/secure")["MAIL-URL-003"]
    assert f.severity is Severity.HIGH


def test_at_sign_in_path_or_query_is_fine():
    assert "MAIL-URL-003" not in _ids(text="https://example.com/users/@alice?ref=a@example.org")


# --- MAIL-URL-004 shorteners ---

def test_url_shortener():
    f = _ids(text="Track your parcel: https://bit.ly/abc123")["MAIL-URL-004"]
    assert f.severity is Severity.LOW


def test_lookalike_of_shortener_name_is_not_a_shortener():
    assert "MAIL-URL-004" not in _ids(text="https://notbit.ly.example.com/x")


# --- MAIL-URL-005 forms ---

def test_form_with_password_field():
    f = _ids('<form action="https://example.net/c"><input type="password" name="p"></form>')["MAIL-URL-005"]
    assert f.severity is Severity.HIGH
    assert f.mitre_technique == "T1598"


def test_form_without_password_is_medium():
    f = _ids('<form action="https://example.net/survey"><input name="q"></form>')["MAIL-URL-005"]
    assert f.severity is Severity.MEDIUM


def test_password_mentioned_in_text_without_form_is_not_a_form():
    assert "MAIL-URL-005" not in _ids("<p>Never share your password.</p>")


def test_no_body_no_findings():
    assert _ids() == {}
