from email.message import EmailMessage

import pytest
from test_files import make_zip

from mailsentinel.detectors import attachments
from mailsentinel.models import Severity
from mailsentinel.parser import parse_bytes

PDF = b"%PDF-1.4\n%%EOF\n"
OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64


def _email(*files: tuple[str, bytes], inline: bool = False):
    msg = EmailMessage()
    msg["From"] = "a@example.com"
    msg["Subject"] = "files"
    msg.set_content("See attached.\n")
    for name, data in files:
        msg.add_attachment(data, maintype="application", subtype="octet-stream", filename=name,
                           disposition="inline" if inline else "attachment")
    return parse_bytes(msg.as_bytes())


def _ids(*files, **kw):
    return {f.rule_id: f for f in attachments.detect(_email(*files, **kw))}


def test_parser_reads_attachments():
    e = _email(("invoice.pdf", PDF))
    assert [(a.filename, a.size, a.magic) for a in e.attachments] == [("invoice.pdf", len(PDF), "pdf")]
    assert "See attached." in e.text_body


def test_encoded_filename_is_decoded():
    msg = EmailMessage()
    msg["From"] = "a@example.com"
    msg.set_content("x")
    msg.add_attachment(PDF, maintype="application", subtype="pdf", filename="Relatório_Março.pdf")
    assert parse_bytes(msg.as_bytes()).attachments[0].filename == "Relatório_Março.pdf"


# --- legitimate attachments: no findings ---

@pytest.mark.parametrize("name, data", [
    ("invoice.pdf", PDF),
    ("contract.docx", make_zip({"word/document.xml": b"<w/>"})),
    ("budget.xls", OLE),
    ("photos.zip", make_zip({"beach.jpg": b"\xff\xd8", "notes.txt": b"x"})),
    ("report.final.v2.pdf", PDF),
])
def test_ordinary_attachments_are_fine(name, data):
    assert _ids((name, data)) == {}


def test_inline_logo_is_fine():
    assert _ids(("logo.png", b"\x89PNG\r\n\x1a\n"), inline=True) == {}


# --- MAIL-ATT-001 executables and scripts ---

@pytest.mark.parametrize("name", ["setup.exe", "invoice.js", "Document.lnk", "update.hta", "run.ps1", "a.vbs", "notes.one"])
def test_executable_or_script(name):
    f = _ids((name, b"x"))["MAIL-ATT-001"]
    assert f.severity is Severity.HIGH
    assert f.mitre_technique == "T1566.001"


def test_trailing_dot_does_not_hide_executable():
    assert "MAIL-ATT-001" in _ids(("invoice.exe.", b"x"))


# --- MAIL-ATT-002 disk images ---

def test_disk_image_by_extension():
    assert "MAIL-ATT-002" in _ids(("Shipping_Docs.iso", b"x"))


def test_disk_image_by_content():
    assert "MAIL-ATT-002" in _ids(("Shipping_Docs.dat", b"\x00" * 0x8001 + b"CD001"))


# --- MAIL-ATT-003 macros ---

def test_macro_enabled_extension():
    assert "MAIL-ATT-003" in _ids(("Payroll.xlsm", make_zip({"xl/workbook.xml": b"x"})))


def test_macros_hidden_in_a_docx():
    assert "MAIL-ATT-003" in _ids(("CV.docx", make_zip({"word/vbaProject.bin": b"x"})))


def test_macros_in_legacy_doc():
    assert "MAIL-ATT-003" in _ids(("Order.doc", OLE + "_VBA_PROJECT".encode("utf-16-le")))


# --- MAIL-ATT-004 HTML / SVG ---

@pytest.mark.parametrize("name", ["Voicemail.html", "Fax_0042.htm", "Payment.svg"])
def test_html_attachment(name):
    assert _ids((name, b"<html></html>"))["MAIL-ATT-004"].severity is Severity.MEDIUM


# --- MAIL-ATT-005 disguised names ---

def test_double_extension():
    f = _ids(("Invoice_2026.pdf.exe", b"x"))["MAIL-ATT-005"]
    assert "double extension" in f.details["reason"]


def test_right_to_left_override_is_shown_safely():
    f = _ids(("invoice‮fdp.exe", b"x"))["MAIL-ATT-005"]
    assert "<U+202E>" in f.details["files"]
    assert "‮" not in f.details["files"]


def test_dotted_but_honest_name_is_fine():
    assert "MAIL-ATT-005" not in _ids(("minutes.2026.11.pdf", PDF))


# --- MAIL-ATT-006 executable content under another extension ---

def test_executable_renamed_to_pdf():
    f = _ids(("invoice.pdf", b"MZ\x90\x00" + b"\x00" * 60))["MAIL-ATT-006"]
    assert f.details["real_type"] == "Windows executable"


def test_real_executable_is_not_a_mismatch():
    assert "MAIL-ATT-006" not in _ids(("setup.exe", b"MZ\x90\x00"))


# --- MAIL-ATT-007 archives ---

def test_archive_with_dangerous_file_inside():
    f = _ids(("Remittance.zip", make_zip({"Remittance.pdf.lnk": b"x"})))["MAIL-ATT-007"]
    assert f.severity is Severity.HIGH
    assert f.details["archive_contents"] == "Remittance.pdf.lnk"


def test_password_protected_archive():
    f = _ids(("Invoice.zip", make_zip({"Invoice.pdf": PDF}, encrypted=True)))["MAIL-ATT-007"]
    assert f.severity is Severity.MEDIUM


def test_dangerous_inside_wins_over_encrypted():
    f = _ids(("x.zip", make_zip({"a.exe": b"x"}, encrypted=True)))["MAIL-ATT-007"]
    assert f.severity is Severity.HIGH


def test_office_document_parts_are_not_archive_contents():
    # .docx is a ZIP whose parts may include .bin or .xml files: not "files inside an archive".
    assert "MAIL-ATT-007" not in _ids(("a.docx", make_zip({"word/embeddings/oleObject1.bin": b"x"})))


# --- scoring ---

def test_many_attachments_score_once_per_rule():
    ids = _ids(*[(f"tool{i}.exe", b"x") for i in range(7)])
    assert ids["MAIL-ATT-001"].score == 40
    assert "(+2 more)" in ids["MAIL-ATT-001"].details["files"]
