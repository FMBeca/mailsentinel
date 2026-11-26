import hashlib
import io
import zipfile

import pytest

from mailsentinel import files


def make_zip(names: dict[str, bytes], encrypted: bool = False) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in names.items():
            zf.writestr(name, data)
    data = bytearray(buf.getvalue())
    if encrypted:
        # zipfile cannot write encrypted archives: set the "encrypted" flag bit by hand,
        # in every local header (offset 6) and central directory entry (offset 8).
        for sig, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            i = data.find(sig)
            while i != -1:
                data[i + offset] |= 0x1
                i = data.find(sig, i + 4)
    return bytes(data)


@pytest.mark.parametrize("name, exts", [
    ("invoice.pdf", ["pdf"]),
    ("Invoice.PDF.exe", ["pdf", "exe"]),
    ("archive.tar.gz", ["tar", "gz"]),
    ("run.exe.  ", ["exe"]),                  # Windows ignores trailing dots and spaces
    ("noextension", []),
    ("folder/inner.js", ["js"]),
    ("C:\\Users\\x\\a.hta", ["hta"]),
])
def test_extensions(name, exts):
    assert files.extensions(name) == exts


@pytest.mark.parametrize("name", [
    "invoice.pdf.exe",
    "photo.jpg.scr",
    "scan.PDF.iso",
    "statement.docx.html",
    "invoice\u202efdp.exe",                  # displays as "invoiceexe.pdf"
    "document.pdf                         .exe",
    "document_____________.js",
])
def test_disguised_names(name):
    assert files.disguise(name)


@pytest.mark.parametrize("name", [
    "report.final.pdf",
    "backup.tar.gz",
    "setup.exe",                              # dangerous, but not disguised (ATT-001 covers it)
    "v1.2.3.zip",
    "Q3 results.xlsx",
    "minutes of meeting.docx",
])
def test_honest_names(name):
    assert files.disguise(name) == ""


def test_display_name_makes_bidi_and_control_characters_visible():
    assert files.display_name("invoice\u202efdp.exe") == "invoice<U+202E>fdp.exe"
    assert files.display_name("a\x07b.txt") == "a<U+0007>b.txt"
    assert files.display_name("Relatório.pdf") == "Relatório.pdf"


@pytest.mark.parametrize("data, kind", [
    (b"MZ\x90\x00", "pe"),
    (b"\x7fELF\x02", "elf"),
    (make_zip({"a.txt": b"x"}), "zip"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 8, "ole"),
    (b"%PDF-1.7\n", "pdf"),
    (b"\r\n%PDF-1.4", "pdf"),
    (b"Rar!\x1a\x07\x01\x00", "rar"),
    (b"\x00" * 0x8001 + b"CD001", "iso"),
    (b"hello", ""),
    (b"", ""),
])
def test_magic(data, kind):
    assert files.magic(data) == kind


def test_inspect_hashes_and_sizes():
    a = files.inspect("a.txt", "text/plain", b"hello")
    assert a.sha256 == hashlib.sha256(b"hello").hexdigest()
    assert a.size == 5


def test_inspect_lists_zip_contents_without_extracting():
    a = files.inspect("x.zip", "application/zip", make_zip({"one.txt": b"1", "dir/two.js": b"2"}))
    assert a.archive_names == ("one.txt", "dir/two.js")
    assert not a.encrypted


def test_inspect_detects_encrypted_zip():
    assert files.inspect("x.zip", "application/zip", make_zip({"a.exe": b"x"}, encrypted=True)).encrypted


def test_broken_zip_does_not_crash():
    a = files.inspect("x.zip", "application/zip", b"PK\x03\x04garbage")
    assert a.archive_names == ()


def test_macros_in_ooxml_even_when_renamed():
    a = files.inspect("report.docx", "application/octet-stream", make_zip({"word/vbaProject.bin": b"x"}))
    assert a.has_macros


def test_macros_in_legacy_ole_document():
    data = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64 + "_VBA_PROJECT".encode("utf-16-le")
    assert files.inspect("old.doc", "application/msword", data).has_macros


def test_plain_office_files_have_no_macros():
    assert not files.inspect("a.docx", "x", make_zip({"word/document.xml": b"<w/>"})).has_macros
    assert not files.inspect("a.doc", "x", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64).has_macros


@pytest.mark.parametrize("name, kind, mismatch", [
    ("invoice.pdf", "pe", True),
    ("contract.docx", "zip", False),
    ("old.xls", "ole", False),
    ("setup.exe", "pe", False),
    ("photo.jpg", "zip", True),
    ("notes.txt", "", False),
])
def test_type_mismatch(name, kind, mismatch):
    assert files.type_mismatch(name, kind) is mismatch
