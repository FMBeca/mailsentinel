"""Generate the attachment samples in samples/ (run from the repository root).

    python scripts/make_attachment_samples.py

The attachments are harmless placeholders: a one-line JavaScript comment, a few bytes named
.lnk inside a ZIP, a minimal PDF and a tiny PNG header. They only need the names and the
first bytes of real files for the detection rules to have something to look at.
Output is deterministic (fixed MIME boundaries and ZIP timestamps), so re-running it does
not change the files.
"""
from __future__ import annotations

import io
import zipfile
from email.message import EmailMessage
from email.policy import SMTP
from pathlib import Path

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
ZIP_TIME = (2026, 11, 24, 9, 0, 0)


def _zip(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(zipfile.ZipInfo(name, ZIP_TIME), data)
    return buf.getvalue()


def _fix_boundaries(msg: EmailMessage, prefix: str) -> None:
    for i, part in enumerate(msg.walk()):
        if part.is_multipart():
            part.set_boundary(f"{prefix}_{i}")


def phishing() -> EmailMessage:
    msg = EmailMessage()
    msg["Return-Path"] = "<ap@supplier-invoices.example.net>"
    msg["Authentication-Results"] = (
        "mx.example.com; spf=pass smtp.mailfrom=supplier-invoices.example.net; dkim=none; "
        "dmarc=none header.from=supplier-invoices.example.net"
    )
    msg["Received"] = (
        "from smtp.supplier-invoices.example.net (smtp.supplier-invoices.example.net [203.0.113.120]) "
        "by mx.example.com with ESMTP id 5d4c3b2a; Tue, 24 Nov 2026 10:21:07 +0000"
    )
    msg["From"] = '"Accounts Payable" <ap@supplier-invoices.example.net>'
    msg["To"] = "finance@example.com"
    msg["Subject"] = "Overdue invoice 2026-11 - payment details attached"
    msg["Date"] = "Tue, 24 Nov 2026 10:21:05 +0000"
    msg["Message-ID"] = "<inv-2026-11-0042@supplier-invoices.example.net>"
    msg.set_content(
        "Hello,\n\nPlease find attached the overdue invoice and the remittance advice.\n"
        "Payment is due today to avoid late fees.\n\nAccounts Payable\n"
    )
    msg.add_attachment(b"// Harmless placeholder written for MailSentinel tests. It does nothing.\n",
                       maintype="application", subtype="javascript", filename="Invoice_2026-11.pdf.js")
    msg.add_attachment(_zip({"Remittance_Advice.pdf.lnk": b"placeholder, not a real shortcut\n"}),
                       maintype="application", subtype="zip", filename="Remittance.zip")
    _fix_boundaries(msg, "att_phish")
    return msg


def legitimate() -> EmailMessage:
    msg = EmailMessage()
    msg["Return-Path"] = "<billing@example.com>"
    msg["Authentication-Results"] = (
        "mx.example.org; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com header.s=b1; "
        "dmarc=pass (p=REJECT) header.from=example.com"
    )
    msg["Received"] = (
        "from mail.example.com (mail.example.com [198.51.100.10]) by mx.example.org with ESMTPS id 1a2b3c; "
        "Wed, 25 Nov 2026 09:00:03 +0000"
    )
    msg["From"] = '"Example Billing" <billing@example.com>'
    msg["To"] = "customer@example.org"
    msg["Subject"] = "Your November invoice and updated contract"
    msg["Date"] = "Wed, 25 Nov 2026 09:00:00 +0000"
    msg["Message-ID"] = "<invoice-2026-11-7781@example.com>"
    msg.set_content("Hello,\n\nYour November invoice and the updated contract are attached.\n\nExample Billing\n")
    msg.add_alternative('<html><body><img src="cid:logo"><p>Your November invoice and the updated contract '
                        "are attached.</p></body></html>", subtype="html")
    msg.get_payload()[1].add_related(b"\x89PNG\r\n\x1a\n" + b"\x00" * 24, maintype="image", subtype="png",
                                     cid="<logo>", filename="logo.png", disposition="inline")
    pdf = b"%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF\n"
    msg.add_attachment(pdf, maintype="application", subtype="pdf", filename="invoice-2026-11.pdf")
    docx = _zip({"[Content_Types].xml": b"<Types/>", "word/document.xml": b"<w:document/>"})
    msg.add_attachment(docx, maintype="application",
                       subtype="vnd.openxmlformats-officedocument.wordprocessingml.document", filename="contract.docx")
    _fix_boundaries(msg, "att_legit")
    return msg


def main() -> None:
    for name, msg in (("phish-attachment.eml", phishing()), ("legit-invoice.eml", legitimate())):
        (SAMPLES / name).write_bytes(msg.as_bytes(policy=SMTP))
        print(f"wrote samples/{name}")


if __name__ == "__main__":
    main()
