"""Attachments: would opening the file run code, or hide what it really is?

    MAIL-ATT-001  Executable or script (.exe, .js, .lnk, .hta...)          High
    MAIL-ATT-002  Disk image (.iso, .img, .vhd)                            High
    MAIL-ATT-003  Office document with macros (by extension or content)    High
    MAIL-ATT-004  HTML / SVG file (local phishing page, HTML smuggling)    Medium
    MAIL-ATT-005  Filename disguises its type (double extension, RLO)      High
    MAIL-ATT-006  Content is an executable but the extension says not      High
    MAIL-ATT-007  Archive with a dangerous file inside / password-protected  High / Medium

All map to T1566.001 (Spearphishing Attachment). Files are never opened or run: see files.py.
"""
from __future__ import annotations

from mailsentinel import files
from mailsentinel.models import Attachment, Finding, ParsedEmail, Severity

PHISHING_ATTACHMENT = "T1566.001"
MAX_EXAMPLES = 5


def _names(items: list[Attachment]) -> str:
    names = list(dict.fromkeys(files.display_name(a.filename) or "(no name)" for a in items))
    shown = ", ".join(names[:MAX_EXAMPLES])
    return shown + (f" (+{len(names) - MAX_EXAMPLES} more)" if len(names) > MAX_EXAMPLES else "")


def _finding(rule_id: str, title: str, severity: Severity, score: int, items: list[Attachment], **extra: str) -> Finding:
    return Finding(rule_id, title, severity, score, PHISHING_ATTACHMENT, {"files": _names(items), **extra})


def _dangerous_inside(a: Attachment) -> list[str]:
    bad = files.EXECUTABLE | files.DISK_IMAGE | files.MACRO_OFFICE | files.HTML
    return [n for n in a.archive_names if files.extension(n) in bad or files.disguise(n)]


def detect(email: ParsedEmail) -> list[Finding]:
    atts = email.attachments
    ext = {id(a): files.extension(a.filename) for a in atts}
    findings: list[Finding] = []

    executables = [a for a in atts if ext[id(a)] in files.EXECUTABLE]
    if executables:
        findings.append(_finding("MAIL-ATT-001", "Executable or script attachment", Severity.HIGH, 40, executables))

    images = [a for a in atts if ext[id(a)] in files.DISK_IMAGE or a.magic == "iso"]
    if images:
        findings.append(_finding("MAIL-ATT-002", "Disk image attachment (can bypass download warnings)",
                                 Severity.HIGH, 30, images))

    macros = [a for a in atts if ext[id(a)] in files.MACRO_OFFICE or a.has_macros]
    if macros:
        findings.append(_finding("MAIL-ATT-003", "Office document with macros", Severity.HIGH, 30, macros))

    html = [a for a in atts if ext[id(a)] in files.HTML]
    if html:
        findings.append(_finding("MAIL-ATT-004", "HTML or SVG attachment (local phishing page or HTML smuggling)",
                                 Severity.MEDIUM, 20, html))

    disguised = [(a, files.disguise(a.filename)) for a in atts]
    disguised = [(a, why) for a, why in disguised if why]
    if disguised:
        findings.append(_finding("MAIL-ATT-005", "Attachment name disguises its real file type", Severity.HIGH, 30,
                                 [a for a, _ in disguised], reason=disguised[0][1]))

    mismatch = [a for a in atts if a.magic in ("pe", "elf") and ext[id(a)] not in files.EXECUTABLE]
    if mismatch:
        findings.append(_finding("MAIL-ATT-006", "Attachment is an executable despite its extension", Severity.HIGH, 35,
                                 mismatch, real_type="Windows executable" if mismatch[0].magic == "pe" else "Linux executable"))

    # Office files (.docx, .xlsx) are ZIPs too, but their parts are not files a user would open.
    archives = [a for a in atts if a.archive_names and files.is_archive(a.filename, a.magic)]
    inside = [(a, _dangerous_inside(a)) for a in archives]
    inside = [(a, names) for a, names in inside if names]
    if inside:
        listed = ", ".join(files.display_name(n) for _, names in inside for n in names[:MAX_EXAMPLES])
        findings.append(_finding("MAIL-ATT-007", "Archive contains an executable, script or other dangerous file",
                                 Severity.HIGH, 35, [a for a, _ in inside], archive_contents=listed))
    else:
        locked = [a for a in atts if a.encrypted]
        if locked:
            findings.append(_finding("MAIL-ATT-007", "Password-protected archive (mail gateways cannot scan it)",
                                     Severity.MEDIUM, 20, locked))

    return findings
