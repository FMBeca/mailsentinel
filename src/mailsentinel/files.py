"""Look at attachment names and contents without opening or running anything.

Nothing is extracted or executed: archives are only listed, Office files are only searched
for the name of a VBA project, and the type is read from the first bytes ("magic numbers").
"""
from __future__ import annotations

import hashlib
import io
import re
import unicodedata
import zipfile

from mailsentinel.models import Attachment

# Run code when opened on Windows (or with a double click on most systems).
EXECUTABLE = frozenset({
    "exe", "scr", "com", "pif", "bat", "cmd", "msi", "msp", "dll", "cpl", "sys", "jar",
    "js", "jse", "vbs", "vbe", "wsf", "wsh", "hta", "ps1", "psm1", "lnk", "reg", "chm",
    "msc", "scf", "url", "application", "appref-ms", "gadget", "inf", "xll", "one",
})
# Disk images: Windows mounts them with a double click, and files inside used to lose the
# "downloaded from the internet" mark that triggers SmartScreen and Protected View.
DISK_IMAGE = frozenset({"iso", "img", "vhd", "vhdx"})
MACRO_OFFICE = frozenset({"docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam", "ppsm", "sldm"})
HTML = frozenset({"htm", "html", "shtml", "xhtml", "svg", "mht", "mhtml"})
ARCHIVE = frozenset({"zip", "rar", "7z", "gz", "tgz", "tar", "ace", "cab", "arj", "xz", "bz2", "z", "lzh"})
# Extensions people trust, used as decoys in "invoice.pdf.exe".
DECOY = frozenset({
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "txt", "csv", "odt", "ods",
    "jpg", "jpeg", "png", "gif", "bmp", "tif", "tiff", "mp3", "mp4", "wav", "zip", "rar",
})

_BIDI = re.compile("[‎‏‪-‮⁦-⁩]")
_PADDING = re.compile(r"\s{3,}\.?[A-Za-z0-9]+$|_{5,}\.?[A-Za-z0-9]+$")
_VBA_OLE = "_VBA_PROJECT".encode("utf-16-le")


def display_name(filename: str) -> str:
    """Filename safe to print: control and bidirectional characters become visible tags.

    U+202E (right-to-left override) makes "invoice‮fdp.exe" display as "invoiceexe.pdf";
    printing it raw would let the trick work on the analyst's own screen.
    """
    out = []
    for ch in filename:
        if _BIDI.match(ch) or unicodedata.category(ch) == "Cc":
            out.append(f"<U+{ord(ch):04X}>")
        else:
            out.append(ch)
    return "".join(out)


def extensions(filename: str) -> list[str]:
    """Lowercased extensions, last one = the one Windows uses.

    Trailing dots and spaces are dropped (Windows ignores them: "a.exe. " runs as "a.exe"),
    and so are bidirectional control characters.
    """
    name = _BIDI.sub("", filename).strip().rstrip(". ")
    name = name.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    parts = [p.strip().lower() for p in name.split(".")[1:]]
    return [p for p in parts if p]


def extension(filename: str) -> str:
    exts = extensions(filename)
    return exts[-1] if exts else ""


def disguise(filename: str) -> str:
    """Why a filename hides its real type, or "" if it does not."""
    if _BIDI.search(filename):
        return "right-to-left override character reverses part of the name"
    exts = extensions(filename)
    if len(exts) >= 2 and exts[-1] in EXECUTABLE | DISK_IMAGE | HTML and exts[-2] in DECOY:
        return f"double extension: looks like .{exts[-2]}, is .{exts[-1]}"
    stem = _BIDI.sub("", filename).strip().rstrip(". ")
    if exts and exts[-1] in EXECUTABLE and _PADDING.search(stem):
        return "padding before the extension pushes it out of view"
    return ""


def magic(data: bytes) -> str:
    if data.startswith(b"MZ"):
        return "pe"
    if data.startswith(b"\x7fELF"):
        return "elf"
    if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06"):
        return "zip"
    if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"
    if data[:1024].lstrip().startswith(b"%PDF") or b"%PDF-" in data[:1024]:
        return "pdf"
    if data.startswith(b"Rar!\x1a\x07"):
        return "rar"
    if data.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if data[0x8001:0x8006] == b"CD001":
        return "iso"
    return ""


# Extensions whose files legitimately are ZIP or OLE containers.
_ZIP_BASED = ARCHIVE | {"docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "dotx", "dotm", "xltx", "xltm", "xlam",
                        "potx", "potm", "ppsx", "ppsm", "ppam", "sldm", "odt", "ods", "odp", "epub", "jar", "apk", "xpi"}
_OLE_BASED = {"doc", "xls", "ppt", "dot", "xlt", "pot", "pps", "msg", "msi", "msp", "one"}


def type_mismatch(filename: str, kind: str) -> bool:
    """True when the real type read from the content does not match the extension."""
    ext = extension(filename)
    if not kind or kind == ext:
        return False
    return not ((kind == "zip" and ext in _ZIP_BASED) or (kind == "ole" and ext in _OLE_BASED)
                or (kind == "pe" and ext in EXECUTABLE) or (kind == "iso" and ext in DISK_IMAGE))


def is_archive(filename: str, kind: str) -> bool:
    """A real archive (as opposed to an Office file, which is also a ZIP)."""
    ext = extension(filename)
    return ext in ARCHIVE or (kind in ("zip", "rar", "7z") and not ext)


def _zip_info(data: bytes) -> tuple[tuple[str, ...], bool]:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()[:1000]       # names only: nothing is decompressed
    except (zipfile.BadZipFile, ValueError, OSError, EOFError):
        return (), False
    return tuple(i.filename for i in infos), any(i.flag_bits & 0x1 for i in infos)


def inspect(filename: str, content_type: str, data: bytes, inline: bool = False) -> Attachment:
    kind = magic(data)
    names: tuple[str, ...] = ()
    encrypted = False
    if kind == "zip":
        names, encrypted = _zip_info(data)
    # Macros: a VBA project inside an OOXML zip (even if renamed to .docx), or in an old OLE file.
    has_macros = any(n.lower().endswith("vbaproject.bin") for n in names) or (kind == "ole" and _VBA_OLE in data)
    return Attachment(
        filename=filename,
        content_type=content_type,
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        inline=inline,
        magic=kind,
        archive_names=names,
        encrypted=encrypted,
        has_macros=has_macros,
    )
