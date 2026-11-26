"""Command-line interface.

    mailsentinel message.eml                 # table in the terminal
    mailsentinel message.eml --json          # JSON for scripts and SOAR playbooks
    mailsentinel message.eml --no-defang     # show IOCs as they are (careful: clickable)
    cat message.eml | mailsentinel -         # read from stdin

Exit codes: 0 clean, 1 suspicious or phishing (see --fail-on), 2 the input is not an email
or cannot be read.
"""
from __future__ import annotations

import argparse
import json
import sys

from mailsentinel import __version__
from mailsentinel.analysis import Analysis, analyze
from mailsentinel.models import Verdict
from mailsentinel.parser import NotAnEmailError, parse_bytes

_COLORS = {"low": "\033[36m", "medium": "\033[33m", "high": "\033[31m", "critical": "\033[1;41m",
           "clean": "\033[32m", "suspicious": "\033[33m", "phishing": "\033[1;41m"}
_RESET = "\033[0m"
MAX_URLS_SHOWN = 15
_LABELS = {Verdict.CLEAN: "CLEAN", Verdict.SUSPICIOUS: "SUSPICIOUS", Verdict.PHISHING: "LIKELY PHISHING"}


def _paint(text: str, key: str, color: bool) -> str:
    return f"{_COLORS[key]}{text}{_RESET}" if color else text


def _print_table(result: Analysis, source: str, safe: bool, color: bool) -> None:
    d = result.to_dict(safe=safe)
    h, a = d["headers"], d["authentication"]
    print(f"File       : {source}")
    print(f"Subject    : {h['subject']}")
    print(f"From       : {h['from'] or '(missing)'}")
    if h["reply_to"]:
        print(f"Reply-To   : {', '.join(h['reply_to'])}")
    if h["return_path"]:
        print(f"Return-Path: {h['return_path']}")
    auth = f"SPF {a['spf']} | DKIM {a['dkim']} | DMARC {a['dmarc']}"
    print(f"Auth       : {auth}" + ("" if a["source"] != "absent" else "  (no authentication headers)"))
    print()
    verdict = _paint(_LABELS[result.verdict], result.verdict.value, color)
    print(f"Verdict    : {verdict}  (score {d['score']}/100)")
    print()

    for f in d["findings"]:
        sev = _paint(f["severity"].upper(), f["severity"], color)
        print(f"[{sev}] {f['title']}  ({f['rule_id']})")
        print(f"    +{f['score']} points  MITRE: {f['mitre_technique']}")
        for key, value in f["details"].items():
            if value:
                print(f"    {key}: {value}")
        print()
    if not d["findings"]:
        print("No phishing indicators found.")
        print()

    iocs = d["iocs"]
    if any(iocs.values()):
        print("IOCs" + (" (defanged)" if safe else ""))
        if iocs["sender_domains"]:
            print(f"    sender domains: {', '.join(iocs['sender_domains'])}")
        if iocs["received_ips"]:
            print(f"    received IPs  : {', '.join(iocs['received_ips'])}  (oldest hop first)")
        if iocs["url_domains"]:
            print(f"    URL domains   : {', '.join(iocs['url_domains'])}")
        for u in iocs["urls"][:MAX_URLS_SHOWN]:
            shown_as = f'  (shown as "{u["text"]}")' if u["text"] and u["text"] != u["url"] else ""
            print(f"    URL           : {u['url']}{shown_as}")
        if len(iocs["urls"]) > MAX_URLS_SHOWN:
            print(f"    ... {len(iocs['urls']) - MAX_URLS_SHOWN} more URLs (use --json for all)")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mailsentinel", description="Triage a suspicious email (.eml).")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("eml", help="Path to the .eml file, or '-' for stdin")
    p.add_argument("--json", action="store_true", help="Output JSON")
    p.add_argument("--no-defang", action="store_true", help="Show URLs, domains and IPs as they are")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--fail-on", choices=["suspicious", "phishing"], default="suspicious",
                   help="Lowest verdict that makes the exit code 1 (default: suspicious)")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    # Subjects and names can hold any character; never crash on a console that can't show it.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    try:
        if args.eml == "-":
            data = sys.stdin.buffer.read()
        else:
            with open(args.eml, "rb") as fh:
                data = fh.read()
        email = parse_bytes(data)
    except OSError as exc:
        print(f"mailsentinel: cannot read {args.eml}: {exc.strerror or exc}", file=sys.stderr)
        return 2
    except NotAnEmailError as exc:
        print(f"mailsentinel: {args.eml}: {exc}", file=sys.stderr)
        return 2

    result = analyze(email)
    safe = not args.no_defang
    if args.json:
        print(json.dumps({"file": args.eml, **result.to_dict(safe=safe)}, indent=2))  # ASCII-only: safe in any console or pipe
    else:
        _print_table(result, args.eml, safe, color=not args.no_color and sys.stdout.isatty())

    threshold = Verdict.SUSPICIOUS if args.fail_on == "suspicious" else Verdict.PHISHING
    order = [Verdict.CLEAN, Verdict.SUSPICIOUS, Verdict.PHISHING]
    return 1 if order.index(result.verdict) >= order.index(threshold) else 0


if __name__ == "__main__":
    raise SystemExit(main())
