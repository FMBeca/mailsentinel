# MailSentinel

![CI](https://github.com/FMBeca/mailsentinel/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**MailSentinel** is a command-line tool, with no required dependencies, that triages a suspicious
email saved as `.eml`. It reads the headers and body, checks what the receiving server said about
the sender's authentication, looks for signs of impersonation, and returns a scored verdict with
the reasons behind it, each mapped to **MITRE ATT&CK**.

> Status: under development towards v0.1. See [Roadmap](#roadmap).

## What it does, in plain terms

When someone reports a suspicious email, an analyst has to answer a few questions quickly: did
it really come from who it claims to be, where would a reply or a click go, and what should be
blocked. The answers are in the message itself, mostly in headers that email clients hide.
MailSentinel reads them and points out what does not add up, for example:

- the receiving server checked the sender's domain (SPF, DKIM, DMARC) and it failed;
- the name shown says "PayPal", or shows a company address, but the real address is somewhere else;
- replies would go to a different organisation than the one in the From line;
- the message was handed over by servers that do not belong to the sender's domain.

Each finding adds points to a risk score. The output is a verdict (clean, suspicious, likely
phishing), the evidence for it, and the indicators (domains, IPs) in a defanged form that can be
pasted into a ticket or chat without turning into clickable links.

## Detections

| Detection | Rule | Severity | MITRE ATT&CK | Status |
|---|---|---|---|---|
| SPF fail / soft fail | MAIL-AUTH-001 | High / Low | [T1566](https://attack.mitre.org/techniques/T1566/) | Done |
| DKIM signature failed | MAIL-AUTH-002 | Medium | [T1566](https://attack.mitre.org/techniques/T1566/) | Done |
| DMARC failed (From domain not authenticated) | MAIL-AUTH-003 | High | [T1566](https://attack.mitre.org/techniques/T1566/) | Done |
| Reply-To points to another organisation | MAIL-SND-001 | Medium | [T1566](https://attack.mitre.org/techniques/T1566/) | Done |
| Return-Path from another organisation, without DMARC pass | MAIL-SND-002 | Low | [T1566](https://attack.mitre.org/techniques/T1566/) | Done |
| Display name shows a different address or domain | MAIL-SND-003 | High | [T1656](https://attack.mitre.org/techniques/T1656/) | Done |
| Display name claims a brand the sender does not own | MAIL-SND-004 | Medium | [T1656](https://attack.mitre.org/techniques/T1656/) | Done |
| Lookalike sender domains (punycode, mixed scripts, edit distance) | | | [T1656](https://attack.mitre.org/techniques/T1656/) | Planned |
| Links whose visible text differs from the real destination | | | [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | Planned |
| URL and domain extraction from text and HTML | | | [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | Planned |
| Attachments: SHA-256, dangerous extensions, double extensions, macros | | | [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Planned |
| Requests for credentials or other information | | | [T1598](https://attack.mitre.org/techniques/T1598/) | Planned |

T1566 is Phishing; T1656 is Impersonation (pretending to be a trusted person or organisation).

## Installation

```bash
git clone https://github.com/FMBeca/mailsentinel.git
cd mailsentinel
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e .
```

## Usage

```bash
mailsentinel samples/phish-brand-spoof.eml           # table in the terminal
mailsentinel samples/phish-brand-spoof.eml --json    # JSON for scripts
mailsentinel message.eml --no-defang                 # show indicators as they are
cat message.eml | mailsentinel -                     # read from stdin
```

Example (synthetic sample, abridged):

```
From       : "PayPal" <security[@]account-verify[.]example[.]net>
Reply-To   : <helpdesk-resolution[@]example[.]org>
Return-Path: bounce-7731[@]mailer[.]example[.]org
Auth       : SPF softfail | DKIM none | DMARC fail

Verdict    : LIKELY PHISHING  (score 90/100)

[HIGH] DMARC failed: the From domain could not be authenticated (possible spoofing)  (MAIL-AUTH-003)
    +30 points  MITRE: T1566
    from_domain: account-verify[.]example[.]net

[MEDIUM] Display name claims a brand that does not match the sending domain  (MAIL-SND-004)
    +20 points  MITRE: T1656
    brand: PayPal
    from: security[@]account-verify[.]example[.]net
...
IOCs (defanged)
    sender domains: account-verify[.]example[.]net, example[.]org, mailer[.]example[.]org
    received IPs  : 192[.]0[.]2[.]77, 203[.]0[.]113[.]45  (oldest hop first)
```

To get an `.eml` file: in Outlook on the web or Thunderbird, use "Save as" / "Download"; in Gmail,
"Show original" then "Download original". Outlook desktop `.msg` files are not supported yet.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Clean |
| 1 | Suspicious or likely phishing (`--fail-on phishing` to exit 1 only for the latter) |
| 2 | The file cannot be read or is not an email |

### Scoring

Each finding adds its points; the score is capped at 100. A score of 20 or more is *suspicious*
(one strong signal, such as a DMARC failure), 50 or more is *likely phishing* (several signals
pointing the same way). The verdict supports a decision; it does not replace the analyst.

## How it works

- **Parsing** uses Python's `email` package. Address headers are read from the raw text, because
  the structured parser silently drops the address from a malformed header, and malformed headers
  are common in phishing.
- **Authentication results are read, not recomputed.** MailSentinel trusts only the topmost
  `Authentication-Results` header, the one added by the server that received the message. Headers
  further down were added earlier in the path, and a sender can write a fake `spf=pass` there.
- **Domains are compared by organisation** (`news.example.com` and `example.com` match), using a
  short built-in list of multi-label suffixes such as `co.uk` and `com.pt` instead of the full
  Public Suffix List.
- **No network access.** Nothing is looked up or sent anywhere; the analysis works offline on the
  file alone.
- **Missing evidence is not evidence.** A message without authentication headers gets no finding
  for it, and a file that does not look like an email is an error (exit code 2), never "clean".

## Roadmap

v0.1:

- [x] Parser for headers and text/HTML bodies; Received chain
- [x] SPF / DKIM / DMARC results and sender consistency rules
- [x] Scored verdict, table and JSON output, exit codes, defanged indicators
- [ ] URLs and domains from text and HTML, including links whose text differs from the destination
- [ ] Attachments with SHA-256 and dangerous or double extensions
- [ ] Lookalike sender domains

Later: Outlook `.msg` files, HTML report, optional reputation lookups.

## Samples and testing

All messages in `samples/` and in the tests are synthetic, written for this project, and use only
documentation domains (`example.com`, `.net`, `.org`) and IP ranges (RFC 5737, RFC 3849). Every
detection rule has tests for the malicious case and for legitimate mail that must not trigger it.

```bash
pip install -e ".[dev]"
pytest -q
ruff check .
```

Do not commit real emails: they contain other people's personal data. The `private/` folder is
ignored by git for local testing.

## License

MIT
