# WPT — Web Penetration Toolkit

![Python](https://img.shields.io/badge/Python-3.7+-3776AB?style=flat-square&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Version](https://img.shields.io/badge/Version-2.1.0-orange?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

A modular, CLI-first web application security scanner built for penetration testers and bug bounty hunters. WPT automates the reconnaissance and vulnerability discovery phase of a web assessment — covering DNS, SSL/TLS, headers, WAF fingerprinting, API endpoints, JavaScript analysis, cookies, and forms — and outputs structured reports you can drop straight into a pentest report.

> ⚠️ **Authorized use only.** Only run WPT against targets you own or have explicit written permission to test.

---

## What It Does

WPT runs 8 parallel scanning modules against a target and consolidates findings with severity ratings and remediation guidance. Output can be JSON, HTML, CSV, or plain text — making it easy to pipe into a report or feed into a SIEM.

```
$ wpt https://example.com -f html -o report.html

[*] Starting WPT scan on https://example.com
[*] Running 8 modules...

[+] DNS Enumeration         ✓  3 findings
[+] SSL/TLS Analysis        ✓  2 findings (1 HIGH)
[+] Security Headers        ✓  5 findings (2 HIGH, 3 MEDIUM)
[+] WAF Detection           ✓  Cloudflare detected
[+] API Discovery           ✓  4 endpoints found
[+] JavaScript Analysis     ✓  1 finding (CRITICAL - hardcoded secret)
[+] Cookie Security         ✓  2 findings
[+] Form Analysis           ✓  1 finding (CSRF token missing)

[*] Scan complete. 19 findings. Report saved to report.html
```

---

## Modules

| Module | What It Checks |
|---|---|
| **DNS Enumeration** | A/AAAA/MX/NS/TXT/SOA records, subdomain discovery, DNS misconfigs |
| **SSL/TLS Analysis** | Certificate validity, expiry, weak ciphers, TLS version support |
| **Security Headers** | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| **WAF Detection** | Cloudflare, AWS WAF, Akamai, Imperva, F5 BIG-IP fingerprinting |
| **API Discovery** | Common API paths, HTTP method enumeration, CORS policy checks |
| **JavaScript Analysis** | Hardcoded credentials, eval() usage, XSS vectors, data exposure |
| **Cookie Security** | Secure/HttpOnly/SameSite flags, session cookie analysis |
| **Form Analysis** | CSRF token detection, autocomplete, input validation patterns |

---

## Installation

```bash
git clone https://github.com/Dawn-Fighter/WPT.git
cd WPT
pip install -r requirements.txt

# Or install as a package (run `wpt` from anywhere)
pip install -e .
```

**Requirements:** Python 3.7+, pip

---

## Usage

```bash
# Basic scan
wpt example.com

# Generate HTML report
wpt example.com -o report.html -f html

# JSON output for tool chaining
wpt example.com -o scan.json -f json

# Verbose with custom threads and timeout
wpt https://example.com -v -t 10 --timeout 15

# CSV for spreadsheet analysis
wpt example.com -o findings.csv -f csv
```

### All Options

```
positional arguments:
  url                   Target domain or URL

optional arguments:
  -h, --help            Show help
  -t THREADS            Concurrent threads (default: 5)
  -v, --verbose         Verbose output
  -o OUTPUT             Output file path
  -f FORMAT             Output format: console | txt | json | html | csv
  --timeout TIMEOUT     Request timeout in seconds (default: 10)
```

---

## Output Formats

**HTML** — Styled report with color-coded severities. Good for client deliverables.

**JSON** — Machine-readable. Pipe into other tools or a SIEM.

**CSV** — Flat findings list. Import into Excel or Notion for triage.

**TXT** — Plain text. Drop into a pentest report doc.

---

## Severity Levels

Every finding is tagged with a severity:

| Level | Color | Meaning |
|---|---|---|
| CRITICAL | 🔴 | Immediate risk — hardcoded secrets, RCE vectors |
| HIGH | 🟠 | Significant attack surface — missing HSTS, weak TLS |
| MEDIUM | 🟡 | Should be fixed — missing headers, CORS issues |
| LOW | 🔵 | Best practice gaps |
| INFO | ⚪ | Informational — WAF detected, tech stack |

---

## Extending WPT

Adding a new scanner module takes about 10 lines:

```python
from wpt.modules.base_module import BaseModule, Finding, Severity

class CustomScanner(BaseModule):
    def scan(self):
        # your logic here
        self.add_finding(
            category='Custom Check',
            description='Found something interesting',
            severity=Severity.MEDIUM,
            recommendation='Here is how to fix it'
        )
        return self.findings
```

Drop it in `wpt/modules/` and register it in `core/scanner.py`. That's it.

---

## Project Structure

```
WPT/
├── wpt/
│   ├── core/
│   │   ├── scanner.py        # Orchestrates all modules
│   │   └── reporter.py       # Report generation (HTML/JSON/CSV/TXT)
│   ├── modules/
│   │   ├── base_module.py
│   │   ├── dns_scanner.py
│   │   ├── ssl_scanner.py
│   │   ├── headers_scanner.py
│   │   ├── waf_detector.py
│   │   ├── api_scanner.py
│   │   ├── js_analyzer.py
│   │   ├── cookie_analyzer.py
│   │   └── form_analyzer.py
│   └── utils/
│       ├── logger.py
│       ├── exceptions.py
│       └── constants.py
├── tests/
├── requirements.txt
└── wpt.py                    # Legacy entry point
```

---

## Roadmap

- [ ] XSS scanner module
- [ ] SQLi detection
- [ ] Directory bruteforcer
- [ ] Technology fingerprinting (Wappalyzer-style)
- [ ] CVSS score per finding
- [ ] CI/CD pipeline integration
- [ ] Plugin system

---

## Disclaimer

WPT is built for authorized security testing, research, and education. Do not use it against systems without explicit written permission. The author takes no responsibility for misuse.

---

## Author

**Chethas Dileep** — Penetration Tester & Security Developer

[![GitHub](https://img.shields.io/badge/GitHub-Dawn--Fighter-181717?style=flat-square&logo=github)](https://github.com/Dawn-Fighter)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-chethas--dileep-0077B5?style=flat-square&logo=linkedin)](https://www.linkedin.com/in/chethas-dileep-530722211)
[![Portfolio](https://img.shields.io/badge/Portfolio-edneam.site-FF4500?style=flat-square&logo=firefox)](http://www.edneam.site)
