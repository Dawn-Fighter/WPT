# WPT v2.0 Quick Start Guide

## Installation

```bash
# Clone the repository
git clone https://github.com/Dawn-Fighter/WPT.git
cd WPT

# Install dependencies
pip install -r requirements.txt

# Optional: Install as package (recommended)
pip install -e .
```

## Basic Usage

### Method 1: Using the wpt command (after package install)
```bash
wpt example.com
```

### Method 2: Using Python module
```bash
python3 -m wpt example.com
```

### Method 3: Using the script directly
```bash
python3 wpt.py example.com
```

## Common Use Cases

### 1. Quick Security Scan
```bash
wpt example.com
```
Output: Console report with findings organized by category

### 2. Verbose Scan with Details
```bash
wpt example.com -v
```
Output: Detailed logging showing progress and debug information

### 3. Generate HTML Report
```bash
wpt example.com -o report.html -f html
```
Output: Beautiful HTML report at `report.html`

### 4. Export to JSON for Automation
```bash
wpt example.com -o scan.json -f json
```
Output: Machine-readable JSON at `scan.json`

### 5. CSV Report for Analysis
```bash
wpt example.com -o findings.csv -f csv
```
Output: Spreadsheet-compatible CSV file

### 6. Full-Featured Scan
```bash
wpt https://example.com -v -t 10 --timeout 15 -o report.html -f html
```
- Verbose logging enabled
- 10 concurrent threads
- 15-second request timeout
- HTML report output

## Understanding the Output

### Severity Levels
- **[!!!] CRITICAL**: Immediate action required
- **[!!] HIGH**: Important security issue
- **[!] MEDIUM**: Notable concern
- **[*] LOW**: Minor issue
- **[i] INFO**: Informational finding

### Finding Categories
- **DNS Records**: Domain configuration
- **Subdomain Discovery**: Found subdomains
- **SSL/TLS**: Certificate and encryption status
- **WAF Detection**: Web Application Firewall presence
- **API Discovery**: API endpoints found
- **JavaScript Security**: JS code vulnerabilities
- **Cookie Security**: Cookie configuration issues
- **Form Security**: Form validation concerns

## Troubleshooting

### Issue: Import errors when running
**Solution**: Install dependencies
```bash
pip install -r requirements.txt
```

### Issue: Selenium-related errors
**Solution**: Selenium is optional for JavaScript analysis
- Install ChromeDriver if needed
- Tool will fallback to basic analysis if Selenium unavailable

### Issue: Permission denied
**Solution**: Make script executable
```bash
chmod +x wpt.py
```

### Issue: Timeout errors
**Solution**: Increase timeout
```bash
wpt example.com --timeout 30
```

## Security Best Practices

⚠️ **IMPORTANT**:
- Only scan sites you own or have permission to test
- Use responsibly and follow applicable laws
- Respect rate limits to avoid DoS
- Follow responsible disclosure for vulnerabilities

## What's Checked

✅ **DNS**: A, AAAA, MX, NS, TXT, SOA records + subdomains
✅ **SSL/TLS**: HTTPS, certificate expiry, TLS version, ciphers
✅ **WAF**: Cloudflare, AWS, Akamai, Imperva, F5, and more
✅ **APIs**: Common endpoints, HTTP methods, CORS policies
✅ **JavaScript**: Hardcoded secrets, XSS, eval(), unsafe DOM
✅ **Cookies**: Secure, HttpOnly, SameSite flags
✅ **Forms**: CSRF tokens, method validation, input patterns

## Example Output

```
======================================================================
       WPT - Web Penetration Testing Tool - Scan Report
======================================================================

Target: https://example.com
Scan completed: 2026-01-12 02:15:30
Total findings: 15

Findings by Severity:
  [!!] HIGH: 2
  [!] MEDIUM: 5
  [*] LOW: 3
  [i] INFO: 5

----------------------------------------------------------------------
DETAILED FINDINGS
----------------------------------------------------------------------

[DNS Records]
  [i] A record: 93.184.216.34
  [i] MX record: mail.example.com

[SSL/TLS]
  [i] Certificate expires: Mar 15 12:00:00 2026 GMT
  [i] Using recommended TLSv1.3

[Cookie Security]
  [!] Cookie "sessionid" has security issues: Missing HttpOnly flag
     → Recommendation: Set HttpOnly flag to prevent JavaScript access
```

## Getting Help

- Documentation: See README.md
- Issues: https://github.com/Dawn-Fighter/WPT/issues
- Full list of changes: See CHANGELOG.md
- Implementation details: See IMPLEMENTATION_SUMMARY.md

## Next Steps

1. Run your first scan: `wpt example.com`
2. Try different output formats
3. Review the findings
4. Customize scan parameters
5. Integrate into your workflow

Happy scanning! 🔍🛡️
