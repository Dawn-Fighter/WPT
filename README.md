<div align="center">

[![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![GitHub](https://img.shields.io/badge/GitHub-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com)

</div>

---


# Web Penetration Testing Tool (WPT) v2.0

## Overview
**Web Penetration Testing Tool (WPT)** is an advanced security scanner designed to perform comprehensive security analysis of web applications. It helps security professionals, bug bounty hunters, and developers identify vulnerabilities in their web applications.

## Features
- 🔍 **DNS Enumeration & Subdomain Discovery**
- 🔐 **SSL/TLS Configuration Analysis**
- 🛡️ **Security Headers Checker** (NEW in v2.1!)
- 🔒 **Web Application Firewall (WAF) Detection**
- 📡 **API Endpoint Discovery**
- 📜 **JavaScript Security Analysis**
- 🍪 **Cookie Security Analysis**
- 📝 **Form Input Validation Testing**
- 📊 **Multiple Output Formats** (Console, TXT, JSON, HTML, CSV)
- 🏗️ **Modular Architecture** for easy extension
- 🔧 **Configurable Scan Settings**

## What's New in v2.0

### Major Improvements
- ✅ **Modular Architecture** - Completely refactored codebase with separate modules for each scanner
- ✅ **Fixed Critical Bugs** - Selenium resource leaks, cookie checking issues, and timeout handling
- ✅ **Better Error Handling** - Specific exception handling with comprehensive logging
- ✅ **Type Hints & Documentation** - Full type annotations and detailed docstrings
- ✅ **Severity Levels** - Findings now include severity ratings (Critical, High, Medium, Low, Info)
- ✅ **Multiple Output Formats** - Export reports as TXT, JSON, HTML, or CSV
- ✅ **Context Manager Support** - Proper resource cleanup
- ✅ **Package Installation** - Install as a Python package with pip

### Bug Fixes
- Fixed Selenium WebDriver resource leaks
- Fixed cookie security attribute checking (HttpOnly, SameSite)
- Added proper timeout handling for all HTTP requests
- Removed unused imports
- Fixed bare exception handling

## Installation

### Prerequisites
Ensure you have Python 3.7+ installed. You can check by running:
```bash
python3 --version
```

### Clone the Repository
```bash
git clone https://github.com/Dawn-Fighter/WPT.git
cd WPT
```

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Install as Package (Recommended)
```bash
pip install -e .
```

This allows you to run `wpt` from anywhere:
```bash
wpt example.com
```

## Usage

### Quick Start
```bash
# Using the wpt command (if installed as package)
wpt example.com

# Using Python module
python3 -m wpt example.com

# Using the script directly (backward compatible)
python3 wpt.py example.com
```

### Command-Line Options
```bash
usage: wpt [options] url

positional arguments:
  url                   Target domain or URL

optional arguments:
  -h, --help            Show this help message and exit
  -t THREADS, --threads THREADS
                        Number of concurrent threads (default: 5)
  -v, --verbose         Enable verbose output
  -o OUTPUT, --output OUTPUT
                        Save the results to a file
  -f FORMAT, --format FORMAT
                        Output format: console, txt, json, html, csv (default: console)
  --timeout TIMEOUT     Request timeout in seconds (default: 10)
```

### Example Usage
```bash
# Basic scan with console output
wpt example.com

# Verbose scan
wpt example.com -v

# Save as HTML report
wpt example.com -o report.html -f html

# Save as JSON with custom threads and timeout
wpt https://example.com -t 10 --timeout 15 -o scan.json -f json

# Generate CSV report
wpt example.com -o findings.csv -f csv
```

## File Structure
```
WPT/
├── wpt/                      # Main package directory
│   ├── __init__.py           # Package initialization
│   ├── __main__.py           # Module entry point
│   ├── cli.py                # Command-line interface
│   ├── core/                 # Core functionality
│   │   ├── scanner.py        # Main scanner orchestrator
│   │   └── reporter.py       # Report generation
│   ├── modules/              # Scanner modules
│   │   ├── base_module.py    # Base class for scanners
│   │   ├── dns_scanner.py    # DNS enumeration
│   │   ├── ssl_scanner.py    # SSL/TLS analysis
│   │   ├── waf_detector.py   # WAF detection
│   │   ├── api_scanner.py    # API discovery
│   │   ├── js_analyzer.py    # JavaScript analysis
│   │   ├── cookie_analyzer.py # Cookie security
│   │   └── form_analyzer.py  # Form analysis
│   └── utils/                # Utilities
│       ├── logger.py         # Logging configuration
│       ├── exceptions.py     # Custom exceptions
│       └── constants.py      # Constants and configuration
├── tests/                    # Test directory
├── wpt.py                    # Backward compatibility wrapper
├── setup.py                  # Package setup (legacy)
├── pyproject.toml            # Modern package configuration
├── requirements.txt          # Production dependencies
├── requirements-dev.txt      # Development dependencies
├── README.md                 # This file
├── LICENSE                   # MIT License
└── .gitignore                # Git ignore rules
```

## Output Formats

### Console Output
Default format showing findings organized by category with severity levels.

### Text Report
Plain text file suitable for documentation and archiving.
```bash
wpt example.com -o report.txt -f txt
```

### JSON Report
Machine-readable format for integration with other tools.
```bash
wpt example.com -o report.json -f json
```

### HTML Report
Beautiful, styled HTML report with color-coded severities.
```bash
wpt example.com -o report.html -f html
```

### CSV Report
Spreadsheet-compatible format for data analysis.
```bash
wpt example.com -o report.csv -f csv
```

## Security Checks

### DNS Enumeration
- Checks A, AAAA, MX, NS, TXT, SOA records
- Discovers common subdomains
- Identifies DNS configuration issues

### SSL/TLS Analysis
- Checks if HTTPS is enabled
- Analyzes SSL certificate validity and expiration
- Checks supported TLS versions
- Detects weak cipher suites

### Security Headers Analysis (NEW!)
- Checks for missing security headers (HSTS, CSP, X-Frame-Options, etc.)
- Validates header configurations
- Identifies information disclosure headers
- Provides specific remediation recommendations

### WAF Detection
- Identifies common WAF solutions
- Checks for Cloudflare, AWS WAF, Akamai, Imperva, F5 BIG-IP, and more

### API Discovery
- Tests common API endpoint paths
- Checks allowed HTTP methods
- Identifies overly permissive CORS policies

### JavaScript Analysis
- Detects hardcoded credentials
- Identifies unsafe DOM manipulation
- Finds eval() usage
- Checks for potential XSS vectors
- Identifies data exposure via console.log

### Cookie Security
- Verifies Secure flag
- Checks HttpOnly flag
- Validates SameSite attribute
- Provides security recommendations

### Form Security
- Validates form submission methods
- Checks autocomplete settings
- Identifies missing CSRF tokens
- Validates input field patterns

## Development

### Install Development Dependencies
```bash
pip install -r requirements-dev.txt
```

### Running Tests
```bash
pytest tests/
```

### Code Formatting
```bash
black wpt/
```

### Type Checking
```bash
mypy wpt/
```

## Architecture

WPT v2.0 uses a modular architecture where each security check is implemented as a separate module inheriting from `BaseModule`. This design provides:

- **Extensibility**: Easy to add new scanner modules
- **Maintainability**: Each module is self-contained and testable
- **Reusability**: Modules can be used independently
- **Consistency**: All modules follow the same interface

### Creating a Custom Scanner Module

```python
from wpt.modules.base_module import BaseModule, Finding, Severity

class CustomScanner(BaseModule):
    def scan(self):
        # Your scanning logic here
        self.add_finding(
            category='Custom Check',
            description='Found something interesting',
            severity=Severity.MEDIUM,
            recommendation='Fix this issue'
        )
        return self.findings
```

## Security Disclaimer

⚠️ **IMPORTANT**: This tool is designed for authorized security testing only. Always ensure you have explicit permission before scanning any website or web application. Unauthorized security testing may be illegal in your jurisdiction.

- Only use this tool on systems you own or have written permission to test
- Respect rate limits and avoid causing denial of service
- Follow responsible disclosure practices for any vulnerabilities found
- The authors are not responsible for misuse of this tool

## Contributing

We welcome contributions! Follow these steps:

1. Fork the repository
2. Create a new branch (`git checkout -b feature-name`)
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass (`pytest`)
6. Format your code (`black .`)
7. Commit your changes (`git commit -m 'Add new feature'`)
8. Push to the branch (`git push origin feature-name`)
9. Open a Pull Request

## Roadmap

Future enhancements planned:
- [ ] XSS vulnerability scanner
- [ ] SQL injection detection
- [ ] CORS policy analysis
- [ ] robots.txt and sitemap.xml analysis
- [ ] Directory bruteforcing capability
- [ ] Technology fingerprinting
- [ ] Integration with CI/CD pipelines
- [ ] Plugin system for custom modules
- [ ] Web interface

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Changelog

### v2.1.0 (Current)
- Added Security Headers Scanner module
- Enhanced subdomain enumeration
- Improved error handling and logging
- Updated to 8 scanner modules total
- Better severity classification

### v2.0.0
- Complete rewrite with modular architecture
- Fixed critical bugs (Selenium leaks, cookie checking, timeouts)
- Added severity levels to findings
- Multiple output formats (TXT, JSON, HTML, CSV)
- Comprehensive error handling and logging
- Full type hints and documentation
- Package installation support
- Context manager support

### v1.0.0
- Initial release
- Basic security scanning capabilities

## Contact

For issues, suggestions, or questions:
- Open an issue: https://github.com/Dawn-Fighter/WPT/issues
- GitHub: https://github.com/Dawn-Fighter

## Acknowledgments

Built with:
- [Requests](https://requests.readthedocs.io/) - HTTP library
- [Beautiful Soup](https://www.crummy.com/software/BeautifulSoup/) - HTML parsing
- [dnspython](https://www.dnspython.org/) - DNS toolkit
- [Selenium](https://www.selenium.dev/) - Browser automation
- [tqdm](https://tqdm.github.io/) - Progress bars

<div align="center">

[![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![GitHub](https://img.shields.io/badge/GitHub-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com)

**Happy Bug Hunting! 🐛🔍**

</div>

---
