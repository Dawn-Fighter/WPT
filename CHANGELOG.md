# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-01-12

### Added
- **Modular Architecture**: Complete rewrite with separate modules for each scanner type
- **Severity Levels**: All findings now include severity ratings (Critical, High, Medium, Low, Info)
- **Multiple Output Formats**: Export reports as TXT, JSON, HTML, or CSV
- **Better Error Handling**: Specific exception handling with comprehensive logging
- **Type Hints**: Full type annotations throughout the codebase
- **Comprehensive Documentation**: Detailed docstrings following Google style
- **Context Manager Support**: Proper resource cleanup using context managers
- **Package Installation**: Can be installed as a Python package with pip
- **Command-line Tool**: Added `wpt` command when installed as package
- **Development Tools**: Added requirements-dev.txt with testing and linting tools
- **Modern Packaging**: Added pyproject.toml for modern Python packaging

### Changed
- Refactored monolithic `wpt.py` (433 lines) into modular package structure (15+ files)
- Improved DNS scanner with better subdomain enumeration
- Enhanced SSL/TLS analysis with certificate expiration warnings
- Better API discovery with CORS policy checking
- Improved JavaScript analysis with fallback when Selenium unavailable
- More detailed form security analysis
- Updated README with comprehensive documentation

### Fixed
- **Critical**: Fixed Selenium WebDriver resource leak (driver not closed on errors)
- **Critical**: Fixed cookie security attribute checking (HttpOnly/SameSite detection)
- **Critical**: Added timeout to all HTTP requests (prevents hanging)
- **Critical**: Fixed bare exception handling (now catches specific exceptions)
- Removed unused imports (subprocess, json, cryptography modules, warnings)
- Fixed --output parameter being ignored
- Fixed --verbose parameter being ignored
- Fixed --threads parameter not being used

### Security
- Added proper request timeout handling to prevent DoS
- Improved SSL error handling
- Better credential detection in JavaScript analysis
- Enhanced CSRF token detection in forms
- Added security disclaimer to README

## [1.0.0] - 2025-01-XX

### Added
- Initial release
- DNS enumeration and subdomain discovery
- SSL/TLS configuration analysis
- WAF detection
- API endpoint discovery
- JavaScript security analysis
- Cookie security analysis
- Form input validation testing
- Basic console output reporting

[2.0.0]: https://github.com/Dawn-Fighter/WPT/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/Dawn-Fighter/WPT/releases/tag/v1.0.0
