# Installation & Testing Guide

## Prerequisites

Python 3.7 or higher is required.

## Step 1: Install Dependencies

```bash
cd WPT
pip install -r requirements.txt
```

This will install:
- requests (HTTP library)
- beautifulsoup4 (HTML parsing)
- dnspython (DNS toolkit)
- tqdm (progress bars)
- selenium (browser automation for JS analysis)

## Step 2: Optional - Install as Package

For the best experience, install WPT as a package:

```bash
pip install -e .
```

This enables the `wpt` command globally.

## Step 3: Verify Installation

Test that the tool is working:

```bash
# If installed as package:
wpt --help

# Or using Python module:
python3 -m wpt --help

# Or using script directly:
python3 wpt.py --help
```

You should see the help message with all available options.

## Quick Test

Run a quick scan on a safe test site:

```bash
wpt example.com
```

## Troubleshooting

### Issue: ModuleNotFoundError: No module named 'dns'

**Solution**: Install dependencies
```bash
pip install -r requirements.txt
```

### Issue: Selenium/ChromeDriver errors

**Solution**: Selenium is optional. The tool will automatically fall back to basic JavaScript analysis if Selenium/ChromeDriver is not available.

To install ChromeDriver:
```bash
# Ubuntu/Debian
sudo apt-get install chromium-chromedriver

# macOS
brew install chromedriver

# Or download from: https://chromedriver.chromium.org/
```

### Issue: Permission errors

**Solution**: Install in user directory
```bash
pip install --user -r requirements.txt
```

## Development Setup

For development work:

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
pytest tests/

# Format code
black wpt/

# Type checking
mypy wpt/
```

## Docker Installation (Alternative)

If you prefer Docker:

```bash
# Build image
docker build -t wpt-scanner .

# Run scan
docker run wpt-scanner example.com
```

Note: Dockerfile not included in v2.0 but can be added if needed.

## Next Steps

Once installed, see:
- **QUICKSTART.md** for usage examples
- **README.md** for full documentation
- **CHANGELOG.md** for version history
