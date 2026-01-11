"""Setup configuration for WPT package."""

from setuptools import setup, find_packages
import pathlib

here = pathlib.Path(__file__).parent.resolve()

# Get the long description from the README file
long_description = (here / "README.md").read_text(encoding="utf-8")

setup(
    name="wpt-scanner",
    version="2.0.0",
    description="Web Penetration Testing Tool - Comprehensive security scanner for web applications",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Dawn-Fighter/WPT",
    author="Chethas Dileep",
    author_email="",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Software Development :: Testing",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    keywords="security, penetration testing, web security, vulnerability scanner, security audit",
    packages=find_packages(exclude=["tests", "*.tests", "*.tests.*", "tests.*"]),
    python_requires=">=3.7",
    install_requires=[
        "requests>=2.25.0",
        "beautifulsoup4>=4.9.0",
        "dnspython>=2.0.0",
        "tqdm>=4.50.0",
        "selenium>=4.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=6.0",
            "pytest-cov>=2.10",
            "black>=21.0",
            "flake8>=3.8",
            "mypy>=0.900",
        ],
    },
    entry_points={
        "console_scripts": [
            "wpt=wpt.cli:main",
        ],
    },
    project_urls={
        "Bug Reports": "https://github.com/Dawn-Fighter/WPT/issues",
        "Source": "https://github.com/Dawn-Fighter/WPT",
    },
)
