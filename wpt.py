#!/usr/bin/env python3
"""
Backward compatibility wrapper for WPT v1.0 users.

This script maintains compatibility with the original wpt.py interface
while using the new modular architecture internally.
"""

from wpt.cli import main

if __name__ == "__main__":
    main()
