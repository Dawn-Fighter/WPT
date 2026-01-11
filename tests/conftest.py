"""Test configuration for pytest."""

import pytest


@pytest.fixture
def sample_url():
    """Sample URL for testing."""
    return "https://example.com"


@pytest.fixture
def sample_domain():
    """Sample domain for testing."""
    return "example.com"
