"""Sample test file demonstrating test structure."""

import pytest
from wpt.modules.base_module import BaseModule, Finding, Severity


def test_finding_creation():
    """Test that Finding dataclass works correctly."""
    finding = Finding(
        category="Test Category",
        description="Test description",
        severity=Severity.MEDIUM,
        recommendation="Fix this",
    )

    assert finding.category == "Test Category"
    assert finding.description == "Test description"
    assert finding.severity == Severity.MEDIUM
    assert finding.recommendation == "Fix this"


def test_finding_to_dict():
    """Test Finding to_dict() method."""
    finding = Finding(
        category="Test", description="Description", severity=Severity.HIGH
    )

    result = finding.to_dict()

    assert result["category"] == "Test"
    assert result["description"] == "Description"
    assert result["severity"] == "high"
    assert result["recommendation"] is None


def test_severity_enum():
    """Test Severity enum values."""
    assert Severity.CRITICAL.value == "critical"
    assert Severity.HIGH.value == "high"
    assert Severity.MEDIUM.value == "medium"
    assert Severity.LOW.value == "low"
    assert Severity.INFO.value == "info"
