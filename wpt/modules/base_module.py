"""Base module class for all scanner modules."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any
import logging


class Severity(Enum):
    """Severity levels for security findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """Represents a security finding from a scanner module."""

    category: str
    description: str
    severity: Severity = Severity.INFO
    recommendation: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary for JSON export."""
        return {
            "category": self.category,
            "description": self.description,
            "severity": self.severity.value,
            "recommendation": self.recommendation,
            "details": self.details,
        }


class BaseModule(ABC):
    """
    Base class for all scanner modules.

    All scanner modules should inherit from this class and implement
    the scan() method.
    """

    def __init__(
        self,
        target_url: str,
        domain: str,
        session: Any,
        timeout: int = 10,
        verbose: bool = False,
    ):
        """
        Initialize base module.

        Args:
            target_url: Full target URL (e.g., https://example.com)
            domain: Domain name only (e.g., example.com)
            session: Requests session object
            timeout: Request timeout in seconds
            verbose: Enable verbose logging
        """
        self.target_url = target_url
        self.domain = domain
        self.session = session
        self.timeout = timeout
        self.verbose = verbose
        self.logger = logging.getLogger(self.__class__.__name__)
        self.findings: List[Finding] = []

    @abstractmethod
    def scan(self) -> List[Finding]:
        """
        Perform the security scan.

        Returns:
            List of Finding objects
        """
        pass

    def add_finding(
        self,
        category: str,
        description: str,
        severity: Severity = Severity.INFO,
        recommendation: Optional[str] = None,
        **details,
    ) -> None:
        """
        Add a finding to the results.

        Args:
            category: Finding category
            description: Description of the finding
            severity: Severity level
            recommendation: Optional remediation recommendation
            **details: Additional details as keyword arguments
        """
        finding = Finding(
            category=category,
            description=description,
            severity=severity,
            recommendation=recommendation,
            details=details,
        )
        self.findings.append(finding)

        if self.verbose:
            self.logger.debug(f"Found: [{severity.value}] {category}: {description}")
