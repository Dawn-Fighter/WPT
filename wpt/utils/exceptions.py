"""Custom exceptions for WPT scanner."""


class WPTException(Exception):
    """Base exception for WPT scanner."""

    pass


class ScannerError(WPTException):
    """Raised when a scanner module encounters an error."""

    pass


class ConfigurationError(WPTException):
    """Raised when there's a configuration error."""

    pass


class TimeoutError(WPTException):
    """Raised when a request times out."""

    pass


class SSLError(WPTException):
    """Raised when there's an SSL/TLS error."""

    pass
