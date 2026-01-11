"""Form security analysis module."""

from typing import List
import re
import requests
from bs4 import BeautifulSoup
from wpt.modules.base_module import BaseModule, Finding, Severity


class FormAnalyzer(BaseModule):
    """
    Analyzes form security and input validation.

    Checks:
        - Form submission method (GET vs POST)
        - Autocomplete settings
        - CSRF token presence
        - Input validation patterns
        - Password field requirements
    """

    def scan(self) -> List[Finding]:
        """
        Perform form security analysis.

        Returns:
            List of findings from form analysis
        """
        self.logger.info(f"Starting form analysis for {self.target_url}")

        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            self._analyze_forms(response)
        except requests.exceptions.Timeout:
            self.logger.error(f"Request timeout to {self.target_url}")
            self.add_finding(
                category="Form Analysis Error",
                description="Request timeout during form analysis",
                severity=Severity.LOW,
            )
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request error: {e}")
            self.add_finding(
                category="Form Analysis Error",
                description=f"Request error during form analysis: {str(e)}",
                severity=Severity.LOW,
            )
        except Exception as e:
            self.logger.error(f"Error during form analysis: {e}")
            self.add_finding(
                category="Form Analysis Error",
                description=f"Error during form analysis: {str(e)}",
                severity=Severity.LOW,
            )

        return self.findings

    def _analyze_forms(self, response: requests.Response) -> None:
        """
        Analyze forms for security issues.

        Args:
            response: HTTP response object
        """
        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")

        if not forms:
            self.add_finding(
                category="Form Security",
                description="No forms found on page",
                severity=Severity.INFO,
            )
            self.logger.info("No forms found")
            return

        self.logger.info(f"Found {len(forms)} form(s) to analyze")

        for idx, form in enumerate(forms, 1):
            self._analyze_single_form(form, idx)

    def _analyze_single_form(self, form, form_number: int) -> None:
        """
        Analyze a single form element.

        Args:
            form: BeautifulSoup form element
            form_number: Form index for identification
        """
        form_id = form.get("id", f"form-{form_number}")
        form_action = form.get("action", "current page")

        # Check form method
        method = form.get("method", "").lower()
        if method != "post":
            self.add_finding(
                category="Form Security",
                description=f'Form "{form_id}" using {method.upper() or "GET"} method instead of POST',
                severity=Severity.MEDIUM,
                recommendation="Use POST method for forms to prevent sensitive data in URL",
                form_id=form_id,
                form_action=form_action,
            )
            self.logger.warning(
                f"Form {form_id} uses {method or 'GET'} instead of POST"
            )

        # Check autocomplete
        autocomplete = form.get("autocomplete", "").lower()
        has_sensitive_fields = self._has_sensitive_fields(form)

        if has_sensitive_fields and autocomplete != "off":
            self.add_finding(
                category="Form Security",
                description=f'Form "{form_id}" with sensitive fields does not disable autocomplete',
                severity=Severity.LOW,
                recommendation='Set autocomplete="off" for forms with sensitive data',
                form_id=form_id,
            )
            self.logger.info(f"Form {form_id} should disable autocomplete")

        # Check CSRF protection
        csrf_token = form.find(
            "input", {"name": re.compile(r"csrf|token|_token", re.I)}
        )
        if not csrf_token and method == "post":
            self.add_finding(
                category="Form Security",
                description=f'Form "{form_id}" may lack CSRF protection',
                severity=Severity.HIGH,
                recommendation="Implement CSRF tokens for all POST forms",
                form_id=form_id,
                form_action=form_action,
            )
            self.logger.warning(f"Form {form_id} may lack CSRF protection")

        # Check input validation
        self._check_input_validation(form, form_id)

    def _has_sensitive_fields(self, form) -> bool:
        """
        Check if form contains sensitive input fields.

        Args:
            form: BeautifulSoup form element

        Returns:
            True if form has sensitive fields
        """
        sensitive_types = ["password", "email", "tel", "credit"]
        inputs = form.find_all("input")

        for input_field in inputs:
            input_type = input_field.get("type", "").lower()
            input_name = input_field.get("name", "").lower()

            if input_type in sensitive_types:
                return True

            if any(
                keyword in input_name
                for keyword in ["password", "ssn", "credit", "card"]
            ):
                return True

        return False

    def _check_input_validation(self, form, form_id: str) -> None:
        """
        Check input fields for validation patterns.

        Args:
            form: BeautifulSoup form element
            form_id: Form identifier
        """
        inputs = form.find_all("input")

        for input_field in inputs:
            input_type = input_field.get("type", "").lower()
            input_name = input_field.get("name", "")
            has_pattern = input_field.get("pattern")
            has_required = input_field.has_attr("required")
            has_minlength = input_field.get("minlength")
            has_maxlength = input_field.get("maxlength")

            # Check password field validation
            if input_type == "password":
                if not has_pattern and not has_minlength:
                    self.add_finding(
                        category="Form Security",
                        description=f'Password field in "{form_id}" lacks validation pattern',
                        severity=Severity.MEDIUM,
                        recommendation="Add pattern validation to enforce strong passwords",
                        form_id=form_id,
                        field_name=input_name,
                    )
                    self.logger.info(f"Password field in {form_id} lacks validation")

            # Check email field validation
            elif input_type == "email":
                if not has_pattern:
                    self.add_finding(
                        category="Form Security",
                        description=f'Email field in "{form_id}" lacks custom validation pattern',
                        severity=Severity.LOW,
                        recommendation="Consider adding custom email validation pattern",
                        form_id=form_id,
                        field_name=input_name,
                    )
