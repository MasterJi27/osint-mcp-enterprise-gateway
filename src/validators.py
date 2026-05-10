#!/usr/bin/env python3
"""
Input Validation & Sanitization for OSINT MCP Enterprise Gateway.
Provides comprehensive input validation for all target types.
"""

import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from enum import Enum


class TargetKind(Enum):
    EMAIL = "email"
    USERNAME = "username"
    DOMAIN = "domain"
    PHONE = "phone"
    IP = "ip"
    UNKNOWN = "unknown"


@dataclass
class ValidationResult:
    is_valid: bool
    kind: str
    normalized_value: str
    errors: List[str]
    warnings: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "kind": self.kind,
            "normalized_value": self.normalized_value,
            "errors": self.errors,
            "warnings": self.warnings,
        }


class TargetValidator:
    """Comprehensive target validation and normalization."""

    EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
    DOMAIN_REGEX = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?$")
    USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9._-]{3,64}$")
    PHONE_REGEX = re.compile(r"^\+?[1-9]\d{6,14}$")
    IPV4_REGEX = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
    IPV6_REGEX = re.compile(r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,7}:$")

    COMMON_DANGEROUS_PATTERNS = [
        r"localhost",
        r"127\.0\.0\.1",
        r"0\.0\.0\.0",
        r"\.onion",
        r"\.i2p",
    ]

    def __init__(self, strict: bool = False):
        self.strict = strict

    def _check_dangerous(self, value: str) -> List[str]:
        warnings = []
        for pattern in self.COMMON_DANGEROUS_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                warnings.append(f"Potential dangerous pattern detected: {pattern}")
        return warnings

    def _normalize_value(self, value: str) -> str:
        value = value.strip()
        value = unicodedata.normalize("NFKC", value)
        value = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", value)
        return value

    def validate_email(self, value: str) -> ValidationResult:
        errors = []
        warnings = []
        normalized = self._normalize_value(value)

        if not normalized:
            errors.append("Email cannot be empty")
            return ValidationResult(False, TargetKind.EMAIL.value, "", errors, warnings)

        if not self.EMAIL_REGEX.match(normalized):
            errors.append(f"Invalid email format: {normalized}")
            return ValidationResult(False, TargetKind.EMAIL.value, normalized, errors, warnings)

        local, domain = normalized.rsplit("@", 1)

        if len(local) > 64:
            errors.append("Email local part exceeds 64 characters")
        if len(domain) > 255:
            errors.append("Email domain exceeds 255 characters")
        if len(normalized) > 320:
            errors.append("Full email exceeds 320 characters")

        common_typos = {
            "gmial.com": "gmail.com",
            "gmal.com": "gmail.com",
            "gamil.com": "gmail.com",
            "gnail.com": "gmail.com",
            "hotmal.com": "hotmail.com",
            "yaho.com": "yahoo.com",
            "yahooo.com": "yahoo.com",
            "outloo.com": "outlook.com",
        }
        if domain.lower() in common_typos:
            warnings.append(f"Possible typo: {domain} -> {common_typos[domain.lower()]}")

        warnings.extend(self._check_dangerous(normalized))

        return ValidationResult(
            is_valid=len(errors) == 0,
            kind=TargetKind.EMAIL.value,
            normalized_value=normalized.lower(),
            errors=errors,
            warnings=warnings,
        )

    def validate_username(self, value: str) -> ValidationResult:
        errors = []
        warnings = []
        normalized = self._normalize_value(value)

        if not normalized:
            errors.append("Username cannot be empty")
            return ValidationResult(False, TargetKind.USERNAME.value, "", errors, warnings)

        if not self.USERNAME_REGEX.match(normalized):
            errors.append("Username must be 3-64 characters, alphanumeric with ._- allowed")

        if normalized.startswith((".", "_", "-")) or normalized.endswith((".", "_", "-")):
            errors.append("Username cannot start or end with ._-")

        if ".." in normalized:
            errors.append("Username cannot contain consecutive dots")

        if re.search(r"\.{2,}", normalized):
            errors.append("Username cannot contain multiple consecutive dots")

        if len(normalized) < 3:
            errors.append("Username must be at least 3 characters")
        if len(normalized) > 64:
            errors.append("Username cannot exceed 64 characters")

        if normalized.lower() in {"admin", "root", "administrator", "test", "user", "null", "undefined"}:
            warnings.append("This is a common/reserved username")

        warnings.extend(self._check_dangerous(normalized))

        return ValidationResult(
            is_valid=len(errors) == 0,
            kind=TargetKind.USERNAME.value,
            normalized_value=normalized.lower(),
            errors=errors,
            warnings=warnings,
        )

    def validate_domain(self, value: str) -> ValidationResult:
        errors = []
        warnings = []
        normalized = self._normalize_value(value)

        if not normalized:
            errors.append("Domain cannot be empty")
            return ValidationResult(False, TargetKind.DOMAIN.value, "", errors, warnings)

        if normalized.startswith(("http://", "https://", "ftp://", "//")):
            errors.append("Domain should not include protocol prefix")
            normalized = re.sub(r"^(?:https?|ftp)://", "", normalized)

        normalized = normalized.strip("/").lower()

        if not self.DOMAIN_REGEX.match(normalized):
            errors.append(f"Invalid domain format: {normalized}")
            return ValidationResult(False, TargetKind.DOMAIN.value, normalized, errors, warnings)

        parts = normalized.split(".")
        if len(parts) < 2:
            errors.append("Domain must have at least two parts (e.g., example.com)")
        if len(parts[0]) > 63:
            errors.append("Domain label exceeds 63 characters")
        if len(normalized) > 253:
            errors.append("Full domain exceeds 253 characters")

        if parts[-1].lower() in {"test", "example", "localhost"}:
            warnings.append("This is a reserved TLD for documentation/testing")

        if normalized.endswith(".onion"):
            warnings.append("Dark web domain detected - ensure authorized use")

        warnings.extend(self._check_dangerous(normalized))

        return ValidationResult(
            is_valid=len(errors) == 0,
            kind=TargetKind.DOMAIN.value,
            normalized_value=normalized,
            errors=errors,
            warnings=warnings,
        )

    def validate_phone(self, value: str) -> ValidationResult:
        errors = []
        warnings = []
        normalized = self._normalize_value(value)

        normalized = re.sub(r"[\s\-\(\)\.]", "", normalized)

        if not normalized:
            errors.append("Phone number cannot be empty")
            return ValidationResult(False, TargetKind.PHONE.value, "", errors, warnings)

        if not self.PHONE_REGEX.match(normalized):
            errors.append("Invalid phone number format")

        if len(normalized) < 10:
            errors.append("Phone number too short")
        if len(normalized) > 15:
            errors.append("Phone number too long")

        warnings.extend(self._check_dangerous(normalized))

        return ValidationResult(
            is_valid=len(errors) == 0,
            kind=TargetKind.PHONE.value,
            normalized_value=normalized,
            errors=errors,
            warnings=warnings,
        )

    def validate_ip(self, value: str) -> ValidationResult:
        errors = []
        warnings = []
        normalized = self._normalize_value(value)

        if not normalized:
            errors.append("IP address cannot be empty")
            return ValidationResult(False, TargetKind.IP.value, "", errors, warnings)

        if not (self.IPV4_REGEX.match(normalized) or self.IPV6_REGEX.match(normalized)):
            errors.append("Invalid IP address format")

        if normalized.startswith(("127.", "10.", "192.168.", "172.16.", "172.31.")):
            warnings.append("Private IP address detected")
        if normalized in {"::1", "127.0.0.1", "0.0.0.0", "255.255.255.255"}:
            warnings.append("Special/reserved IP address detected")

        return ValidationResult(
            is_valid=len(errors) == 0,
            kind=TargetKind.IP.value,
            normalized_value=normalized,
            errors=errors,
            warnings=warnings,
        )

    def validate_target(self, value: str) -> ValidationResult:
        normalized = self._normalize_value(value)

        if self.EMAIL_REGEX.match(normalized):
            return self.validate_email(value)
        if self.IPV4_REGEX.match(normalized) or self.IPV6_REGEX.match(normalized):
            return self.validate_ip(value)
        if self.PHONE_REGEX.match(self._normalize_value(value)):
            return self.validate_phone(value)
        if self.DOMAIN_REGEX.match(normalized.strip().lower()):
            return self.validate_domain(value)
        if self.USERNAME_REGEX.match(normalized):
            return self.validate_username(value)

        return ValidationResult(
            is_valid=self.strict,
            kind=TargetKind.UNKNOWN.value,
            normalized_value=normalized,
            errors=["Unknown target type"] if self.strict else [],
            warnings=["Could not determine target type"],
        )


def sanitize_for_output(value: str, max_length: int = 1000) -> str:
    if not value:
        return ""

    sanitized = unicodedata.normalize("NFKC", value)

    sanitized = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]", "", sanitized)

    if max_length and len(sanitized) > max_length:
        sanitized = sanitized[:max_length] + "..."

    return sanitized


def is_safe_target(target: str, allowed_targets: List[str]) -> Tuple[bool, str]:
    if not allowed_targets:
        return True, ""

    target_lower = target.lower()
    for allowed in allowed_targets:
        allowed_lower = allowed.lower()
        if allowed_lower in target_lower or target_lower in allowed_lower:
            return True, ""
        if allowed_lower.startswith("*.") and (target_lower == allowed_lower[2:] or target_lower.endswith(allowed_lower[2:])):
            return True, ""

    return False, f"Target '{target}' not in allowed list"


target_validator = TargetValidator()
