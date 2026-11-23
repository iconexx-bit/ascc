"""Нормализованные шкалы. Единственное место, где знают про конкретные сканеры."""

from __future__ import annotations

from enum import IntEnum, StrEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    # The scanner gave no severity (CLAUDE.md, Contracts). Defined last so that
    # iteration still starts at INFO; its value orders nothing: code that ranks
    # severities must handle UNKNOWN explicitly, never as "below INFO".
    UNKNOWN = -1

    @classmethod
    def from_severity_string(cls, value: str | None) -> Severity:
        # Open-source Checkov reports null, Trivy can report "UNKNOWN": a
        # severity the scanner did not give, or one ASCC does not recognise,
        # is UNKNOWN, never INFO.
        if value is None:
            return cls.UNKNOWN
        if not isinstance(value, str):
            raise TypeError(f"severity must be a string or null, not {type(value).__name__}")
        return {
            "INFO": cls.INFO,
            "LOW": cls.LOW,
            "MEDIUM": cls.MEDIUM,
            "HIGH": cls.HIGH,
            "CRITICAL": cls.CRITICAL,
        }.get(value.upper(), cls.UNKNOWN)

    @classmethod
    def from_trivy(cls, value: str) -> Severity:
        return cls.from_severity_string(value)

    @classmethod
    def from_ocsf(cls, severity_id: int) -> Severity:
        # OCSF: 0 Unknown, 1 Info, 2 Low, 3 Medium, 4 High, 5 Critical, 6 Fatal,
        # 99 Other. Unknown, Other and any id not listed are UNKNOWN, never INFO.
        return {
            1: cls.INFO,
            2: cls.LOW,
            3: cls.MEDIUM,
            4: cls.HIGH,
            5: cls.CRITICAL,
            6: cls.CRITICAL,
        }.get(severity_id, cls.UNKNOWN)

    @classmethod
    def from_security_severity(cls, score: float) -> Severity:
        # GitHub code scanning bands for rule properties["security-severity"]
        # (0.0-10.0, CVSS-like): >= 9 critical, >= 7 high, >= 4 medium, > 0 low.
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.INFO


class Category(StrEnum):
    """Кросс-сканерная категория. Основа для ASCC-CORR-010.

    rule_id принадлежит сканеру, Category принадлежит ASCC.
    Здесь AVD-AWS-0028 / CKV_AWS_19 / prowler-encryption-check
    становятся одним фактом.
    """

    ENCRYPTION_AT_REST = "encryption_at_rest"
    PUBLIC_ACCESS = "public_access"
    LOGGING_DISABLED = "logging_disabled"
    NETWORK_EXPOSURE = "network_exposure"
    EXCESSIVE_PRIVILEGE = "excessive_privilege"
    VULNERABILITY = "vulnerability"
    DATA_CLASSIFICATION = "data_classification"
    CONTAINMENT = "containment"  # runtime containment control violated (clab); never an entry
    UNCATEGORIZED = "uncategorized"
