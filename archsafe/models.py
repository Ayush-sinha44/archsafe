"""Data models for ArchSafe."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class RiskLevel(Enum):
    """Risk assessment levels."""
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

    @staticmethod
    def from_score(score: int) -> RiskLevel:
        """Map a 0-100 risk score to a RiskLevel."""
        if score <= 25:
            return RiskLevel.SAFE
        elif score <= 50:
            return RiskLevel.LOW
        elif score <= 75:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.HIGH


class FindingSeverity(Enum):
    """Severity levels for individual findings."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class NewsItem:
    """A parsed Arch Linux news entry."""
    title: str
    summary: str
    published: datetime
    link: str
    matched_keywords: list[str] = field(default_factory=list)
    affected_packages: list[str] = field(default_factory=list)


@dataclass
class SystemInfo:
    """Local system state information."""
    installed_packages: dict[str, str]  # {package_name: version}
    kernel_version: str
    desktop_environment: str
    gpu_info: str


@dataclass
class Finding:
    """A single finding from PKGBUILD analysis."""
    category: str
    severity: FindingSeverity
    description: str
    line_number: int | None = None


@dataclass
class UpdateCheckResult:
    """Complete result of an update safety check."""
    news_items: list[NewsItem]
    system_info: SystemInfo
    affected_packages: list[str]
    risk_score: int
    risk_level: RiskLevel
    ai_explanation: str = ""


@dataclass
class AURPackageInfo:
    """AUR package metadata."""
    name: str
    version: str
    description: str
    num_votes: int
    popularity: float
    maintainer: str | None
    first_submitted: datetime
    last_modified: datetime
    out_of_date: datetime | None
    url: str | None
    depends: list[str] = field(default_factory=list)
    make_depends: list[str] = field(default_factory=list)


@dataclass
class PKGBUILDAnalysis:
    """Results of PKGBUILD static analysis."""
    source_urls: list[str] = field(default_factory=list)
    has_install_script: bool = False
    checksums_skipped: bool = False
    findings: list[Finding] = field(default_factory=list)


@dataclass
class AURCheckResult:
    """Complete result of an AUR package analysis."""
    package_info: AURPackageInfo
    pkgbuild_analysis: PKGBUILDAnalysis
    risk_score: int
    risk_level: RiskLevel
    findings: list[Finding]
    ai_explanation: str = ""
