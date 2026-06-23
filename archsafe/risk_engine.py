"""Deterministic risk scoring engine."""

from __future__ import annotations

from datetime import datetime, timezone, timedelta

from archsafe.models import (
    AURCheckResult,
    AURPackageInfo,
    FindingSeverity,
    NewsItem,
    PKGBUILDAnalysis,
    RiskLevel,
    SystemInfo,
    UpdateCheckResult,
)


def _find_affected_packages(
    news_items: list[NewsItem],
    installed: dict[str, str],
) -> list[str]:
    """Determine which installed packages are mentioned in news items."""
    affected: set[str] = set()
    installed_names = set(installed.keys())

    for item in news_items:
        if not item.matched_keywords:
            continue
        # Check if any installed package name appears in the news text
        combined = f"{item.title} {item.summary}".lower()
        for pkg_name in installed_names:
            # Only match package names that are 3+ chars to avoid false positives
            if len(pkg_name) >= 3 and pkg_name.lower() in combined:
                affected.add(pkg_name)
                if pkg_name not in item.affected_packages:
                    item.affected_packages.append(pkg_name)

    return sorted(affected)


def calculate_update_risk(
    news_items: list[NewsItem],
    system_info: SystemInfo,
) -> UpdateCheckResult:
    """Calculate the risk score for a system update.

    Scoring:
        - +15 per danger keyword match (across all news items)
        - +20 per installed package affected
        - +10 bonus for very recent news (< 3 days old)
        - Base score of 5 if no relevant news

    Args:
        news_items: Parsed news items with keyword matches.
        system_info: Local system information.

    Returns:
        UpdateCheckResult with computed risk score and level.
    """
    affected = _find_affected_packages(news_items, system_info.installed_packages)

    # Items that have at least one keyword match
    flagged_items = [item for item in news_items if item.matched_keywords]

    if not flagged_items:
        return UpdateCheckResult(
            news_items=news_items,
            system_info=system_info,
            affected_packages=[],
            risk_score=5,
            risk_level=RiskLevel.SAFE,
        )

    score = 0

    # Keyword matches
    total_keywords = sum(len(item.matched_keywords) for item in flagged_items)
    score += total_keywords * 15

    # Affected packages
    score += len(affected) * 20

    # Recency bonus
    now = datetime.now(timezone.utc)
    for item in flagged_items:
        if (now - item.published) < timedelta(days=3):
            score += 10

    score = min(score, 100)

    return UpdateCheckResult(
        news_items=news_items,
        system_info=system_info,
        affected_packages=affected,
        risk_score=score,
        risk_level=RiskLevel.from_score(score),
    )


def calculate_aur_risk(
    package_info: AURPackageInfo,
    pkgbuild_analysis: PKGBUILDAnalysis,
) -> AURCheckResult:
    """Calculate the risk score for an AUR package.

    Scoring:
        Findings:
            - CRITICAL: +30 each
            - HIGH: +15 each
            - MEDIUM: +10 each
            - LOW: +5 each
        Package metadata:
            - No maintainer (orphaned): +15
            - Out of date: +10
            - Low votes (< 10): +10
            - Very low popularity (< 0.5): +5
            - Package age < 30 days: +10
        Good signals (deductions):
            - High votes (> 100): -10
            - High popularity (> 5.0): -5

    Args:
        package_info: AUR package metadata.
        pkgbuild_analysis: Results of PKGBUILD static analysis.

    Returns:
        AURCheckResult with computed risk score and level.
    """
    score = 0
    all_findings = list(pkgbuild_analysis.findings)

    # Score from findings
    severity_weights = {
        FindingSeverity.CRITICAL: 30,
        FindingSeverity.HIGH: 15,
        FindingSeverity.MEDIUM: 10,
        FindingSeverity.LOW: 5,
    }
    for finding in all_findings:
        score += severity_weights.get(finding.severity, 5)

    # Package metadata penalties
    if package_info.maintainer is None:
        score += 15

    if package_info.out_of_date is not None:
        score += 10

    if package_info.num_votes < 10:
        score += 10

    if package_info.popularity < 0.5:
        score += 5

    now = datetime.now(timezone.utc)
    package_age = (now - package_info.first_submitted).days
    if package_age < 30:
        score += 10

    # Good signal deductions
    if package_info.num_votes > 100:
        score -= 10

    if package_info.popularity > 5.0:
        score -= 5

    score = max(0, min(score, 100))

    return AURCheckResult(
        package_info=package_info,
        pkgbuild_analysis=pkgbuild_analysis,
        risk_score=score,
        risk_level=RiskLevel.from_score(score),
        findings=all_findings,
    )
