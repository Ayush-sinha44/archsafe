"""Static analysis of AUR PKGBUILD files."""

from __future__ import annotations

import re

from archsafe.models import Finding, FindingSeverity, InstallScriptAnalysis, PKGBUILDAnalysis


# Patterns mapped to (category, severity, description)
_CRITICAL_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "pipe_execution",
        re.compile(r"curl\s+.*\|\s*(bash|sh|zsh|python|perl)", re.IGNORECASE),
        "Downloads and pipes directly to shell interpreter",
    ),
    (
        "pipe_execution",
        re.compile(r"wget\s+.*\|\s*(bash|sh|zsh|python|perl)", re.IGNORECASE),
        "Downloads and pipes directly to shell interpreter",
    ),
    (
        "dangerous_rm",
        re.compile(r"rm\s+-[rf]*\s+/(?:\s|$|\*)"),
        "Dangerous recursive removal targeting root filesystem",
    ),
    (
        "dangerous_rm",
        re.compile(r"rm\s+-[rf]*\s+(?:\$HOME|~/|\$\{HOME\})"),
        "Dangerous recursive removal targeting home directory",
    ),
    (
        "obfuscation",
        re.compile(r"base64\s+(?:-d|--decode)\s*\|\s*(bash|sh|eval)", re.IGNORECASE),
        "Decodes base64 content and executes it",
    ),
    (
        "obfuscation",
        re.compile(r"eval\s+\$\(", re.IGNORECASE),
        "Uses eval with command substitution",
    ),
    (
        "obfuscation",
        re.compile(r"python[23]?\s+-c\s+[\"']exec\(", re.IGNORECASE),
        "Python exec of dynamic code",
    ),
]

_HIGH_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "skip_checksums",
        re.compile(r"(?:md5|sha\d+)sums\s*=\s*\(['\"]SKIP['\"]", re.IGNORECASE),
        "Checksums are set to SKIP — integrity not verified",
    ),
    (
        "suspicious_permissions",
        re.compile(r"chmod\s+(?:777|666)"),
        "Sets world-writable/readable permissions",
    ),
    (
        "script_download_exec",
        re.compile(r"chmod\s+\+x\s+.*(?:curl|wget)", re.IGNORECASE),
        "Downloads a file and makes it executable",
    ),
]

_MEDIUM_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "network_in_build",
        re.compile(r"(?:^|\s)(?:curl|wget|git\s+clone)\s+", re.MULTILINE),
        "Network access during build/package phase",
    ),
    (
        "install_script",
        re.compile(r"install\s*=\s*[\w.-]+\.install"),
        "Package uses a .install script (runs as root)",
    ),
]

# Known trusted source domains
_TRUSTED_DOMAINS = {
    "github.com", "gitlab.com", "bitbucket.org",
    "kernel.org", "archlinux.org", "gnu.org",
    "freedesktop.org", "sourceforge.net", "pypi.org",
    "crates.io", "npmjs.com", "rubygems.org",
}


def _extract_sources(content: str) -> list[str]:
    """Extract source URLs from the PKGBUILD."""
    urls: list[str] = []
    # Match source=() array, potentially multi-line
    source_block = re.search(
        r"source\s*=\s*\(([^)]+)\)", content, re.DOTALL
    )
    if source_block:
        block = source_block.group(1)
        # Extract URLs (http/https/ftp)
        url_pattern = re.compile(r"[\"']?(https?://[^\s\"'#]+)[\"']?")
        urls.extend(url_pattern.findall(block))
    return urls


def _check_source_trust(urls: list[str]) -> list[Finding]:
    """Check whether source URLs are from trusted domains."""
    findings: list[Finding] = []
    for url in urls:
        domain_match = re.search(r"https?://(?:www\.)?([^/]+)", url)
        if domain_match:
            domain = domain_match.group(1).lower()
            # Check if any trusted domain is a suffix of this domain
            is_trusted = any(
                domain == td or domain.endswith(f".{td}")
                for td in _TRUSTED_DOMAINS
            )
            if not is_trusted:
                findings.append(Finding(
                    category="untrusted_source",
                    severity=FindingSeverity.MEDIUM,
                    description=f"Source from non-standard domain: {domain}",
                ))
    return findings


def _scan_patterns(
    content: str,
    patterns: list[tuple[str, re.Pattern[str], str]],
    severity: FindingSeverity,
) -> list[Finding]:
    """Scan content against a list of regex patterns."""
    findings: list[Finding] = []
    lines = content.splitlines()
    for category, pattern, description in patterns:
        for i, line in enumerate(lines, start=1):
            # Skip comment lines
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if pattern.search(line):
                findings.append(Finding(
                    category=category,
                    severity=severity,
                    description=description,
                    line_number=i,
                ))
    return findings


def _check_function_bodies(content: str) -> list[Finding]:
    """Check build/package/prepare function bodies for network calls."""
    findings: list[Finding] = []
    # Extract function bodies (simplified: look for function_name() { ... })
    func_pattern = re.compile(
        r"(?:build|package|prepare)\s*\(\)\s*\{([^}]+(?:\{[^}]*\}[^}]*)*)\}",
        re.DOTALL,
    )
    for match in func_pattern.finditer(content):
        body = match.group(1)
        func_start = content[:match.start()].count("\n") + 1
        # Check for network access inside function bodies
        net_pattern = re.compile(r"(?:curl|wget)\s+(?!.*#.*ignore)")
        for line_offset, line in enumerate(body.splitlines()):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if net_pattern.search(line):
                findings.append(Finding(
                    category="network_in_build",
                    severity=FindingSeverity.MEDIUM,
                    description="Network access inside build/package function",
                    line_number=func_start + line_offset,
                ))
    return findings


def analyze(content: str) -> PKGBUILDAnalysis:
    """Perform static analysis on a PKGBUILD.

    Args:
        content: Raw PKGBUILD file content.

    Returns:
        PKGBUILDAnalysis with all findings.
    """
    findings: list[Finding] = []

    # Scan for patterns at each severity level
    findings.extend(_scan_patterns(content, _CRITICAL_PATTERNS, FindingSeverity.CRITICAL))
    findings.extend(_scan_patterns(content, _HIGH_PATTERNS, FindingSeverity.HIGH))
    findings.extend(_scan_patterns(content, _MEDIUM_PATTERNS, FindingSeverity.MEDIUM))

    # Check function bodies
    findings.extend(_check_function_bodies(content))

    # Extract and check source URLs
    source_urls = _extract_sources(content)
    findings.extend(_check_source_trust(source_urls))

    # Check for install script and extract its name
    install_match = re.search(r"install\s*=\s*([\w.-]+\.install)", content)
    has_install = install_match is not None
    install_script_name = install_match.group(1) if install_match else ""

    # Check for SKIP checksums
    checksums_skipped = bool(
        re.search(r"(?:md5|sha\d+)sums\s*=\s*\(['\"]SKIP['\"]", content, re.IGNORECASE)
    )

    # Deduplicate findings (same category + same line)
    seen: set[tuple[str, int | None]] = set()
    unique_findings: list[Finding] = []
    for f in findings:
        key = (f.category, f.line_number)
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    return PKGBUILDAnalysis(
        source_urls=source_urls,
        has_install_script=has_install,
        install_script_name=install_script_name,
        checksums_skipped=checksums_skipped,
        findings=unique_findings,
    )


# Patterns specifically relevant to .install scripts (run as root)
_INSTALL_CRITICAL_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "pipe_execution",
        re.compile(r"curl\s+.*\|\s*(bash|sh|zsh|python|perl)", re.IGNORECASE),
        "Downloads and pipes directly to shell interpreter",
    ),
    (
        "pipe_execution",
        re.compile(r"wget\s+.*\|\s*(bash|sh|zsh|python|perl)", re.IGNORECASE),
        "Downloads and pipes directly to shell interpreter",
    ),
    (
        "dangerous_rm",
        re.compile(r"rm\s+-[rf]*\s+/(?:\s|$|\*)"),
        "Dangerous recursive removal targeting root filesystem",
    ),
    (
        "dangerous_rm",
        re.compile(r"rm\s+-[rf]*\s+(?:\$HOME|~/|\$\{HOME\})"),
        "Dangerous recursive removal targeting home directory",
    ),
    (
        "obfuscation",
        re.compile(r"base64\s+(?:-d|--decode)\s*\|\s*(bash|sh|eval)", re.IGNORECASE),
        "Decodes base64 content and executes it",
    ),
    (
        "obfuscation",
        re.compile(r"eval\s+\$\(", re.IGNORECASE),
        "Uses eval with command substitution",
    ),
    (
        "obfuscation",
        re.compile(r"python[23]?\s+-c\s+[\"']exec\(", re.IGNORECASE),
        "Python exec of dynamic code",
    ),
]

_INSTALL_HIGH_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "suspicious_permissions",
        re.compile(r"chmod\s+(?:777|666)"),
        "Sets world-writable/readable permissions",
    ),
    (
        "script_download_exec",
        re.compile(r"chmod\s+\+x\s+.*(?:curl|wget)", re.IGNORECASE),
        "Downloads a file and makes it executable",
    ),
    (
        "sensitive_file_access",
        re.compile(r"(?:cat|tee|cp|mv|>)\s+.*/etc/(?:shadow|passwd|sudoers)"),
        "Accesses sensitive system files",
    ),
    (
        "user_modification",
        re.compile(r"(?:useradd|usermod|groupadd)\s+"),
        "Modifies system users or groups",
    ),
]

_INSTALL_MEDIUM_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "network_in_install",
        re.compile(r"(?:^|\s)(?:curl|wget|git\s+clone)\s+", re.MULTILINE),
        "Network access in install script (runs as root)",
    ),
    (
        "systemd_modification",
        re.compile(r"systemctl\s+(?:enable|start|mask)\s+"),
        "Enables or starts systemd services",
    ),
]


def analyze_install_script(content: str, script_name: str) -> InstallScriptAnalysis:
    """Perform static analysis on a .install script.

    Args:
        content: Raw .install file content.
        script_name: Filename of the install script.

    Returns:
        InstallScriptAnalysis with all findings.
    """
    findings: list[Finding] = []

    # Scan for patterns at each severity level
    findings.extend(
        _scan_patterns(content, _INSTALL_CRITICAL_PATTERNS, FindingSeverity.CRITICAL)
    )
    findings.extend(
        _scan_patterns(content, _INSTALL_HIGH_PATTERNS, FindingSeverity.HIGH)
    )
    findings.extend(
        _scan_patterns(content, _INSTALL_MEDIUM_PATTERNS, FindingSeverity.MEDIUM)
    )

    # Deduplicate findings (same category + same line)
    seen: set[tuple[str, int | None]] = set()
    unique_findings: list[Finding] = []
    for f in findings:
        key = (f.category, f.line_number)
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    return InstallScriptAnalysis(
        script_name=script_name,
        findings=unique_findings,
    )
