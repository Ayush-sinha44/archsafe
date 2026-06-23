"""Arch Linux update safety checker."""

from __future__ import annotations

import os
import re
import subprocess
from datetime import datetime, timezone, timedelta
from html import unescape

import feedparser

from archsafe.models import NewsItem, SystemInfo


ARCH_NEWS_RSS = "https://archlinux.org/feeds/news/"

DANGER_KEYWORDS = [
    "manual intervention",
    "breaking change",
    "migration",
    "requires action",
    "keyring update",
    "filesystem change",
    "package replacement",
    "incompatible",
    "downgrade",
    "removed from",
    "conflict",
    "rebuild required",
]


def _strip_html(html: str) -> str:
    """Remove HTML tags and unescape entities."""
    text = re.sub(r"<[^>]+>", " ", html)
    return unescape(text).strip()


def _match_keywords(text: str) -> list[str]:
    """Find danger keywords in text (case-insensitive)."""
    text_lower = text.lower()
    return [kw for kw in DANGER_KEYWORDS if kw in text_lower]


def fetch_news(days: int = 14) -> list[NewsItem]:
    """Fetch and parse recent Arch Linux news articles.

    Args:
        days: Number of days to look back.

    Returns:
        List of NewsItem with matched keywords populated.
    """
    feed = feedparser.parse(ARCH_NEWS_RSS)
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    items: list[NewsItem] = []

    for entry in feed.entries:
        # Parse published date
        published = datetime(*entry.published_parsed[:6], tzinfo=timezone.utc)
        if published < cutoff:
            continue

        title = entry.get("title", "")
        summary_html = entry.get("summary", "")
        summary_text = _strip_html(summary_html)
        link = entry.get("link", "")

        # Scan for danger keywords in title + summary
        combined_text = f"{title} {summary_text}"
        matched = _match_keywords(combined_text)

        items.append(NewsItem(
            title=title,
            summary=summary_text,
            published=published,
            link=link,
            matched_keywords=matched,
        ))

    return items


def get_system_info() -> SystemInfo:
    """Gather local system information.

    Returns:
        SystemInfo with installed packages, kernel, DE, and GPU info.
    """
    # Installed packages
    installed_packages: dict[str, str] = {}
    try:
        result = subprocess.run(
            ["pacman", "-Q"],
            capture_output=True, text=True, timeout=30
        )
        for line in result.stdout.strip().splitlines():
            parts = line.split(maxsplit=1)
            if len(parts) == 2:
                installed_packages[parts[0]] = parts[1]
    except (subprocess.SubprocessError, FileNotFoundError):
        pass

    # Kernel version
    kernel_version = "unknown"
    try:
        result = subprocess.run(
            ["uname", "-r"],
            capture_output=True, text=True, timeout=10
        )
        kernel_version = result.stdout.strip()
    except (subprocess.SubprocessError, FileNotFoundError):
        pass

    # Desktop environment
    desktop_environment = (
        os.environ.get("XDG_CURRENT_DESKTOP")
        or os.environ.get("DESKTOP_SESSION")
        or "unknown"
    )

    # GPU info
    gpu_info = "unknown"
    try:
        result = subprocess.run(
            ["lspci"],
            capture_output=True, text=True, timeout=10
        )
        vga_lines = [
            line.strip() for line in result.stdout.splitlines()
            if "vga" in line.lower() or "3d" in line.lower() or "display" in line.lower()
        ]
        if vga_lines:
            gpu_info = "; ".join(vga_lines)
    except (subprocess.SubprocessError, FileNotFoundError):
        pass

    return SystemInfo(
        installed_packages=installed_packages,
        kernel_version=kernel_version,
        desktop_environment=desktop_environment,
        gpu_info=gpu_info,
    )
