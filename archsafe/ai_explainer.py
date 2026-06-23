"""LLM integration for human-readable risk explanations.

Supports Groq and OpenAI as providers. The active provider and API key are
resolved via config_manager (env var → stored config), or can be overridden
by passing ``api_key`` directly (used by the --api-key CLI flag).
"""

from __future__ import annotations

from archsafe import config_manager
from archsafe.models import AURCheckResult, UpdateCheckResult


MAX_TOKENS = 300
TEMPERATURE = 0.3

SYSTEM_PROMPT = (
    "You are a security advisor for Arch Linux users. Your role is to EXPLAIN "
    "findings that have already been determined by deterministic analysis — "
    "you do NOT make the risk assessment yourself. Be concise (2-4 sentences), "
    "actionable, and focus on what the user should do next. Do not use markdown "
    "formatting. Speak directly to the user."
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _is_available(api_key: str | None = None) -> bool:
    """Return True if an API key is available for the active provider."""
    if api_key:
        return True
    return bool(config_manager.get_active_api_key())


def _call_groq(user_prompt: str, api_key: str, model: str) -> str:
    """Send a prompt to Groq and return the response text."""
    try:
        from groq import Groq

        client = Groq(api_key=api_key)
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            max_tokens=MAX_TOKENS,
            temperature=TEMPERATURE,
        )
        return response.choices[0].message.content.strip()
    except Exception:
        return ""


def _call_openai(user_prompt: str, api_key: str, model: str) -> str:
    """Send a prompt to OpenAI and return the response text."""
    try:
        from openai import OpenAI

        client = OpenAI(api_key=api_key)
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            max_tokens=MAX_TOKENS,
            temperature=TEMPERATURE,
        )
        return response.choices[0].message.content.strip()
    except Exception:
        return ""


def _call_llm(user_prompt: str, api_key: str | None = None) -> str:
    """Dispatch to the appropriate LLM provider and return the response."""
    provider = config_manager.get_provider()
    resolved_key = api_key or config_manager.get_active_api_key(provider)
    if not resolved_key:
        return ""
    model = config_manager.get_model(provider)

    if provider == "openai":
        return _call_openai(user_prompt, resolved_key, model)
    # Default: groq
    return _call_groq(user_prompt, resolved_key, model)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def explain_update(result: UpdateCheckResult, api_key: str | None = None) -> str:
    """Generate an AI explanation for an update check result.

    Args:
        result:  The deterministic update check result.
        api_key: Optional one-shot API key override (from --api-key flag).

    Returns:
        Human-readable explanation string, or empty string on failure.
    """
    if not _is_available(api_key):
        return ""

    # Build context for the LLM
    news_summary = ""
    for item in result.news_items:
        if item.matched_keywords:
            news_summary += (
                f"- \"{item.title}\" (keywords: {', '.join(item.matched_keywords)})"
            )
            if item.affected_packages:
                news_summary += (
                    f" [affects installed: {', '.join(item.affected_packages)}]"
                )
            news_summary += "\n"

    if not news_summary:
        news_summary = "No flagged news items.\n"

    prompt = (
        f"Risk Score: {result.risk_score}/100 ({result.risk_level.value})\n"
        f"Kernel: {result.system_info.kernel_version}\n"
        f"DE: {result.system_info.desktop_environment}\n"
        f"GPU: {result.system_info.gpu_info}\n"
        f"Installed packages: {len(result.system_info.installed_packages)}\n"
        f"Affected packages: {', '.join(result.affected_packages) or 'None'}\n"
        f"\nFlagged News:\n{news_summary}"
        f"\nExplain these findings to the user in 2-4 sentences. "
        f"What should they do before updating?"
    )

    return _call_llm(prompt, api_key)


def explain_aur(result: AURCheckResult, api_key: str | None = None) -> str:
    """Generate an AI explanation for an AUR package analysis.

    Args:
        result:  The deterministic AUR check result.
        api_key: Optional one-shot API key override (from --api-key flag).

    Returns:
        Human-readable explanation string, or empty string on failure.
    """
    if not _is_available(api_key):
        return ""

    findings_text = ""
    for f in result.findings:
        findings_text += f"- [{f.severity.value}] {f.description}"
        if f.line_number:
            findings_text += f" (line {f.line_number})"
        findings_text += "\n"

    if not findings_text:
        findings_text = "No suspicious patterns detected.\n"

    pkg = result.package_info
    prompt = (
        f"Package: {pkg.name} {pkg.version}\n"
        f"Risk Score: {result.risk_score}/100 ({result.risk_level.value})\n"
        f"Votes: {pkg.num_votes}, Popularity: {pkg.popularity}\n"
        f"Maintainer: {pkg.maintainer or 'ORPHANED'}\n"
        f"Out of date: {'Yes' if pkg.out_of_date else 'No'}\n"
        f"\nFindings:\n{findings_text}"
        f"\nExplain these findings to the user in 2-4 sentences. "
        f"Should they proceed with installation?"
    )

    return _call_llm(prompt, api_key)
