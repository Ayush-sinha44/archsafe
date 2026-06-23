"""Persistent configuration manager for ArchSafe.

Stores API keys and provider settings in ~/.config/archsafe/config.json.
Key priority (highest → lowest):
  1. CLI --api-key flag (handled in main.py, passed directly)
  2. Environment variable (GROQ_API_KEY / OPENAI_API_KEY)
  3. Stored config file
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SUPPORTED_PROVIDERS = ("groq", "openai")
DEFAULT_PROVIDER = "groq"

_ENV_VARS: dict[str, str] = {
    "groq": "GROQ_API_KEY",
    "openai": "OPENAI_API_KEY",
}

_DEFAULT_MODELS: dict[str, str] = {
    "groq": "llama-3.3-70b-versatile",
    "openai": "gpt-4o-mini",
}


def _config_path() -> Path:
    """Return the path to the config file, honouring XDG_CONFIG_HOME."""
    xdg = os.environ.get("XDG_CONFIG_HOME", "")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "archsafe" / "config.json"


# ---------------------------------------------------------------------------
# Low-level read / write
# ---------------------------------------------------------------------------

def load_config() -> dict:
    """Load the config file and return its contents as a dict.

    Returns an empty dict if the file does not exist or cannot be parsed.
    """
    path = _config_path()
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError):
        return {}


def save_config(data: dict) -> None:
    """Write *data* to the config file, creating parent dirs as needed.

    The file is created with permissions 0600 so only the owner can read it.
    """
    path = _config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    # Restrict permissions to owner r/w only
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)


def clear_config() -> None:
    """Delete the config file entirely."""
    path = _config_path()
    if path.exists():
        path.unlink()


# ---------------------------------------------------------------------------
# Higher-level helpers
# ---------------------------------------------------------------------------

def get_provider() -> str:
    """Return the active provider name (default: 'groq')."""
    cfg = load_config()
    return cfg.get("provider", DEFAULT_PROVIDER)


def set_provider(provider: str) -> None:
    """Persist the active provider choice."""
    if provider not in SUPPORTED_PROVIDERS:
        raise ValueError(f"Unsupported provider '{provider}'. Choose from: {', '.join(SUPPORTED_PROVIDERS)}")
    cfg = load_config()
    cfg["provider"] = provider
    save_config(cfg)


def set_api_key(api_key: str, provider: str | None = None) -> None:
    """Store an API key for the given provider (defaults to active provider)."""
    cfg = load_config()
    provider = provider or cfg.get("provider", DEFAULT_PROVIDER)
    if provider not in SUPPORTED_PROVIDERS:
        raise ValueError(f"Unsupported provider '{provider}'.")
    cfg[f"{provider}_api_key"] = api_key
    cfg["provider"] = provider  # also set as active provider
    save_config(cfg)


def get_stored_api_key(provider: str | None = None) -> str | None:
    """Return the stored API key for the given provider, or None."""
    cfg = load_config()
    provider = provider or cfg.get("provider", DEFAULT_PROVIDER)
    return cfg.get(f"{provider}_api_key") or None


def get_active_api_key(provider: str | None = None) -> str | None:
    """Return the best available API key for *provider*, following priority chain.

    Priority: env var → stored config.
    (The CLI --api-key flag is handled upstream and passed in directly.)
    """
    provider = provider or get_provider()
    env_var = _ENV_VARS.get(provider, "")
    # 1. Environment variable
    env_key = os.environ.get(env_var, "").strip()
    if env_key:
        return env_key
    # 2. Stored config
    return get_stored_api_key(provider)


def get_model(provider: str | None = None) -> str:
    """Return the model name to use for the given provider."""
    provider = provider or get_provider()
    cfg = load_config()
    key = f"{provider}_model"
    return cfg.get(key) or _DEFAULT_MODELS.get(provider, "")


def mask_key(key: str) -> str:
    """Return a masked version of an API key for display (e.g. gsk_****abcd)."""
    if not key or len(key) < 8:
        return "****"
    return key[:4] + "****" + key[-4:]


def config_summary() -> dict:
    """Return a display-safe summary of the current configuration."""
    cfg = load_config()
    provider = cfg.get("provider", DEFAULT_PROVIDER)
    summary: dict = {"provider": provider, "config_file": str(_config_path())}
    for p in SUPPORTED_PROVIDERS:
        raw_key = cfg.get(f"{p}_api_key", "")
        env_key = os.environ.get(_ENV_VARS.get(p, ""), "")
        if env_key:
            summary[f"{p}_api_key"] = f"{mask_key(env_key)} (from env)"
        elif raw_key:
            summary[f"{p}_api_key"] = f"{mask_key(raw_key)} (stored)"
        else:
            summary[f"{p}_api_key"] = "not set"
        summary[f"{p}_model"] = cfg.get(f"{p}_model") or _DEFAULT_MODELS.get(p, "")
    return summary
