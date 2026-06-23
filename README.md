# 🛡️ ArchSafe

A safety analysis tool for Arch Linux updates and AUR packages. ArchSafe checks recent Arch Linux news for breaking changes, analyzes AUR packages for potential risks, and optionally uses AI to provide detailed safety assessments.

## Features

- **Update Checker** — Scans the Arch Linux news feed for recent announcements that may require manual intervention before updating. Highlights breaking changes, package removals, and configuration migrations.
- **AUR Package Analyzer** — Evaluates AUR packages by inspecting maintainer activity, vote count, popularity, out-of-date status, and upstream health. Produces a risk score so you can make informed decisions before installing.
- **AI-Powered Analysis** (optional) — Uses Groq or OpenAI to provide detailed, human-readable safety summaries and recommendations. No API key is needed for the core analysis.

## Installation

```bash
git clone https://github.com/ayush/archsafe.git
cd archsafe
pip install -e .
```

After installation, the `archsafe` command is available system-wide.

## Configuration

ArchSafe works out of the box without any API keys — AI analysis is **optional**.

### Setting an API key from the CLI (recommended)

```bash
# Store a Groq key (default provider)
archsafe config set-key gsk_xxxxxxxxxxxx

# Store an OpenAI key
archsafe config set-key sk-xxxxxxxxxxxx --provider openai

# Switch the active provider
archsafe config set-provider openai

# View current configuration (keys are masked)
archsafe config show

# Remove a stored key for a single run (use --no-ai to skip entirely)
archsafe config clear
```

Keys are stored in `~/.config/archsafe/config.json` with permissions `0600` (owner read/write only).

### Environment variables (alternative)

```bash
export GROQ_API_KEY="your_groq_key"
export OPENAI_API_KEY="your_openai_key"
```

### Key priority order

For any given run, ArchSafe resolves the API key in this order:

1. `--api-key` flag (one-shot, highest priority)
2. Environment variable (`GROQ_API_KEY` / `OPENAI_API_KEY`)
3. Stored config file (`~/.config/archsafe/config.json`)

Get your Groq key from: https://console.groq.com/keys  
Get your OpenAI key from: https://platform.openai.com/api-keys

## Usage

### Check for update safety

Scan recent Arch Linux news for potential issues before running `pacman -Syu`:

```bash
# Check news from the last 14 days (default)
archsafe update

# Check news from the last 30 days
archsafe update --days 30

# Skip AI analysis, show raw data only
archsafe update --no-ai

# Use a one-shot API key for this run only (not stored)
archsafe update --api-key gsk_xxxxxxxxxxxx
```

### Analyze an AUR package

Evaluate an AUR package before installing:

```bash
# Analyze a package
archsafe aur <package-name>

# Example
archsafe aur yay

# Skip AI analysis
archsafe aur yay --no-ai

# Use a one-shot API key
archsafe aur yay --api-key sk-xxxxxxxxxxxx
```

### Config management

```bash
archsafe config set-key <KEY>               # store key (uses active provider)
archsafe config set-key <KEY> --provider openai  # store for a specific provider
archsafe config get-key                     # show masked key for active provider
archsafe config get-key --provider groq     # show masked key for a specific provider
archsafe config set-provider groq           # switch active provider
archsafe config show                        # full config summary
archsafe config clear                       # delete all stored config
archsafe config clear --yes                 # skip confirmation prompt
```

### Example Output

```
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃       AUR Package Analysis          ┃
┃            yay                      ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

  Risk Score: 2/10 (Low Risk) ✅

  Maintainer:    Jguer
  Votes:         1842
  Popularity:    3.21
  Out of Date:   No
  Last Modified: 2026-05-10

  AI Summary:
  yay is a well-maintained AUR helper with strong
  community trust. No safety concerns detected.
```


