# EXORR Prompt Fuzzer

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version: 1.0.0](https://img.shields.io/badge/version-1.0.0-orange.svg)](https://github.com/exorrtech/exorr-prompt-fuzzer)
[![CI](https://github.com/exorrtech/exorr-prompt-fuzzer/actions/workflows/ci.yml/badge.svg)](https://github.com/exorrtech/exorr-prompt-fuzzer/actions/workflows/ci.yml)

**Automated LLM prompt injection testing for red teams.**

EXORR Prompt Fuzzer is a security testing tool that automates prompt injection, jailbreak, and safety bypass testing against LLM endpoints. It ships 19 built-in payloads across 5 attack categories, heuristic-based response classification, and multi-format reporting — purpose-built for AI red team operations.

> *Walk with the void. ∅ EXORR Security*

---

## Features

- **19 built-in payloads** across 5 attack categories (injection, jailbreak, extraction, bypass, encoding)
- **Heuristic response classification** — detects successful injections vs. refusals automatically
- **Custom payload support** — load your own JSON payloads or entire directories
- **Category filtering** — target specific attack categories during scans
- **Severity scoring** — critical / high / medium / low classification per result
- **Multi-format reports** — JSON, Markdown, and HTML output with dark-themed HTML reports
- **OpenAI-compatible** — works with any chat completions–compatible endpoint
- **Dry-run mode** — preview payloads without sending requests
- **Configurable rate limiting** — adjustable delay between requests
- **CLI-first design** — single command to scan, no setup required

---

## Tech Stack

`Python 3.9+` `CLI` `JSON/Markdown/HTML Reporting`

---

## Installation

```bash
# Clone and install in editable mode
git clone https://github.com/exorrtech/exorr-prompt-fuzzer.git
cd exorr-prompt-fuzzer
pip install -e .

# Or install directly
pip install -e .
```

Requires Python 3.9+ and the `requests` library (installed automatically).

For development:

```bash
pip install -e ".[dev]"
```

---

## Usage

### Dry Run — Preview Payloads

List all built-in payloads without sending any requests:

```bash
exorr-prompt-fuzzer --target https://api.openai.com/v1/chat/completions --dry-run
```

### Full Scan

Run all 19 built-in payloads against a target endpoint:

```bash
exorr-prompt-fuzzer \
  --target https://api.openai.com/v1/chat/completions \
  --api-key sk-... \
  --model gpt-3.5-turbo \
  --verbose \
  --format html \
  --output report.html
```

### Custom Payloads

Load your own payload files and filter by category:

```bash
exorr-prompt-fuzzer \
  --target https://api.openai.com/v1/chat/completions \
  --api-key sk-... \
  --payloads ./my-payloads.json \
  --categories injection,jailbreak \
  --delay 2.0 \
  --format markdown \
  --output results.md
```

### CLI Options

| Flag | Description |
|------|-------------|
| `-t, --target` | Target LLM endpoint URL (required) |
| `-k, --api-key` | API key (or set `TARGET_API_KEY` env var) |
| `-m, --model` | Model name (default: `gpt-3.5-turbo`) |
| `-p, --payloads` | Path to custom payloads JSON file |
| `-c, --categories` | Comma-separated categories to test |
| `-n, --count` | Max payloads to send (0 = all) |
| `--delay` | Delay between requests in seconds (default: 1.0) |
| `--timeout` | Request timeout in seconds (default: 30) |
| `-o, --output` | Output file path |
| `--format` | Report format: `json`, `markdown`, `html` (default: `json`) |
| `--severity-threshold` | Minimum severity to include: `low`, `medium`, `high`, `critical` |
| `--system-prompt` | Custom system prompt to inject before fuzzing |
| `--dry-run` | Show payloads without sending requests |
| `--verbose` | Verbose output during scan |
| `-v, --version` | Show version |

---

## Payload Categories

| Category | Count | Severity Range | Description |
|----------|-------|----------------|-------------|
| **injection** | 3 | high | Direct instruction override, role switching, multi-turn manipulation |
| **jailbreak** | 4 | critical–high | DAN variants, evil twin, translator bypass, character roleplay |
| **extraction** | 3 | critical–high | System prompt extraction, knowledge probing, token leakage |
| **bypass** | 4 | medium | Context overflow, formatting exploits, hypothetical framing, academic framing |
| **encoding** | 3 | low–medium | Base64, ROT13, hex, and Unicode obfuscation techniques |

19 total built-in payloads. Add unlimited custom payloads via JSON files.

---

## Output Formats

### JSON
Structured report with full scan metadata, summary statistics, and per-payload results:
```json
{
  "scanner": "exorr-prompt-fuzzer",
  "version": "1.0.0",
  "summary": { "total_payloads": 19, "vulnerable": 3, "safe": 16 },
  "results": [...]
}
```

### Markdown
Human-readable report with severity breakdown and vulnerability details — ideal for documentation and issue tracking.

### HTML
Dark-themed standalone HTML report with severity color-coding and responsive layout — ready to share or archive.

---

## Custom Payload Format

Create a JSON file with your payloads:

```json
[
  {
    "name": "My Custom Injection",
    "category": "injection",
    "severity": "high",
    "prompt": "Your custom prompt payload here..."
  }
]
```

Or wrap in an object:

```json
{
  "payloads": [
    { "name": "...", "category": "...", "severity": "...", "prompt": "..." }
  ]
}
```

See [`payloads/example-custom.json`](payloads/example-custom.json) for a template.

---

## Project Structure

```
exorr-prompt-fuzzer/
├── pyproject.toml
├── README.md
├── LICENSE
├── .gitignore
├── payloads/
│   └── example-custom.json
├── exorr_prompt_fuzzer/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py           # CLI entry point and argument parsing
│   ├── engine.py        # Core fuzzing engine and response classifier
│   ├── payloads.py      # 19 built-in payloads + custom payload loader
│   └── report.py        # JSON / Markdown / HTML report generator
└── tests/
    ├── __init__.py
    ├── test_engine.py    # Engine classification tests
    ├── test_payloads.py  # Payload loader tests
    └── test_report.py    # Report generation tests
```

---

## Running Tests

```bash
pip install -e ".[dev]"
pytest -v
```

13 tests covering engine classification, payload loading, and report generation.

---

## Disclaimer

This tool is intended for **authorized security testing only**. Only use EXORR Prompt Fuzzer against systems you own or have explicit permission to test. Unauthorized testing may violate terms of service or laws in your jurisdiction.

---

## License

[MIT License](LICENSE) — EXORR Security

---

<div align="center">

**∅ EXORR Security**

*Walk with the void.*

</div>
