<p align="center">
  <img src="https://raw.githubusercontent.com/ecrou-exact/RuleCast/main/doc/logo.png" width="300" alt="RuleCast logo">
</p>

<p align="center">
  A security rule parser and normalizer — converts multi-format detection signatures into structured JSON.<br>
  Built to complement <a href="https://github.com/ngsoti/rulezet-core">rulezet-core</a>.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-blue" alt="version 1.0.0">
  <img src="https://img.shields.io/badge/python-3.11+-blue" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/formats-10-green" alt="10 formats">
  <img src="https://img.shields.io/badge/license-MIT-lightgrey" alt="MIT license">
</p>

---

## What it does

RuleCast takes raw cybersecurity detection rules via text or file, validates their syntax, and outputs structured JSON ready for integration or automation. It supports ten rule formats out of the box and is designed to be extended with new formats in minutes.

## Supported formats

| Format | Extension(s) | Validator | Status |
|--------|-------------|-----------|--------|
| YARA | `.yar` `.yara` | `yara-python` | ✅ Implemented |
| Sigma | `.yaml` `.yml` | `pysigma` | ✅ Implemented |
| Suricata | `.rules` | `suricataparser` | ✅ Implemented |
| CRS (ModSecurity / OWASP) | `.conf` | `msc-pyparser` | ✅ Implemented |
| NSE (Nmap Scripting Engine) | `.nse` | `luac -p` | ✅ Implemented |
| Nova (AI/LLM hunting) | `.nov` | `nova-hunting` | ✅ Implemented |
| Zeek | `.zeek` `.bro` | `zeekscript` | ✅ Implemented |
| Wazuh SIEM | `.xml` | stdlib XML | ✅ Implemented |
| Elastic Security | `.toml` | stdlib `tomllib` | ✅ Implemented |
| ATR (Agent Threat Rules) | `.yaml` `.yml` | `PyYAML` | ✅ Implemented |

## Installation

```bash
git clone https://github.com/rulezet/rulezet-cast.git
cd rulezet-cast
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

**Interactive menu:**
```bash
python3 main.py or ./run.sh
```

<img width="703" height="488" alt="Screenshot from 2026-05-11 11-56-13" src="https://github.com/user-attachments/assets/1eb2ba37-74e9-478a-84e1-ac5bde20cc73" />

**Direct commands:**
```bash
# Parse a rule from text
python3 main.py parse -t 'rule MyTest { condition: true }'

# Parse from a file
python3 main.py parse -i rules.yar

# Validate only
python3 main.py validate -i rules.yar -f yara

# Auto-detect format
python3 main.py detect -t 'rule MyTest { condition: true }'

# Output as JSON
python3 main.py parse -i rules.yar --json

# Normalize to Rulezet schema
python3 main.py parse -i rules.yar --normalize

# List all registered parsers
python3 main.py list

# Launch the interactive test runner
python3 main.py test

# Scaffold a new parser
python3 main.py new myformat
```

## Test runner

RuleCast includes an interactive test runner to validate parsers against rule fixtures:

```bash
python3 main.py test
```

Choose a format, load a test file or paste content, then get per-rule results and a summary that checks counts against the expected values declared in the fixture header.

The test runner also includes a **format clash detection test** (press `c` at the format menu). It runs all formats that share an extension against a mixed fixture and verifies that each rule is correctly identified — catching `can_handle()` false positives automatically.

## Adding a new format

See **[CONTRIBUTING.md](CONTRIBUTING.md)** for the full step-by-step guide with screenshots.

Quick start:

```bash
python3 main.py new <format_name>
```

This generates a ready-to-fill template at `parsers/formats/<format_name>_parser.py`, registers the parser, creates a test fixture, and adds the fixture to the test runner. Implement the five methods, add your test rules, and open a PR.
