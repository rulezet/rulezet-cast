<p align="center">
  <img src="https://raw.githubusercontent.com/ecrou-exact/RuleCast/main/doc/logo.png" width="300" alt="RuleCast logo">
</p>

<p align="center">
  A security rule parser and normalizer — converts multi-format detection signatures into structured JSON.<br>
  Built to complement <a href="https://github.com/ngsoti/rulezet-core">rulezet-core</a>.
</p>

---

## What it does

RuleCast takes raw cybersecurity detection rules (YARA, Sigma, Suricata, and more) via text or file, validates their syntax, and outputs structured JSON ready for integration or automation.

## Supported formats

| Format | Status |
|--------|--------|
| YARA | ✅ Implemented |
| Sigma | 🔜 Planned |
| Suricata | 🔜 Planned |
| Zeek | 🔜 Planned |
| Wazuh | 🔜 Planned |
| NSE / CRS / Nova | 🔜 Planned |

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
python3 main.py
```

<img width="703" height="488" alt="Screenshot from 2026-05-11 11-56-13" src="https://github.com/user-attachments/assets/1eb2ba37-74e9-478a-84e1-ac5bde20cc73" />


**Direct commands:**
```bash
# Parse a rule from text
python3 main.py parse -t 'rule MyTest { condition: true }'

# Parse from a file
python3 main.py parse -i rules.yar

# Validate only
python3 main.py validate -i rules.yar

# Auto-detect format
python3 main.py detect -t 'rule MyTest { condition: true }'

# Output as JSON
python3 main.py parse -i rules.yar --json

# Launch the interactive test runner
python3 main.py test

# Scaffold a new parser
python3 main.py new sigma
```

## Test runner

RuleCast includes an interactive test runner to validate parsers against rule fixtures:

```bash
python3 main.py test
```

It lets you choose a format, load a test file or paste content, then shows per-rule results and a summary that checks found counts against the expected counts declared in the test file header.

## Adding a new format

See **[CONTRIBUTING.md](CONTRIBUTING.md)** for the full guide: how the pipeline works, what methods to implement, how to write test fixtures, and how to open a pull request.

Quick start:

```bash
python3 main.py new <format_name>
```

This generates a ready-to-fill template at `parsers/formats/<format_name>_parser.py`. Implement the methods, add the parser to `parsers/__init__.py`, add a test fixture, and you're done.
