# Contributing to RuleCast

This guide explains how RuleCast works internally and walks you through every step to add a new rule format and submit a pull request.

---

## Table of Contents

1. [How RuleCast works](#1-how-rulecast-works)
2. [Project structure](#2-project-structure)
3. [The pipeline explained](#3-the-pipeline-explained)
4. [The BaseRuleParser contract](#4-the-baseruleparser-contract)
5. [Output schemas](#5-output-schemas)
6. [Step-by-step: adding a new format](#6-step-by-step-adding-a-new-format)
7. [Writing tests](#7-writing-tests)
8. [Design rules you must follow](#8-design-rules-you-must-follow)
9. [Submitting a pull request](#9-submitting-a-pull-request)

---

## 1. How RuleCast works

RuleCast takes raw cybersecurity detection rule text (from a file or pasted input), figures out what format it is, breaks it into individual rules, validates and parses each one, then outputs structured JSON.

The core idea is **one parser class per format**. Each parser is a self-contained module that knows everything about its format. The engine just calls them in sequence.

```
raw text / file
      │
      ▼
  RuleCastEngine
      │
      ├─ detect_format()      → finds which parser can handle this content
      │
      ├─ split_rules()        → splits multi-rule content into individual strings
      │
      ├─ validate()           → checks syntax, returns ValidationResult
      │
      ├─ parse()              → extracts structured data, returns dict
      │
      └─ normalize()          → maps to the universal Rulezet schema
```

All of this happens on **strings only** — parsers never open files themselves.

---

## 2. Project structure

```
rulezet-cast/
├── main.py                        # CLI: interactive menu + direct commands
├── test_runner.py                 # Interactive test tool
├── requirements.txt
├── parsers/
│   ├── __init__.py                # ALL_PARSERS — register your parser here
│   ├── base.py                    # BaseRuleParser + ValidationResult
│   ├── engine.py                  # RuleCastEngine + ParseResult
│   └── formats/
│       ├── yara_parser.py         # YARA (reference implementation)
│       └── your_format_parser.py  # ← your file goes here
├── utils/
│   └── scaffold.py                # generates a new parser template
└── tests/
    └── formats/
        ├── test_yara_rules.yar
        └── test_your_format.*     # ← your test file goes here
```

---

## 3. The pipeline explained

### Step 1 — `can_handle(chunk: str) -> bool`

Called by the engine to auto-detect the format. Should return `True` if the input looks like rules from your format. Keep it fast — a regex check on distinctive keywords is enough.

```python
# Suricata example
def can_handle(self, chunk: str) -> bool:
    return bool(re.search(r'^(alert|drop|pass|reject)\s+\w+', chunk, re.MULTILINE))
```

### Step 2 — `split_rules(raw_content: str) -> List[str]`

Takes the full content of a file (or pasted text) and returns a list of individual rule strings. This is critical for resilience: if one rule is broken, the others should still be extractable.

Rules of thumb:
- Work on the raw string, never open files here.
- Use regex to find rule boundaries, not character-level state machines.
- Return each rule as a standalone string that can be passed directly to `validate()` and `parse()`.

```python
# Suricata: one rule per non-comment line
def split_rules(self, raw_content: str) -> List[str]:
    rules = []
    for line in raw_content.splitlines():
        line = line.strip()
        if line and not line.startswith('#'):
            rules.append(line)
    return rules
```

### Step 3 — `validate(raw_rule: str) -> ValidationResult`

Checks whether a single rule is syntactically and semantically valid. Returns a `ValidationResult`:

```python
@dataclass
class ValidationResult:
    ok: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    normalized_content: Optional[str] = None  # corrected version if auto-fixed
```

Always return a `ValidationResult` — never raise exceptions from `validate()`.

### Step 4 — `parse(raw_rule: str) -> Dict[str, Any]`

Extracts structured data from one rule. Must always return the full schema (see section 5), even if parsing fails — use a fallback with empty defaults.

```python
def parse(self, raw_rule: str) -> Dict[str, Any]:
    try:
        # ... real parsing logic ...
        return { "format": self.format, "identity": {...}, ... , "status": "parsed" }
    except Exception as e:
        return {
            "format": self.format,
            "identity": {"name": None, "tags": [], "scopes": []},
            "metadata": {}, "content": raw_rule, "tags": [],
            "vulnerabilities": [], "references": [], "sources": [],
            "original_uuid": None, "status": "parsing_error", "error": str(e),
        }
```

### Step 5 — `normalize(parsed_data: Dict[str, Any]) -> Dict[str, Any]`

Maps the `parse()` output to the flat Rulezet schema (see section 5). Always use `.get()` with defaults — never direct key access.

---

## 4. The BaseRuleParser contract

```python
from parsers.base import BaseRuleParser, ValidationResult

class MyFormatParser(BaseRuleParser):

    @property
    def format(self) -> str:
        return "myformat"           # lowercase, no spaces

    @property
    def extensions(self) -> List[str]:
        return [".ext1", ".ext2"]   # file extensions for this format

    def can_handle(self, chunk: str) -> bool:
        ...                         # fast format detection from raw text

    def split_rules(self, raw_content: str) -> List[str]:
        ...                         # segment multi-rule content

    def validate(self, raw_rule: str) -> ValidationResult:
        ...                         # syntax + semantic check

    def parse(self, raw_rule: str) -> Dict[str, Any]:
        ...                         # extract structured data

    def normalize(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        ...                         # map to Rulezet schema
```

---

## 5. Output schemas

### `parse()` output — mandatory keys

Every `parse()` call, including fallback paths, must return a dict with **all** of these keys:

```python
{
    "format":          str,            # e.g. "sigma"
    "identity": {
        "name":        str | None,     # rule name or title
        "tags":        List[str],      # rule-level tags
        "scopes":      List[str],      # e.g. ["global"] for YARA
    },
    "metadata":        Dict[str, Any], # all key=value pairs from the rule's meta block
    "content":         str,            # original raw rule string, never modified
    "tags":            List[str],
    "vulnerabilities": List[str],      # CVE IDs found (e.g. ["CVE-2021-44228"])
    "references":      List[str],
    "sources":         List[str],      # authors
    "original_uuid":   str | None,
    "status":          str,            # "parsed" or "parsing_error"
}
```

Missing keys will crash `normalize()`. Always include them.

### `normalize()` output — Rulezet schema

```python
{
    "title":         str | None,
    "format":        str,
    "description":   str,
    "author":        str,
    "content":       str,
    "tags":          List[str],
    "original_uuid": str | None,
}
```

---

## 6. Step-by-step: adding a new format

### 6.1 — Generate the template

From the project root:

```bash
python3 main.py new sigma
# or
python3 -m utils.scaffold sigma
```

This creates `parsers/formats/sigma_parser.py` with all methods stubbed and correct imports.

### 6.2 — Install dependencies

Add any required libraries to `requirements.txt` and install them:

```bash
pip install pysigma
echo "pysigma>=0.11.0" >> requirements.txt
```

### 6.3 — Implement `can_handle()`

Return `True` if the raw text looks like your format. Use a regex on a distinctive pattern — a keyword, a required field, a file structure marker.

```python
# Sigma: YAML with a 'detection:' key
def can_handle(self, chunk: str) -> bool:
    return bool(re.search(r'^detection\s*:', chunk, re.MULTILINE))
```

### 6.4 — Implement `split_rules()`

Most formats are either one-rule-per-file (return `[raw_content]`) or line-based. For block-based formats, use regex to find rule boundaries.

```python
# Sigma: one rule per YAML document, separated by ---
def split_rules(self, raw_content: str) -> List[str]:
    docs = re.split(r'^---\s*$', raw_content, flags=re.MULTILINE)
    return [d.strip() for d in docs if d.strip()]
```

### 6.5 — Implement `validate()`

Use the format's official library if available. Always catch exceptions and return `ValidationResult(ok=False, errors=[str(e)])`. Never raise.

```python
from sigma.rule import SigmaRule
from sigma.exceptions import SigmaError

def validate(self, raw_rule: str) -> ValidationResult:
    try:
        SigmaRule.from_yaml(raw_rule)
        return ValidationResult(ok=True)
    except SigmaError as e:
        return ValidationResult(ok=False, errors=[str(e)])
    except Exception as e:
        return ValidationResult(ok=False, errors=[f"Unexpected error: {e}"])
```

### 6.6 — Implement `parse()`

Extract all useful fields. Always include a fallback `except` block that returns the full schema with safe empty defaults.

```python
def parse(self, raw_rule: str) -> Dict[str, Any]:
    try:
        rule = SigmaRule.from_yaml(raw_rule)
        return {
            "format": self.format,
            "identity": {"name": str(rule.title), "tags": [str(t) for t in rule.tags], "scopes": []},
            "metadata": {"level": str(rule.level), "status": str(rule.status)},
            "content": raw_rule,
            "tags": [str(t) for t in rule.tags],
            "vulnerabilities": [],
            "references": list(rule.references) if rule.references else [],
            "sources": [str(rule.author)] if rule.author else [],
            "original_uuid": str(rule.id) if rule.id else None,
            "status": "parsed",
        }
    except Exception as e:
        return {
            "format": self.format,
            "identity": {"name": None, "tags": [], "scopes": []},
            "metadata": {}, "content": raw_rule, "tags": [],
            "vulnerabilities": [], "references": [], "sources": [],
            "original_uuid": None, "status": "parsing_error", "error": str(e),
        }
```

### 6.7 — Implement `normalize()`

Map to the flat Rulezet schema. Always use `.get()`.

```python
def normalize(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
    sources = parsed_data.get("sources", [])
    meta = parsed_data.get("metadata", {})
    return {
        "title":         parsed_data.get("identity", {}).get("name"),
        "format":        self.format,
        "description":   meta.get("description", ""),
        "author":        sources[0] if sources else "Unknown",
        "content":       parsed_data.get("content", ""),
        "tags":          parsed_data.get("tags", []),
        "original_uuid": parsed_data.get("original_uuid"),
    }
```

### 6.8 — Register the parser

Open `parsers/__init__.py` and add your parser:

```python
from parsers.formats.yara_parser import YaraParser
from parsers.formats.sigma_parser import SigmaParser   # ← add this

ALL_PARSERS = [
    YaraParser(),
    SigmaParser(),   # ← and this
]
```

### 6.9 — Verify it works

```bash
python3 main.py list
# should show your format in the list

python3 main.py detect -t 'title: Test\ndetection:\n  condition: true'
# should detect "sigma"

python3 main.py parse -t 'your rule here'
```

---

## 7. Writing tests

### 7.1 — Create a test fixture file

Create `tests/formats/test_sigma_rules.yml` following the same structure as `test_yara_rules.yar`:

```yaml
# ============================================================
# RULECAST — SIGMA TEST SUITE
#
# EXPECTED RESULTS (update when adding rules):
#   Total rules  : 20
#   Valid        : 15
#   Invalid      : 5
#   Incomplete   : 0
# ============================================================

# --- valid rule ---
title: Valid Minimal
status: test
logsource:
    category: process_creation
detection:
    condition: selection
    selection:
        Image|endswith: '\cmd.exe'

---

# --- invalid rule (missing detection) ---
title: Invalid No Detection
status: test
logsource:
    category: process_creation
```

The `EXPECTED RESULTS` header is parsed automatically by the test runner to verify counts.

### 7.2 — Register the test file in test_runner.py

Open `tests/test_runner.py` and uncomment (or add) your format in `TEST_FILES`:

```python
TEST_FILES = {
    "1": ("yara",  os.path.join(SCRIPT_DIR, "formats", "test_yara_rules.yar")),
    "2": ("sigma", os.path.join(SCRIPT_DIR, "formats", "test_sigma_rules.yml")),  # ← add
}
```

### 7.3 — Run the test runner

```bash
python3 main.py test
# choose your format → file → number
```

The summary will show `✓` or `✗` next to each count compared to the expected values in the header.

---

## 8. Design rules you must follow

These are non-negotiable. PRs that violate them will be asked to change.

**No I/O in parsers.** `split_rules`, `validate`, `parse` receive strings. File reading happens only in `engine.process_file()` or `main.py`. Never call `open()` inside a parser.

**Explicit registration.** Add your parser to `parsers/__init__.py → ALL_PARSERS`. There is no autodiscovery.

**`parse()` ≠ `normalize()`.** `parse()` extracts what the rule says in the format's own vocabulary. `normalize()` translates it to Rulezet's schema. Never put Rulezet-specific logic in `parse()`.

**Full schema always.** The fallback path in `parse()` must return every key with safe empty defaults. A partial dict will crash `normalize()`.

**`.get()` in `normalize()`.** Never `parsed_data['key']`. Always `parsed_data.get('key', default)`.

**Never raise from `validate()`.** Always catch and return `ValidationResult(ok=False, errors=[...])`.

**`self.ply.clear()` pattern (YARA-specific).** If your parser wraps a stateful library instance, call its reset method at the start of each `parse()` call.

**English only.** All code, comments, docstrings, and commit messages in English.

---

## 9. Submitting a pull request

### Checklist

Before opening a PR, verify:

- [ ] `parsers/formats/myformat_parser.py` created and all 6 methods implemented
- [ ] `parsers/__init__.py` updated with your parser in `ALL_PARSERS`
- [ ] `requirements.txt` updated if new dependencies added
- [ ] `tests/formats/test_myformat_rules.*` created with `EXPECTED RESULTS` header
- [ ] `tests/test_runner.py` updated with your test file in `TEST_FILES`
- [ ] `python3 main.py list` shows your format
- [ ] `python3 main.py test` → your format → all expected counts match (`✓`)
- [ ] No file I/O inside the parser
- [ ] `normalize()` uses `.get()` throughout
- [ ] Fallback `parse()` path returns all schema keys

### Branch naming

```
feature/parser-sigma
feature/parser-suricata
fix/yara-split-tags
```

### PR title format

```
[Parser] Add Sigma format support
[Parser] Add Suricata format support
[Fix] YARA: handle multi-tag rules in split_rules
```

### What to include in the PR description

```
## What this adds
Brief description of the format and what library is used.

## Test results
Paste the summary output from `python3 main.py test`:
  ✓  Total rules   : 20  (expected 20)
  ✓  Valid         : 15  (expected 15)
  ✓  Invalid       :  5  (expected  5)
  ✓  All expected counts match.

## Dependencies added
- pysigma>=0.11.0
```