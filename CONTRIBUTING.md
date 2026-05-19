# Contributing to RuleCast

This guide walks you through every step to add a new rule format and submit a pull request — from scaffolding the file to verifying the test results.

---

## Table of Contents

1. [How RuleCast works](#1-how-rulecast-works)
2. [Project structure](#2-project-structure)
3. [The pipeline explained](#3-the-pipeline-explained)
4. [The BaseRuleParser contract](#4-the-baseruleparser-contract)
5. [Output schemas](#5-output-schemas)
6. [Step-by-step: adding a new format](#6-step-by-step-adding-a-new-format)
7. [Writing test fixtures](#7-writing-test-fixtures)
8. [Running and reading the test runner](#8-running-and-reading-the-test-runner)
9. [Format clash detection test](#9-format-clash-detection-test)
10. [Design rules you must follow](#10-design-rules-you-must-follow)
11. [Submitting a pull request](#11-submitting-a-pull-request)

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
├── main.py                          # CLI: interactive menu + direct commands
├── requirements.txt
├── parsers/
│   ├── __init__.py                  # ALL_PARSERS — register your parser here
│   ├── base.py                      # BaseRuleParser + ValidationResult
│   ├── engine.py                    # RuleCastEngine + ParseResult
│   └── formats/
│       ├── yara_parser.py           # YARA (reference implementation — read first)
│       ├── sigma_parser.py
│       ├── suricata_parser.py
│       ├── crs_parser.py
│       ├── nse_parser.py
│       ├── nova_parser.py
│       ├── zeek_parser.py
│       ├── wazuh_parser.py
│       ├── elastic_parser.py
│       ├── atr_parser.py
│       └── your_format_parser.py    # ← your file goes here
├── utils/
│   └── scaffold.py                  # generates a new parser template
└── tests/
    ├── test_runner.py               # interactive test tool
    └── formats/
        ├── conflict/
        │   └── test_clash.yaml      # format clash detection fixture
        ├── yara/
        ├── sigma/
        │   └── ...
        └── your_format/
            └── test_your_format.*   # ← your test file goes here
```

---

## 3. The pipeline explained

### `can_handle(chunk: str) -> bool`

Called by the engine to auto-detect the format. Returns `True` if the raw text looks like your format. Keep it fast — a regex on a distinctive keyword or structure marker is enough. Never parse the full document here.

```python
# Suricata example — triggers on Suricata action keywords
def can_handle(self, chunk: str) -> bool:
    return bool(re.search(r'^(alert|drop|pass|reject)\s+\w+', chunk, re.MULTILINE))
```

> **Important:** If your format shares a file extension with an existing parser (e.g. `.yaml` for both Sigma and ATR), place your parser **before** the competing one in `ALL_PARSERS` and make your signals specific enough to not match the other format. Run the [clash detection test](#9-format-clash-detection-test) to verify.

### `split_rules(raw_content: str) -> List[str]`

Takes the full file content and returns a list of individual rule strings. This is critical for resilience: if one rule is broken, the others should still be extractable.

```python
# Suricata: one rule per non-comment line
def split_rules(self, raw_content: str) -> List[str]:
    return [l.strip() for l in raw_content.splitlines()
            if l.strip() and not l.lstrip().startswith('#')]
```

```python
# YAML-based: split on document separators
def split_rules(self, raw_content: str) -> List[str]:
    docs = re.split(r'^---\s*$', raw_content, flags=re.MULTILINE)
    return [d.strip() for d in docs if d.strip()]
```

```python
# XML-based (Wazuh): parse tree, yield each <rule> element
def split_rules(self, raw_content: str) -> List[str]:
    root = ET.fromstring(raw_content)
    return [ET.tostring(el, encoding='unicode') for el in root.iter('rule')]
```

### `validate(raw_rule: str) -> ValidationResult`

Checks whether a single rule string is syntactically and semantically valid.

```python
@dataclass
class ValidationResult:
    ok: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    normalized_content: Optional[str] = None
```

**Always return a `ValidationResult` — never raise.** Catch everything:

```python
def validate(self, raw_rule: str) -> ValidationResult:
    try:
        SigmaRule.from_yaml(raw_rule)
        return ValidationResult(ok=True, normalized_content=raw_rule)
    except SigmaError as e:
        return ValidationResult(ok=False, errors=[str(e)], normalized_content=raw_rule)
    except Exception as e:
        return ValidationResult(ok=False, errors=[f"Unexpected error: {e}"], normalized_content=raw_rule)
```

### `parse(raw_rule: str) -> Dict[str, Any]`

Extracts structured data. Must always return the **full schema** (see [section 5](#5-output-schemas)) — even on failure. A partial dict crashes `normalize()`.

### `normalize(parsed_data: Dict[str, Any]) -> Dict[str, Any]`

Maps `parse()` output to the flat Rulezet schema. Always use `.get()` — never direct key access.

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
        ...                         # syntax + semantic check, never raises

    def parse(self, raw_rule: str) -> Dict[str, Any]:
        ...                         # extract structured data, always full schema

    def normalize(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        ...                         # map to Rulezet schema, always .get()
```

---

## 5. Output schemas

### `parse()` — mandatory keys

Every `parse()` call, **including the fallback exception path**, must return a dict with all of these keys:

```python
{
    "format":          str,              # e.g. "sigma"
    "identity": {
        "name":        str | None,       # rule name / title — used by the test runner
        "tags":        List[str],
        "scopes":      List[str],        # e.g. MITRE technique IDs
    },
    "metadata":        Dict[str, Any],   # format-native key=value pairs
    "content":         str,              # original raw rule, never modified
    "tags":            List[str],
    "vulnerabilities": List[str],        # CVE IDs, e.g. ["CVE-2021-44228"]
    "references":      List[str],
    "sources":         List[str],        # authors
    "original_uuid":   str | None,
    "status":          str,              # "parsed" or "parsing_error"
}
```

Missing keys will crash `normalize()`. Always include them, even empty.

### `normalize()` — Rulezet schema

```python
{
    "title":           str | None,
    "format":          str,
    "description":     str,
    "author":          str,
    "content":         str,
    "tags":            List[str],
    "original_uuid":   str | None,
    "version":         str,
    "references":      List[str],
    "vulnerabilities": List[str],
}
```

---

## 6. Step-by-step: adding a new format

### Step 1 — Fork and create a branch

```bash
git checkout -b feature/parser-myformat
```

Use the naming convention `feature/parser-<format>` or `fix/<format>-<description>`.

---

### Step 2 — Run the scaffold command

From the project root:

```bash
python3 main.py new myformat
```

This does four things automatically:

1. Creates `parsers/formats/myformat_parser.py` — all five methods stubbed with correct imports
2. Registers `MyformatParser()` in `parsers/__init__.py → ALL_PARSERS`
3. Creates `tests/formats/myformat/test_myformat_rules.myformat` — empty fixture with section structure
4. Registers the fixture in `tests/test_runner.py → TEST_FILES` under the next available key

> You only need to fill in the code and the test rules. Everything else is wired up.

![Step 2 — scaffold output showing the four files created](doc/screenshots/02-scaffold.png)

---

### Step 3 — Install dependencies

If your parser needs a third-party library, add it to `requirements.txt` and install it:

```bash
pip install pysigma
echo "pysigma>=0.11.0" >> requirements.txt
```

Prefer libraries that provide an official parser or AST for the format. If none exists, use regex on the raw string. See the table in `CLAUDE.md` for what each existing parser uses.

---

### Step 4 — Implement `can_handle()`

Open `parsers/formats/myformat_parser.py`. Implement `can_handle()` to return `True` when the raw chunk looks like your format.

Use a regex on the most distinctive pattern in your format — a mandatory keyword, a unique field name, a structural marker. Do **not** parse YAML/XML/JSON here; stay with regex for speed.

```python
def can_handle(self, chunk: str) -> bool:
    # Example: detect by a mandatory header field unique to your format
    return bool(re.search(r'^\s*my_format_header\s*:', chunk, re.MULTILINE))
```

If your format shares an extension with another parser (e.g. `.yaml`), make your signal as specific as possible and place your parser before the competing one in `ALL_PARSERS`. Run the [clash test](#9-format-clash-detection-test) after.

---

### Step 5 — Implement `split_rules()`

Choose the strategy that matches your format's structure:

| Format type | Strategy |
|-------------|----------|
| One rule per file | Return `[raw_content.strip()]` |
| One rule per line | Split on newlines, skip blank/comment lines |
| Block-delimited | Find block boundaries with regex |
| YAML multi-document | Split on `^---$` |
| XML container | Parse with ElementTree, yield each child element |

Always strip fixture `#` comment headers before parsing structured content (see Wazuh parser for the XML pattern).

```python
def split_rules(self, raw_content: str) -> List[str]:
    # example: block-delimited with a keyword at rule start
    boundaries = [m.start() for m in re.finditer(r'^rule\s+\w+', raw_content, re.MULTILINE)]
    chunks = []
    for i, start in enumerate(boundaries):
        end = boundaries[i + 1] if i + 1 < len(boundaries) else len(raw_content)
        chunk = raw_content[start:end].strip()
        if chunk:
            chunks.append(chunk)
    return chunks
```

---

### Step 6 — Implement `validate()`

Use the format's official library if one exists. Otherwise apply semantic checks with regex. Cover the most common error classes: missing required fields, invalid enum values, malformed structure.

```python
def validate(self, raw_rule: str) -> ValidationResult:
    errors = []
    warnings = []
    try:
        # parse with official library
        rule = MyLibrary.parse(raw_rule)
    except MyLibraryError as e:
        return ValidationResult(ok=False, errors=[str(e)], normalized_content=raw_rule)
    except Exception as e:
        return ValidationResult(ok=False, errors=[f"Unexpected: {e}"], normalized_content=raw_rule)

    # semantic checks
    if not rule.name:
        errors.append("Missing required field: name")
    if rule.severity not in {"low", "medium", "high", "critical"}:
        errors.append(f"Invalid severity: {rule.severity!r}")

    return ValidationResult(
        ok=(len(errors) == 0),
        errors=errors,
        warnings=warnings,
        normalized_content=raw_rule,
    )
```

---

### Step 7 — Implement `parse()`

Extract all useful fields and map them to the mandatory schema. Wrap everything in a `try/except` that returns safe empty defaults — a partial dict will crash `normalize()`.

```python
def parse(self, raw_rule: str) -> Dict[str, Any]:
    try:
        rule = MyLibrary.parse(raw_rule)
        return {
            "format":   self.format,
            "identity": {"name": rule.name, "tags": rule.tags, "scopes": []},
            "metadata": {"severity": rule.severity, "author": rule.author},
            "content":  raw_rule,
            "tags":     rule.tags,
            "vulnerabilities": rule.cves,
            "references":      rule.references,
            "sources":         [rule.author] if rule.author else [],
            "original_uuid":   rule.id or None,
            "status":          "parsed",
        }
    except Exception as e:
        return {
            "format":   self.format,
            "identity": {"name": None, "tags": [], "scopes": []},
            "metadata": {},
            "content":  raw_rule,
            "tags":     [],
            "vulnerabilities": [],
            "references":      [],
            "sources":         [],
            "original_uuid":   None,
            "status":          "parsing_error",
            "error":           str(e),
        }
```

> `identity.name` is what the test runner uses to classify rules as `Valid_` / `Invalid_` / `Nasty_`. Make sure it is set to the rule's title or name.

---

### Step 8 — Implement `normalize()`

Map to the flat Rulezet schema. Use `.get()` everywhere — never direct key access.

```python
def normalize(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
    meta    = parsed_data.get("metadata", {})
    sources = parsed_data.get("sources", [])
    return {
        "title":           parsed_data.get("identity", {}).get("name"),
        "format":          self.format,
        "description":     meta.get("description", ""),
        "author":          sources[0] if sources else "Unknown",
        "content":         parsed_data.get("content", ""),
        "tags":            parsed_data.get("tags", []),
        "original_uuid":   parsed_data.get("original_uuid"),
        "version":         meta.get("version", "1.0"),
        "references":      parsed_data.get("references", []),
        "vulnerabilities": parsed_data.get("vulnerabilities", []),
    }
```

---

### Step 9 — Verify the parser is registered

```bash
python3 main.py list
```

Your format should appear in the list with its extensions and class name.

![Step 9 — list command showing the new format in the registered parsers](doc/screenshots/09-list.png)

---

### Step 10 — Test format auto-detection

Pick a sample rule from your format and run:

```bash
python3 main.py detect -t 'paste a sample rule here'
# or
python3 main.py detect -i path/to/sample.ext
```

The output should say `Detected format: myformat`.

![Step 10 — detect command output confirming format is auto-detected](doc/screenshots/10-detect.png)

---

### Step 11 — Test parsing

```bash
python3 main.py parse -t 'paste a sample rule here'
python3 main.py parse -i path/to/sample.ext --json
python3 main.py parse -i path/to/sample.ext --normalize
```

Verify the output fields look correct. Check that `identity.name`, `tags`, `vulnerabilities`, and `references` contain what you expect.

![Step 11 — parse command showing structured JSON output](doc/screenshots/11-parse.png)

---

## 7. Writing test fixtures

### 7.1 — Fixture location and naming

The scaffold command already created the fixture at:

```
tests/formats/myformat/test_myformat_rules.<ext>
```

Open it and fill in the three sections.

### 7.2 — Rule naming convention

The test runner reads `identity.name` from `parse()` to decide what outcome to expect. Name your rules accordingly:

| Prefix | Meaning | What the test checks |
|--------|---------|---------------------|
| `Valid_` | A well-formed, representative rule | `validate()` must return `ok=True` |
| `Invalid_` | A rule with a clear defect | `validate()` must return `ok=False` |
| `Nasty_` | An edge case (unusual but legal) | No expectation — result is only observed |

For example, in an Elastic TOML fixture:
```toml
[rule]
name = "Valid_PowershellBase64 - Encoded command execution"
...
```

In a Wazuh XML fixture:
```xml
<rule id="100001" level="10">
  <description>Valid_SSHBruteforce - Detects repeated SSH failures</description>
  ...
</rule>
```

### 7.3 — What to cover

Aim for at minimum:

- **3–5 valid rules** — cover different sub-cases (various categories, optional fields, multi-condition logic)
- **2–3 invalid rules** — one per distinct error class: missing required field, invalid enum value, bad structure
- **1 nasty rule** (optional) — a legal-but-unusual edge case that exercises a corner of the validator

### 7.4 — Update the EXPECTED RESULTS header

After adding rules, update the counts at the top of the fixture file:

```
# EXPECTED RESULTS (update when adding rules):
#   Total rules  : 8
#   Valid        : 5
#   Invalid      : 3
```

The test runner compares these against actual results and reports `✓` or `✗`.

---

## 8. Running and reading the test runner

### 8.1 — Launch

```bash
python3 main.py test
```

A spinner appears while parsers load, then the format selection menu is shown.

![Step 8.1 — test runner launch with loading spinner](doc/screenshots/81-launch.png)

### 8.2 — Choose a format

Type the number or name of your format and press Enter.

![Step 8.2 — format selection menu showing all registered parsers plus the clash option](doc/screenshots/82-format-menu.png)

### 8.3 — Choose the source

Press `f` for file, then enter the number shown next to your fixture or type the path directly.

![Step 8.3 — file source selection showing known test files for the chosen format](doc/screenshots/83-file-source.png)

### 8.4 — Per-rule results

Each rule is shown with its name, the detected outcome, and the test verdict:

- `✓` green — outcome matched expectation (`Valid_` passed, `Invalid_` rejected)
- `✗` red — outcome did not match (false positive or false negative)
- `·` cyan — `Nasty_` rule, no expectation, result observed only

Errors and warnings from `validate()` are printed below failing rules.

![Step 8.4 — per-rule results display with green checkmarks and rule names](doc/screenshots/84-results.png)

### 8.5 — Summary

After all rules are processed, the summary shows:

```
  ✓  Total rules           : 8   (expected 8)
  ✓  Valid                 : 5   (expected 5)
  ✓  Invalid               : 3   (expected 3)

  Test outcomes
  ─────────────────────────────────────────
  ✓  Valid rules pass      : 5   (expected 5)
  ✓  Invalid detected      : 3   (expected 3)

  ✓  All 8 tests passed — parser behaves as expected.
```

All counts must show `✓` before you open a PR.

![Step 8.5 — test summary showing all counts matching expected values](doc/screenshots/85-summary.png)

### 8.6 — Post-test menu

After the summary you can:

- `j` — export full JSON results to a file
- `n` — show normalized output only
- `f` — show only test failures (false positives / false negatives)
- `r` — run again with different input
- `q` — quit

![Step 8.6 — post-test menu options](doc/screenshots/86-postmenu.png)

---

## 9. Format clash detection test

If your format shares an extension with an existing parser (currently both ATR and Sigma use `.yaml`/`.yml`), you must run the clash test to verify there are no false positives.

### 9.1 — Run the clash test

From the format selection menu, press `c` (or type `clash`):

![Step 9.1 — format menu with the clash option highlighted](doc/screenshots/91-clash-menu.png)

The test reads `tests/formats/conflict/test_clash.yaml` — a single file with rules from multiple formats mixed together. For each rule it calls `engine.detect_format()` and checks the result against the declared format.

![Step 9.2 — clash test output showing 6/6 correctly identified](doc/screenshots/92-clash-results.png)

### 9.2 — Add your format to the clash fixture

If your format shares an extension with any existing parser, add sample rules to `tests/formats/conflict/test_clash.yaml`:

```yaml
---
# format: myformat
<paste a representative rule here>

---
# format: sigma
<a Sigma rule that uses the same extension>
```

The `# format: <name>` line must be the **first line** of each chunk, right after `---`. The test runner strips it before calling the detector.

Run the test again and verify all rules are still identified correctly.

### 9.3 — Fix collisions

If a rule is misidentified, your `can_handle()` signal is too broad. Make it more specific:

- Add more mandatory fields to the check (AND instead of OR)
- Use a pattern that is unique to your format and absent from competing formats
- Re-read the competing parser's `can_handle()` to understand what it matches

---

## 10. Design rules you must follow

These are non-negotiable. PRs that violate them will be asked to change before merge.

**No I/O in parsers.** `split_rules`, `validate`, `parse` receive strings. File reading happens only in `engine.process_file()` or `main.py`. Never call `open()` inside a parser.

**Explicit registration.** Add your parser to `parsers/__init__.py → ALL_PARSERS`. There is no autodiscovery.

**`parse()` ≠ `normalize()`.** `parse()` extracts what the rule says in the format's own vocabulary. `normalize()` translates that to Rulezet's schema. Never put Rulezet-specific logic in `parse()` and never format-specific logic in `normalize()`.

**Full schema always.** The fallback path in `parse()` must return every key with safe empty defaults. A partial dict crashes `normalize()`. Copy the error result block from an existing parser.

**`.get()` in `normalize()`.** Never `parsed_data['key']`. Always `parsed_data.get('key', default)`.

**`validate()` never raises.** Always catch everything and return `ValidationResult(ok=False, errors=[str(e)])`.

**Stateful libraries.** If your parser wraps a stateful library instance (like `plyara`), call its reset method at the start of each `parse()` call (see `yara_parser.py: self.ply.clear()`).

**English only.** All code, comments, docstrings, and commit messages in English.

---

## 11. Submitting a pull request

### Pre-flight checklist

Before opening a PR, go through each item:

- [ ] Branch is named `feature/parser-<format>` or `fix/<format>-<description>`
- [ ] `python3 main.py new <format>` was run — parser file, fixture, and TEST_FILES entry all exist
- [ ] All five methods implemented: `can_handle`, `split_rules`, `validate`, `parse`, `normalize`
- [ ] `requirements.txt` updated if new dependencies were added
- [ ] Fixture has at least 3 valid and 2 invalid rules
- [ ] `EXPECTED RESULTS` header in the fixture matches actual counts
- [ ] `python3 main.py list` shows your format
- [ ] `python3 main.py detect -i <sample_file>` returns the correct format
- [ ] `python3 main.py test` → your format → all counts show `✓`
- [ ] If your format shares an extension: clash test passes with 0 misidentifications
- [ ] No `open()` call inside any parser method
- [ ] `normalize()` uses `.get()` throughout
- [ ] Fallback `parse()` path returns all schema keys

### Branch naming

```
feature/parser-sigma
feature/parser-suricata
fix/yara-split-tags
fix/elastic-level-validation
```

### PR title format

```
[Parser] Add Sigma format support
[Parser] Add Suricata format support
[Fix] YARA: handle multi-tag rules in split_rules
[Fix] Elastic: accept level values above 10
```

### What to include in the PR description

```markdown
## What this adds

Brief description of the format and what library is used for validation.

## Validated against

Link or name of the upstream rule corpus used to write the test fixture
(e.g. https://github.com/elastic/detection-rules).

## Test results

Paste the summary output from `python3 main.py test`:

  ✓  Total rules           : 8   (expected 8)
  ✓  Valid                 : 5   (expected 5)
  ✓  Invalid               : 3   (expected 3)
  ✓  Valid rules pass      : 5   (expected 5)
  ✓  Invalid detected      : 3   (expected 3)
  ✓  All 8 tests passed — parser behaves as expected.

## Clash test (if applicable)

  ✓  All 6/6 rules correctly identified — no format leakage.

## Dependencies added

- pysigma>=0.11.0
```
