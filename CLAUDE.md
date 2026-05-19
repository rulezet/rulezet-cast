# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Setup

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

## Commands

```bash
python3 main.py                                          # interactive menu
python3 main.py parse -t 'rule X { condition: true }'
python3 main.py parse -i rules.yar --json
python3 main.py parse -i rules.yar --normalize          # output flat Rulezet schema
python3 main.py validate -i rules.yar -f yara
python3 main.py detect -t 'rule X { condition: true }'
python3 main.py list                                     # list registered parsers
python3 main.py test                                     # interactive test runner
python3 main.py new sigma                                # scaffold new parser template
```

## Architecture

RuleCast is a **pipeline-based security rule parser**. Raw text in → structured JSON out. Core design: one parser class per format, all stateless, no file I/O inside parsers — strings only.

```
raw text / file
      │
      ▼
  RuleCastEngine  (parsers/engine.py)
      │
      ├─ detect_format()   → iterates ALL_PARSERS, first can_handle() match wins
      ├─ split_rules()     → segments multi-rule content into individual strings
      ├─ validate()        → returns ValidationResult (never raises)
      ├─ parse()           → returns structured dict with mandatory schema
      └─ normalize()       → maps to flat Rulezet schema
```

**Key files:**
- `parsers/base.py` — `BaseRuleParser` (ABC) + `ValidationResult` dataclass
- `parsers/engine.py` — `RuleCastEngine`; `process()` runs the full pipeline; file I/O lives here only
- `parsers/__init__.py` — `ALL_PARSERS` list; explicit registration, no autodiscovery
- `parsers/formats/yara_parser.py` — reference implementation; read before writing any parser
- `tests/test_runner.py` — interactive test runner; `TEST_FILES` dict maps format names to fixtures
- `utils/scaffold.py` — generates parser templates

### Implemented parsers

| Format | File | Extension(s) | Validator | Notes |
|--------|------|-------------|-----------|-------|
| YARA | `yara_parser.py` | `.yar` `.yara` | `yara-python` + `plyara` | Reference implementation |
| Sigma | `sigma_parser.py` | `.yaml` `.yml` | `pysigma` | |
| Suricata | `suricata_parser.py` | `.rules` | `suricataparser` | |
| CRS | `crs_parser.py` | `.conf` | `msc-pyparser` | ModSecurity/OWASP CRS |
| NSE | `nse_parser.py` | `.nse` | `luac -p` → `luaparser` fallback | Nmap Scripting Engine (Lua) |
| Nova | `nova_parser.py` | `.nov` | `nova-hunting` | AI/LLM hunting rules |
| Zeek | `zeek_parser.py` | `.zeek` `.bro` | `zeekscript` (tree-sitter) | |
| Wazuh | `wazuh_parser.py` | `.xml` | `xml.etree.ElementTree` | SIEM rules (XML) |
| Elastic | `elastic_parser.py` | `.toml` | `tomllib` (stdlib) | Elastic Security detection rules |
| ATR | `atr_parser.py` | `.yaml` `.yml` | `PyYAML` | Agent Threat Rules for AI agents |

### ALL_PARSERS ordering

Order matters — `detect_format()` returns the first `can_handle()` match. Current order in `parsers/__init__.py`:

```
YaraParser → ATRParser → SigmaParser → SuricataParser → CrsParser →
NseParser → NovaParser → ZeekParser → WazuhParser → ElasticParser
```

**ATR must come before Sigma** — both handle `.yaml`/`.yml`. ATR signals (`ATR-YYYY-NNNNN` id, `agent_source:`, ATR taxonomy category names) are specific enough not to collide with Sigma, but putting ATR first ensures it wins cleanly.

### Output schemas

**`parse()` must return all keys** on both normal and fallback (exception) paths:

```python
{
    "format": str,
    "identity": {"name": str | None, "tags": list, "scopes": list},
    "metadata": dict,           # raw key=value pairs from the rule's meta block
    "content": str,             # original raw rule string, never modified
    "tags": list,
    "vulnerabilities": list,    # CVE IDs e.g. ["CVE-2021-44228"]
    "references": list,
    "sources": list,            # authors
    "original_uuid": str | None,
    "status": "parsed" | "parsing_error",
}
```

**`normalize()` maps to the flat Rulezet schema:**

```python
{"title": str | None, "format": str, "description": str,
 "author": str, "content": str, "tags": list, "original_uuid": str | None,
 "version": str, "references": list, "vulnerabilities": list}
```

## YARA parser internals

The reference implementation (`parsers/formats/yara_parser.py`) uses `yara-python` for compilation/validation and `plyara` for AST extraction.

- **`validate()`** — retry loop (max 10) on `yara.compile()`: auto-inserts missing `import` statements for known YARA modules; injects `"dummy"` externals for unknown identifiers; returns `ValidationResult(ok=False)` on any other syntax error.
- **`split_rules()`** — regex-based via `re.finditer` on the rule header pattern; slices content between consecutive match positions. Resilient: one broken rule doesn't prevent others from being extracted.
- **`parse()`** — must call `self.ply.clear()` at the start of every call; plyara is stateful and accumulates state across calls.

## Adding a new parser

1. `python3 main.py new <format>` → creates `parsers/formats/<format>_parser.py`
2. Implement 5 methods: `can_handle`, `split_rules`, `validate`, `parse`, `normalize`
3. Register: add instance to `ALL_PARSERS` in `parsers/__init__.py` (mind the ordering)
4. Add test fixture `tests/formats/<format>/test_<format>_rules.*` with the `EXPECTED RESULTS` header
5. Register fixture in `TEST_FILES` in `tests/test_runner.py`

**Non-negotiable rules:**
- No `open()` inside any parser method — strings only
- `validate()` never raises — always `return ValidationResult(ok=False, errors=[str(e)])`
- `parse()` fallback returns every schema key with safe empty defaults — a partial dict crashes `normalize()`
- `normalize()` uses `.get()` throughout — never `parsed_data['key']`
- `parse()` extracts format-native data; `normalize()` maps to Rulezet schema — never merge them

### Recommended libraries by format

| Format | Library | Notes |
|--------|---------|-------|
| Sigma | `pysigma` | |
| Suricata | `suricataparser` | |
| Zeek | `zeekscript` | tree-sitter based |
| Wazuh | `xml.etree.ElementTree` | stdlib |
| NSE (Lua) | `luac -p` (subprocess) | `luaparser` as fallback when luac not found |
| CRS | `msc-pyparser` | |
| Nova | `nova-hunting` | |
| Elastic | `tomllib` | stdlib (Python ≥ 3.11) |
| ATR | `PyYAML` | already a transitive dep — no extra install needed |

## Test fixtures

Fixture files live in `tests/formats/`. The `EXPECTED RESULTS` header is parsed automatically by the test runner:

```
# EXPECTED RESULTS (update when adding rules):
#   Total rules  : 20
#   Valid        : 15
#   Invalid      : 5
```

Rule naming convention — the test runner reads `identity.name` (= rule title or description) to classify each rule:

| Prefix | Expectation |
|--------|-------------|
| `Valid_` | `validate()` must return `ok=True` |
| `Invalid_` | `validate()` must return `ok=False` |
| `Nasty_` | No expectation — edge case, result observed only |

## Format clash test

The test runner has a built-in **clash detection test** (option `c` in the format menu). It reads `tests/formats/conflict/test_clash.yaml` — a single file with rules from multiple formats separated by `---`. The first line of each chunk must be `# format: <name>`.

The clash test calls `engine.detect_format()` on each rule and checks that the detected format matches the declared one. Run it whenever a new format shares an extension with an existing parser to catch `can_handle()` false positives.

**Clash fixture layout** — `# format:` goes on the FIRST line of each chunk, right after `---`:
```yaml
---
# format: atr
id: ATR-2026-00001
...
---
# format: sigma
title: "..."
logsource: ...
```

## Commit and branch conventions

Branch names: `feature/parser-<format>` or `fix/<format>-<description>`
PR title format: `[Parser] Add Sigma format support` / `[Fix] YARA: handle multi-tag rules`
