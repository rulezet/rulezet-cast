import re
import yara
import plyara
import plyara.utils
from typing import Dict, Any, List, Optional
from parsers.base import BaseRuleParser, ValidationResult


# ── helpers ───────────────────────────────────────────────────────────────────

def insert_import_module(rule_text: str, module_name: str) -> str:
    lines = rule_text.strip().splitlines()
    if not any(line.strip().startswith(f'import "{module_name}"') for line in lines):
        return f'import "{module_name}"\n' + rule_text
    return rule_text


def _plyara_meta_to_dict(metadata_list: list) -> Dict[str, Any]:
    """
    Convert plyara metadata list to a flat dict.

    plyara >= 2.x returns items as single-key dicts:
        [{'author': 'test'}, {'description': 'foo'}, ...]
    Older versions used:
        [{'name': 'author', 'value': 'test'}, ...]
    This function handles both formats.
    Duplicate keys: last value wins (mirrors YARA behaviour).
    """
    meta = {}
    for item in metadata_list:
        if not isinstance(item, dict):
            continue
        if 'name' in item and 'value' in item:
            # old plyara format
            meta[item['name']] = item['value']
        else:
            # current plyara format: {'author': 'test'}
            for k, v in item.items():
                meta[k] = v
    return meta


# ── rule header pattern ───────────────────────────────────────────────────────

_RULE_HEADER = re.compile(
    r'(?:global\s+|private\s+)*rule\s+[\w\d_]+\s*(?::\s*(?:[\w\d_]+\s*)+)?\{'
)


class YaraParser(BaseRuleParser):
    """
    YARA parser — state-machine splitting, plyara AST extraction.

    Key design decisions:
    - split_rules() uses a state machine that skips strings and comments,
      so 'rule' keywords inside strings/comments never cause false splits.
    - validate() auto-inserts missing module imports and external variables.
    - parse() uses _plyara_meta_to_dict() which handles both old and new
      plyara metadata formats (the {'name': k, 'value': v} vs {k: v} split).
    - All paths in parse() (normal + fallback) return the full schema.
    - normalize() uses .get() throughout — never direct key access.
    """

    YARA_MODULES = {"pe", "math", "cuckoo", "magic", "hash", "dotnet", "elf", "macho", "vt"}

    def __init__(self):
        self.ply = plyara.Plyara()

    @property
    def format(self) -> str:
        return "yara"

    @property
    def extensions(self) -> List[str]:
        return [".yar", ".yara"]

    def can_handle(self, chunk: str) -> bool:
        return bool(_RULE_HEADER.search(chunk))

    # ── validate ──────────────────────────────────────────────────────────────

    def validate(self, content: str, **kwargs) -> ValidationResult:
        """
        Validate a single YARA rule string.
        Auto-inserts missing module imports (pe, math, …) and dummy externals.
        Never raises — always returns a ValidationResult.
        """
        externals = {}
        attempts  = 0
        current   = content

        while attempts < 10:
            try:
                yara.compile(source=current, externals=externals)
                return ValidationResult(ok=True, errors=[], normalized_content=current)
            except yara.SyntaxError as e:
                msg = str(e)
                m = re.search(r'undefined identifier "(\w+)"', msg)
                if m:
                    var = m.group(1)
                    if var in self.YARA_MODULES:
                        current = insert_import_module(current, var)
                        attempts += 1
                        continue
                    else:
                        externals[var] = "dummy"
                        attempts += 1
                        continue
                return ValidationResult(ok=False, errors=[msg], normalized_content=current)
            except Exception as e:
                return ValidationResult(ok=False, errors=[str(e)], normalized_content=current)

        return ValidationResult(
            ok=False,
            errors=["Max validation attempts exceeded"],
            normalized_content=current,
        )

    # ── split_rules ───────────────────────────────────────────────────────────

    def split_rules(self, raw_content: str) -> List[str]:
        """
        State-machine splitter — skips strings and comments before trying to
        match rule headers. This prevents false splits on 'rule' keywords
        that appear inside string literals or comments.

        Handles:
        - Double-quoted strings with escape sequences
        - Line comments (//)
        - Block comments (/* */)
        - global/private modifiers (any order)
        - Multiple tags: rule Foo : tag1 tag2 tag3 {
        - Rules with no blank line between them
        """
        starts = []
        i = 0
        n = len(raw_content)

        while i < n:
            c   = raw_content[i]
            nxt = raw_content[i + 1] if i + 1 < n else ''

            # Skip line comment
            if c == '/' and nxt == '/':
                while i < n and raw_content[i] != '\n':
                    i += 1
                continue

            # Skip block comment
            if c == '/' and nxt == '*':
                i += 2
                while i < n - 1:
                    if raw_content[i] == '*' and raw_content[i + 1] == '/':
                        i += 2
                        break
                    i += 1
                continue

            # Skip double-quoted string (handles \" escapes).
            # Exit on newline too — YARA rule definitions never span lines,
            # so an unterminated string (e.g. invalid rules) won't swallow
            # the rest of the file.
            if c == '"':
                i += 1
                while i < n:
                    if raw_content[i] == '\\':
                        i += 2
                        continue
                    if raw_content[i] in ('"', '\n'):
                        i += 1
                        break
                    i += 1
                continue

            # Try to match a rule header at current position
            m = _RULE_HEADER.match(raw_content, i)
            if m:
                starts.append(i)
                i = m.end()
                continue

            i += 1

        # Slice content between consecutive header positions
        rules = []
        for idx, start in enumerate(starts):
            end   = starts[idx + 1] if idx + 1 < len(starts) else len(raw_content)
            chunk = raw_content[start:end].strip()
            if chunk:
                rules.append(chunk)

        return rules

    # ── parse ─────────────────────────────────────────────────────────────────

    def parse(self, raw_rule: str) -> Dict[str, Any]:
        """
        Extract structured data from a single YARA rule string.
        Uses plyara for AST extraction; falls back to regex on failure.
        Both paths always return all required schema keys.
        """
        self.ply.clear()
        try:
            parsed_list = self.ply.parse_string(raw_rule)
            if not parsed_list:
                raise ValueError("Plyara returned empty AST")

            data = parsed_list[0]

            # metadata — handles both plyara formats
            meta = _plyara_meta_to_dict(data.get('metadata', []))

            # CVEs in description
            cves = re.findall(
                r'CVE-\d{4}-\d{4,7}',
                meta.get("description", ""),
                re.IGNORECASE,
            )

            # strings block
            strings = []
            for s in data.get('strings', []):
                strings.append({
                    "name":      s.get('name', ''),
                    "type":      s.get('type', ''),
                    "value":     s.get('value', ''),
                    "modifiers": s.get('modifiers', []),
                })

            # imports declared in the rule
            imports = data.get('imports', [])
            tags    = data.get('tags', [])
            scopes  = data.get('scopes', [])

            return {
                "format":    self.format,
                "identity": {
                    "name":   data.get('rule_name'),
                    "tags":   tags,
                    "scopes": scopes,
                },
                "metadata":        meta,
                "content":         raw_rule,
                "strings":         strings,
                "imports":         imports,
                "tags":            tags,
                "vulnerabilities": cves,
                "references":      [meta["reference"]] if "reference" in meta else [],
                "sources":         [meta["author"]]    if "author"    in meta else [],
                "original_uuid":   meta.get("id") or meta.get("uuid"),
                "status":          "parsed",
            }

        except Exception as e:
            # Regex fallback — extracts what it can, returns all required keys
            name_m = re.search(r'rule\s+(\w+)', raw_rule)
            tags_m = re.search(r'rule\s+\w+\s*:\s*([\w\s]+)\{', raw_rule)
            tags   = tags_m.group(1).split() if tags_m else []

            return {
                "format":    self.format,
                "identity": {
                    "name":   name_m.group(1) if name_m else "unknown",
                    "tags":   tags,
                    "scopes": [],
                },
                "metadata":        {},
                "content":         raw_rule,
                "strings":         [],
                "imports":         [],
                "tags":            tags,
                "vulnerabilities": [],
                "references":      [],
                "sources":         [],
                "original_uuid":   None,
                "status":          "parsing_error",
                "error":           str(e),
            }

    # ── normalize ─────────────────────────────────────────────────────────────

    def normalize(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Map parse() output to the Universal Rulezet Schema.
        Always uses .get() — never direct key access.
        """
        sources = parsed_data.get("sources", [])
        meta    = parsed_data.get("metadata", {})
        return {
            "title":           parsed_data.get("identity", {}).get("name"),
            "format":          self.format,
            "description":     meta.get("description", ""),
            "author":          sources[0] if sources else "Unknown",
            "content":         parsed_data.get("content", ""),
            "tags":            parsed_data.get("tags", []),
            "original_uuid":   parsed_data.get("original_uuid"),
            "license":         meta.get("license", "unknown"),
            "version":         meta.get("version", "1.0"),
            "references":      parsed_data.get("references", []),
            "imports":         parsed_data.get("imports", []),
            "vulnerabilities": parsed_data.get("vulnerabilities", []),
        }