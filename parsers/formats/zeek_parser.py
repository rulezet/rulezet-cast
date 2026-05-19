import io
import re
from typing import Any, Dict, List
from parsers.base import BaseRuleParser, ValidationResult

try:
    import zeekscript
    _ZEEKSCRIPT_AVAILABLE = True
except ImportError:
    _ZEEKSCRIPT_AVAILABLE = False

_CVE_RE = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)

# Zeek-specific signals: module declaration, event handler, @load directive
_ZEEK_SIGNALS = re.compile(
    r'^module\s+\w+\s*;'
    r'|^@load\b'
    r'|^##!'
    r'|\bevent\s+zeek_init\s*\(',
    re.MULTILINE,
)

# Module boundary: 'module Name;' at start of a line
_MODULE_HEADER = re.compile(r'^module\s+\w+\s*;', re.MULTILINE)


def _extract_notices(raw: str) -> List[str]:
    """Extract Notice::Type enum values from redef enum blocks."""
    block_m = re.search(
        r'redef\s+enum\s+Notice::Type\s*\+=\s*\{([^}]+)\}', raw, re.DOTALL
    )
    if not block_m:
        return []
    # Each entry is an identifier on its own line, may be followed by ',' or '##<'
    return [
        m.group(1)
        for m in re.finditer(r'^\s+([\w]+(?:::\w+)?)\s*,?', block_m.group(1), re.MULTILINE)
        if m.group(1)
    ]


class ZeekParser(BaseRuleParser):
    """
    Parser for Zeek (formerly Bro) network monitoring scripts (.zeek / .bro).

    Validation: zeekscript (tree-sitter) — authoritative Zeek syntax check.
    Extraction: regex on raw source (Zeekygen ##!/## comments, module, events,
                @load directives, Notice types).

    Split boundary: 'module Name;' at the start of a line — allows multiple
    scripts in one test fixture file. Single-script files (no module or one
    module) are returned as a single chunk.
    """

    @property
    def format(self) -> str:
        return "zeek"

    @property
    def extensions(self) -> List[str]:
        return ['.zeek', '.bro']

    def can_handle(self, chunk: str) -> bool:
        return bool(_ZEEK_SIGNALS.search(chunk))

    def split_rules(self, raw_content: str) -> List[str]:
        # Find each 'module Name;' position, then extend the boundary backwards
        # to include any preceding ##!/## comment block (Zeekygen docs always
        # appear before the module declaration).
        module_matches = list(_MODULE_HEADER.finditer(raw_content))
        if not module_matches:
            stripped = raw_content.strip()
            return [stripped] if stripped and _ZEEK_SIGNALS.search(stripped) else []

        # Compute true start for each module: walk back over comment/blank lines
        boundaries = []
        for m in module_matches:
            pos = m.start()
            # Walk backwards line by line through the text before this module
            before = raw_content[:pos]
            lines  = before.splitlines()
            keep   = 0
            for line in reversed(lines):
                s = line.strip()
                if s.startswith('#') or s == '':
                    keep += len(line) + 1  # +1 for the newline
                else:
                    break
            # Only pull in the comment block if it has real ## content
            block = raw_content[pos - keep: pos]
            if keep > 0 and re.search(r'^#', block, re.MULTILINE):
                boundaries.append(pos - keep)
            else:
                boundaries.append(pos)

        if len(boundaries) <= 1:
            stripped = raw_content.strip()
            return [stripped] if stripped else []

        scripts = []
        for i, start in enumerate(boundaries):
            end = boundaries[i + 1] if i + 1 < len(boundaries) else len(raw_content)
            chunk = raw_content[start:end].strip()
            if chunk:
                scripts.append(chunk)
        return scripts

    def validate(self, raw_rule: str) -> ValidationResult:
        errors = []
        warnings = []

        if _ZEEKSCRIPT_AVAILABLE:
            s = zeekscript.Script(io.BytesIO(raw_rule.encode('utf-8', errors='replace')))
            s.parse()
            if s.has_error():
                _, _, msg = s.get_error()
                errors.append(msg or "Zeek syntax error")
        else:
            warnings.append("zeekscript not installed — syntax unverified")

        if not re.search(r'\bevent\s+\w+', raw_rule):
            warnings.append("No event handler found")

        return ValidationResult(
            ok=(len(errors) == 0),
            errors=errors,
            warnings=warnings,
            normalized_content=raw_rule,
        )

    def parse(self, raw_rule: str) -> Dict[str, Any]:
        try:
            module_m  = re.search(r'^module\s+(\w+)\s*;', raw_rule, re.MULTILINE)
            desc_m    = re.findall(r'^##!\s*(.+)', raw_rule, re.MULTILINE)
            cont_m    = re.findall(r'^##\s+(?!@)(.+)', raw_rule, re.MULTILINE)
            author_m  = re.search(r'^##\s+@author\s+(.+)', raw_rule, re.MULTILINE)
            version_m = re.search(r'^##\s+@version\s+(.+)', raw_rule, re.MULTILINE)

            module_name = module_m.group(1) if module_m else None
            description = ' '.join(filter(None, desc_m + cont_m)).strip()
            author      = author_m.group(1).strip() if author_m else None
            version     = version_m.group(1).strip() if version_m else "1.0"

            events  = list(dict.fromkeys(re.findall(r'\bevent\s+(\w+)\s*\(', raw_rule)))
            loads   = re.findall(r'^@load\s+(\S+)', raw_rule, re.MULTILINE)
            notices = _extract_notices(raw_rule)
            cves    = list(dict.fromkeys(_CVE_RE.findall(description + raw_rule[:500])))
            refs    = re.findall(r'https?://[^\s\'">\]]+', raw_rule)

            return {
                "format": self.format,
                "identity": {"name": module_name, "tags": notices, "scopes": events},
                "metadata": {
                    "description": description,
                    "module":       module_name,
                    "events":       events,
                    "loads":        loads,
                    "notice_types": notices,
                    "version":      version,
                    **({"author": author} if author else {}),
                },
                "content":         raw_rule,
                "tags":            notices,
                "vulnerabilities": cves,
                "references":      refs,
                "sources":         [author] if author else [],
                "original_uuid":   None,
                "status":          "parsed",
            }

        except Exception as e:
            return {
                "format": self.format,
                "identity": {"name": None, "tags": [], "scopes": []},
                "metadata": {},
                "content":         raw_rule,
                "tags":            [],
                "vulnerabilities": [],
                "references":      [],
                "sources":         [],
                "original_uuid":   None,
                "status":          "parsing_error",
                "error":           str(e),
            }

    def normalize(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
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
            "version":         meta.get("version", "1.0"),
            "references":      parsed_data.get("references", []),
            "vulnerabilities": parsed_data.get("vulnerabilities", []),
        }
