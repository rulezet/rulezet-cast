import re
from typing import Any, Dict, List
from parsers.base import BaseRuleParser, ValidationResult

try:
    from nova import NovaParser as _NovaParser
    _NOVA_AVAILABLE = True
except ImportError:
    _NOVA_AVAILABLE = False

_CVE_RE = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)

# Matches 'rule <Name>' at the start of a line — used to find rule boundaries
_RULE_HEADER = re.compile(r'^rule\s+\w+', re.MULTILINE)


class NovaParser(BaseRuleParser):
    """
    Parser for Nova LLM security rules (.nov format).

    Validation uses nova-hunting's NovaParser when available (authoritative),
    falling back to structural regex checks when the library is missing.
    Parsing uses nova-hunting to extract the AST; regex fallback on failure.
    """

    @property
    def format(self) -> str:
        return "nova"

    @property
    def extensions(self) -> List[str]:
        return ['.nov']

    def can_handle(self, chunk: str) -> bool:
        # Nova: 'rule <Name>' with '{' on the NEXT line, or contains nova-specific sections.
        # YARA: 'rule <Name> {' on the same line — ruled out by checking for own-line rule name.
        if not _RULE_HEADER.search(chunk):
            return False
        nova_sections = bool(re.search(r'\b(semantics|llm)\s*:', chunk))
        rule_alone    = bool(re.search(r'^rule\s+\w+\s*$', chunk, re.MULTILINE))
        return nova_sections or rule_alone

    def split_rules(self, raw_content: str) -> List[str]:
        # Each Nova rule starts with 'rule <Name>' at column 0.
        # Slice content between consecutive headers.
        boundaries = [m.start() for m in _RULE_HEADER.finditer(raw_content)]
        if not boundaries:
            return []
        rules = []
        for i, start in enumerate(boundaries):
            end = boundaries[i + 1] if i + 1 < len(boundaries) else len(raw_content)
            chunk = raw_content[start:end].strip()
            if chunk:
                rules.append(chunk)
        return rules

    def validate(self, raw_rule: str) -> ValidationResult:
        if _NOVA_AVAILABLE:
            try:
                _NovaParser().parse(raw_rule)
                return ValidationResult(ok=True, errors=[], normalized_content=raw_rule)
            except Exception as e:
                return ValidationResult(ok=False, errors=[str(e)], normalized_content=raw_rule)

        # Fallback: manual structural checks when nova-hunting is absent
        errors = []
        if not _RULE_HEADER.search(raw_rule):
            errors.append("Missing 'rule <name>' header")
        if 'meta:' not in raw_rule:
            errors.append("Missing 'meta' section")
        if 'condition:' not in raw_rule:
            errors.append("Missing 'condition' section")
        if not any(s in raw_rule for s in ('keywords:', 'semantics:', 'llm:')):
            errors.append("Must include at least one detection section: keywords, semantics, or llm")
        return ValidationResult(ok=len(errors) == 0, errors=errors, normalized_content=raw_rule)

    def parse(self, raw_rule: str) -> Dict[str, Any]:
        if _NOVA_AVAILABLE:
            try:
                rule = _NovaParser().parse(raw_rule)
                return self._from_nova_rule(rule, raw_rule)
            except Exception as e:
                # Regex fallback: extract what we can
                return self._parse_regex(raw_rule, error=str(e))

        return self._parse_regex(raw_rule)

    def _from_nova_rule(self, rule: Any, raw_rule: str) -> Dict[str, Any]:
        meta = rule.meta or {}
        desc = meta.get('description', '')
        cves = list(dict.fromkeys(_CVE_RE.findall(desc)))

        refs = []
        if 'reference' in meta:
            refs.append(meta['reference'])
        for url in re.findall(r'https?://[^\s\'">\]]+', desc):
            if url not in refs:
                refs.append(url)

        tags = [t for t in (meta.get('category'), meta.get('severity')) if t]

        return {
            "format": self.format,
            "identity": {"name": rule.name, "tags": tags, "scopes": []},
            "metadata": {
                **meta,
                "condition": rule.condition,
                "keywords":  {k: {"pattern": v.pattern, "is_regex": v.is_regex}
                              for k, v in (rule.keywords or {}).items()},
                "semantics": {k: {"description": v.pattern, "threshold": v.threshold}
                              for k, v in (rule.semantics or {}).items()},
                "llm":       {k: {"prompt": v.pattern, "threshold": v.threshold}
                              for k, v in (rule.llms or {}).items()},
            },
            "content":         raw_rule,
            "tags":            tags,
            "vulnerabilities": cves,
            "references":      refs,
            "sources":         [meta['author']] if 'author' in meta else [],
            "original_uuid":   meta.get('uuid'),
            "status":          "parsed",
        }

    def _parse_regex(self, raw_rule: str, error: str = "") -> Dict[str, Any]:
        """Regex-based fallback — always returns the full schema."""
        name_m = re.search(r'^rule\s+(\w+)', raw_rule, re.MULTILINE)
        meta: Dict[str, str] = {}
        for m in re.finditer(r'(\w+)\s*=\s*"([^"]*)"', raw_rule):
            if m.group(1) not in meta:
                meta[m.group(1)] = m.group(2)

        desc = meta.get('description', '')
        cves = list(dict.fromkeys(_CVE_RE.findall(desc)))
        tags = [t for t in (meta.get('category'), meta.get('severity')) if t]
        refs = [meta['reference']] if 'reference' in meta else []

        return {
            "format": self.format,
            "identity": {"name": name_m.group(1) if name_m else None, "tags": tags, "scopes": []},
            "metadata": meta,
            "content":         raw_rule,
            "tags":            tags,
            "vulnerabilities": cves,
            "references":      refs,
            "sources":         [meta['author']] if 'author' in meta else [],
            "original_uuid":   meta.get('uuid'),
            "status":          "parsing_error" if error else "parsed",
            **({"error": error} if error else {}),
        }

    def normalize(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        sources = parsed_data.get("sources", [])
        meta = parsed_data.get("metadata", {})
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
