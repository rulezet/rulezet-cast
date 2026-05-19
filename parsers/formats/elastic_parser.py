import re
import tomllib
from typing import Any, Dict, List
from parsers.base import BaseRuleParser, ValidationResult

_CVE_RE = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
_UUID_RE = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE
)

# Elastic-specific signals: UUID-shaped rule_id or known query languages
_ELASTIC_SIGNALS = re.compile(
    r'rule_id\s*=\s*"[0-9a-f]{8}-[0-9a-f]{4}'
    r'|language\s*=\s*"(?:eql|kql|lucene|esql|threshold|new_terms)"',
    re.IGNORECASE
)

_METADATA_BOUNDARY = re.compile(r'^\[metadata\]', re.MULTILINE)
_RULE_BOUNDARY = re.compile(r'^\[rule\]', re.MULTILINE)

_VALID_SEVERITIES = {'low', 'medium', 'high', 'critical'}
_VALID_LANGUAGES = {'eql', 'kql', 'lucene', 'esql', 'threshold', 'new_terms', 'ml', 'machine_learning'}
_QUERYLESS_TYPES = {'ml', 'machine_learning'}


class ElasticParser(BaseRuleParser):
    """
    Parser for Elastic Security detection rules (TOML format, .toml).

    Validation: stdlib tomllib — catches TOML syntax errors plus semantic
    checks (rule_id UUID, name, language, query, severity, risk_score).

    Split: splits on '[metadata]' section headers (each Elastic rule file
    starts with [metadata]); falls back to '[rule]' if no [metadata] present.
    """

    @property
    def format(self) -> str:
        return "elastic"

    @property
    def extensions(self) -> List[str]:
        return ['.toml']

    def can_handle(self, chunk: str) -> bool:
        return bool(_ELASTIC_SIGNALS.search(chunk))

    def split_rules(self, raw_content: str) -> List[str]:
        meta_matches = list(_METADATA_BOUNDARY.finditer(raw_content))
        if meta_matches:
            boundaries = [m.start() for m in meta_matches]
        else:
            rule_matches = list(_RULE_BOUNDARY.finditer(raw_content))
            if not rule_matches:
                stripped = raw_content.strip()
                return [stripped] if stripped and _ELASTIC_SIGNALS.search(stripped) else []
            boundaries = [m.start() for m in rule_matches]

        chunks = []
        for i, start in enumerate(boundaries):
            end = boundaries[i + 1] if i + 1 < len(boundaries) else len(raw_content)
            chunk = raw_content[start:end].strip()
            if chunk:
                chunks.append(chunk)
        return chunks

    def validate(self, raw_rule: str) -> ValidationResult:
        errors = []
        warnings = []

        try:
            data = tomllib.loads(raw_rule)
        except Exception as e:
            return ValidationResult(ok=False, errors=[f"TOML parse error: {e}"], normalized_content=raw_rule)

        rule = data.get('rule', {})

        name = rule.get('name', '').strip()
        if not name:
            errors.append("Missing or empty 'name' in [rule]")

        rule_id = rule.get('rule_id', '').strip()
        if not rule_id:
            errors.append("Missing 'rule_id' in [rule]")
        elif not _UUID_RE.match(rule_id):
            errors.append(f"'rule_id' must be a valid UUID, got: {rule_id!r}")

        lang = rule.get('language', '').strip()
        if not lang:
            errors.append("Missing 'language' in [rule]")
        elif lang.lower() not in _VALID_LANGUAGES:
            errors.append(f"'language' must be one of {sorted(_VALID_LANGUAGES)}, got: {lang!r}")

        rule_type = rule.get('type', '')
        if rule_type not in _QUERYLESS_TYPES and not rule.get('query', '').strip():
            errors.append("Missing or empty 'query' in [rule]")

        sev = rule.get('severity', '').strip()
        if not sev:
            errors.append("Missing 'severity' in [rule]")
        elif sev.lower() not in _VALID_SEVERITIES:
            errors.append(f"'severity' must be one of {sorted(_VALID_SEVERITIES)}, got: {sev!r}")

        rs = rule.get('risk_score')
        if rs is None:
            errors.append("Missing 'risk_score' in [rule]")
        else:
            try:
                if not 0 <= int(rs) <= 100:
                    errors.append(f"'risk_score' must be 0-100, got: {rs}")
            except (TypeError, ValueError):
                errors.append(f"'risk_score' must be an integer, got: {rs!r}")

        if not rule.get('author'):
            warnings.append("Missing 'author' in [rule]")

        return ValidationResult(
            ok=(len(errors) == 0),
            errors=errors,
            warnings=warnings,
            normalized_content=raw_rule,
        )

    def parse(self, raw_rule: str) -> Dict[str, Any]:
        try:
            data = tomllib.loads(raw_rule)
        except Exception as e:
            return self._error_result(raw_rule, f"TOML parse error: {e}")

        try:
            rule = data.get('rule', {})
            meta = data.get('metadata', {})

            name        = rule.get('name', '').strip()
            rule_id     = rule.get('rule_id', '').strip()
            language    = rule.get('language', '')
            rule_type   = rule.get('type', '')
            query       = rule.get('query', '').strip()
            description = rule.get('description', '').strip()
            severity    = rule.get('severity', '')
            risk_score  = rule.get('risk_score')
            author      = rule.get('author', [])
            tags        = rule.get('tags', [])
            references  = rule.get('references', [])
            index       = rule.get('index', [])

            mitre_ids = []
            for threat in rule.get('threat', []):
                for tech in threat.get('technique', []):
                    if tech.get('id'):
                        mitre_ids.append(tech['id'])
                    for sub in tech.get('subtechnique', []):
                        if sub.get('id'):
                            mitre_ids.append(sub['id'])

            cves = list(dict.fromkeys(_CVE_RE.findall(description + raw_rule[:1000])))

            return {
                "format":   self.format,
                "identity": {"name": name, "tags": tags, "scopes": mitre_ids},
                "metadata": {
                    "rule_id":       rule_id,
                    "language":      language,
                    "type":          rule_type,
                    "query":         query,
                    "severity":      severity,
                    "risk_score":    risk_score,
                    "description":   description,
                    "index":         index,
                    "author":        author,
                    "creation_date": meta.get('creation_date', ''),
                    "updated_date":  meta.get('updated_date', ''),
                    "maturity":      meta.get('maturity', ''),
                    "integration":   meta.get('integration', []),
                    "threat":        rule.get('threat', []),
                },
                "content":         raw_rule,
                "tags":            tags,
                "vulnerabilities": cves,
                "references":      references,
                "sources":         author if isinstance(author, list) else [author],
                "original_uuid":   rule_id or None,
                "status":          "parsed",
            }

        except Exception as e:
            return self._error_result(raw_rule, str(e))

    def _error_result(self, raw_rule: str, error: str) -> Dict[str, Any]:
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
            "error":           error,
        }

    def normalize(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        meta    = parsed_data.get("metadata", {})
        sources = parsed_data.get("sources", [])
        return {
            "title":           parsed_data.get("identity", {}).get("name"),
            "format":          self.format,
            "description":     meta.get("description", ""),
            "author":          sources[0] if sources else "Elastic",
            "content":         parsed_data.get("content", ""),
            "tags":            parsed_data.get("tags", []),
            "original_uuid":   parsed_data.get("original_uuid"),
            "version":         "1.0",
            "references":      parsed_data.get("references", []),
            "vulnerabilities": parsed_data.get("vulnerabilities", []),
        }
