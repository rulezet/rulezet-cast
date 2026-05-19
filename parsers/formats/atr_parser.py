import re
import yaml
from typing import Any, Dict, List
from parsers.base import BaseRuleParser, ValidationResult

_CVE_RE = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
_ATR_ID_RE = re.compile(r'^ATR-\d{4}-\d{5}$')

_ATR_CATEGORIES = frozenset({
    'prompt-injection', 'tool-poisoning', 'skill-compromise',
    'agent-manipulation', 'context-exfiltration', 'data-poisoning',
    'excessive-autonomy', 'model-abuse', 'model-security', 'privilege-escalation',
})
_ATR_SEVERITIES = frozenset({'critical', 'high', 'medium', 'low'})
_ATR_AGENT_SOURCE_TYPES = frozenset({'llm_io', 'tool_call', 'skill_manifest', 'agent_loop'})

# Signals unique to ATR among YAML-based formats (must not match Sigma)
_ATR_CAN_HANDLE = re.compile(
    r'^\s*id\s*:\s*ATR-\d{4}-\d{5}\b'
    r'|^\s*agent_source\s*:'
    r'|^\s*category\s*:\s*(?:prompt-injection|tool-poisoning|skill-compromise'
    r'|agent-manipulation|context-exfiltration|data-poisoning'
    r'|excessive-autonomy|model-abuse|model-security|privilege-escalation)',
    re.MULTILINE,
)


class ATRParser(BaseRuleParser):
    """
    Parser for Agent Threat Rules (ATR) — YAML-based detection rules for AI
    agent threats (.yaml / .yml).

    Rules carry a stable identifier ATR-YYYY-NNNNN and cover ten attack
    categories (prompt-injection, tool-poisoning, context-exfiltration, …).

    Validation: YAML parse + semantic checks (id pattern, severity enum,
    tags.category taxonomy, agent_source.type, detection.conditions shape).

    Split: YAML document separators (---). Fixture header comment blocks
    are skipped automatically.

    Upstream: https://github.com/Agent-Threat-Rule/agent-threat-rules
    """

    @property
    def format(self) -> str:
        return "atr"

    @property
    def extensions(self) -> List[str]:
        return ['.yaml', '.yml']

    def can_handle(self, chunk: str) -> bool:
        return bool(_ATR_CAN_HANDLE.search(chunk))

    def split_rules(self, raw_content: str) -> List[str]:
        parts = re.split(r'^---\s*$', raw_content, flags=re.MULTILINE)
        chunks = []
        for part in parts:
            stripped = part.strip()
            if not stripped:
                continue
            # Skip pure-comment blocks (fixture file headers)
            non_comment = '\n'.join(
                l for l in stripped.splitlines() if not l.lstrip().startswith('#')
            ).strip()
            if non_comment:
                chunks.append(stripped)
        return chunks if chunks else ([raw_content.strip()] if raw_content.strip() else [])

    def validate(self, raw_rule: str) -> ValidationResult:
        errors = []
        warnings = []

        try:
            doc = yaml.safe_load(raw_rule)
        except Exception as exc:
            return ValidationResult(ok=False, errors=[f"YAML parse error: {exc}"], normalized_content=raw_rule)

        if doc is None or not isinstance(doc, dict):
            return ValidationResult(
                ok=False,
                errors=["Empty or invalid YAML — expected a single rule mapping"],
                normalized_content=raw_rule,
            )

        # id
        rule_id = doc.get('id')
        if not isinstance(rule_id, str):
            errors.append("Missing or non-string required field: id")
        elif not _ATR_ID_RE.match(rule_id):
            errors.append(f"Rule id {rule_id!r} does not match pattern ATR-YYYY-NNNNN")

        # title
        title = doc.get('title')
        if not isinstance(title, str) or not title.strip():
            errors.append("Missing or empty required field: title")

        # severity
        severity = doc.get('severity')
        if severity is None:
            errors.append("Missing required field: severity")
        elif severity not in _ATR_SEVERITIES:
            errors.append(f"Severity {severity!r} is not one of {sorted(_ATR_SEVERITIES)}")

        # tags.category
        tags = doc.get('tags')
        if not isinstance(tags, dict):
            errors.append("Missing or non-mapping required field: tags")
        else:
            category = tags.get('category')
            if category is None:
                errors.append("Missing required field: tags.category")
            elif category not in _ATR_CATEGORIES:
                errors.append(
                    f"Category {category!r} is not in the ATR taxonomy. "
                    f"Valid: {sorted(_ATR_CATEGORIES)}"
                )

        # agent_source.type
        agent_source = doc.get('agent_source')
        if not isinstance(agent_source, dict):
            errors.append("Missing or non-mapping required field: agent_source")
        else:
            atype = agent_source.get('type')
            if atype is None:
                errors.append("Missing required field: agent_source.type")
            elif atype not in _ATR_AGENT_SOURCE_TYPES:
                # Schema is additive — unknown types are warnings, not errors
                warnings.append(
                    f"agent_source.type {atype!r} is not in the known set "
                    f"{sorted(_ATR_AGENT_SOURCE_TYPES)} — accepting but flagging"
                )

        # detection block
        detection = doc.get('detection')
        if not isinstance(detection, dict):
            errors.append("Missing or non-mapping required field: detection")
        else:
            conditions = detection.get('conditions')
            if conditions is None:
                errors.append("Missing required field: detection.conditions")
            elif isinstance(conditions, list):
                if len(conditions) == 0:
                    errors.append("detection.conditions must be a non-empty list")
                else:
                    for idx, cond in enumerate(conditions):
                        if not isinstance(cond, dict):
                            errors.append(f"detection.conditions[{idx}] must be a mapping")
                            continue
                        for key in ('field', 'operator', 'value'):
                            if key not in cond:
                                errors.append(
                                    f"detection.conditions[{idx}] missing required key {key!r}"
                                )
                expr = detection.get('condition')
                if expr is not None and expr not in {'any', 'all', 'or', 'and'}:
                    errors.append(
                        f"detection.condition {expr!r} must be one of: any | all | or | and"
                    )
            elif not isinstance(conditions, dict):
                errors.append("detection.conditions must be a list or mapping")

        return ValidationResult(
            ok=(len(errors) == 0),
            errors=errors,
            warnings=warnings,
            normalized_content=raw_rule,
        )

    def parse(self, raw_rule: str) -> Dict[str, Any]:
        try:
            doc = yaml.safe_load(raw_rule)
        except Exception as e:
            return self._error_result(raw_rule, f"YAML parse error: {e}")
        if not isinstance(doc, dict):
            return self._error_result(raw_rule, "Not a YAML mapping")

        try:
            rule_id    = doc.get('id', '')
            title      = doc.get('title', '').strip()
            description = doc.get('description', '')
            severity   = doc.get('severity', 'unknown')
            author     = doc.get('author', 'ATR Community')
            version    = str(doc.get('rule_version', doc.get('version', '1')))
            license_   = doc.get('license', 'MIT')

            # Flatten tags mapping to ["key:value", …]
            tags_dict = doc.get('tags') or {}
            tags_list: List[str] = []
            if isinstance(tags_dict, dict):
                for k, v in tags_dict.items():
                    if isinstance(v, str):
                        tags_list.append(f"{k}:{v}")
                    elif isinstance(v, (list, tuple)):
                        for item in v:
                            tags_list.append(f"{k}:{item}")

            category = tags_dict.get('category', '') if isinstance(tags_dict, dict) else ''

            # CVEs: prefer explicit references.cve list, fall back to description scan
            references_block = doc.get('references') or {}
            explicit_cves: List[str] = []
            ref_urls: List[str] = []
            if isinstance(references_block, dict):
                raw_cves = references_block.get('cve') or []
                if isinstance(raw_cves, list):
                    explicit_cves = [str(c).strip().upper() for c in raw_cves if c]
                for key, val in references_block.items():
                    if key == 'cve':
                        continue
                    if isinstance(val, list):
                        ref_urls += [i for i in val if isinstance(i, str) and i.startswith('http')]
                    elif isinstance(val, str) and val.startswith('http'):
                        ref_urls.append(val)
            elif isinstance(references_block, list):
                ref_urls = [r for r in references_block if isinstance(r, str)]

            desc_text = description if isinstance(description, str) else ''
            cves = list(dict.fromkeys(
                explicit_cves if explicit_cves else _CVE_RE.findall(desc_text)
            ))

            # MITRE ATT&CK techniques
            mitre_ids: List[str] = []
            if isinstance(tags_dict, dict):
                attack = tags_dict.get('attack')
                if isinstance(attack, list):
                    mitre_ids = [t for t in attack if isinstance(t, str)]
                elif isinstance(attack, str):
                    mitre_ids = [attack]

            return {
                "format":   self.format,
                "identity": {"name": title, "tags": tags_list, "scopes": mitre_ids},
                "metadata": {
                    "rule_id":      rule_id,
                    "description":  description,
                    "severity":     severity,
                    "category":     category,
                    "version":      version,
                    "license":      license_,
                    "author":       author,
                    "agent_source": doc.get('agent_source') or {},
                    "detection":    doc.get('detection') or {},
                },
                "content":         raw_rule,
                "tags":            tags_list,
                "vulnerabilities": cves,
                "references":      ref_urls,
                "sources":         [author] if isinstance(author, str) else (author or []),
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
            "author":          sources[0] if sources else "ATR Community",
            "content":         parsed_data.get("content", ""),
            "tags":            parsed_data.get("tags", []),
            "original_uuid":   parsed_data.get("original_uuid"),
            "version":         meta.get("version", "1"),
            "references":      parsed_data.get("references", []),
            "vulnerabilities": parsed_data.get("vulnerabilities", []),
        }
