import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List
from parsers.base import BaseRuleParser, ValidationResult

_CVE_RE = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)

# Wazuh detection condition tags — at least one is required in a meaningful rule
_DETECTION_TAGS = {
    'match', 'regex', 'if_sid', 'if_matched_sid', 'if_group',
    'if_matched_group', 'decoded_as', 'program_name', 'hostname',
    'id', 'field', 'srcip', 'dstip',
}


def _strip_fixture_comments(raw: str) -> str:
    """Remove '#' comment lines (test-fixture header) before XML parsing."""
    lines = [l for l in raw.splitlines() if not l.lstrip().startswith('#')]
    return '\n'.join(lines)


def _rule_to_str(el: ET.Element) -> str:
    """Serialise a <rule> Element back to a compact XML string."""
    return ET.tostring(el, encoding='unicode')


class WazuhParser(BaseRuleParser):
    """
    Parser for Wazuh SIEM detection rules (XML format, .xml / .wazuh).

    Validation: stdlib xml.etree.ElementTree — catches malformed XML plus
    semantic checks (id, level range 0-15, description present, detection
    condition present).

    Split: strips fixture '#' comment header, parses XML, yields each
    <rule> element serialised as an individual XML string.
    """

    @property
    def format(self) -> str:
        return "wazuh"

    @property
    def extensions(self) -> List[str]:
        return ['.xml', '.wazuh']

    def can_handle(self, chunk: str) -> bool:
        # Wazuh: <rule … level="N"> or <group name="…"> wrapping rules
        return bool(re.search(r'<rule\b[^>]*\blevel\s*=|<group\b[^>]*\bname\s*=', chunk))

    def split_rules(self, raw_content: str) -> List[str]:
        cleaned = _strip_fixture_comments(raw_content).strip()
        if not cleaned:
            return []
        try:
            root = ET.fromstring(cleaned)
        except ET.ParseError:
            # Return the whole content as one "rule" so validate() can report it
            return [cleaned]

        # If root IS a <rule>, it's already a single rule
        if root.tag == 'rule':
            return [_rule_to_str(root)]

        # Otherwise collect all <rule> elements anywhere in the tree
        rules = [_rule_to_str(el) for el in root.iter('rule')]
        return rules if rules else [cleaned]

    def validate(self, raw_rule: str) -> ValidationResult:
        errors = []
        warnings = []

        # 1. XML must parse
        try:
            rule = ET.fromstring(raw_rule.strip())
        except ET.ParseError as e:
            return ValidationResult(ok=False, errors=[f"XML parse error: {e}"], normalized_content=raw_rule)

        if rule.tag != 'rule':
            return ValidationResult(ok=False, errors=[f"Root element must be <rule>, got <{rule.tag}>"], normalized_content=raw_rule)

        # 2. id — must exist and be a non-negative integer
        rule_id = rule.get('id')
        if rule_id is None:
            errors.append("Missing required attribute 'id'")
        elif not rule_id.strip().lstrip('-').isdigit() or int(rule_id) < 0:
            errors.append(f"Attribute 'id' must be a non-negative integer, got: {rule_id!r}")

        # 3. level — must exist and be an integer 0-15
        level = rule.get('level')
        if level is None:
            errors.append("Missing required attribute 'level'")
        else:
            try:
                lvl = int(level)
                if not 0 <= lvl <= 15:
                    errors.append(f"Attribute 'level' must be 0-15, got: {lvl}")
            except ValueError:
                errors.append(f"Attribute 'level' must be an integer, got: {level!r}")

        # 4. <description> — must exist and be non-empty
        desc_el = rule.find('description')
        if desc_el is None or not (desc_el.text or '').strip():
            errors.append("Missing or empty <description> element")

        # 5. At least one detection condition
        child_tags = {child.tag for child in rule}
        if not child_tags & _DETECTION_TAGS:
            warnings.append(
                "No detection condition found "
                "(expected at least one of: match, regex, if_sid, …)"
            )

        return ValidationResult(
            ok=(len(errors) == 0),
            errors=errors,
            warnings=warnings,
            normalized_content=raw_rule,
        )

    def parse(self, raw_rule: str) -> Dict[str, Any]:
        try:
            rule = ET.fromstring(raw_rule.strip())
        except ET.ParseError as e:
            return self._error_result(raw_rule, f"XML parse error: {e}")

        try:
            rule_id    = rule.get('id', '')
            level      = rule.get('level', '')
            overwrite  = rule.get('overwrite', 'no')

            desc_el    = rule.find('description')
            desc       = (desc_el.text or '').strip() if desc_el is not None else ''

            # tags from <group> element (comma-separated list)
            group_el   = rule.find('group')
            group_tags = [t for t in (group_el.text or '').split(',') if t.strip()] if group_el is not None else []

            # MITRE ATT&CK IDs
            mitre_ids  = [el.text.strip() for el in rule.findall('./mitre/id') if el.text]

            # CVEs from <cve> element(s) and description
            cves_el    = [el.text.strip() for el in rule.findall('cve') if el.text]
            cves_desc  = _CVE_RE.findall(desc)
            cves       = list(dict.fromkeys(cves_el + cves_desc))

            # References from <info type="link">
            refs       = [el.text.strip() for el in rule.findall('info') if el.get('type') == 'link' and el.text]

            # Detection conditions
            conditions = {}
            for tag in _DETECTION_TAGS:
                vals = [el.text for el in rule.findall(tag) if el.text]
                if vals:
                    conditions[tag] = vals if len(vals) > 1 else vals[0]

            # Parent rule(s)
            if_sid     = rule.findtext('if_sid', '').strip()
            if_matched = rule.findtext('if_matched_sid', '').strip()

            meta = {
                "rule_id":    rule_id,
                "level":      level,
                "description": desc,
                "group_tags": group_tags,
                "mitre":      mitre_ids,
                "conditions": conditions,
                "overwrite":  overwrite,
            }
            if if_sid:      meta["if_sid"]          = if_sid
            if if_matched:  meta["if_matched_sid"]  = if_matched

            freq_el = rule.find('frequency')
            tf_el   = rule.find('timeframe')
            if freq_el is not None and freq_el.text:
                meta["frequency"] = freq_el.text.strip()
            if tf_el is not None and tf_el.text:
                meta["timeframe"] = tf_el.text.strip()

            return {
                "format":   self.format,
                "identity": {"name": desc, "tags": group_tags, "scopes": mitre_ids},
                "metadata": meta,
                "content":  raw_rule,
                "tags":     group_tags,
                "vulnerabilities": cves,
                "references":      refs,
                "sources":         [],
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
        meta = parsed_data.get("metadata", {})
        return {
            "title":           parsed_data.get("identity", {}).get("name"),
            "format":          self.format,
            "description":     meta.get("description", ""),
            "author":          "Wazuh",
            "content":         parsed_data.get("content", ""),
            "tags":            parsed_data.get("tags", []),
            "original_uuid":   parsed_data.get("original_uuid"),
            "version":         "1.0",
            "references":      parsed_data.get("references", []),
            "vulnerabilities": parsed_data.get("vulnerabilities", []),
        }
