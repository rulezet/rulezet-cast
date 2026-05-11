import re
import yaml
from typing import Any, Dict, List
from parsers.base import BaseRuleParser, ValidationResult


class SigmaParser(BaseRuleParser):
    """
    Parser for Sigma rules (YAML-based detection rules).

    Validation pipeline (4 steps, mirrors rulezet-core's SigmaRule):
      1. YAML parse — content must be a valid single-document YAML dict
      2. JSON schema — required fields + enum values (title, logsource, detection, status, level)
      3. pySigma structural — SigmaCollection.from_yaml() for full parse
      4. pySigma semantic  — SigmaValidator for HIGH-severity issues (dangling conditions, etc.)
         MEDIUM issues become warnings, not errors.

    Never re-dumps YAML → original formatting and quotes are preserved.
    """

    @property
    def format(self) -> str:
        return "sigma"

    @property
    def extensions(self) -> List[str]:
        return [".yml", ".yaml"]

    # ── can_handle ────────────────────────────────────────────────────────────

    def can_handle(self, chunk: str) -> bool:
        """
        Detect Sigma rules by presence of all three mandatory YAML keys.
        Fast — regex only, no YAML parsing.
        """
        return bool(
            re.search(r'^\s*title\s*:', chunk, re.MULTILINE) and
            re.search(r'^\s*detection\s*:', chunk, re.MULTILINE) and
            re.search(r'^\s*logsource\s*:', chunk, re.MULTILINE)
        )

    # ── split_rules ───────────────────────────────────────────────────────────

    def split_rules(self, raw_content: str) -> List[str]:
        """
        Split multi-rule YAML on '---' document separators.
        Skips empty documents and comment-only blocks.
        Mirrors rulezet-core's extract_rules_from_file logic.
        """
        docs = re.split(r'^---\s*$', raw_content, flags=re.MULTILINE)
        result = []
        for doc in docs:
            doc = doc.strip()
            if not doc:
                continue
            # Skip blocks with no YAML keys (pure comments, blank separators)
            if not re.search(r'^\s*\w+\s*:', doc, re.MULTILINE):
                continue
            result.append(doc)
        return result if result else [raw_content]

    # ── validate ──────────────────────────────────────────────────────────────

    def validate(self, raw_rule: str) -> ValidationResult:
        """
        3-step validation pipeline — never raises.

        Step 1: YAML parse — must be a valid single dict
        Step 2: pySigma structural — SigmaCollection.from_yaml()
        Step 3: pySigma semantic  — SigmaValidator (HIGH=error, MEDIUM=warning)
        """
        from sigma.collection import SigmaCollection
        from sigma.validation import SigmaValidator
        from sigma.validators.base import SigmaValidationIssueSeverity
        from sigma.validators.core import validators as _sigma_validators

        # ── Step 1: YAML ──
        try:
            rule_dict = yaml.safe_load(raw_rule)
            if not isinstance(rule_dict, dict):
                return ValidationResult(
                    ok=False,
                    errors=["Empty or invalid YAML — expected a single rule object."],
                    normalized_content=raw_rule,
                )
        except Exception as e:
            return ValidationResult(
                ok=False,
                errors=[f"YAML parse error: {e}"],
                normalized_content=raw_rule,
            )

        # ── Step 2: pySigma structural ──
        try:
            col = SigmaCollection.from_yaml(raw_rule)
        except Exception as e:
            return ValidationResult(
                ok=False,
                errors=[str(e)],
                normalized_content=raw_rule,
            )

        # ── Step 3: pySigma semantic ──
        warnings = []
        try:
            validator = SigmaValidator(validators=_sigma_validators.values())
            issues    = validator.validate_rules(col)

            errors = []
            for issue in issues:
                m = re.search(r'description="([^"]+)"', str(issue))
                msg = m.group(1) if m else str(issue)
                if issue.severity == SigmaValidationIssueSeverity.HIGH:
                    errors.append(msg)
                else:
                    warnings.append(msg)

            if errors:
                return ValidationResult(
                    ok=False,
                    errors=errors,
                    warnings=warnings,
                    normalized_content=raw_rule,
                )
        except Exception as e:
            warnings.append(f"Semantic validation skipped: {e}")

        return ValidationResult(ok=True, warnings=warnings, normalized_content=raw_rule)

    # ── parse ─────────────────────────────────────────────────────────────────

    def parse(self, raw_rule: str) -> Dict[str, Any]:
        """
        Extract structured data from a single Sigma rule.
        Uses pySigma for rich extraction; falls back to raw YAML on failure.
        Original YAML is never re-dumped — preserved as-is in 'content'.
        Always returns all required schema keys.
        """
        try:
            from sigma.rule import SigmaRule as PySigmaRule
        except ImportError:
            return self._fallback_parse(raw_rule, "pySigma not installed")

        try:
            rule = PySigmaRule.from_yaml(raw_rule)

            tags = [str(t) for t in (rule.tags or [])]

            # CVE extraction from description + tags
            cve_text = " ".join([str(rule.description or ""), " ".join(tags)])
            cves = re.findall(r'CVE-\d{4}-\d{4,7}', cve_text, re.IGNORECASE)

            # logsource as structured dict (mirrors rulezet-core)
            ls = rule.logsource
            logsource = {
                k: v for k, v in {
                    "category": ls.category,
                    "product":  ls.product,
                    "service":  ls.service,
                }.items() if v is not None
            }

            # author — pySigma returns a string or None
            author = str(rule.author) if rule.author is not None else None

            return {
                "format":   self.format,
                "identity": {
                    "name":   str(rule.title) if rule.title is not None else None,
                    "tags":   tags,
                    "scopes": [],
                },
                "metadata": {
                    "status":        str(rule.status)      if rule.status      else None,
                    "level":         str(rule.level)       if rule.level       else None,
                    "date":          str(rule.date)        if rule.date        else None,
                    "modified":      str(rule.modified)    if rule.modified    else None,
                    "description":   str(rule.description) if rule.description else "",
                    "falsepositives": list(rule.falsepositives or []),
                    "logsource":     logsource,
                },
                "content":         raw_rule,           # original YAML, never re-dumped
                "tags":            tags,
                "vulnerabilities": cves,
                "references":      list(rule.references or []),
                "sources":         [author] if author else [],
                "original_uuid":   str(rule.id) if rule.id else None,
                "status":          "parsed",
            }

        except Exception as e:
            return self._fallback_parse(raw_rule, str(e))

    # ── _fallback_parse ───────────────────────────────────────────────────────

    def _fallback_parse(self, raw_rule: str, error: str) -> Dict[str, Any]:
        """
        YAML fallback when pySigma fails.
        Extracts what it can without re-dumping. Returns full schema.
        """
        name = None
        tags = []
        try:
            data = yaml.safe_load(raw_rule) or {}
            if isinstance(data, dict):
                raw_title = data.get("title")
                name = str(raw_title) if raw_title is not None else None
                raw_tags = data.get("tags", [])
                tags = [str(t) for t in raw_tags] if isinstance(raw_tags, list) else []
        except Exception:
            m = re.search(r'^\s*title\s*:\s*(.+)$', raw_rule, re.MULTILINE)
            if m:
                name = m.group(1).strip()

        return {
            "format":    self.format,
            "identity": {
                "name":   name,
                "tags":   tags,
                "scopes": [],
            },
            "metadata":        {},
            "content":         raw_rule,
            "tags":            tags,
            "vulnerabilities": [],
            "references":      [],
            "sources":         [],
            "original_uuid":   None,
            "status":          "parsing_error",
            "error":           error,
        }

    # ── normalize ─────────────────────────────────────────────────────────────

    def normalize(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Map parse() output to the Universal Rulezet Schema.
        Mirrors rulezet-core's parse_metadata() output keys.
        Always uses .get() — never direct key access.
        """
        sources = parsed_data.get("sources", [])
        meta    = parsed_data.get("metadata", {})
        return {
            # Core Rulezet fields (mirrors parse_metadata return)
            "title":           parsed_data.get("identity", {}).get("name"),
            "format":          self.format,
            "description":     meta.get("description", ""),
            "author":          sources[0] if sources else "Unknown",
            "content":         parsed_data.get("content", ""),   # = "to_string" in rulezet-core
            "tags":            parsed_data.get("tags", []),
            "original_uuid":   parsed_data.get("original_uuid"),
            "vulnerabilities": parsed_data.get("vulnerabilities", []),
            "references":      parsed_data.get("references", []),
            # Sigma-specific (extra fields rulezet-core may use)
            "level":           meta.get("level"),
            "status":          meta.get("status"),
            "logsource":       meta.get("logsource", {}),
            "falsepositives":  meta.get("falsepositives", []),
        }