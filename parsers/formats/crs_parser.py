import re
from typing import Any, Dict, List, Optional
from parsers.base import BaseRuleParser, ValidationResult

_SEC_DIRECTIVE_RE = re.compile(
    r'^\s*Sec(?:Rule|Action|Marker|DefaultAction)\b',
    re.IGNORECASE | re.MULTILINE,
)
_CVE_RE = re.compile(r'CVE-(\d{4}-\d{4,7})', re.IGNORECASE)

# Action verbs that determine what the rule does when matched
_ACTION_VERBS = frozenset(("deny", "pass", "allow", "block", "redirect", "drop", "proxy"))


class CrsParser(BaseRuleParser):
    """
    Parser for OWASP CRS / ModSecurity rules (.conf files).

    Uses msc_pyparser for full AST extraction and validation.
    Falls back to regex for every field when the AST path fails.

    Multi-line rules (backslash continuation) are normalised before
    parsing — the stored 'content' is always the normalised form.
    """

    @property
    def format(self) -> str:
        return "crs"

    @property
    def extensions(self) -> List[str]:
        return [".conf"]

    # ── can_handle ────────────────────────────────────────────────────────────

    def can_handle(self, chunk: str) -> bool:
        return bool(_SEC_DIRECTIVE_RE.search(chunk))

    # ── split_rules ───────────────────────────────────────────────────────────

    def split_rules(self, raw_content: str) -> List[str]:
        """
        Normalise backslash-continuation lines, then extract one
        SecRule / SecAction / SecMarker / SecDefaultAction per entry.
        Non-Sec* lines (e.g. SecRequestBodyAccess) and pure comments
        are silently dropped.
        """
        normalized = self._normalize_multiline(raw_content)
        rules = []
        for line in normalized.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            if re.match(r'^Sec(?:Rule|Action|Marker|DefaultAction)\b', stripped, re.IGNORECASE):
                rules.append(stripped)
        return rules if rules else [raw_content]

    # ── validate ──────────────────────────────────────────────────────────────

    def validate(self, raw_rule: str) -> ValidationResult:
        normalized = self._normalize_multiline(raw_rule)
        try:
            import msc_pyparser
            mparser = msc_pyparser.MSCParser()
            mparser.parser.parse(normalized, debug=False)
            if not mparser.configlines:
                return ValidationResult(
                    ok=False,
                    errors=["No parseable Sec* directive found."],
                    normalized_content=normalized,
                )
            rx_err = self._validate_rx_patterns(normalized)
            if rx_err:
                return ValidationResult(ok=False, errors=[rx_err], normalized_content=normalized)
            return ValidationResult(ok=True, normalized_content=normalized)
        except Exception as e:
            msg = str(e.args[0]) if e.args else str(e)
            return ValidationResult(ok=False, errors=[msg], normalized_content=normalized)

    @staticmethod
    def _validate_rx_patterns(normalized: str) -> Optional[str]:
        """Return an error string if any @rx pattern in the rule is an invalid regex."""
        for m in re.finditer(r'"@rx\s+((?:[^"\\]|\\.)*)"', normalized, re.IGNORECASE):
            pattern = m.group(1)
            try:
                re.compile(pattern)
            except re.error as e:
                return f"Invalid @rx regex: {e}"
        return None

    # ── parse ─────────────────────────────────────────────────────────────────

    def parse(self, raw_rule: str) -> Dict[str, Any]:
        normalized = self._normalize_multiline(raw_rule)

        # Regex fallbacks — computed before any import so the fallback path is always safe
        id_m  = re.search(r'\bid\s*:\s*(\d+)', normalized, re.IGNORECASE)
        fb_id = id_m.group(1) if id_m else None
        fb_msg = self._regex_msg(normalized)
        fb_title = fb_msg or (f"CRS Rule {fb_id}" if fb_id else "Untitled CRS Rule")

        try:
            import msc_pyparser
            mparser = msc_pyparser.MSCParser()
            mparser.parser.parse(normalized, debug=False)

            if not mparser.configlines:
                raise ValueError("No configlines parsed")

            rule_data = next(
                (l for l in mparser.configlines if l.get("type") in ("SecRule", "SecAction")),
                None,
            )
            if rule_data is None:
                raise ValueError("No SecRule or SecAction found")

            am = self._actions_map(rule_data.get("actions", []))

            rule_id  = am.get("id")  or fb_id
            msg      = am.get("msg") or fb_msg or "Untitled CRS Rule"
            tags     = am.get("tag", [])
            phase    = am.get("phase")
            severity = am.get("severity")
            ver      = am.get("ver")
            rev      = am.get("rev")

            # The terminating action verb (deny / pass / block …)
            action_verb = next(
                (a["act_name"] for a in rule_data.get("actions", [])
                 if a.get("act_name") in _ACTION_VERBS),
                None,
            )

            cves = self._extract_cves(msg, tags)

            metadata: Dict[str, Any] = {}
            if phase:       metadata["phase"]    = phase
            if severity:    metadata["severity"] = severity
            if ver:         metadata["ver"]      = ver
            if rev:         metadata["rev"]      = rev
            if action_verb: metadata["action"]   = action_verb

            return {
                "format":          self.format,
                "identity":        {"name": msg, "tags": tags, "scopes": []},
                "metadata":        metadata,
                "content":         normalized,
                "tags":            tags,
                "vulnerabilities": cves,
                "references":      [],
                "sources":         [],
                "original_uuid":   str(rule_id) if rule_id else None,
                "status":          "parsed",
            }

        except Exception as e:
            return self._fallback_parse(normalized, str(e), fb_title, fb_id)

    # ── helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _normalize_multiline(raw: str) -> str:
        """Join backslash-continued lines into one logical rule per line."""
        return re.sub(r'\\\s*\n\s*', ' ', raw)

    @staticmethod
    def _regex_msg(text: str) -> Optional[str]:
        """Extract msg value from raw text — handles single and double quotes."""
        m = re.search(r"msg\s*:'([^']*)'", text, re.IGNORECASE)
        if not m:
            m = re.search(r'msg\s*:"([^"]*)"', text, re.IGNORECASE)
        return m.group(1).strip() if m else None

    @staticmethod
    def _actions_map(actions: list) -> Dict[str, Any]:
        """
        Flatten msc_pyparser's actions list into a dict.
        Keys that appear multiple times (tag, t, setvar, ctl) become lists.
        """
        result: Dict[str, Any] = {}
        for action in actions:
            name = action.get("act_name")
            arg  = action.get("act_arg")
            if name is None:
                continue
            if name in result:
                existing = result[name]
                if isinstance(existing, list):
                    existing.append(arg)
                else:
                    result[name] = [existing, arg]
            else:
                result[name] = arg

        for multi_key in ("tag", "t", "setvar", "ctl"):
            if multi_key in result and not isinstance(result[multi_key], list):
                result[multi_key] = [result[multi_key]]
            result.setdefault(multi_key, [])

        return result

    def _extract_cves(self, msg: str, tags: List[str]) -> List[str]:
        """Scan msg text and tags for CVE-YYYY-NNNNN patterns."""
        cves: set = set()
        for text in [msg or ""] + (tags or []):
            for m in _CVE_RE.finditer(text):
                cves.add(f"CVE-{m.group(1).upper()}")
        return sorted(cves)

    def _fallback_parse(self, normalized: str, error: str, title: str, rule_id) -> Dict[str, Any]:
        tags = []
        for m in re.finditer(r"tag\s*:'([^']*)'", normalized, re.IGNORECASE):
            tags.append(m.group(1))
        for m in re.finditer(r'tag\s*:"([^"]*)"', normalized, re.IGNORECASE):
            tags.append(m.group(1))
        cves = self._extract_cves(title, tags)
        return {
            "format":          self.format,
            "identity":        {"name": title, "tags": tags, "scopes": []},
            "metadata":        {},
            "content":         normalized,
            "tags":            tags,
            "vulnerabilities": cves,
            "references":      [],
            "sources":         [],
            "original_uuid":   str(rule_id) if rule_id else None,
            "status":          "parsing_error",
            "error":           error,
        }

    # ── normalize ─────────────────────────────────────────────────────────────

    def normalize(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        sources = parsed_data.get("sources", [])
        meta    = parsed_data.get("metadata", {})
        return {
            "title":           parsed_data.get("identity", {}).get("name"),
            "format":          self.format,
            "description":     meta.get("severity", ""),
            "author":          sources[0] if sources else "Unknown",
            "content":         parsed_data.get("content", ""),
            "tags":            parsed_data.get("tags", []),
            "original_uuid":   parsed_data.get("original_uuid"),
            "vulnerabilities": parsed_data.get("vulnerabilities", []),
            "references":      parsed_data.get("references", []),
            "phase":           meta.get("phase"),
            "severity":        meta.get("severity"),
            "ver":             meta.get("ver"),
        }
