import re
from typing import Any, Dict, List
from parsers.base import BaseRuleParser, ValidationResult

_ACTIONS = r'(?:alert|drop|pass|reject|rejectsrc|rejectdst|rejectboth|log)'

# Matches the start of a Suricata rule line (including disabled rules prefixed with #)
_RULE_HEADER_RE = re.compile(
    rf'^\s*(?:#\s*)?{_ACTIONS}\s+\S+\s+\S+\s+\S+\s+(?:<>|->|<-)\s+\S+\s+\S+\s*\(',
    re.IGNORECASE | re.MULTILINE,
)
_DISABLED_PREFIX_RE = re.compile(rf'^\s*#\s*{_ACTIONS}\s+', re.IGNORECASE)
_CVE_RE = re.compile(r'CVE-(\d{4}-\d{4,7})', re.IGNORECASE)


class SuricataParser(BaseRuleParser):
    """Parser for Suricata / Snort-compatible IDS rules."""

    @property
    def format(self) -> str:
        return "suricata"

    @property
    def extensions(self) -> List[str]:
        return [".rules", ".rule"]

    # ── can_handle ────────────────────────────────────────────────────────────

    def can_handle(self, chunk: str) -> bool:
        return bool(_RULE_HEADER_RE.search(chunk))

    # ── split_rules ───────────────────────────────────────────────────────────

    def split_rules(self, raw_content: str) -> List[str]:
        """
        One Suricata rule = one line.
        Skips blank lines and pure comment lines.
        Keeps disabled rules (# alert ...) as individual entries so they
        can be validated / parsed as disabled.
        """
        rules = []
        for line in raw_content.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith('#') and not _DISABLED_PREFIX_RE.match(stripped):
                continue
            rules.append(stripped)
        return rules if rules else [raw_content]

    # ── validate ──────────────────────────────────────────────────────────────

    def validate(self, raw_rule: str) -> ValidationResult:
        try:
            from suricataparser import parse_rules
            parsed = parse_rules(raw_rule)
            if not parsed:
                return ValidationResult(
                    ok=False,
                    errors=["No valid Suricata rule found — check action, header, and options syntax."],
                    normalized_content=raw_rule,
                )
            return ValidationResult(
                ok=True,
                normalized_content="\n".join(r.raw for r in parsed),
            )
        except Exception as e:
            return ValidationResult(ok=False, errors=[str(e)], normalized_content=raw_rule)

    # ── parse ─────────────────────────────────────────────────────────────────

    def parse(self, raw_rule: str) -> Dict[str, Any]:
        msg_m    = re.search(r'msg\s*:\s*"(.*?)"', raw_rule)
        sid_m    = re.search(r'\bsid\s*:\s*(\d+)', raw_rule)
        rev_m    = re.search(r'\brev\s*:\s*(\d+)', raw_rule)
        fb_title = msg_m.group(1).strip() if msg_m else "Untitled Suricata Rule"
        fb_sid   = sid_m.group(1) if sid_m else None
        fb_rev   = rev_m.group(1) if rev_m else "1"

        try:
            from suricataparser import parse_rule as _parse_rule
            rule = _parse_rule(raw_rule)

            if rule is None:
                return self._fallback_parse(raw_rule, "suricataparser returned None — invalid rule structure", fb_title, fb_sid)

            title  = rule.msg  or fb_title
            sid    = str(rule.sid) if rule.sid else fb_sid
            rev    = str(rule.rev) if rule.rev else fb_rev
            action = str(rule.action) if getattr(rule, 'action', None) else None

            refs, cves = self._extract_refs_and_cves(raw_rule, title)

            ct_m      = re.search(r'\bclasstype\s*:\s*([^;]+)', raw_rule)
            classtype = ct_m.group(1).strip() if ct_m else None

            meta_kw_m = re.search(r'\bmetadata\s*:\s*([^;]+)', raw_rule)

            metadata: Dict[str, Any] = {}
            if action:
                metadata["action"] = action
            if classtype:
                metadata["classtype"] = classtype
            if rev:
                metadata["rev"] = rev
            if meta_kw_m:
                # Parse comma-separated key value pairs from metadata keyword
                meta_pairs = {}
                for pair in meta_kw_m.group(1).split(','):
                    parts = pair.strip().split(None, 1)
                    if len(parts) == 2:
                        meta_pairs[parts[0]] = parts[1]
                    elif len(parts) == 1:
                        meta_pairs[parts[0]] = True
                metadata["metadata"] = meta_pairs

            return {
                "format":          self.format,
                "identity":        {"name": title, "tags": [], "scopes": []},
                "metadata":        metadata,
                "content":         raw_rule,
                "tags":            [classtype] if classtype else [],
                "vulnerabilities": cves,
                "references":      refs,
                "sources":         [],
                "original_uuid":   sid,
                "status":          "parsed",
            }

        except Exception as e:
            return self._fallback_parse(raw_rule, str(e), fb_title, fb_sid)

    # ── helpers ───────────────────────────────────────────────────────────────

    def _extract_refs_and_cves(self, raw_rule: str, title: str):
        """
        Extract structured references and CVE IDs.
        Suricata reference syntax: reference:type,value;
        CVEs also extracted from inline msg text as a fallback.
        """
        refs = []
        cves: set = set()

        for m in re.finditer(r'\breference\s*:\s*([^,;]+)\s*,\s*([^;]+)', raw_rule):
            ref_type  = m.group(1).strip().lower()
            ref_value = m.group(2).strip()
            if ref_type == "cve":
                normalized = ref_value.upper()
                cve_id = f"CVE-{normalized}" if not normalized.startswith("CVE") else normalized
                cves.add(cve_id)
                refs.append(f"cve:{ref_value}")
            elif ref_type == "url":
                refs.append(ref_value)
            else:
                refs.append(f"{ref_type}:{ref_value}")

        for m in _CVE_RE.finditer(title):
            cves.add(f"CVE-{m.group(1).upper()}")

        return refs, sorted(cves)

    def _fallback_parse(self, raw_rule: str, error: str, title: str, sid) -> Dict[str, Any]:
        refs, cves = self._extract_refs_and_cves(raw_rule, title)
        return {
            "format":          self.format,
            "identity":        {"name": title, "tags": [], "scopes": []},
            "metadata":        {},
            "content":         raw_rule,
            "tags":            [],
            "vulnerabilities": cves,
            "references":      refs,
            "sources":         [],
            "original_uuid":   sid,
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
            "description":     meta.get("classtype", ""),
            "author":          sources[0] if sources else "Unknown",
            "content":         parsed_data.get("content", ""),
            "tags":            parsed_data.get("tags", []),
            "original_uuid":   parsed_data.get("original_uuid"),
            "vulnerabilities": parsed_data.get("vulnerabilities", []),
            "references":      parsed_data.get("references", []),
        }
