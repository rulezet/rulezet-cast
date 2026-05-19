import os
import re
import subprocess
import tempfile
from typing import Any, Dict, List
from parsers.base import BaseRuleParser, ValidationResult

try:
    from luaparser import ast as lua_ast
    _LUAPARSER_AVAILABLE = True
except ImportError:
    _LUAPARSER_AVAILABLE = False

_CVE_RE = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)

_NSE_SIGNALS = re.compile(
    r'\b(?:portrule|hostrule|prerule|postrule)\s*='
    r'|categories\s*=\s*\{'
    r'|description\s*=\s*\[\[',
    re.IGNORECASE,
)

# Script boundary: '-- scriptname.nse' on its own line
_SCRIPT_HEADER = re.compile(r'^--\s+[\w][\w\-]*\.nse\s*$', re.MULTILINE)


class NseParser(BaseRuleParser):
    """Parser for NSE (Nmap Scripting Engine) Lua scripts."""

    @property
    def format(self) -> str:
        return "nse"

    @property
    def extensions(self) -> List[str]:
        return ['.nse']

    def can_handle(self, chunk: str) -> bool:
        return bool(_NSE_SIGNALS.search(chunk))

    def split_rules(self, raw_content: str) -> List[str]:
        # Each NSE script may start with '-- scriptname.nse' as a header comment.
        # If multiple such headers are found, split on them (enables multi-script
        # test fixtures). A single script with or without a header is returned as-is.
        boundaries = [m.start() for m in _SCRIPT_HEADER.finditer(raw_content)]
        if len(boundaries) <= 1:
            stripped = raw_content.strip()
            return [stripped] if stripped else []

        scripts = []
        for i, start in enumerate(boundaries):
            end = boundaries[i + 1] if i + 1 < len(boundaries) else len(raw_content)
            chunk = raw_content[start:end].strip()
            if chunk and _NSE_SIGNALS.search(chunk):
                scripts.append(chunk)
        return scripts

    def validate(self, raw_rule: str) -> ValidationResult:
        errors = []
        warnings = []

        # Primary: luac -p (parse only, no output, no execution)
        # Tries 'luac' first, then 'luac5.4' (Debian/Ubuntu apt name).
        tmp_path = None
        luac_found = False
        try:
            with tempfile.NamedTemporaryFile(
                suffix=".nse", delete=False, mode='w', encoding='utf-8'
            ) as tmp:
                tmp.write(raw_rule)
                tmp_path = tmp.name

            for binary in ("luac", "luac5.4"):
                try:
                    result = subprocess.run(
                        [binary, "-p", tmp_path],
                        capture_output=True, text=True,
                    )
                    luac_found = True
                    if result.returncode != 0:
                        errors.append(result.stderr.strip())
                    break
                except FileNotFoundError:
                    continue

            if not luac_found:
                # Neither luac binary found — fall back to pure-Python luaparser
                if _LUAPARSER_AVAILABLE:
                    try:
                        lua_ast.parse(raw_rule)
                    except Exception as e:
                        errors.append(f"Lua syntax error: {e}")
                else:
                    warnings.append("luac not found and luaparser not installed — syntax unverified")

        except Exception as e:
            errors.append(str(e))
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)

        if not re.search(r'\baction\s*=\s*function', raw_rule):
            errors.append("Missing required action() function")

        if not re.search(r'\b(?:portrule|hostrule|prerule|postrule)\s*=', raw_rule):
            warnings.append("No rule type found (portrule/hostrule/prerule/postrule)")

        return ValidationResult(
            ok=(len(errors) == 0),
            errors=errors,
            warnings=warnings,
            normalized_content=raw_rule,
        )

    def parse(self, raw_rule: str) -> Dict[str, Any]:
        try:
            # Title: from '-- name.nse' header comment, then 'id = "..."'
            title = None
            comment_m = re.search(r'^--\s+([\w][\w\-]*)\.nse\s*$', raw_rule, re.MULTILINE)
            if comment_m:
                title = comment_m.group(1)
            if not title:
                id_m = re.search(r'\bid\s*=\s*["\']([^"\']+)["\']', raw_rule)
                if id_m:
                    title = id_m.group(1)

            # Description
            desc_m = re.search(r'description\s*=\s*\[\[([\s\S]*?)\]\]', raw_rule)
            description = desc_m.group(1).strip() if desc_m else ""

            cves = list(dict.fromkeys(_CVE_RE.findall(description)))

            # Scalar fields
            author_m = re.search(r'\bauthor\s*=\s*["\'](.+?)["\']', raw_rule)
            author = author_m.group(1).strip() if author_m else None

            license_m = re.search(r'\blicense\s*=\s*["\'](.+?)["\']', raw_rule)
            license_val = license_m.group(1).strip() if license_m else "unknown"

            version_m = re.search(r'\bversion\s*=\s*["\'](.+?)["\']', raw_rule)
            version = version_m.group(1).strip() if version_m else "1.0"

            # Categories
            cat_m = re.search(r'categories\s*=\s*\{([^\}]*)\}', raw_rule)
            categories = re.findall(r'["\']([^"\']+)["\']', cat_m.group(1)) if cat_m else []

            # Rule type
            rule_type = "unknown"
            for rt in ("portrule", "hostrule", "prerule", "postrule"):
                if re.search(rf'\b{rt}\s*=', raw_rule):
                    rule_type = rt
                    break

            refs = re.findall(r'https?://[^\s\'">\]\)]+', description)

            return {
                "format": self.format,
                "identity": {"name": title, "tags": categories, "scopes": [rule_type]},
                "metadata": {
                    "description": description,
                    "license": license_val,
                    "version": version,
                    "rule_type": rule_type,
                    "categories": categories,
                },
                "content": raw_rule,
                "tags": categories,
                "vulnerabilities": cves,
                "references": refs,
                "sources": [author] if author else [],
                "original_uuid": None,
                "status": "parsed",
            }

        except Exception as e:
            return {
                "format": self.format,
                "identity": {"name": None, "tags": [], "scopes": []},
                "metadata": {},
                "content": raw_rule,
                "tags": [],
                "vulnerabilities": [],
                "references": [],
                "sources": [],
                "original_uuid": None,
                "status": "parsing_error",
                "error": str(e),
            }

    def normalize(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        sources = parsed_data.get("sources", [])
        meta = parsed_data.get("metadata", {})
        return {
            "title": parsed_data.get("identity", {}).get("name"),
            "format": self.format,
            "description": meta.get("description", ""),
            "author": sources[0] if sources else "Unknown",
            "content": parsed_data.get("content", ""),
            "tags": parsed_data.get("tags", []),
            "original_uuid": parsed_data.get("original_uuid"),
            "license": meta.get("license", "unknown"),
            "version": meta.get("version", "1.0"),
            "references": parsed_data.get("references", []),
            "vulnerabilities": parsed_data.get("vulnerabilities", []),
        }
