from __future__ import annotations
import os
from typing import Any, Dict, List, Optional

from parsers.base import BaseRuleParser, ValidationResult
from parsers import ALL_PARSERS


class ParseResult:
    """Result of processing a single rule."""

    def __init__(
        self,
        raw: str,
        validation: ValidationResult,
        parsed: Dict[str, Any],
        normalized: Dict[str, Any],
        format_name: str,
    ):
        self.raw = raw
        self.validation = validation
        self.parsed = parsed
        self.normalized = normalized
        self.format_name = format_name

    def to_dict(self) -> Dict[str, Any]:
        return {
            "format": self.format_name,
            "validation": {
                "ok": self.validation.ok,
                "errors": self.validation.errors,
                "warnings": self.validation.warnings,
            },
            "parsed": self.parsed,
            "normalized": self.normalized,
        }


class RuleCastEngine:
    """
    Central dispatcher. Parsers are registered explicitly — no magic autodiscovery.
    To add a format: implement BaseRuleParser, then add an instance to ALL_PARSERS.
    """

    def __init__(self, parsers: Optional[List[BaseRuleParser]] = None):
        self.parsers: List[BaseRuleParser] = parsers if parsers is not None else ALL_PARSERS

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect_format(self, content: str) -> Optional[BaseRuleParser]:
        """Return the first parser that can handle this content, or None."""
        for p in self.parsers:
            if p.can_handle(content):
                return p
        return None

    def get_parser(self, format_name: str) -> Optional[BaseRuleParser]:
        """Return the parser for a given format name, or None."""
        for p in self.parsers:
            if p.format.lower() == format_name.lower():
                return p
        return None

    def process(
        self,
        content: str,
        format_name: Optional[str] = None,
    ) -> List[ParseResult]:
        """
        Full pipeline: detect → split → validate → parse → normalize.
        If format_name is given, skip auto-detection.
        Returns a list of ParseResult (one per rule found in content).
        """
        if format_name:
            parser = self.get_parser(format_name)
            if not parser:
                raise ValueError(f"Unknown format: '{format_name}'")
        else:
            parser = self.detect_format(content)
            if not parser:
                raise ValueError("Could not auto-detect format. Use --format to specify it.")

        raw_rules = parser.split_rules(content)
        results = []

        for raw in raw_rules:
            validation = parser.validate(raw)
            parsed = parser.parse(raw)
            normalized = parser.normalize(parsed)
            results.append(ParseResult(raw, validation, parsed, normalized, parser.format))

        return results

    def process_file(
        self,
        filepath: str,
        format_name: Optional[str] = None,
    ) -> List[ParseResult]:
        """Read a file and run process() on its content."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        return self.process(content, format_name)

    def list_parsers(self) -> List[Dict[str, Any]]:
        """Return info about all registered parsers (includes display metadata)."""
        from parsers.formats_manifest import FORMAT_METADATA
        result = []
        for p in self.parsers:
            meta = FORMAT_METADATA.get(p.format.lower(), {})
            result.append({
                'format':          p.format,
                'display_name':    meta.get('display_name', p.format.upper()),
                'description':     meta.get('description', ''),
                'icon':            meta.get('icon', 'fa-file-code'),
                'color':           meta.get('color', '#888888'),
                'file_extension':  meta.get('file_extension',
                                            p.extensions[0].lstrip('.') if p.extensions else ''),
                'all_extensions':  p.extensions,
                'can_be_executed': meta.get('can_be_executed', False),
                'class':           p.__class__.__name__,
            })
        return result