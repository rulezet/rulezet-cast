import re
from typing import Any, Dict, List
from parsers.base import BaseRuleParser, ValidationResult


class SigmaParser(BaseRuleParser):
    """Parser for SIGMA rules."""

    @property
    def format(self) -> str:
        return "sigma"

    @property
    def extensions(self) -> List[str]:
        # TODO: set the correct extensions
        return [".sigma"]

    def can_handle(self, chunk: str) -> bool:
        # TODO: return True if chunk looks like a SIGMA rule
        raise NotImplementedError

    def split_rules(self, raw_content: str) -> List[str]:
        # TODO: split multi-rule content into individual rule strings
        return [raw_content]

    def validate(self, raw_rule: str) -> ValidationResult:
        # TODO: implement syntax validation
        return ValidationResult(ok=True)

    def parse(self, raw_rule: str) -> Dict[str, Any]:
        # TODO: extract structured data from the raw rule
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
        }

    def normalize(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        # TODO: map to Rulezet universal schema
        sources = parsed_data.get("sources", [])
        return {
            "title": parsed_data.get("identity", {}).get("name"),
            "format": self.format,
            "description": parsed_data.get("metadata", {}).get("description", ""),
            "author": sources[0] if sources else "Unknown",
            "content": parsed_data.get("content", ""),
            "tags": parsed_data.get("tags", []),
            "original_uuid": parsed_data.get("original_uuid"),
        }
