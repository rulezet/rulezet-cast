import os
import sys


def _register_parser(base_dir: str, format_name: str, class_name: str):
    init_path = os.path.join(base_dir, "parsers", "__init__.py")
    with open(init_path, "r", encoding="utf-8") as f:
        src = f.read()

    import_line = f"from parsers.formats.{format_name}_parser import {class_name}Parser\n"
    entry_line  = f"    {class_name}Parser(),\n"

    if import_line.strip() in src:
        print(f"[!] {class_name}Parser already registered — skipping __init__.py update.")
        return

    # Insert import after the last existing import block line
    lines = src.splitlines(keepends=True)
    last_import_idx = 0
    for i, line in enumerate(lines):
        if line.startswith("from parsers.formats."):
            last_import_idx = i
    lines.insert(last_import_idx + 1, import_line)

    # Insert instance before the sentinel comment
    src_after = "".join(lines)
    sentinel = "    # add new parsers here as you implement them\n"
    src_after = src_after.replace(sentinel, entry_line + sentinel)

    with open(init_path, "w", encoding="utf-8") as f:
        f.write(src_after)

    print(f"[+] Registered {class_name}Parser in parsers/__init__.py")


def create_parser_template(format_name: str):
    format_name = format_name.lower().strip().replace(" ", "_")

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    target_dir = os.path.join(base_dir, "parsers", "formats")

    filename = f"{format_name}_parser.py"
    filepath = os.path.join(target_dir, filename)

    if os.path.exists(filepath):
        print(f"[-] ERROR: Parser for '{format_name}' already exists at:")
        print(f"    {filepath}")
        print("[-] Aborting to prevent accidental overwrite.")
        return

    os.makedirs(target_dir, exist_ok=True)

    class_name = "".join(w.capitalize() for w in format_name.split("_"))

    template = f"""\
import re
from typing import Any, Dict, List
from parsers.base import BaseRuleParser, ValidationResult


class {class_name}Parser(BaseRuleParser):
    \"\"\"Parser for {format_name.upper()} rules.\"\"\"

    @property
    def format(self) -> str:
        return "{format_name}"

    @property
    def extensions(self) -> List[str]:
        # TODO: set the correct extensions
        return [".{format_name}"]

    def can_handle(self, chunk: str) -> bool:
        # TODO: return True if chunk looks like a {format_name.upper()} rule
        raise NotImplementedError

    def split_rules(self, raw_content: str) -> List[str]:
        # TODO: split multi-rule content into individual rule strings
        return [raw_content]

    def validate(self, raw_rule: str) -> ValidationResult:
        # TODO: implement syntax validation
        return ValidationResult(ok=True)

    def parse(self, raw_rule: str) -> Dict[str, Any]:
        # TODO: extract structured data from the raw rule
        return {{
            "format": self.format,
            "identity": {{"name": None, "tags": [], "scopes": []}},
            "metadata": {{}},
            "content": raw_rule,
            "tags": [],
            "vulnerabilities": [],
            "references": [],
            "sources": [],
            "original_uuid": None,
        }}

    def normalize(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        # TODO: map to Rulezet universal schema
        sources = parsed_data.get("sources", [])
        return {{
            "title": parsed_data.get("identity", {{}}).get("name"),
            "format": self.format,
            "description": parsed_data.get("metadata", {{}}).get("description", ""),
            "author": sources[0] if sources else "Unknown",
            "content": parsed_data.get("content", ""),
            "tags": parsed_data.get("tags", []),
            "original_uuid": parsed_data.get("original_uuid"),
        }}
"""

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(template)

    print(f"[+] Created: {filepath}")
    _register_parser(base_dir, format_name, class_name)
    print(f"[!] Next steps:")
    print(f"    1. Implement can_handle(), split_rules(), validate(), parse(), normalize()")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 -m utils.scaffold <format_name>")
    else:
        create_parser_template(sys.argv[1])