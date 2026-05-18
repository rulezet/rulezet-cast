import os
import re
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


def _create_test_fixture(base_dir: str, format_name: str) -> str:
    """
    Create the test fixture skeleton for a new format.
    Returns the path of the created file, or empty string if it already exists.
    """
    fmt_upper = format_name.upper()
    ext = format_name  # matches the scaffold's default extension

    fixture_dir  = os.path.join(base_dir, "tests", "formats", format_name)
    fixture_name = f"test_{format_name}_rules.{ext}"
    fixture_path = os.path.join(fixture_dir, fixture_name)

    if os.path.exists(fixture_path):
        print(f"[!] Test fixture already exists at {fixture_path} — skipping.")
        return ""

    os.makedirs(fixture_dir, exist_ok=True)

    template = f"""\
# ============================================================
# RULECAST — {fmt_upper} TEST SUITE
#
# EXPECTED RESULTS (update when adding rules):
#   Total rules  : 0
#   Valid        : 0
#   Invalid      : 0
#
# Run with: python3 main.py test → choose {format_name} → file
# ============================================================
#
# ── HOW TO NAME YOUR RULES ───────────────────────────────────
#
# The test runner reads each rule's name from parse() → identity.name
# and checks the prefix to decide what outcome to expect:
#
#   Valid_    → rule MUST pass validate()   (correct accept)
#   Invalid_  → rule MUST fail validate()   (correct reject)
#   Nasty_    → no expectation             (edge case, result observed)
#
# Make sure your parse() sets identity.name to a string that
# starts with one of those prefixes.
#
# ── SECTIONS ─────────────────────────────────────────────────
#
# Organise rules into the three sections below.
# Cover at least:
#   • Well-formed, representative rules            (Valid_)
#   • Rules with syntax errors the parser must catch (Invalid_)
#   • Legal-but-unusual edge cases if relevant     (Nasty_)
#
# After filling in rules, update the EXPECTED RESULTS header
# so the test runner can verify counts automatically.
#
# ============================================================


# ============================================================
# VALID RULES
# Must pass validate(). identity.name must start with "Valid_"
# ============================================================

# TODO: add valid {fmt_upper} rules here


# ============================================================
# INVALID RULES
# Must fail validate(). identity.name must start with "Invalid_"
# ============================================================

# TODO: add invalid {fmt_upper} rules here (clear syntax errors)


# ============================================================
# NASTY / EDGE-CASE RULES  (optional)
# No pass/fail expectation — result is observed only.
# identity.name must start with "Nasty_"
# ============================================================

# TODO: add edge-case rules here if applicable
"""

    with open(fixture_path, "w", encoding="utf-8") as f:
        f.write(template)

    print(f"[+] Created test fixture: {fixture_path}")
    return fixture_name


def _register_test_file(base_dir: str, format_name: str, fixture_filename: str):
    """Insert the new format into TEST_FILES in tests/test_runner.py."""
    runner_path = os.path.join(base_dir, "tests", "test_runner.py")
    with open(runner_path, "r", encoding="utf-8") as f:
        src = f.read()

    # Already registered? (ignore commented-out lines)
    active_lines = [l for l in src.splitlines() if not l.lstrip().startswith("#")]
    if any(f'("{format_name}",' in l for l in active_lines):
        print(f"[!] {format_name} already in TEST_FILES — skipping test_runner.py update.")
        return

    # Next available numeric key (reads all active "N": entries)
    keys = [int(k) for k in re.findall(r'"(\d+)"\s*:\s*\(', src)]
    next_key = str(max(keys) + 1) if keys else "1"

    new_entry = (
        f'    "{next_key}": ("{format_name}", '
        f'os.path.join(SCRIPT_DIR, "formats", "{format_name}", "{fixture_filename}")),\n'
    )

    # Insert just before the closing } of TEST_FILES
    tf_idx = src.find("TEST_FILES = {")
    if tf_idx == -1:
        print("[!] Cannot find TEST_FILES in test_runner.py — skipping.")
        return

    m = re.search(r'\n}', src[tf_idx:])
    if not m:
        print("[!] Cannot find closing } of TEST_FILES — skipping.")
        return

    insert_pos = tf_idx + m.start() + 1  # points at the } character
    src = src[:insert_pos] + new_entry + src[insert_pos:]

    with open(runner_path, "w", encoding="utf-8") as f:
        f.write(src)

    print(f"[+] Registered {format_name} in tests/test_runner.py (key: {next_key})")


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

    print(f"[+] Created parser: {filepath}")
    _register_parser(base_dir, format_name, class_name)

    fixture_filename = _create_test_fixture(base_dir, format_name)
    if fixture_filename:
        _register_test_file(base_dir, format_name, fixture_filename)

    print()
    print(f"[!] Next steps:")
    print(f"    1. Implement can_handle(), split_rules(), validate(), parse(), normalize()")
    print(f"       in parsers/formats/{format_name}_parser.py")
    print(f"    2. Fill in test rules in tests/formats/{format_name}/test_{format_name}_rules.{format_name}")
    print(f"    3. Update the EXPECTED RESULTS header in the test fixture")
    print(f"    4. Run: python3 main.py test → choose {format_name} → file")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 -m utils.scaffold <format_name>")
    else:
        create_parser_template(sys.argv[1])
