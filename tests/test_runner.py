#!/usr/bin/env python3
"""
RuleCast — Test Runner
Interactive tool to test parsers against rule files or pasted content.

Usage: python3 test_runner.py
"""

import os
import re
import sys
import json

# ── colour helpers ────────────────────────────────────────────────────────────

RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
GREEN   = "\033[32m"
RED     = "\033[31m"
YELLOW  = "\033[33m"
CYAN    = "\033[36m"
WHITE   = "\033[97m"
MAGENTA = "\033[35m"

def c(text, *codes):
    return "".join(codes) + str(text) + RESET

def ok(msg):    print(c("  ✓ ", GREEN, BOLD) + msg)
def err(msg):   print(c("  ✗ ", RED,   BOLD) + msg)
def info(msg):  print(c("  · ", CYAN)        + msg)
def warn(msg):  print(c("  ! ", YELLOW, BOLD) + msg)
def title(msg): print(c(f"\n  {msg}", BOLD, WHITE))
def sep():      print(c("  " + "─" * 60, DIM))
def blank():    print()

# ── known test files ──────────────────────────────────────────────────────────

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

TEST_FILES = {
    "1": ("yara",     os.path.join(SCRIPT_DIR, "formats", "yara",     "test_yara_rules.yar")),
    "2": ("sigma",    os.path.join(SCRIPT_DIR, "formats", "sigma",    "test_sigma_rules.yml")),
    "3": ("suricata", os.path.join(SCRIPT_DIR, "formats", "suricata", "test_suricata_rules.rules")),
    "4": ("crs",      os.path.join(SCRIPT_DIR, "formats", "crs",      "test_crs_rules.conf")),
    # "4": ("zeek",     os.path.join(SCRIPT_DIR, "formats", "zeek",     "test_zeek_scripts.zeek")),
    # "5": ("wazuh",    os.path.join(SCRIPT_DIR, "formats", "wazuh",    "test_wazuh_rules.xml")),
    # "6": ("nse",      os.path.join(SCRIPT_DIR, "formats", "nse",      "test_nse_scripts.nse")),
    # "7": ("crs",      os.path.join(SCRIPT_DIR, "formats", "crs",      "test_crs_rules.conf")),
    "8": ("nse", os.path.join(SCRIPT_DIR, "formats", "nse", "test_nse_rules.nse")),
    "9": ("nova", os.path.join(SCRIPT_DIR, "formats", "nova", "test_nova_rules.nov")),
}

# ── expected counts from file header ─────────────────────────────────────────

def _parse_expected(filepath: str) -> dict:
    """
    Read the EXPECTED RESULTS header from a test file.
    Looks for lines like:  //   Total rules  : 113
    Returns dict with keys: total, valid, invalid (int, -1 if not found).
    """
    expected = {"total": -1, "valid": -1, "invalid": -1}
    if not filepath or not os.path.exists(filepath):
        return expected
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                for key in expected:
                    m = re.search(
                        rf'(?://|#)\s+{key.capitalize()}\s+\w*\s*:\s*(\d+)',
                        line, re.IGNORECASE
                    )
                    if m:
                        expected[key] = int(m.group(1))
    except Exception:
        pass
    return expected


def _rule_expected_validity(name: str) -> str:
    """
    Infer expected validity from rule name prefix.
    Returns 'valid', 'invalid', or 'unknown'.
    """
    if name.startswith("Valid_"):
        return "valid"
    if name.startswith("Invalid_") or name.startswith("Incomplete_"):
        return "invalid"
    # Nasty_ rules: some valid, some invalid — mark as unknown (no expectation)
    return "unknown"

# ── engine ────────────────────────────────────────────────────────────────────

def get_engine():
    root = os.path.dirname(SCRIPT_DIR)
    sys.path.insert(0, root)
    from parsers.engine import RuleCastEngine
    return RuleCastEngine()

def get_available_formats(engine):
    return [p["format"] for p in engine.list_parsers()]

# ── display ───────────────────────────────────────────────────────────────────

BANNER = f"""
{BOLD}{CYAN}  ╔══════════════════════════════════════╗
  ║     RuleCast — Parser Test Runner    ║
  ╚══════════════════════════════════════╝{RESET}
"""


def print_rule_result(index, total, fmt, raw, validation, parsed, normalized):
    blank()
    name = (
        parsed.get("identity", {}).get("name")
        or parsed.get("title")
        or "unknown"
    )

    # Determine test outcome
    expected = _rule_expected_validity(name)
    actually_valid = validation.ok

    if expected == "valid":
        test_pass = actually_valid        # Valid_ rule must pass validation
    elif expected == "invalid":
        test_pass = not actually_valid    # Invalid_ rule must FAIL validation
    else:
        test_pass = None                  # Nasty_ — no expectation, just show result

    # Icon: shows parser result (✓ valid / ✗ invalid) + test outcome
    if test_pass is True:
        result_icon = c("  ✓", GREEN, BOLD)
    elif test_pass is False:
        result_icon = c("  ✗", RED, BOLD)
    else:
        # Nasty_: show cyan dot + actual result
        result_icon = c("  ·", CYAN, BOLD)

    verdict = ""
    if expected == "invalid" and not actually_valid:
        verdict = c("  [correctly rejected]", GREEN)
    elif expected == "invalid" and actually_valid:
        verdict = c("  [FALSE POSITIVE]", RED, BOLD)
    elif expected == "valid" and not actually_valid:
        verdict = c("  [FALSE NEGATIVE]", RED, BOLD)

    print(
        f"{result_icon}  "
        f"{c(f'Rule {index}/{total}', BOLD)}  "
        f"{c(name, CYAN)}"
        f"{verdict}"
        f"  {c(f'[{fmt}]', DIM)}"
    )

    # Only show errors for rules that surprise us
    if not actually_valid and expected != "invalid":
        for e in validation.errors:
            print(f"     {c('error:', RED)} {e}")
    if validation.warnings:
        for w in validation.warnings:
            print(f"     {c('warn:', YELLOW)} {w}")

    status = parsed.get("status", "")
    if status == "parsing_error" and expected != "invalid":
        parse_err = parsed.get("error", "")
        print(f"     {c('parse:', YELLOW)} fallback used — {parse_err[:80]}")

    tags = parsed.get("tags", [])
    if tags:
        print(f"     {c('tags:', DIM)} {', '.join(str(t) for t in tags)}")

    vulns = parsed.get("vulnerabilities", [])
    if vulns:
        print(f"     {c('CVEs:', YELLOW)} {', '.join(vulns)}")

    meta = parsed.get("metadata", {})
    if meta and expected != "invalid":
        items = list(meta.items())[:3]
        for k, v in items:
            print(f"     {c(k + ':', DIM)} {str(v)[:60]}")
        if len(meta) > 3:
            print(f"     {c(f'... +{len(meta)-3} more metadata fields', DIM)}")


def _check_line(label: str, found: int, expected: int, reverse: bool = False):
    """
    reverse=True: 'found' should equal 'expected', but
    the metric is "correctly handled" so we always want found == expected.
    """
    if expected == -1:
        info(f"{label:<22}: {c(found, BOLD)}")
        return True
    if found == expected:
        print(f"{c('  ✓ ', GREEN, BOLD)}{label:<22}: {c(found, GREEN, BOLD)}  {c(f'(expected {expected})', DIM)}")
        return True
    else:
        print(f"{c('  ✗ ', RED, BOLD)}{label:<22}: {c(found, RED, BOLD)}  {c(f'expected {expected}, diff {found - expected:+d}', YELLOW)}")
        return False


def print_summary(results, expected: dict):
    blank()
    sep()

    total   = len(results)
    valid   = sum(1 for r in results if r.validation.ok)
    invalid = total - valid

    parsed_ok = sum(1 for r in results if r.parsed.get("status") == "parsed")
    fallback  = sum(1 for r in results if r.parsed.get("status") == "parsing_error")

    # ── per-rule test outcomes ──
    # A "test" passes when:
    #   - Valid_*    rule → validation.ok == True  (correctly accepted)
    #   - Invalid_*  rule → validation.ok == False (correctly rejected)
    #   - Incomplete_* rule → validation.ok == False (correctly rejected)
    # Nasty_* rules have no expectation → counted separately

    expected_valid_pass   = 0  # Valid_ rules that passed   → correct
    expected_valid_fail   = 0  # Valid_ rules that failed   → false negative
    expected_invalid_pass = 0  # Invalid_ rules that failed → correct (detected)
    expected_invalid_fail = 0  # Invalid_ rules that passed → false positive
    nasty_count           = 0
    nasty_valid           = 0

    for r in results:
        name = r.parsed.get("identity", {}).get("name") or ""
        exp  = _rule_expected_validity(name)
        ok_  = r.validation.ok

        if exp == "valid":
            if ok_: expected_valid_pass += 1
            else:   expected_valid_fail += 1
        elif exp == "invalid":
            if not ok_: expected_invalid_pass += 1
            else:       expected_invalid_fail += 1
        else:
            nasty_count += 1
            if ok_: nasty_valid += 1

    total_tested   = expected_valid_pass + expected_valid_fail + expected_invalid_pass + expected_invalid_fail
    total_correct  = expected_valid_pass + expected_invalid_pass
    total_wrong    = expected_valid_fail + expected_invalid_fail

    title("Summary")

    # ── counts ──
    _check_line("Total rules",   total,   expected["total"])
    _check_line("Valid",         valid,   expected["valid"])
    _check_line("Invalid",       invalid, expected["invalid"])
    blank()

    # ── test outcomes ──
    print(c("  Test outcomes", BOLD))
    print(c("  " + "─" * 40, DIM))

    # Valid_ rules
    _check_line("Valid rules pass",    expected_valid_pass, expected_valid_pass + expected_valid_fail)
    if expected_valid_fail:
        print(f"    {c('↳ false negatives:', RED)} {expected_valid_fail}  (valid rules rejected by parser)")

    # Invalid_ rules — this is the key insight
    _check_line("Invalid detected",    expected_invalid_pass, expected_invalid_pass + expected_invalid_fail)
    if expected_invalid_fail:
        print(f"    {c('↳ false positives:', RED)} {expected_invalid_fail}  (invalid rules accepted by parser)")

    # Nasty_ rules
    if nasty_count:
        info(f"{'Nasty rules':<22}: {nasty_valid} valid / {nasty_count - nasty_valid} invalid  {c('(no expectation)', DIM)}")

    # Parser quality stats
    blank()
    print(c("  Parser stats", BOLD))
    print(c("  " + "─" * 40, DIM))
    info(f"{'Parsed (AST)':<22}: {c(parsed_ok, BOLD)}")
    info(f"{'Fallback used':<22}: {c(fallback, YELLOW, BOLD) if fallback else c('0', DIM)}")

    # ── final verdict ──
    blank()
    all_counts_ok = (
        (expected["total"]   == -1 or total   == expected["total"]) and
        (expected["valid"]   == -1 or valid   == expected["valid"]) and
        (expected["invalid"] == -1 or invalid == expected["invalid"])
    )
    test_suite_pass = total_wrong == 0 and all_counts_ok

    if test_suite_pass:
        ok(c(f"All {total_correct} tests passed — parser behaves as expected.", GREEN, BOLD))
    else:
        lines = []
        if expected_valid_fail:
            lines.append(f"{expected_valid_fail} false negative(s)")
        if expected_invalid_fail:
            lines.append(f"{expected_invalid_fail} false positive(s)")
        if not all_counts_ok:
            lines.append("count mismatch")
        err(c(f"Issues: {', '.join(lines)}", RED))
    blank()

# ── step 1: choose format ─────────────────────────────────────────────────────

def step_choose_format(engine):
    formats = get_available_formats(engine)
    blank()
    title("Which format do you want to test?")
    sep()
    for i, fmt in enumerate(formats, 1):
        print(f"  {c(str(i), CYAN, BOLD)}  {c(fmt.upper(), BOLD)}")
    blank()
    while True:
        choice = input(c("  › ", CYAN, BOLD)).strip().lower()
        if choice.isdigit() and 1 <= int(choice) <= len(formats):
            return formats[int(choice) - 1]
        if choice in formats:
            return choice
        err(f"Invalid choice. Enter a number (1-{len(formats)}) or format name.")

# ── step 2: choose source ─────────────────────────────────────────────────────

def step_choose_source(fmt):
    blank()
    title("Input source")
    sep()
    print(f"  {c('p', CYAN, BOLD)}  Paste rules directly")
    print(f"  {c('f', CYAN, BOLD)}  Load from file")
    blank()
    while True:
        choice = input(c("  › ", CYAN, BOLD)).strip().lower()
        if choice in ("p", "paste"):
            return _read_paste(), None
        if choice in ("f", "file"):
            return _read_file(fmt)
        err("Enter 'p' for paste or 'f' for file.")

def _read_paste():
    blank()
    print(c("  Paste your rules below.", BOLD))
    print(c("  Press Enter on a blank line then Ctrl+D (or Ctrl+Z on Windows) to finish.", DIM))
    blank()
    lines = []
    try:
        while True:
            lines.append(input())
    except EOFError:
        pass
    content = "\n".join(lines).strip()
    if not content:
        err("Nothing pasted.")
        sys.exit(1)
    return content

def _read_file(fmt):
    blank()
    title("File source")
    sep()
    matching = {k: v for k, v in TEST_FILES.items() if v[0] == fmt}
    if matching:
        print(c("  Known test files for this format:", DIM))
        for num, (f, path) in matching.items():
            exists = os.path.exists(path)
            status = c("✓", GREEN) if exists else c("✗ missing", RED)
            short  = os.path.relpath(path, SCRIPT_DIR)
            print(f"  {c(num, CYAN, BOLD)}  {short}  {status}")
        blank()
        print(c("  Enter a number from above, or type a custom file path:", DIM))
    else:
        print(c(f"  No built-in test files for '{fmt}' yet.", YELLOW))
        print(c("  Enter the path to your rule file:", DIM))
    blank()
    while True:
        raw = input(c("  › ", CYAN, BOLD)).strip()
        if not raw:
            err("No input."); continue
        if raw in TEST_FILES:
            _, path = TEST_FILES[raw]
            if not os.path.exists(path):
                err(f"File not found: {path}"); continue
            ok(f"Loaded: {os.path.relpath(path, SCRIPT_DIR)}")
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read(), path
        path = os.path.expanduser(raw)
        if not os.path.exists(path):
            err(f"File not found: {path}"); continue
        ok(f"Loaded: {path}")
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read(), path

# ── step 3: run pipeline ──────────────────────────────────────────────────────

def run_pipeline(engine, content, fmt):
    blank()
    info(f"Format   : {c(fmt.upper(), BOLD)}")
    try:
        parser = engine.get_parser(fmt)
        if not parser:
            err(f"No parser registered for '{fmt}'."); sys.exit(1)
        raw_rules = parser.split_rules(content)
        info(f"Rules found : {c(len(raw_rules), BOLD)}")
        sep()
        results = []
        for raw in raw_rules:
            validation = parser.validate(raw)
            parsed     = parser.parse(raw)
            normalized = parser.normalize(parsed)
            from parsers.engine import ParseResult
            results.append(ParseResult(raw, validation, parsed, normalized, fmt))
        return results, parser
    except Exception as e:
        err(f"Pipeline error: {e}"); sys.exit(1)

# ── step 4: display + post menu ───────────────────────────────────────────────

def display_results(results, fmt, expected: dict):
    total = len(results)
    for i, r in enumerate(results, 1):
        print_rule_result(i, total, fmt, r.raw, r.validation, r.parsed, r.normalized)
    print_summary(results, expected)


def post_menu(results, fmt):
    while True:
        print_detail_menu()
        choice = input(c("  › ", CYAN, BOLD)).strip().lower()

        if choice == "j":
            data = [r.to_dict() for r in results]
            out_path = os.path.join(SCRIPT_DIR, f"results_{fmt}.json")
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
            ok(f"Saved to {out_path}")

        elif choice == "n":
            blank(); title("Normalized output"); sep()
            for r in results:
                name = r.normalized.get("title") or "unknown"
                print(f"\n  {c(name, CYAN, BOLD)}")
                for k, v in r.normalized.items():
                    if k != "title" and v:
                        print(f"  {c(k.ljust(14), DIM)}: {str(v)[:80]}")

        elif choice == "f":
            # Show only rules where the test FAILED (false positives / false negatives)
            failures = []
            for r in results:
                name = r.parsed.get("identity", {}).get("name") or ""
                exp  = _rule_expected_validity(name)
                ok_  = r.validation.ok
                if exp == "valid" and not ok_:
                    failures.append((r, "false negative — valid rule rejected"))
                elif exp == "invalid" and ok_:
                    failures.append((r, "false positive — invalid rule accepted"))

            if not failures:
                ok("No test failures — parser behaves correctly on all named rules!")
            else:
                blank(); title(f"{len(failures)} test failure(s)"); sep()
                for r, reason in failures:
                    name = r.parsed.get("identity", {}).get("name") or "unknown"
                    print(f"\n  {c('✗', RED, BOLD)}  {c(name, BOLD)}  {c(reason, YELLOW)}")
                    for e in r.validation.errors:
                        print(f"     {c(e, RED)}")
                    blank()
                    print(c("  Raw content:", DIM))
                    preview = r.raw[:200].replace("\n", "\n  ")
                    print(c(f"  {preview}{'...' if len(r.raw) > 200 else ''}", DIM))

        elif choice in ("r", "restart"):
            return "restart"

        elif choice in ("q", "quit", "exit"):
            blank(); info("Goodbye."); blank()
            return "quit"

        else:
            err(f"Unknown option: '{choice}'")


def print_detail_menu():
    blank()
    print(c("  What now?", BOLD))
    sep()
    print(f"  {c('j', CYAN, BOLD)}  Export full JSON results")
    print(f"  {c('n', CYAN, BOLD)}  Show normalized output only")
    print(f"  {c('f', CYAN, BOLD)}  Show only test failures (false positives / negatives)")
    print(f"  {c('r', CYAN, BOLD)}  Run again with different input")
    print(f"  {c('q', CYAN, BOLD)}  Quit")
    blank()

# ── main ──────────────────────────────────────────────────────────────────────

def main():
    print(BANNER)
    try:
        engine = get_engine()
    except ImportError as e:
        print(c(f"  [error] Could not load engine: {e}", RED))
        print(c("  Make sure you run this from the rulezet-cast root directory.", DIM))
        sys.exit(1)

    while True:
        fmt            = step_choose_format(engine)
        content, fpath = step_choose_source(fmt)
        expected       = _parse_expected(fpath)
        results, _     = run_pipeline(engine, content, fmt)
        display_results(results, fmt, expected)
        action         = post_menu(results, fmt)
        if action == "quit":
            break

if __name__ == "__main__":
    main()