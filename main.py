#!/usr/bin/env python3
"""
RuleCast CLI — interactive menu + direct commands.

Interactive menu:   python3 main.py
Direct commands:    python3 main.py <command> [options]

Commands:
  parse   -t <text>  [-f <format>]   Parse raw rule text
  parse   -i <file>  [-f <format>]   Parse a rule file
  valid   -t <text>  [-f <format>]   Validate only (no full parse)
  valid   -i <file>  [-f <format>]   Validate a file
  detect  -t <text>                  Detect format of raw text
  detect  -i <file>                  Detect format of a file
  list                               List all registered parsers
  new     <format>                   Scaffold a new parser
  test                               Launch the interactive test runner
"""

import argparse
import json
import os
import sys
import textwrap
from typing import Optional

# ── colour helpers (no external dep) ────────────────────────────────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
GREEN  = "\033[32m"
RED    = "\033[31m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
BLUE   = "\033[34m"
WHITE  = "\033[97m"

def c(text: str, *codes: str) -> str:
    return "".join(codes) + str(text) + RESET

def ok(msg):   print(c("  ✓ ", GREEN, BOLD) + msg)
def err(msg):  print(c("  ✗ ", RED,   BOLD) + msg)
def info(msg): print(c("  · ", CYAN)        + msg)
def warn(msg): print(c("  ! ", YELLOW, BOLD) + msg)

# ── banner ───────────────────────────────────────────────────────────────────

BANNER = f"""
{BOLD}{CYAN}
  ██████╗ ██╗   ██╗██╗     ███████╗ ██████╗ █████╗ ███████╗████████╗
  ██╔══██╗██║   ██║██║     ██╔════╝██╔════╝██╔══██╗██╔════╝╚══██╔══╝
  ██████╔╝██║   ██║██║     █████╗  ██║     ███████║███████╗   ██║
  ██╔══██╗██║   ██║██║     ██╔══╝  ██║     ██╔══██║╚════██║   ██║
  ██║  ██║╚██████╔╝███████╗███████╗╚██████╗██║  ██║███████║   ██║
  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝{RESET}
{DIM}  Security Rule Parser & Normalizer{RESET}
"""

# ── engine (lazy import so errors surface cleanly) ────────────────────────────

def get_engine():
    from parsers.engine import RuleCastEngine
    return RuleCastEngine()

# ── output helpers ────────────────────────────────────────────────────────────

def _print_validation(result, label: str = ""):
    """result can be a ValidationResult or a ParseResult."""
    from parsers.base import ValidationResult as VR
    v = result if isinstance(result, VR) else result.validation
    tag = f" {c(label, DIM)}" if label else ""
    if v.ok:
        ok(f"Valid{tag}")
        for w in v.warnings:
            warn(w)
    else:
        err(f"Invalid{tag}")
        for e in v.errors:
            print(f"     {c(e, RED)}")

def _print_parse_results(results, output_json: bool = False, normalize: bool = False):
    if output_json:
        data = [r.to_dict() for r in results]
        if normalize:
            data = [r.normalized for r in results]
        print(json.dumps(data, indent=2, default=str))
        return

    for i, r in enumerate(results, 1):
        print()
        print(c(f"  Rule {i}/{len(results)}", BOLD, WHITE) +
              c(f"  [{r.format_name}]", CYAN))
        print(c("  " + "─" * 60, DIM))

        _print_validation(r)

        target = r.normalized if normalize else r.parsed
        name = (
            target.get("title")
            or target.get("identity", {}).get("name")
            or "—"
        )
        info(f"Name        : {c(name, BOLD)}")

        if not normalize:
            meta = target.get("metadata", {})
            if meta:
                info(f"Metadata    :")
                for k, v in meta.items():
                    print(f"     {c(k, DIM)} = {v}")
            tags = target.get("tags", [])
            if tags:
                info(f"Tags        : {', '.join(str(t) for t in tags)}")
            vulns = target.get("vulnerabilities", [])
            if vulns:
                info(f"CVEs        : {c(', '.join(vulns), YELLOW)}")
        else:
            for k, v in target.items():
                if k not in ("title",):
                    info(f"{k:<12}: {v}")

def _read_input(text: Optional[str], filepath: Optional[str]) -> str:
    if text:
        return text
    if filepath:
        if not os.path.exists(filepath):
            err(f"File not found: {filepath}")
            sys.exit(1)
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    return ""

# ── commands ──────────────────────────────────────────────────────────────────

def cmd_list(_args):
    engine = get_engine()
    parsers = engine.list_parsers()
    print()
    print(c("  Registered parsers", BOLD))
    print(c("  " + "─" * 40, DIM))
    if not parsers:
        warn("No parsers registered.")
        return
    for p in parsers:
        exts = "  ".join(p["extensions"])
        print(
            f"  {c('●', CYAN)}  {c(p['format'].ljust(12), BOLD, WHITE)}"
            f"  {c(exts, DIM)}"
            f"  {c(p['class'], DIM)}"
        )
    print()


def cmd_detect(args):
    content = _read_input(getattr(args, "text", None), getattr(args, "input", None))
    if not content:
        err("No content. Use -t or -i.")
        return
    engine = get_engine()
    parser = engine.detect_format(content)
    print()
    if parser:
        ok(f"Detected format: {c(parser.format, BOLD, WHITE)}")
        info(f"Parser class : {parser.__class__.__name__}")
        info(f"Extensions   : {', '.join(parser.extensions)}")
    else:
        err("Could not detect format. No registered parser matched this content.")
    print()


def cmd_validate(args):
    content = _read_input(getattr(args, "text", None), getattr(args, "input", None))
    if not content:
        err("No content. Use -t or -i.")
        return

    engine = get_engine()
    fmt = getattr(args, "format", None)

    try:
        parser = engine.get_parser(fmt) if fmt else engine.detect_format(content)
        if not parser:
            err(f"Unknown or undetectable format: {fmt or '(auto)'}")
            return

        rules = parser.split_rules(content)
        print()
        info(f"Format   : {c(parser.format, BOLD)}")
        info(f"Rules    : {c(len(rules), BOLD)}")
        print(c("  " + "─" * 40, DIM))

        valid = 0
        for i, raw in enumerate(rules, 1):
            result = parser.validate(raw)
            name_match = None
            try:
                parsed = parser.parse(raw)
                name_match = parsed.get("identity", {}).get("name") or parsed.get("title")
            except Exception:
                pass
            label = name_match or f"rule #{i}"
            _print_validation(result, label)
            if result.ok:
                valid += 1

        print()
        if valid == len(rules):
            ok(f"All {valid}/{len(rules)} rules valid.")
        else:
            bad = len(rules) - valid
            warn(f"{valid}/{len(rules)} valid  —  {c(bad, RED, BOLD)} invalid")
        print()

    except ValueError as e:
        err(str(e))


def cmd_parse(args):
    content = _read_input(getattr(args, "text", None), getattr(args, "input", None))
    if not content:
        err("No content. Use -t or -i.")
        return

    engine = get_engine()
    fmt = getattr(args, "format", None)
    as_json = getattr(args, "json", False)
    normalized = getattr(args, "normalize", False)

    try:
        results = engine.process(content, fmt)
        print()
        info(f"Format  : {c(results[0].format_name, BOLD) if results else '—'}")
        info(f"Rules   : {c(len(results), BOLD)}")
        _print_parse_results(results, as_json, normalized)
        print()
    except ValueError as e:
        err(str(e))


def cmd_new(args):
    from utils.scaffold import create_parser_template, parse_extensions
    extensions = None
    if args.ext:
        valid, bad = parse_extensions(" ".join(args.ext))
        if bad:
            for b in bad:
                err(f"{c(b, BOLD)} is not a valid extension — skipped")
        extensions = valid or None
    create_parser_template(args.format_name, extensions)


def cmd_test(_args):
    """Launch the interactive test runner (test_runner.py) in the same process."""
    runner_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tests", "test_runner.py")
    if not os.path.exists(runner_path):
        err(f"test_runner.py not found at: {runner_path}")
        return
    import importlib.util
    spec = importlib.util.spec_from_file_location("test_runner", runner_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.main()


def cmd_check(_args):
    _interactive_check()

# ── interactive menu ──────────────────────────────────────────────────────────

MENU_ITEMS = [
    ("parse",    "Parse rules from text or file"),
    ("validate", "Validate syntax only"),
    ("detect",   "Auto-detect rule format"),
    ("list",     "List all registered parsers"),
    ("new",      "Scaffold a new parser"),
    ("test",     "Launch the interactive test runner"),
    ("check",    "Health check — verify dependencies & parsers"),
    ("quit",     "Exit"),
]

def _menu_prompt() -> str:
    print()
    print(c("  What do you want to do?", BOLD))
    print(c("  " + "─" * 40, DIM))
    for i, (key, desc) in enumerate(MENU_ITEMS, 1):
        print(f"  {c(str(i), CYAN, BOLD)}  {c(key.ljust(10), BOLD)}  {c(desc, DIM)}")
    print()
    return input(c("  › ", CYAN, BOLD)).strip()


def _ask(prompt: str, optional: bool = False) -> Optional[str]:
    suffix = c(" (optional, Enter to skip)", DIM) if optional else ""
    val = input(c(f"  {prompt}{suffix}: ", DIM)).strip()
    return val if val else None


def _interactive_parse():
    print()
    mode = input(c("  Input mode — [t]ext or [f]ile: ", DIM)).strip().lower()
    if mode in ("f", "file"):
        path = _ask("File path")
        if not path:
            err("No path given.")
            return
        content = _read_input(None, path)
    else:
        print(c("  Paste your rule(s) below. Enter an empty line + Ctrl+D (or Ctrl+Z on Windows) to finish:", DIM))
        lines = []
        try:
            while True:
                lines.append(input())
        except EOFError:
            pass
        content = "\n".join(lines)

    if not content.strip():
        err("Empty input.")
        return

    fmt = _ask("Format (auto-detect if empty)", optional=True)
    normalized = input(c("  Normalize output for Rulezet? [y/N]: ", DIM)).strip().lower() == "y"
    as_json = input(c("  Output as raw JSON? [y/N]: ", DIM)).strip().lower() == "y"

    engine = get_engine()
    try:
        results = engine.process(content, fmt or None)
        print()
        info(f"Format  : {c(results[0].format_name, BOLD) if results else '—'}")
        info(f"Rules   : {c(len(results), BOLD)}")
        _print_parse_results(results, as_json, normalized)
    except ValueError as e:
        err(str(e))


def _interactive_validate():
    print()
    mode = input(c("  Input mode — [t]ext or [f]ile: ", DIM)).strip().lower()
    if mode in ("f", "file"):
        path = _ask("File path")
        content = _read_input(None, path)
    else:
        print(c("  Paste your rule(s) below. Enter an empty line + Ctrl+D to finish:", DIM))
        lines = []
        try:
            while True:
                lines.append(input())
        except EOFError:
            pass
        content = "\n".join(lines)

    fmt = _ask("Format (auto-detect if empty)", optional=True)

    class _FakeArgs:
        pass
    a = _FakeArgs()
    a.text = content
    a.input = None
    a.format = fmt
    cmd_validate(a)


def _interactive_detect():
    print()
    mode = input(c("  Input mode — [t]ext or [f]ile: ", DIM)).strip().lower()
    if mode in ("f", "file"):
        path = _ask("File path")
        content = _read_input(None, path)
    else:
        print(c("  Paste content below. Ctrl+D to finish:", DIM))
        lines = []
        try:
            while True:
                lines.append(input())
        except EOFError:
            pass
        content = "\n".join(lines)

    class _FakeArgs:
        pass
    a = _FakeArgs()
    a.text = content
    a.input = None
    cmd_detect(a)


def _interactive_new():
    from utils.scaffold import create_parser_template, parse_extensions

    print()
    fmt = _ask("New format name (e.g. sigma, suricata)")
    if not fmt:
        err("No format name given.")
        return

    # Ask for extensions with a validation loop
    print()
    info(f"Extensions for this format (e.g. .yar, .yara — comma or space separated)")
    info(f"Press Enter to use the default: {c(f'.{fmt.lower()}', BOLD)}")
    extensions = None
    while True:
        raw = input(c("  › ", CYAN, BOLD)).strip()
        if not raw:
            break  # keep default
        valid, bad = parse_extensions(raw)
        if bad:
            for b in bad:
                err(f"{c(b, BOLD)} is not a valid extension — must be {c('.letters', BOLD)} (e.g. .yar, .conf)")
        if not valid and not bad:
            break
        if valid:
            extensions = valid
            break
        # had only bad entries — re-ask

    create_parser_template(fmt, extensions)


def _interactive_check():
    import subprocess
    from check import run_all_checks

    req_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "requirements.txt")

    print()
    print(c("  RuleCast — Health Check", BOLD, CYAN))
    print(c("  " + "─" * 50, DIM))

    all_ok, missing = run_all_checks(req_path)

    print()
    print(c("  " + "─" * 50, DIM))
    if all_ok:
        ok(c("All checks passed — environment is healthy.", GREEN, BOLD))
        print()
        return

    err(c("One or more checks failed.", RED, BOLD))
    print()

    if missing:
        warn(f"Missing packages: {c(', '.join(missing), BOLD)}")
        print()
        answer = input(c(
            f"  Auto-install missing packages from requirements.txt? [Y/n]: ", DIM
        )).strip().lower()

        if answer in ("", "y", "yes"):
            print()
            info(f"Running: {c('pip install -r requirements.txt', BOLD)}")
            print()
            try:
                subprocess.check_call(
                    [sys.executable, "-m", "pip", "install", "-r", req_path]
                )
                print()
                ok("Installation complete. Re-running checks …")
                print()
                all_ok2, missing2 = run_all_checks(req_path)
                print()
                if all_ok2:
                    ok(c("All checks now pass — environment is healthy.", GREEN, BOLD))
                else:
                    err("Some checks still fail. Check the output above for details.")
            except subprocess.CalledProcessError as e:
                err(f"pip exited with code {e.returncode}. Fix the error above and retry.")
        else:
            info(f"Skipped. Run manually: {c('pip install -r requirements.txt', BOLD)}")

    print()


def run_interactive():
    print(BANNER)
    while True:
        try:
            choice = _menu_prompt()
        except KeyboardInterrupt:
            print()
            info("Goodbye.")
            print()
            break

        if not choice:
            continue

        # accept number or name
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(MENU_ITEMS):
                choice = MENU_ITEMS[idx][0]
            else:
                err("Invalid choice.")
                continue

        if choice in ("quit", "exit", "q"):
            print()
            info("Goodbye.")
            print()
            break

        try:
            if choice == "parse":
                _interactive_parse()
            elif choice in ("validate", "valid"):
                _interactive_validate()
            elif choice == "detect":
                _interactive_detect()
            elif choice == "list":
                cmd_list(None)
            elif choice == "new":
                _interactive_new()
            elif choice == "test":
                cmd_test(None)
            elif choice == "check":
                _interactive_check()
            else:
                err(f"Unknown command: '{choice}'")
        except KeyboardInterrupt:
            print()
            warn("Cancelled — back to menu.")

# ── argparse (direct mode) ────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="rulecast",
        description="RuleCast — Security Rule Parser & Normalizer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python3 main.py                              # interactive menu
              python3 main.py parse -t 'rule X { condition: true }'
              python3 main.py parse -i rules.yar --json
              python3 main.py validate -i rules.yar -f yara
              python3 main.py detect -t 'alert tcp ...'
              python3 main.py list
              python3 main.py new sigma
              python3 main.py test
        """),
    )
    sub = p.add_subparsers(dest="command")

    # parse
    sp = sub.add_parser("parse", help="Parse and display rule structure")
    grp = sp.add_mutually_exclusive_group(required=True)
    grp.add_argument("-t", "--text",  help="Raw rule text")
    grp.add_argument("-i", "--input", metavar="FILE", help="Path to rule file")
    sp.add_argument("-f", "--format",    help="Force a specific format (skip auto-detect)")
    sp.add_argument("--json",            action="store_true", help="Output raw JSON")
    sp.add_argument("--normalize",       action="store_true", help="Output normalized Rulezet schema")

    # validate
    sv = sub.add_parser("validate", aliases=["valid"], help="Validate rule syntax only")
    grp2 = sv.add_mutually_exclusive_group(required=True)
    grp2.add_argument("-t", "--text",  help="Raw rule text")
    grp2.add_argument("-i", "--input", metavar="FILE", help="Path to rule file")
    sv.add_argument("-f", "--format",  help="Force a specific format")

    # detect
    sd = sub.add_parser("detect", help="Auto-detect rule format")
    grp3 = sd.add_mutually_exclusive_group(required=True)
    grp3.add_argument("-t", "--text",  help="Raw rule text")
    grp3.add_argument("-i", "--input", metavar="FILE", help="Path to rule file")

    # list
    sub.add_parser("list", help="List all registered parsers")

    # new
    sn = sub.add_parser("new", help="Scaffold a new parser")
    sn.add_argument("format_name", help="Format name (e.g. sigma)")
    sn.add_argument("--ext", nargs="+", metavar="EXT",
                    help="File extensions (e.g. --ext .yar .yara)")

    # test
    sub.add_parser("test", help="Launch the interactive test runner")

    # check
    sub.add_parser("check", help="Health check — verify dependencies & parsers")

    return p


DISPATCH = {
    "parse":    cmd_parse,
    "validate": cmd_validate,
    "valid":    cmd_validate,
    "detect":   cmd_detect,
    "list":     cmd_list,
    "new":      cmd_new,
    "test":     cmd_test,
    "check":    cmd_check,
}

# ── entry point ───────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) == 1:
        run_interactive()
        return

    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        run_interactive()
        return

    handler = DISPATCH.get(args.command)
    if handler:
        handler(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()