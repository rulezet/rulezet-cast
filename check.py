#!/usr/bin/env python3
"""
RuleCast — Dependency & Parser Health Check

Run after any change (new parser, new library, venv rebuild):
    python3 check.py

Exit codes: 0 = all good, 1 = one or more checks failed.
"""

import sys
import os
import importlib
import importlib.util
import importlib.metadata
import re

# ── colour helpers ────────────────────────────────────────────────────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
GREEN  = "\033[32m"
RED    = "\033[31m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
WHITE  = "\033[97m"

def c(text, *codes): return "".join(codes) + str(text) + RESET
def ok(msg):   print(c("  ✓ ", GREEN, BOLD)  + msg)
def err(msg):  print(c("  ✗ ", RED, BOLD)    + msg)
def info(msg): print(c("  · ", CYAN)         + msg)
def warn(msg): print(c("  ! ", YELLOW, BOLD) + msg)
def sep():     print(c("  " + "─" * 50, DIM))
def title(msg):
    print()
    print(c(f"  {msg}", BOLD, WHITE))
    sep()

# ── pip name → importable module name ────────────────────────────────────────
# Add entries here whenever a new library has a non-obvious import name.

IMPORT_NAME = {
    "yara-python":      "yara",
    "pysigma":          "sigma",
    "suricataparser":   "suricataparser",
    "plyara":           "plyara",
    "msc-pyparser":     "msc_pyparser",
    "idstools":         "idstools",
    "zeekscript":       "zeekscript",
    "lxml":             "lxml",
    "luaparser":        "luaparser",
    "secrules-parsing": "secrules_parsing",
}

# ── step 1: python version ────────────────────────────────────────────────────

def check_python() -> bool:
    title("Python version")
    maj, min_ = sys.version_info[:2]
    ver = f"{maj}.{min_}"
    if (maj, min_) >= (3, 10):
        ok(f"Python {ver}  (>= 3.10 required)")
        return True
    else:
        err(f"Python {ver}  — need >= 3.10")
        return False

# ── step 2: requirements.txt ──────────────────────────────────────────────────

def _parse_requirements(path: str):
    """Return list of (raw_spec, pkg_name) from requirements.txt."""
    pkgs = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Strip version specifiers to get the bare package name
                name = re.split(r'[>=<!@\[]', line)[0].strip()
                pkgs.append((line, name))
    except FileNotFoundError:
        pass
    return pkgs


def check_requirements(req_path: str):
    """Returns (all_ok: bool, missing: list[str])."""
    title("requirements.txt — installed packages")
    specs = _parse_requirements(req_path)
    if not specs:
        warn(f"Could not read {req_path}")
        return False, []

    all_ok  = True
    missing = []
    for spec, pkg_name in specs:
        try:
            version = importlib.metadata.version(pkg_name)
            installed_ok = True
        except importlib.metadata.PackageNotFoundError:
            version = None
            installed_ok = False

        module_name = IMPORT_NAME.get(pkg_name.lower(), pkg_name.replace("-", "_").lower())
        try:
            importlib.import_module(module_name)
            import_ok = True
        except ImportError:
            import_ok = False
        except Exception:
            import_ok = True

        if installed_ok and import_ok:
            ok(f"{pkg_name:<25}  {c(version, DIM)}")
        elif installed_ok and not import_ok:
            warn(f"{pkg_name:<25}  installed ({version}) but import failed — check module name mapping")
            all_ok = False
        else:
            err(f"{pkg_name:<25}  NOT installed")
            missing.append(pkg_name)
            all_ok = False

    return all_ok, missing

# ── step 3: parser-specific smoke imports ─────────────────────────────────────

PARSER_SMOKE = [
    ("YARA",        [("yara",     "compile"),
                     ("plyara",   "Plyara")]),
    ("Sigma",       [("sigma.collection", "SigmaCollection"),
                     ("sigma.rule",       "SigmaRule")]),
    ("Suricata",    [("suricataparser", "parse_rule"),
                     ("suricataparser", "parse_rules")]),
    ("CRS",         [("msc_pyparser", "MSCParser"),
                     ("msc_pyparser", "MSCLexer")]),
]


def check_parser_imports() -> bool:
    title("Parser library smoke tests")
    all_ok = True
    for parser_name, imports in PARSER_SMOKE:
        parser_ok = True
        errors = []
        for module, attr in imports:
            try:
                mod = importlib.import_module(module)
                if not hasattr(mod, attr):
                    errors.append(f"{module}.{attr} not found")
                    parser_ok = False
            except ImportError as e:
                errors.append(str(e))
                parser_ok = False

        if parser_ok:
            ok(f"{parser_name:<14}  all imports OK")
        else:
            err(f"{parser_name:<14}  {'; '.join(errors)}")
            all_ok = False

    return all_ok

# ── step 4: engine + registered parsers ──────────────────────────────────────

def check_engine() -> bool:
    title("Engine — registered parsers")
    root = os.path.dirname(os.path.abspath(__file__))
    if root not in sys.path:
        sys.path.insert(0, root)

    try:
        from parsers.engine import RuleCastEngine
        engine = RuleCastEngine()
    except Exception as e:
        err(f"Could not load RuleCastEngine: {e}")
        return False

    parsers = engine.list_parsers()
    if not parsers:
        warn("No parsers registered in ALL_PARSERS.")
        return False

    all_ok = True
    for p in parsers:
        fmt   = p["format"].ljust(14)
        cls   = p["class"]
        exts  = "  ".join(p["extensions"])
        ok(f"{fmt}  {c(cls, DIM)}  {c(exts, DIM)}")

    # Quick can_handle smoke per parser
    print()
    info("Testing can_handle() on sample snippets …")
    SAMPLES = {
        "yara":     'rule Test { condition: true }',
        "sigma":    'title: Test\ndetection:\n  keywords: test\nlogsource:\n  product: windows',
        "suricata": 'alert tcp any any -> any any (msg:"Test"; sid:1; rev:1;)',
        "crs":      "SecRule ARGS \"@rx <script\" \"id:941100,phase:2,deny,msg:'XSS Test',tag:'OWASP_CRS',ver:'OWASP_CRS/4.0.0'\"",
    }
    for p in parsers:
        fmt = p["format"]
        sample = SAMPLES.get(fmt)
        if sample is None:
            info(f"  {fmt:<14}  no sample snippet defined — skipping can_handle()")
            continue
        try:
            parser_obj = engine.get_parser(fmt)
            result = parser_obj.can_handle(sample)
            if result:
                ok(f"  {fmt:<14}  can_handle() → True")
            else:
                warn(f"  {fmt:<14}  can_handle() → False on own sample!")
                all_ok = False
        except NotImplementedError:
            warn(f"  {fmt:<14}  can_handle() not yet implemented")
            all_ok = False
        except Exception as e:
            err(f"  {fmt:<14}  can_handle() raised: {e}")
            all_ok = False

    return all_ok

# ── step 5: test fixtures ─────────────────────────────────────────────────────

def check_fixtures() -> bool:
    title("Test fixtures")
    runner_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tests", "test_runner.py")
    if not os.path.exists(runner_path):
        warn("tests/test_runner.py not found — skipping fixture check.")
        return True

    # Parse TEST_FILES dict from test_runner.py without importing it
    with open(runner_path, encoding="utf-8") as f:
        src = f.read()

    all_ok = True
    for m in re.finditer(r'"(\w+)"\s*,\s*os\.path\.join\([^)]+\)', src):
        # Extract the tuple value as a path
        pass

    # Simpler: just import the TEST_FILES dict
    try:
        import importlib.util as ilu
        spec   = ilu.spec_from_file_location("test_runner", runner_path)
        module = ilu.module_from_spec(spec)
        # Prevent main() from running
        module.__name__ = "_check_import"
        spec.loader.exec_module(module)
        test_files = getattr(module, "TEST_FILES", {})
    except Exception as e:
        warn(f"Could not read TEST_FILES from test_runner: {e}")
        return True

    if not test_files:
        info("No test fixtures registered in TEST_FILES.")
        return True

    for key, (fmt, path) in test_files.items():
        short = os.path.relpath(path, os.path.dirname(os.path.abspath(__file__)))
        if os.path.exists(path):
            ok(f"[{key}] {fmt:<12}  {short}")
        else:
            err(f"[{key}] {fmt:<12}  {short}  ← FILE MISSING")
            all_ok = False

    return all_ok

# ── programmatic entry-point (used by main.py) ────────────────────────────────

def run_all_checks(req_path: str = None):
    """
    Run every check and return (all_ok: bool, missing_packages: list[str]).
    Designed to be called from main.py without sys.exit().
    """
    if req_path is None:
        req_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "requirements.txt")

    py_ok              = check_python()
    req_ok, missing    = check_requirements(req_path)
    smoke_ok           = check_parser_imports()
    engine_ok          = check_engine()
    fixtures_ok        = check_fixtures()

    all_ok = all([py_ok, req_ok, smoke_ok, engine_ok, fixtures_ok])
    return all_ok, missing

# ── standalone main ───────────────────────────────────────────────────────────

def main():
    print()
    print(c("  RuleCast — Health Check", BOLD, CYAN))
    sep()

    req_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "requirements.txt")
    all_ok, _ = run_all_checks(req_path)

    print()
    sep()
    if all_ok:
        ok(c("All checks passed — environment is healthy.", GREEN, BOLD))
    else:
        err(c("One or more checks failed — see above for details.", RED, BOLD))
    print()

    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
